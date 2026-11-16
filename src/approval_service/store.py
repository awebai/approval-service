"""Approval service's pooled PostgreSQL state. No org keys or external effects."""

from __future__ import annotations

import json
import re
import time
from importlib.resources import files

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager, DatabaseConfig


class StoreRefused(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def request_row(row):
    """asyncpg keeps JSON as text; expose only the explicit retained assertion."""
    if row is not None and isinstance(row["assertion"], str):
        return {**row, "assertion": json.loads(row["assertion"])}
    return row


class Store:
    def __init__(
        self, dsn: str, *, schema="approval", min_connections=1, max_connections=10
    ):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema):
            raise ValueError("invalid schema")
        self.schema = schema
        self.db = AsyncDatabaseManager(
            DatabaseConfig(
                connection_string=dsn,
                schema=schema,
                min_connections=min_connections,
                max_connections=max_connections,
                server_settings={"application_name": "awsign"},
            )
        )

    async def connect(self):
        """One pool for the process lifespan, shared by ceremonies and polling."""
        await self.db.connect()

    async def close(self):
        await self.db.disconnect()

    async def migrate(self):
        """Explicit installation command; the shared runner owns checksums/locking."""
        return await AsyncMigrationManager(
            self.db,
            migrations_path=str(files("approval_service").joinpath("migrations")),
            module_name="awsign",
        ).apply_pending_migrations()

    def transaction(self):
        return self.db.transaction()

    @staticmethod
    async def _terminal(tx, row, outcome, now, assertion=None, binding_ref=None):
        changed = await tx.fetch_one(
            """UPDATE {{tables.approval_requests}} SET outcome=$1, decided_at=$2,
            request_bytes=NULL, admission=NULL, assertion=$3::jsonb,binding_ref=$4
            WHERE operation_id=$5 AND outcome='pending' RETURNING *""",
            outcome,
            now,
            json.dumps(assertion) if assertion is not None else None,
            binding_ref,
            row["operation_id"],
        )
        if changed is None:
            raise StoreRefused("already_decided")
        await tx.execute(
            "INSERT INTO {{tables.approval_audit}}(operation_id,digest,person_id,decided_at,outcome) VALUES($1,$2,$3,$4,$5)",
            row["operation_id"],
            row["digest"],
            row["person_id"],
            now,
            outcome,
        )
        return request_row(changed)

    @staticmethod
    async def _expire(tx, row, now):
        if now >= row["deadline"]:
            if row["outcome"] == "pending":
                row = await Store._terminal(tx, row, "expired", now)
            if row["assertion"] is not None:
                await tx.execute(
                    "UPDATE {{tables.approval_requests}} SET assertion=NULL WHERE operation_id=$1",
                    row["operation_id"],
                )
                row = {**row, "assertion": None}
        return request_row(row)

    async def prepare(
        self,
        operation_id,
        digest,
        requester_hash,
        person_id,
        request_bytes,
        now,
        deadline,
        *,
        admission=None,
    ):
        if deadline <= now:
            raise StoreRefused("request_expired")
        async with self.transaction() as tx:
            # Serialize this requester's bounded queue and duplicate admission only.
            await tx.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", requester_hash
            )
            owned = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_requests}} WHERE operation_id=$1 FOR UPDATE",
                operation_id,
            )
            if owned:
                if (owned["digest"], owned["requester_hash"], owned["person_id"]) != (
                    digest,
                    requester_hash,
                    person_id,
                ):
                    raise StoreRefused("selection_conflict")
                return await self._expire(tx, owned, now)
            old = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_requests}} WHERE requester_hash=$1 AND digest=$2 FOR UPDATE",
                requester_hash,
                digest,
            )
            if old:
                return await self._expire(tx, old, now)
            count = await tx.fetch_one(
                "SELECT count(*) AS n FROM {{tables.approval_requests}} WHERE requester_hash=$1 AND outcome='pending' AND deadline>$2",
                requester_hash,
                now,
            )
            if count["n"] >= 32:
                raise StoreRefused("pending_limit")
            row = await tx.fetch_one(
                """INSERT INTO {{tables.approval_requests}}(operation_id,digest,requester_hash,person_id,request_bytes,created_at,deadline,admission)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb) ON CONFLICT DO NOTHING RETURNING *""",
                operation_id,
                digest,
                requester_hash,
                person_id,
                request_bytes,
                now,
                deadline,
                json.dumps(admission) if admission is not None else None,
            )
            if row is None:
                raise StoreRefused("selection_conflict")
            return request_row(row)

    async def pending(self, person_id, now=None):
        if now is None:
            rows = await self.db.fetch_all(
                "SELECT * FROM {{tables.approval_requests}} WHERE person_id=$1 AND outcome='pending' ORDER BY created_at LIMIT 128",
                person_id,
            )
        else:
            rows = await self.db.fetch_all(
                "SELECT * FROM {{tables.approval_requests}} WHERE person_id=$1 AND outcome='pending' AND deadline>$2 ORDER BY created_at LIMIT 128",
                person_id,
                now,
            )
        return [request_row(row) for row in rows]

    async def refuse(self, operation_id, person_id, outcome, now):
        if outcome not in ("denied", "cancelled"):
            raise StoreRefused("invalid_outcome")
        async with self.transaction() as tx:
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_requests}} WHERE operation_id=$1 AND person_id=$2 FOR UPDATE",
                operation_id,
                person_id,
            )
            if row is None:
                raise StoreRefused("request_not_found")
            if now >= row["deadline"]:
                return await self._expire(tx, row, now)
            return await self._terminal(tx, row, outcome, now)

    async def poll(self, operation_id, digest, requester_hash, now):
        # An ordinary read acquires a pooled connection, without a transaction or
        # exclusive lock. Only the expiry act re-reads under the row lock.
        query = "SELECT * FROM {{tables.approval_requests}} WHERE operation_id=$1 AND digest=$2 AND requester_hash=$3"
        args = (operation_id, digest, requester_hash)
        row = await self.db.fetch_one(query, *args)
        if row is None:
            raise StoreRefused("request_not_found")
        if now >= row["deadline"] and (
            row["outcome"] == "pending" or row["assertion"] is not None
        ):
            async with self.transaction() as tx:
                row = await tx.fetch_one(query + " FOR UPDATE", *args)
                if row is None:
                    raise StoreRefused("request_not_found")
                row = await self._expire(tx, row, now)
        row = request_row(row)
        return {
            **row,
            "receipt_available": row["assertion"] is not None and now < row["deadline"],
        }

    async def audit(self, operation_id):
        return await self.db.fetch_all(
            "SELECT digest,person_id,decided_at,outcome FROM {{tables.approval_audit}} WHERE operation_id=$1",
            operation_id,
        )

    async def cleanup(self, now):
        async with self.transaction() as tx:
            rows = await tx.fetch_all(
                "SELECT * FROM {{tables.approval_requests}} WHERE deadline<=$1 AND (outcome='pending' OR assertion IS NOT NULL) ORDER BY deadline LIMIT 128 FOR UPDATE SKIP LOCKED",
                now,
            )
            for row in rows:
                await self._expire(tx, row, now)
            return len(rows)

    async def decision_answer(self, row, locator, *, db=None):
        in_transaction = db is not None
        db = self.db if db is None else db
        answer = {
            "version": 1,
            "locator": locator,
            "digest": row["digest"],
            "deadline": row["deadline"],
            "state": row["outcome"],
            "approval": None,
        }
        row = request_row(row)
        if row["assertion"] is not None:
            version = await db.fetch_one(
                "SELECT binding,id_chain FROM {{tables.approval_binding_versions}} WHERE digest=$1",
                row["binding_ref"],
            )
            if version is None:
                raise StoreRefused("binding_unavailable")
            answer["approval"] = {
                "assertion": row["assertion"],
                "binding": json.loads(version["binding"]),
                "id_chain": json.loads(version["id_chain"]),
            }
        # SQL waits cannot keep an assertion readable beyond its original slot.
        now = int(time.time())
        if answer["approval"] is not None and now >= row["deadline"]:
            if in_transaction:
                await self._expire(db, row, now)
            else:
                await self.poll(
                    row["operation_id"], row["digest"], row["requester_hash"], now
                )
            answer["approval"] = None
        return answer

    async def cancel(self, operation_id, digest, requester_hash, now):
        async with self.transaction() as tx:
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_requests}} WHERE operation_id=$1 AND digest=$2 AND requester_hash=$3 FOR UPDATE",
                operation_id,
                digest,
                requester_hash,
            )
            if row is None:
                raise StoreRefused("request_not_found")
            if now >= row["deadline"]:
                return await self._expire(tx, row, now)
            if row["outcome"] == "pending":
                row = await self._terminal(tx, row, "cancelled", now)
            return request_row(row)
