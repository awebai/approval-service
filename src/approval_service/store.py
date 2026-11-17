"""Approval service's pooled, organisation-scoped PostgreSQL state."""

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
    if row is not None and isinstance(row["assertion"], str):
        return {**row, "assertion": json.loads(row["assertion"])}
    return row


class Store:
    def __init__(
        self, dsn, *, schema="approval", min_connections=1, max_connections=10
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
        await self.db.connect()

    async def close(self):
        await self.db.disconnect()

    async def migrate(self):
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
            """UPDATE {{tables.approval_requests}} SET outcome=$1,decided_at=$2,
            request_bytes=NULL,admission=NULL,assertion=$3::jsonb,binding_ref=$4
            WHERE organisation=$5 AND person_id=$6 AND operation_id=$7 AND outcome='pending' RETURNING *""",
            outcome,
            now,
            json.dumps(assertion) if assertion is not None else None,
            binding_ref,
            row["organisation"],
            row["person_id"],
            row["operation_id"],
        )
        if changed is None:
            raise StoreRefused("already_decided")
        await tx.execute(
            "INSERT INTO {{tables.approval_audit}}(organisation,person_id,operation_id,digest,decided_at,outcome) VALUES($1,$2,$3,$4,$5,$6)",
            row["organisation"],
            row["person_id"],
            row["operation_id"],
            row["digest"],
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
                    "UPDATE {{tables.approval_requests}} SET assertion=NULL WHERE organisation=$1 AND person_id=$2 AND operation_id=$3",
                    row["organisation"],
                    row["person_id"],
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
        organisation,
        requester_key,
        admission=None,
    ):
        if deadline <= now:
            raise StoreRefused("request_expired")
        async with self.transaction() as tx:
            await tx.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                organisation + ":" + requester_key,
            )
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_requests}} WHERE organisation=$1 AND person_id=$2 AND operation_id=$3 FOR UPDATE",
                organisation,
                person_id,
                operation_id,
            )
            if row:
                if (row["digest"], row["requester_hash"]) != (digest, requester_hash):
                    raise StoreRefused("selection_conflict")
                return await self._expire(tx, row, now)
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_requests}} WHERE organisation=$1 AND person_id=$2 AND requester_hash=$3 AND digest=$4 FOR UPDATE",
                organisation,
                person_id,
                requester_hash,
                digest,
            )
            if row:
                return await self._expire(tx, row, now)
            count = await tx.fetch_one(
                "SELECT count(*) AS n FROM {{tables.approval_requests}} WHERE organisation=$1 AND requester_key=$2 AND outcome='pending' AND deadline>$3",
                organisation,
                requester_key,
                now,
            )
            if count["n"] >= 32:
                raise StoreRefused("pending_limit")
            # Never look up enrollment here: a foreign/mistyped approver gets the
            # same submit answer but cannot see this row in any person's list.
            row = await tx.fetch_one(
                """INSERT INTO {{tables.approval_requests}}(organisation,person_id,operation_id,digest,requester_hash,request_bytes,created_at,deadline,admission,requester_key)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10) ON CONFLICT DO NOTHING RETURNING *""",
                organisation,
                person_id,
                operation_id,
                digest,
                requester_hash,
                request_bytes,
                now,
                deadline,
                json.dumps(admission) if admission is not None else None,
                requester_key,
            )
            if row is None:
                raise StoreRefused("selection_conflict")
            return request_row(row)

    async def pending(self, person_id, *, organisation, now=None):
        query = "SELECT *,row_number() OVER (PARTITION BY requester_key ORDER BY created_at,operation_id) AS queue_turn FROM {{tables.approval_requests}} WHERE organisation=$1 AND person_id=$2 AND outcome='pending'"
        args = [organisation, person_id]
        if now is not None:
            query += " AND deadline>$3"
            args.append(now)
        rows = await self.db.fetch_all(
            "SELECT * FROM ("
            + query
            + ") fair ORDER BY queue_turn,created_at,requester_key,operation_id LIMIT 128",
            *args,
        )
        return [request_row(row) for row in rows]

    async def poll(
        self, operation_id, digest, requester_hash, now, *, organisation, person_id
    ):
        query = "SELECT * FROM {{tables.approval_requests}} WHERE organisation=$1 AND person_id=$2 AND operation_id=$3 AND digest=$4 AND requester_hash=$5"
        args = (organisation, person_id, operation_id, digest, requester_hash)
        # Ordinary polling takes a pooled read, no exclusive lock or transaction.
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

    async def cleanup(self, now):
        async with self.transaction() as tx:
            rows = await tx.fetch_all(
                "SELECT * FROM {{tables.approval_requests}} WHERE deadline<=$1 AND (outcome='pending' OR assertion IS NOT NULL) ORDER BY deadline LIMIT 128 FOR UPDATE SKIP LOCKED",
                now,
            )
            for row in rows:
                await self._expire(tx, row, now)
            cutoff = now - 30 * 86400
            await tx.execute(
                "DELETE FROM {{tables.approval_challenges}} WHERE challenge_id IN (SELECT challenge_id FROM {{tables.approval_challenges}} WHERE deadline<=$1 ORDER BY deadline LIMIT 128 FOR UPDATE SKIP LOCKED)",
                cutoff,
            )
            await tx.execute(
                "DELETE FROM {{tables.approval_sessions}} WHERE token_hash IN (SELECT token_hash FROM {{tables.approval_sessions}} WHERE deadline<=$1 ORDER BY deadline LIMIT 128 FOR UPDATE SKIP LOCKED)",
                cutoff,
            )
            # Confirmation rows are part of retained enrollment state: an
            # approved confirmation permits activation after the ceremony.
            await tx.execute(
                """DELETE FROM {{tables.approval_requests}} r WHERE (r.organisation,r.person_id,r.operation_id) IN (
                SELECT q.organisation,q.person_id,q.operation_id FROM {{tables.approval_requests}} q
                WHERE q.outcome<>'pending' AND q.decided_at<=$1
                AND NOT EXISTS (SELECT 1 FROM {{tables.approval_enrollments}} e WHERE e.organisation=q.organisation AND e.person_id=q.person_id AND e.confirmation_id=q.operation_id)
                AND NOT EXISTS (SELECT 1 FROM {{tables.approval_challenges}} c WHERE c.organisation=q.organisation AND c.person_id=q.person_id AND c.operation_id=q.operation_id)
                ORDER BY q.decided_at LIMIT 128 FOR UPDATE OF q SKIP LOCKED)""",
                cutoff,
            )
            return len(rows)

    async def decision_answer(self, row, locator, *, db=None):
        in_transaction = db is not None
        db = self.db if db is None else db
        row = request_row(row)
        answer = {
            "version": 1,
            "locator": locator,
            "digest": row["digest"],
            "deadline": row["deadline"],
            "state": row["outcome"],
            "approval": None,
        }
        if row["assertion"] is not None:
            version = await db.fetch_one(
                "SELECT binding,id_chain FROM {{tables.approval_binding_versions}} WHERE digest=$1 AND organisation=$2 AND person_id=$3",
                row["binding_ref"],
                row["organisation"],
                row["person_id"],
            )
            if version is None:
                raise StoreRefused("binding_unavailable")
            answer["approval"] = {
                "assertion": row["assertion"],
                "binding": json.loads(version["binding"]),
                "id_chain": json.loads(version["id_chain"]),
            }
        now = int(time.time())
        if answer["approval"] is not None and now >= row["deadline"]:
            if in_transaction:
                await self._expire(db, row, now)
            else:
                await self.poll(
                    row["operation_id"],
                    row["digest"],
                    row["requester_hash"],
                    now,
                    organisation=row["organisation"],
                    person_id=row["person_id"],
                )
            answer["approval"] = None
        return answer

    async def cancel(
        self, operation_id, digest, requester_hash, now, *, organisation, person_id
    ):
        async with self.transaction() as tx:
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_requests}} WHERE organisation=$1 AND person_id=$2 AND operation_id=$3 AND digest=$4 AND requester_hash=$5 FOR UPDATE",
                organisation,
                person_id,
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
