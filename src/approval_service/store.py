"""Approval service's own PostgreSQL state. No org keys or external effect state."""

from __future__ import annotations

import hashlib
import json
import re
from contextlib import contextmanager
from importlib.resources import files

import psycopg
from psycopg import sql
from psycopg.rows import dict_row


class StoreRefused(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class Store:
    def __init__(self, dsn: str, *, schema="approval"):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema):
            raise ValueError("invalid schema")
        self._dsn = dsn
        self.schema = schema

    @contextmanager
    def connection(self):
        with psycopg.connect(self._dsn, autocommit=True, row_factory=dict_row) as conn:
            conn.execute(
                sql.SQL("SET search_path TO {}").format(sql.Identifier(self.schema))
            )
            yield conn

    def migrate(self):
        """Explicit installation command, never invoked by a read/startup check."""
        with (
            psycopg.connect(self._dsn, autocommit=True, row_factory=dict_row) as conn,
            conn.transaction(),
        ):
            conn.execute(
                sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(
                    sql.Identifier(self.schema)
                )
            )
            conn.execute(
                sql.SQL("SET LOCAL search_path TO {}").format(
                    sql.Identifier(self.schema)
                )
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS approval_schema_migrations(name text PRIMARY KEY, sha256 text NOT NULL)"
            )
            for path in sorted(
                files("approval_service").joinpath("migrations").iterdir(),
                key=lambda p: p.name,
            ):
                if not path.name.endswith(".sql"):
                    continue
                raw = path.read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                old = conn.execute(
                    "SELECT sha256 FROM approval_schema_migrations WHERE name=%s",
                    (path.name,),
                ).fetchone()
                if old:
                    if old["sha256"] != digest:
                        raise StoreRefused("migration_changed")
                    continue
                conn.execute(raw.decode())
                conn.execute(
                    "INSERT INTO approval_schema_migrations VALUES(%s,%s)",
                    (path.name, digest),
                )

    @staticmethod
    def _terminal(conn, row, outcome, now, assertion=None, binding_ref=None):
        changed = conn.execute(
            """UPDATE approval_requests SET outcome=%s, decided_at=%s,
            request_bytes=NULL, assertion=%s::jsonb,binding_ref=%s WHERE operation_id=%s AND outcome='pending'
            RETURNING *""",
            (
                outcome,
                now,
                json.dumps(assertion) if assertion is not None else None,
                binding_ref,
                row["operation_id"],
            ),
        ).fetchone()
        if changed is None:
            raise StoreRefused("already_decided")
        conn.execute(
            "INSERT INTO approval_audit(operation_id,digest,person_id,decided_at,outcome) VALUES(%s,%s,%s,%s,%s)",
            (row["operation_id"], row["digest"], row["person_id"], now, outcome),
        )
        return changed

    @staticmethod
    def _expire(conn, row, now):
        if now >= row["deadline"]:
            if row["outcome"] == "pending":
                row = Store._terminal(conn, row, "expired", now)
            if row["assertion"] is not None:
                conn.execute(
                    "UPDATE approval_requests SET assertion=NULL WHERE operation_id=%s",
                    (row["operation_id"],),
                )
                row = {**row, "assertion": None}
        return row

    def prepare(
        self,
        operation_id,
        digest,
        requester_hash,
        person_id,
        request_bytes,
        now,
        deadline,
    ):
        if deadline <= now:
            raise StoreRefused("request_expired")
        with self.connection() as conn, conn.transaction():
            # Bound duplicate admission and queue accounting for this requester.
            conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                (requester_hash,),
            )
            owned = conn.execute(
                "SELECT * FROM approval_requests WHERE operation_id=%s FOR UPDATE",
                (operation_id,),
            ).fetchone()
            if owned:
                if (owned["digest"], owned["requester_hash"], owned["person_id"]) != (
                    digest,
                    requester_hash,
                    person_id,
                ):
                    raise StoreRefused("selection_conflict")
                return self._expire(conn, owned, now)
            old = conn.execute(
                "SELECT * FROM approval_requests WHERE requester_hash=%s AND digest=%s FOR UPDATE",
                (requester_hash, digest),
            ).fetchone()
            if old:
                return self._expire(conn, old, now)
            count = conn.execute(
                "SELECT count(*) AS n FROM approval_requests WHERE requester_hash=%s AND outcome='pending' AND deadline>%s",
                (requester_hash, now),
            ).fetchone()["n"]
            if count >= 32:
                raise StoreRefused("pending_limit")
            row = conn.execute(
                """INSERT INTO approval_requests(operation_id,digest,requester_hash,person_id,request_bytes,created_at,deadline)
                VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING *""",
                (
                    operation_id,
                    digest,
                    requester_hash,
                    person_id,
                    request_bytes,
                    now,
                    deadline,
                ),
            ).fetchone()
            if row is None:
                raise StoreRefused("selection_conflict")
            return row

    def pending(self, person_id, now=None):
        with self.connection() as conn:
            if now is None:
                return conn.execute(
                    "SELECT * FROM approval_requests WHERE person_id=%s AND outcome='pending' ORDER BY created_at LIMIT 128",
                    (person_id,),
                ).fetchall()
            return conn.execute(
                "SELECT * FROM approval_requests WHERE person_id=%s AND outcome='pending' AND deadline>%s ORDER BY created_at LIMIT 128",
                (person_id, now),
            ).fetchall()

    def decide(self, operation_id, digest, requester_hash, assertion, binding_ref, now):
        """Trusted storage primitive, not an approval API. Ceremonies use _terminal
        inside their own single challenge/session/counter/decision transaction.
        """
        with self.connection() as conn, conn.transaction():
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE operation_id=%s FOR UPDATE",
                (operation_id,),
            ).fetchone()
            if row is None or (row["digest"], row["requester_hash"]) != (
                digest,
                requester_hash,
            ):
                raise StoreRefused("request_not_found")
            if row["outcome"] != "pending":
                raise StoreRefused("already_decided")
            if now >= row["deadline"]:
                raise StoreRefused("request_expired")
            return self._terminal(conn, row, "approved", now, assertion, binding_ref)

    def refuse(self, operation_id, person_id, outcome, now):
        if outcome not in ("denied", "cancelled"):
            raise StoreRefused("invalid_outcome")
        with self.connection() as conn, conn.transaction():
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE operation_id=%s AND person_id=%s FOR UPDATE",
                (operation_id, person_id),
            ).fetchone()
            if row is None:
                raise StoreRefused("request_not_found")
            if now >= row["deadline"]:
                return self._expire(conn, row, now)
            return self._terminal(conn, row, outcome, now)

    def poll(self, operation_id, digest, requester_hash, now):
        # A normal pending/terminal read takes no transaction or exclusive lock.
        # Only expiry changes state; re-read under the row lock for that act.
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE operation_id=%s AND digest=%s AND requester_hash=%s",
                (operation_id, digest, requester_hash),
            ).fetchone()
            if row is None:
                raise StoreRefused("request_not_found")
            if now >= row["deadline"] and (
                row["outcome"] == "pending" or row["assertion"] is not None
            ):
                with conn.transaction():
                    row = conn.execute(
                        "SELECT * FROM approval_requests WHERE operation_id=%s AND digest=%s AND requester_hash=%s FOR UPDATE",
                        (operation_id, digest, requester_hash),
                    ).fetchone()
                    if row is None:
                        raise StoreRefused("request_not_found")
                    row = self._expire(conn, row, now)
            return {
                **row,
                "receipt_available": row["assertion"] is not None
                and now < row["deadline"],
            }

    def audit(self, operation_id):
        with self.connection() as conn:
            return conn.execute(
                "SELECT digest,person_id,decided_at,outcome FROM approval_audit WHERE operation_id=%s",
                (operation_id,),
            ).fetchall()

    def cleanup(self, now):
        with self.connection() as conn, conn.transaction():
            rows = conn.execute(
                "SELECT * FROM approval_requests WHERE deadline<=%s AND (outcome='pending' OR assertion IS NOT NULL) ORDER BY deadline LIMIT 128 FOR UPDATE SKIP LOCKED",
                (now,),
            ).fetchall()
            for row in rows:
                self._expire(conn, row, now)
            return len(rows)
