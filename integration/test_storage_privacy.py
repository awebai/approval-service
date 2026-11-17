"""Upgrade actual PostgreSQL state without retaining private attestation bytes."""

import json
import os
import uuid
from importlib.resources import files

import asyncpg
import pytest
from pgdbm import AsyncMigrationManager

from approval_service.store import Store


@pytest.mark.asyncio
async def test_upgrade_discards_raw_attestation_and_unused_registration_challenges(
    tmp_path,
):
    migrations = files("approval_service").joinpath("migrations")
    for name in ("001_initial.sql", "002_queue_bounds.sql"):
        (tmp_path / name).write_text(migrations.joinpath(name).read_text())
    store = Store(
        os.environ["APPROVAL_TEST_DATABASE_URL"],
        schema="approval_privacy_" + uuid.uuid4().hex,
    )
    await store.connect()
    try:
        await AsyncMigrationManager(
            store.db, migrations_path=str(tmp_path), module_name="awsign"
        ).apply_pending_migrations()
        # Legacy storage fixture, not an enrollment or authority shortcut.
        await store.db.execute(
            """INSERT INTO {{tables.approval_enrollments}}
            (organisation,person_id,identity_key,certificate,issuer,user_handle,
             deadline,state,enrollment_locator,requester_hash,requester_key)
            VALUES('example.test','person','key','cert','issuer',$1,2000,
                   'pending','locator','hash','key')""",
            b"user",
        )
        await store.db.execute(
            """INSERT INTO {{tables.approval_credentials}}
            (organisation,person_id,credential_id,public_key,sign_count,grade,
             attestation,registration,binding_entry,enrollment_locator)
            VALUES('example.test','person','credential',$1,0,'passkey_uv',
                   $2,'{"pending":true}','{}','locator')""",
            b"public-key",
            b"private-legacy-attestation",
        )
        await store.db.execute(
            """INSERT INTO {{tables.approval_challenges}}
            (challenge_id,organisation,person_id,purpose,challenge,issued_at,
             deadline,enrollment_locator)
            VALUES('unused','example.test','person','registration',$1,1000,
                   1100,'locator')""",
            b"challenge",
        )
        await store.migrate()
        row = await store.db.fetch_one("SELECT * FROM {{tables.approval_credentials}}")
        assert "attestation" not in row
        # Pending material remains available to the issuer until activation.
        assert json.loads(row["registration"]) == {"pending": True}
        assert not await store.db.fetch_all(
            "SELECT * FROM {{tables.approval_challenges}}"
        )
        with pytest.raises(asyncpg.CheckViolationError) as refused:
            await store.db.execute(
                """INSERT INTO {{tables.approval_challenges}}
                (challenge_id,organisation,person_id,purpose,challenge,issued_at,
                 deadline,enrollment_locator)
                VALUES('refused','example.test','person','registration',$1,
                       1000,1100,'locator')""",
                b"challenge",
            )
        assert refused.value.constraint_name == "approval_challenges_purpose_check"
        for purpose in ("login", "approval"):
            await store.db.execute(
                """INSERT INTO {{tables.approval_challenges}}
                (challenge_id,organisation,person_id,purpose,challenge,issued_at,
                 deadline,enrollment_locator)
                VALUES($1,'example.test','person',$1,$2,1000,1100,'locator')""",
                purpose,
                b"challenge",
            )
        assert (await store.migrate())["status"] == "up_to_date"
    finally:
        await store.db.execute('DROP SCHEMA "' + store.schema + '" CASCADE')
        await store.close()
