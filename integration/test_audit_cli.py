"""The installed audit command paginates real refreshes and never migrates."""

import asyncio
import json
import os
import sys
import time
import uuid
from dataclasses import replace
from importlib.resources import files
from pathlib import Path

import pytest
from awid.did import did_from_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pgdbm import AsyncMigrationManager

from approval_service.binding_refresh import BindingRefresher
from approval_service.store import Store

from .test_binding_refresh import refresh_packet
from .test_ceremonies import active_port


async def audit_command(store, *, after, limit):
    environment = {
        **os.environ,
        "AWSIGN_DATABASE_URL": os.environ["APPROVAL_TEST_DATABASE_URL"],
        "AWSIGN_DATABASE_SCHEMA": store.schema,
    }
    environment.pop("PYTHONPATH", None)
    child = await asyncio.create_subprocess_exec(
        str(Path(sys.executable).with_name("awsign")),
        "audit-binding-refreshes",
        "--after",
        str(after),
        "--limit",
        str(limit),
        env=environment,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        output, error = await asyncio.wait_for(child.communicate(), 15)
        return child.returncode, output, error
    finally:
        if child.returncode is None:
            child.terminate()
            await asyncio.wait_for(child.communicate(), 10)


async def applied_migrations(store):
    return [
        row["filename"]
        for row in await store.db.fetch_all(
            "SELECT filename FROM {{tables.schema_migrations}} "
            "WHERE module_name='awsign' ORDER BY filename"
        )
    ]


@pytest.mark.asyncio
async def test_installed_audit_command_returns_bounded_json_from_actual_refreshes(
    store,
):
    world, trust, _ = await active_port(store)
    binding = world["receipt"]["binding"]
    refresher = BindingRefresher(store)
    for _ in range(2):
        issuer = Ed25519PrivateKey.generate()
        public_key = issuer.public_key().public_bytes_raw()
        trust = replace(
            trust,
            issuer=did_from_public_key(public_key),
            issuer_public_key=public_key,
            observed_at=int(time.time()),
        )
        packet, carrier = refresh_packet(binding, trust=trust, issuer=issuer)
        await refresher.refresh(packet, trust=trust, carrier=carrier)
        binding = packet["binding"]
    expected = await refresher.audit()
    assert len(expected) == 2
    migrations_before = await applied_migrations(store)
    after = 0
    for row in expected:
        code, output, error = await audit_command(store, after=after, limit=1)
        assert code == 0, error.decode()
        assert json.loads(output) == [row]
        after = row["audit_id"]
    code, output, error = await audit_command(store, after=after, limit=1)
    assert code == 0, error.decode()
    assert json.loads(output) == []
    assert await applied_migrations(store) == migrations_before


@pytest.mark.asyncio
async def test_audit_command_refuses_database_at_003_without_applying_004(tmp_path):
    packaged = files("approval_service").joinpath("migrations")
    names = sorted(
        item.name for item in packaged.iterdir() if item.name.endswith(".sql")
    )
    previous = [name for name in names if name < "004"]
    assert len(previous) == 3
    for name in previous:
        (tmp_path / name).write_text(packaged.joinpath(name).read_text())
    store = Store(
        os.environ["APPROVAL_TEST_DATABASE_URL"],
        schema="approval_audit_" + uuid.uuid4().hex,
    )
    await store.connect()
    try:
        await AsyncMigrationManager(
            store.db, migrations_path=str(tmp_path), module_name="awsign"
        ).apply_pending_migrations()
        assert await applied_migrations(store) == previous
        code, output, error = await audit_command(store, after=0, limit=1)
        assert code != 0
        assert output == b""
        assert b"Run awsign migrate before starting this service" in error
        assert await applied_migrations(store) == previous
    finally:
        await store.db.execute('DROP SCHEMA "' + store.schema + '" CASCADE')
        await store.close()
