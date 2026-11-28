"""Start the product command with its normal locked SDK and real PostgreSQL."""

import asyncio
import os
import re
import uuid
from importlib.resources import files
from pathlib import Path

import httpx
import pytest
from pgdbm import AsyncMigrationManager

from approval_service.store import Store


async def listening_url(child):
    startup_log = []
    while line := await child.stderr.readline():
        startup_log.append(line)
        listening = re.search(rb"Uvicorn running on (http://127\.0\.0\.1:\d+)", line)
        if listening:
            return listening.group(1).decode()
    raise AssertionError(b"".join(startup_log).decode(errors="replace"))


@pytest.mark.asyncio
async def test_serve_refuses_database_at_002_without_applying_003(tmp_path):
    migrations = files("approval_service").joinpath("migrations")
    for name in ("001_initial.sql", "002_queue_bounds.sql"):
        (tmp_path / name).write_text(migrations.joinpath(name).read_text())
    store = Store(
        os.environ["APPROVAL_TEST_DATABASE_URL"],
        schema="approval_startup_" + uuid.uuid4().hex,
    )
    await store.connect()
    child = None
    try:
        await AsyncMigrationManager(
            store.db, migrations_path=str(tmp_path), module_name="awsign"
        ).apply_pending_migrations()
        env = {
            **os.environ,
            "AWSIGN_DATABASE_URL": os.environ["APPROVAL_TEST_DATABASE_URL"],
            "AWSIGN_DATABASE_SCHEMA": store.schema,
            "AWSIGN_GRADING": "passkey_only",
        }
        env.pop("PYTHONPATH", None)
        child = await asyncio.create_subprocess_exec(
            "uv",
            "run",
            "--frozen",
            "awsign",
            "serve",
            "--port",
            "0",
            cwd=Path(__file__).parents[1],
            env=env,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, error = await asyncio.wait_for(child.communicate(), 10)
        assert child.returncode != 0
        assert b"Run awsign migrate before starting this service" in error
        assert [
            row["filename"]
            for row in await store.db.fetch_all(
                "SELECT filename FROM {{tables.schema_migrations}} WHERE module_name='awsign' ORDER BY filename"
            )
        ] == ["001_initial.sql", "002_queue_bounds.sql"]
        assert await store.db.fetch_one(
            "SELECT 1 FROM information_schema.columns WHERE table_schema=$1 AND table_name='approval_credentials' AND column_name='attestation'",
            store.schema,
        )
    finally:
        if child is not None and child.returncode is None:
            child.terminate()
            await asyncio.wait_for(child.communicate(), 10)
        await store.db.execute('DROP SCHEMA "' + store.schema + '" CASCADE')
        await store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode,health_status", [("passkey_only", 200), ("hardware", 503)]
)
async def test_locked_product_starts_and_reports_metadata_readiness(
    store, tmp_path, mode, health_status
):
    env = {
        **os.environ,
        "AWSIGN_DATABASE_URL": os.environ["APPROVAL_TEST_DATABASE_URL"],
        "AWSIGN_DATABASE_SCHEMA": store.schema,
        "AWSIGN_ORIGIN": "https://approval.example.test",
        "AWSIGN_RP_ID": "approval.example.test",
        "AWSIGN_GRADING": mode,
        "AWSIGN_MDS_CACHE": str(tmp_path / "cache"),
        "AWSIGN_MDS_MANIFEST": str(tmp_path / "not-installed.json"),
    }
    # The broader registry suite can overlay its frozen source. This startup
    # check must use the standalone project's actual installed resolution.
    env.pop("PYTHONPATH", None)
    root = Path(__file__).parents[1]
    child = await asyncio.create_subprocess_exec(
        "uv",
        "run",
        "--frozen",
        "awsign",
        "serve",
        "--bind",
        "127.0.0.1",
        "--port",
        "0",
        cwd=root,
        env=env,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        # Use the port actually bound by the child and one deadline for readiness
        # and sign-in. A short connection probe is not a budget for a database write.
        async with (
            asyncio.timeout(10),
            httpx.AsyncClient(timeout=None, trust_env=False) as client,
        ):
            base = await listening_url(child)
            response = await client.get(f"{base}/health")
            assert response.status_code == 200
            assert response.json()["enrollment_ready"] is (health_status == 200)
            response = await client.get(f"{base}/health/enrollment")
            assert response.status_code == health_status
            assert response.json()["enrollment_ready"] is (health_status == 200)
            # Missing hardware metadata must not take sign-in down.
            response = await client.post(
                f"{base}/browser/login/options",
                json={},
                headers={"Origin": env["AWSIGN_ORIGIN"]},
            )
            assert response.status_code == 200
            assert response.json()["allowCredentials"] == []
    finally:
        if child.returncode is None:
            child.terminate()
        await asyncio.wait_for(child.communicate(), 10)
