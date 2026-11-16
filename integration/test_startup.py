"""Start the product command with its normal locked SDK and real PostgreSQL."""

import asyncio
import os
import socket
from pathlib import Path

import httpx
import pytest


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
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    child = await asyncio.create_subprocess_exec(
        "uv",
        "run",
        "--frozen",
        "awsign",
        "serve",
        "--bind",
        "127.0.0.1",
        "--port",
        str(port),
        cwd=root,
        env=env,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        deadline = asyncio.get_running_loop().time() + 10
        async with httpx.AsyncClient(timeout=0.3, trust_env=False) as client:
            while (
                asyncio.get_running_loop().time() < deadline
                and child.returncode is None
            ):
                try:
                    response = await client.get(f"http://127.0.0.1:{port}/health")
                    break
                except httpx.TransportError:
                    await asyncio.sleep(0.02)
            else:
                raise AssertionError("normal locked service did not start")
            assert response.status_code == health_status
            assert response.json()["enrollment_ready"] is (health_status == 200)
            # Missing hardware metadata must not take sign-in down.
            response = await client.post(
                f"http://127.0.0.1:{port}/browser/login/options",
                json={},
                headers={"Origin": env["AWSIGN_ORIGIN"]},
            )
            assert response.status_code == 200
            assert response.json()["allowCredentials"] == []
    finally:
        if child.returncode is None:
            child.terminate()
        await asyncio.wait_for(child.communicate(), 10)
