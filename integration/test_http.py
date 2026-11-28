"""Real HTTP refusal boundaries on the placed PostgreSQL-backed service."""

import httpx
import pytest
from awid.registry import RegistryClient

from approval_service.grading import EnrollmentGrading
from approval_service.http import create_app
from approval_service.public import PublicReader

from .test_requester_registry import listener


@pytest.mark.asyncio
async def test_browser_origin_and_closed_bodies_are_checked_before_login_or_requests(
    store,
):
    app = create_app(
        store,
        public=PublicReader(RegistryClient(registry_url="http://127.0.0.1:1")),
        origin="https://approval.example.test",
        rp_id="approval.example.test",
        grading=EnrollmentGrading("passkey_only", None),
    )
    async with (
        listener(app) as (base, _server),
        httpx.AsyncClient(base_url=base, timeout=10.0) as client,
    ):
        for origin in (None, "https://foreign.example.test"):
            headers = {} if origin is None else {"Origin": origin}
            r = await client.post("/browser/login/options", json={}, headers=headers)
            assert r.status_code == 403
            assert r.json()["error"]["code"] == "origin_invalid"
        r = await client.post(
            "/browser/login/options",
            json={"person": "did:aw:anyone"},
            headers={"Origin": "https://approval.example.test"},
        )
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "body_invalid"
        assert await store.db.fetch_one(
            "SELECT count(*) AS n FROM {{tables.approval_challenges}}"
        ) == {"n": 0}
        r = await client.post(
            "/browser/login/options",
            json={},
            headers={"Origin": "https://approval.example.test"},
        )
        assert r.status_code == 200
        assert r.json()["allowCredentials"] == []
        r = await client.get("/")
        assert "script-src" in r.headers["content-security-policy"]
        assert "https://" not in r.text
        assert "http://" not in r.text
        r = await client.post(
            "/v1/requests/submit",
            content=b'{"version":1,"version":1}',
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "body_invalid"


@pytest.mark.asyncio
async def test_database_liveness_stays_healthy_while_hardware_readiness_alerts(store):
    from datetime import UTC, datetime, timedelta

    from vendor import Vendor, signed_metadata

    from approval_service.metadata import load_snapshot

    now = datetime.now(UTC)
    signed_at = now - timedelta(days=2)
    snapshot = load_snapshot(
        **signed_metadata(
            [Vendor(now=signed_at).entry()],
            next_update=now - timedelta(days=1),
            now=signed_at,
        )
    )
    grading = EnrollmentGrading("hardware", snapshot)
    assert grading.status()["enrollment_ready"] is False
    app = create_app(
        store,
        public=PublicReader(RegistryClient(registry_url="http://127.0.0.1:1")),
        origin="https://approval.example.test",
        rp_id="approval.example.test",
        grading=grading,
    )
    async with (
        listener(app) as (base, _server),
        httpx.AsyncClient(base_url=base, timeout=10.0) as client,
    ):
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["enrollment_ready"] is False
        response = await client.get("/health/enrollment")
        assert response.status_code == 503
        assert response.json()["enrollment_ready"] is False
        assert response.json()["metadata"]["warning"]


@pytest.mark.asyncio
async def test_trusted_proxy_keeps_separate_real_browser_rate_budgets(store):
    from approval_service.cli import server_config

    app = create_app(
        store,
        public=PublicReader(RegistryClient(registry_url="http://127.0.0.1:1")),
        origin="https://approval.example.test",
        rp_id="approval.example.test",
        grading=EnrollmentGrading("passkey_only", None),
    )
    # Keep the real fixed-minute window intact across this short HTTP burst.
    import asyncio
    import time

    remaining = 60 - time.monotonic() % 60
    if remaining < 5:
        await asyncio.sleep(remaining + 0.05)
    config = server_config(app, bind="127.0.0.1", port=0, trusted_proxy_ips="127.0.0.1")
    async with (
        listener(app, config=config) as (base, _server),
        httpx.AsyncClient(base_url=base, timeout=10.0) as client,
    ):
        for address in ("192.0.2.1", "192.0.2.2"):
            for _ in range(60):
                response = await client.post(
                    "/browser/login/options",
                    json={"person": "no-enrollment-lookup"},
                    headers={
                        "Origin": "https://approval.example.test",
                        "X-Forwarded-For": address,
                    },
                )
                assert response.status_code == 400
            response = await client.post(
                "/browser/login/options",
                json={},
                headers={
                    "Origin": "https://approval.example.test",
                    "X-Forwarded-For": address,
                },
            )
            assert response.status_code == 429
