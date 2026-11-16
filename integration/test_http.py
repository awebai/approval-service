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
        public=PublicReader(RegistryClient()),
        origin="https://approval.example.test",
        rp_id="approval.example.test",
        grading=EnrollmentGrading("passkey_only", None),
    )
    async with (
        listener(app) as (base, _server),
        httpx.AsyncClient(base_url=base) as client,
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
