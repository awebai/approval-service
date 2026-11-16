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


def signed_submit_body(*, kind="team_member", chain=None):
    import base64
    import copy
    import json
    import time
    from pathlib import Path

    from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
    from awid.signing import sign_message

    from approval_service.canonical import canonical
    from approval_service.encoding import encode
    from approval_service.seams import http_authorization

    private, public = generate_keypair()
    key = did_from_public_key(public)
    team_private, _team_public = generate_keypair()
    descriptor = {
        "kind": "team_member",
        "team_id": "private:customer.example",
        "certificate_id": "fixture-certificate",
        "key": key,
    }
    cert = {
        "version": 1,
        "certificate_id": descriptor["certificate_id"],
        "team_id": descriptor["team_id"],
        "member_did_key": key,
        "alias": "requester",
    }
    cert["signature"] = sign_message(team_private, canonical(cert))
    admission = {
        "team_certificate": base64.b64encode(canonical(cert)).decode(),
        "id_chain": [],
    }
    if kind == "identity":
        descriptor = {"kind": "identity", "id": stable_id_from_did_key(key), "key": key}
        admission = {"team_certificate": None, "id_chain": chain}
    r = copy.deepcopy(
        json.loads(
            (
                Path(__file__).parents[1] / "vectors/enforcer-requester-v1.json"
            ).read_text()
        )["cases"][0]["request"]
    )
    r.update(
        requester=descriptor,
        not_before=int(time.time()) - 1,
        deadline=int(time.time()) + 120,
    )
    body = {"version": 1, "request_bytes": encode(canonical(r)), "admission": admission}
    raw = canonical(body)
    authorization = http_authorization(
        raw,
        seed=private,
        requester=descriptor,
        origin="https://approval.example.test",
        purpose="submit",
        issued_at=int(time.time()),
    )
    return raw, authorization


@pytest.mark.asyncio
async def test_registry_outage_and_malformed_evidence_keep_the_closed_http_contract(
    store,
):
    import socket

    # A reserved but non-listening real TCP endpoint refuses connections.
    with socket.socket() as unavailable:
        unavailable.bind(("127.0.0.1", 0))
        bad = f"http://127.0.0.1:{unavailable.getsockname()[1]}"
        app = create_app(
            store,
            public=PublicReader(RegistryClient(registry_url=bad, timeout_seconds=1.0)),
            origin="https://approval.example.test",
            rp_id="approval.example.test",
            grading=EnrollmentGrading("passkey_only", None),
        )
        async with (
            listener(app) as (base, _server),
            httpx.AsyncClient(base_url=base, timeout=10.0) as client,
        ):
            for kind, chain, expected in [
                ("team_member", None, 503),
                ("identity", [{"malformed": True}], 400),
            ]:
                raw, auth = signed_submit_body(kind=kind, chain=chain)
                response = await client.post(
                    "/v1/requests/submit",
                    content=raw,
                    headers={"Authorization": auth, "Content-Type": "application/json"},
                )
                assert response.status_code == expected
                assert set(response.json()) == {"version", "error"}
                assert response.json()["error"]["code"] == (
                    "status_unavailable"
                    if expected == 503
                    else "public_evidence_invalid"
                )
                assert response.headers["cache-control"] == "no-store"
                assert "script-src" in response.headers["content-security-policy"]


@pytest.mark.asyncio
async def test_database_liveness_stays_healthy_while_hardware_readiness_alerts(store):
    from datetime import timedelta

    from vendor import NOW, Vendor, signed_metadata

    from approval_service.metadata import load_snapshot

    inputs = signed_metadata([Vendor().entry()], next_update=NOW)
    inputs["now"] = NOW - timedelta(hours=23)
    snapshot = load_snapshot(**inputs)
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
