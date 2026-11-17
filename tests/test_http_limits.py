"""Real ASGI requests: per-IP work bounds precede parsing and admission."""

import httpx
import pytest
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.registry import RegistryClient

from approval_service.grading import EnrollmentGrading
from approval_service.http import create_app
from approval_service.public import PublicReader


@pytest.mark.asyncio
async def test_ip_budget_cannot_be_reset_by_descriptors_paths_or_forwarded_headers():
    app = create_app(
        None,
        public=PublicReader(RegistryClient("http://127.0.0.1:1")),
        origin="https://approval.example.test",
        rp_id="approval.example.test",
        grading=EnrollmentGrading("passkey_only", None),
        requests_per_ip=3,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("192.0.2.1", 1234)),
        base_url="https://approval.example.test",
    ) as caller:
        for n in range(3):
            _, pub = generate_keypair()
            r = await caller.post(
                "/v1/requests/submit",
                json={"requester": {"key": did_from_public_key(pub)}},
                headers={"X-Forwarded-For": f"198.51.100.{n + 1}"},
            )
            assert r.status_code == 400 and r.json()["error"]["code"] == "body_invalid"
        r = await caller.post(
            "/v1/enrollments/start",
            content=b"not JSON",
            headers={"X-Forwarded-For": "203.0.113.8"},
        )
        assert r.status_code == 429 and r.json()["error"]["code"] == "rate_limited"
        assert (
            r.headers["cache-control"] == "no-store"
            and "content-security-policy" in r.headers
        )
        assert (await caller.get("/")).status_code == 200
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("192.0.2.2", 1234)),
        base_url="https://approval.example.test",
    ) as other:
        r = await other.post("/v1/requests/submit", content=b"not JSON")
        assert r.status_code == 400 and r.json()["error"]["code"] == "body_invalid"


@pytest.mark.asyncio
async def test_missing_peer_has_a_shared_finite_budget():
    app = create_app(
        None,
        public=None,
        origin="https://approval.example.test",
        rp_id="approval.example.test",
        grading=EnrollmentGrading("passkey_only", None),
        requests_per_ip=1,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=None),
        base_url="https://approval.example.test",
    ) as caller:
        assert (await caller.get("/v1/missing")).status_code == 404
        assert (await caller.get("/v1/another")).status_code == 429


@pytest.mark.asyncio
async def test_one_signing_key_cannot_reset_its_budget_with_identity_descriptors():
    import copy
    import json
    import time
    from pathlib import Path

    from approval_service.canonical import canonical, parse
    from approval_service.encoding import decode, encode
    from approval_service.seams import http_authorization

    cases = json.loads(
        (Path(__file__).parents[1] / "vectors/requester-service-v1.json").read_text()
    )["cases"]
    case = next(
        c
        for c in cases
        if c.get("accept") and c.get("purpose") == "submit" and "test_signing_seed" in c
    )
    packet = parse(decode(case["body"]))
    original = parse(decode(packet["request_bytes"]))
    import asyncio

    remaining = 60 - time.monotonic() % 60
    if remaining < 3:
        await asyncio.sleep(remaining + 0.05)
    registry = RegistryClient("http://127.0.0.1:1")
    app = create_app(
        None,
        public=PublicReader(registry),
        origin=case["origin"],
        rp_id=case["origin"][len("https://") :],
        grading=EnrollmentGrading("passkey_only", None),
    )
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=case["origin"]
        ) as client:
            for n in range(100):
                r = copy.deepcopy(original)
                r["requester"]["id"] = stable_id_from_did_key(
                    did_from_public_key(generate_keypair()[1])
                )
                r["enforcer"]["audience"] = "https://holder.example.test"
                r["not_before"] = int(time.time()) - 1
                r["deadline"] = int(time.time()) + 120
                body = canonical(
                    {
                        **packet,
                        "admission": {"team_certificate": None, "id_chain": []},
                        "request_bytes": encode(canonical(r)),
                    }
                )
                header = http_authorization(
                    body,
                    seed=decode(case["test_signing_seed"]),
                    requester=r["requester"],
                    origin=case["origin"],
                    purpose="submit",
                    issued_at=int(time.time()),
                )
                answer = await client.post(
                    "/v1/requests/submit",
                    content=body,
                    headers={"Authorization": header},
                )
                assert answer.json()["error"]["code"] == (
                    "identity_chain_required" if n < 32 else "rate_limited"
                )
    finally:
        await registry.aclose()
