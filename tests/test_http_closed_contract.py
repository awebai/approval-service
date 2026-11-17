"""Real signed HTTP inputs and TCP admission failure need no SQL fixture."""

import httpx
import pytest
from awid.registry import RegistryClient

from approval_service.grading import EnrollmentGrading
from approval_service.http import create_app
from approval_service.public import PublicReader


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
async def test_registry_outage_and_malformed_evidence_keep_the_closed_http_contract():
    import socket

    # A reserved but non-listening real TCP endpoint refuses connections.
    with socket.socket() as unavailable:
        unavailable.bind(("127.0.0.1", 0))
        bad = f"http://127.0.0.1:{unavailable.getsockname()[1]}"
        app = create_app(
            None,
            public=PublicReader(RegistryClient(registry_url=bad, timeout_seconds=1.0)),
            origin="https://approval.example.test",
            rp_id="approval.example.test",
            grading=EnrollmentGrading("passkey_only", None),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://approval.example.test",
            timeout=10.0,
        ) as client:
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
