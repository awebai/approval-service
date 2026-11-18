"""A refresh uses its own covering authorization, preserving existing headers."""

import pytest
from awid.did import did_from_public_key
from nacl.signing import SigningKey

from approval_service.canonical import canonical
from approval_service.seams import check_http, http_authorization


def test_current_person_can_cover_the_additive_binding_refresh_route():
    signer = SigningKey.generate()
    requester = {
        "kind": "identity",
        "id": "did:aw:person-p",
        "key": did_from_public_key(bytes(signer.verify_key)),
    }
    body = canonical({"version": 1, "requester": requester})
    header = http_authorization(
        body,
        seed=bytes(signer),
        requester=requester,
        origin="https://approval.example.test",
        purpose="binding_refresh",
        issued_at=1000,
    )
    checked = check_http(
        header,
        body,
        requester=requester,
        origin="https://approval.example.test",
        method="POST",
        path="/v1/enrollment-bindings/refresh",
        purpose="binding_refresh",
        now=1001,
    )
    assert checked["key"] == requester["key"]


@pytest.mark.asyncio
async def test_refresh_budget_uses_the_signing_key_before_any_public_read():
    import time

    import httpx
    from receipts import fixture

    from approval_service.grading import EnrollmentGrading
    from approval_service.http import create_app
    from approval_service.public import PublicReader

    signer = SigningKey.generate()
    key = did_from_public_key(bytes(signer.verify_key))
    app = create_app(
        None,
        public=PublicReader(None),
        origin="https://approval.example.test",
        rp_id="approval.example.test",
        grading=EnrollmentGrading("passkey_only", None),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://approval.example.test"
    ) as client:
        for index in range(33):
            requester = {
                "kind": "identity",
                "id": "did:aw:different-" + str(index),
                "key": key,
            }
            packet = {
                "version": 1,
                "requester": requester,
                "previous_binding_commitment": "sha256:" + "a" * 64,
                "binding": fixture()["receipt"]["binding"],
                "id_chain": [{}],
            }
            raw = canonical(packet)
            header = http_authorization(
                raw,
                seed=bytes(signer),
                requester=requester,
                origin="https://approval.example.test",
                purpose="binding_refresh",
                issued_at=int(time.time()),
            )
            response = await client.post(
                "/v1/enrollment-bindings/refresh",
                content=raw,
                headers={"Authorization": header},
            )
            assert response.status_code == (403 if index < 32 else 429), response.text
            assert response.json()["error"]["code"] == (
                "requester_mismatch" if index < 32 else "rate_limited"
            )
            assert response.json()["error"]["message"]
