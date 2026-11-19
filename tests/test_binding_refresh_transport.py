"""A refresh uses its own covering authorization, preserving existing headers."""

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
