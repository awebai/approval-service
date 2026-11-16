"""Real PostgreSQL controls. Requires the isolated placement's database URL."""

import pytest

from approval_service.store import StoreRefused


def test_terminal_request_erases_act_and_only_owner_recovers_assertion(store):
    request = b'{"act":{"resource":"private-resource"}}'
    own = "a" * 64
    other = "b" * 64
    digest = "c" * 64
    store.prepare("op-1", digest, own, "person-p", request, 1000, 1300)
    assert store.pending("person-p")[0]["request_bytes"] == request
    raw = {
        "id": "cred",
        "client_data_json": "raw",
        "authenticator_data": "auth",
        "signature": "sig",
    }
    store.decide("op-1", digest, own, raw, "binding-v1", 1100)
    with pytest.raises(StoreRefused):
        store.poll("op-1", digest, other, 1101)
    result = store.poll("op-1", digest, own, 1101)
    assert result["assertion"] == raw
    assert result["request_bytes"] is None
    assert store.poll("op-1", digest, own, 1102)["assertion"] == raw
    assert store.pending("person-p") == []
    expired = store.poll("op-1", digest, own, 1300)
    assert expired["assertion"] is None
    assert expired["outcome"] == "approved"
    assert expired["receipt_available"] is False
    assert store.audit("op-1") == [
        {
            "digest": digest,
            "person_id": "person-p",
            "decided_at": 1100,
            "outcome": "approved",
        }
    ]


def test_same_digest_retries_return_original_locator_and_cannot_change_requester(store):
    own = "a" * 64
    digest = "c" * 64
    first = store.prepare("op-1", digest, own, "person-p", b"{}", 1000, 1300)
    assert (
        store.prepare("op-2", digest, own, "person-p", b"{}", 1001, 1300)[
            "operation_id"
        ]
        == first["operation_id"]
    )
    with pytest.raises(StoreRefused):
        store.prepare("op-1", digest, "b" * 64, "person-p", b"{}", 1002, 1300)
    with pytest.raises(StoreRefused):
        store.prepare("op-1", "d" * 64, own, "person-p", b"{}", 1002, 1300)


def test_denial_or_expiry_never_stores_assertion_or_renews_deadline(store):
    own = "a" * 64
    digest = "c" * 64
    store.prepare("op-1", digest, own, "person-p", b'{"private":true}', 1000, 1300)
    store.refuse("op-1", "person-p", "denied", 1100)
    assert store.poll("op-1", digest, own, 1200)["request_bytes"] is None
    assert store.poll("op-1", digest, own, 1200)["assertion"] is None
    with pytest.raises(StoreRefused):
        store.decide("op-1", digest, own, {}, "binding", 1200)
