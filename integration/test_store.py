"""Real PostgreSQL controls. Requires the isolated placement's database URL."""

import pytest

from approval_service.store import StoreRefused


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
        store.refuse("op-1", "person-p", "denied", 1200)
