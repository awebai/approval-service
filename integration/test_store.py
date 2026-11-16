"""Real PostgreSQL controls. Requires the isolated placement's database URL."""

import pytest
from approval_service.store import StoreRefused


@pytest.mark.asyncio
async def test_same_digest_retries_return_original_locator_and_cannot_change_requester(
    store,
):
    own = "a" * 64
    digest = "c" * 64
    first = await store.prepare("op-1", digest, own, "person-p", b"{}", 1000, 1300)
    assert (await store.prepare("op-2", digest, own, "person-p", b"{}", 1001, 1300))[
        "operation_id"
    ] == first["operation_id"]
    with pytest.raises(StoreRefused):
        await store.prepare("op-1", digest, "b" * 64, "person-p", b"{}", 1002, 1300)
    with pytest.raises(StoreRefused):
        await store.prepare("op-1", "d" * 64, own, "person-p", b"{}", 1002, 1300)


@pytest.mark.asyncio
async def test_denial_or_expiry_never_stores_assertion_or_renews_deadline(store):
    own = "a" * 64
    digest = "c" * 64
    await store.prepare(
        "op-1", digest, own, "person-p", b'{"private":true}', 1000, 1300
    )
    await store.refuse("op-1", "person-p", "denied", 1100)
    assert (await store.poll("op-1", digest, own, 1200))["request_bytes"] is None
    assert (await store.poll("op-1", digest, own, 1200))["assertion"] is None
    with pytest.raises(StoreRefused):
        await store.refuse("op-1", "person-p", "denied", 1200)


@pytest.mark.asyncio
async def test_parallel_polls_reuse_a_bounded_pool_without_read_transactions(store):
    import asyncio

    own, digest = "a" * 64, "c" * 64
    await store.prepare("pooled", digest, own, "person-p", b"{}", 1000, 1300)
    rows = await asyncio.gather(
        *(store.poll("pooled", digest, own, 1100) for _ in range(40))
    )
    assert all(row["outcome"] == "pending" for row in rows)
    stats = await store.db.get_pool_stats()
    assert stats["size"] <= 2
    assert stats["used_size"] == 0
    # No explicit transaction is opened by this ordinary pool read.
    row = await store.db.fetch_one(
        "SELECT txid_current_if_assigned() AS xid, current_schema() AS schema"
    )
    assert row["xid"] is None
    assert row["schema"] == store.schema
    # Reapplying unchanged migrations is supported by the shared runner.
    assert (await store.migrate())["status"] == "up_to_date"
