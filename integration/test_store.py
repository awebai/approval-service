"""Real PostgreSQL controls. Requires the isolated placement's database URL."""

import pytest

from approval_service.store import StoreRefused


@pytest.mark.asyncio
async def test_same_digest_retries_return_original_locator_and_cannot_change_requester(
    store,
):
    own = "a" * 64
    digest = "c" * 64
    first = await store.prepare(
        "op-1",
        digest,
        own,
        "person-p",
        b"{}",
        1000,
        1300,
        organisation="customer.example",
        requester_key="one-test-key",
    )
    assert (
        await store.prepare(
            "op-2",
            digest,
            own,
            "person-p",
            b"{}",
            1001,
            1300,
            organisation="customer.example",
            requester_key="one-test-key",
        )
    )["operation_id"] == first["operation_id"]
    with pytest.raises(StoreRefused):
        await store.prepare(
            "op-1",
            digest,
            "b" * 64,
            "person-p",
            b"{}",
            1002,
            1300,
            organisation="customer.example",
            requester_key="one-test-key",
        )
    with pytest.raises(StoreRefused):
        await store.prepare(
            "op-1",
            "d" * 64,
            own,
            "person-p",
            b"{}",
            1002,
            1300,
            organisation="customer.example",
            requester_key="one-test-key",
        )


@pytest.mark.asyncio
async def test_parallel_polls_reuse_a_bounded_pool_without_read_transactions(store):
    import asyncio

    own, digest = ("a" * 64, "c" * 64)
    await store.prepare(
        "pooled",
        digest,
        own,
        "person-p",
        b"{}",
        1000,
        1300,
        organisation="customer.example",
        requester_key="one-test-key",
    )
    rows = await asyncio.gather(
        *(
            store.poll(
                "pooled",
                digest,
                own,
                1100,
                organisation="customer.example",
                person_id="person-p",
            )
            for _ in range(40)
        )
    )
    assert all(row["outcome"] == "pending" for row in rows)
    stats = await store.db.get_pool_stats()
    assert stats["size"] <= 2
    assert stats["used_size"] == 0
    row = await store.db.fetch_one(
        "SELECT txid_current_if_assigned() AS xid, current_schema() AS schema"
    )
    assert row["xid"] is None
    assert row["schema"] == store.schema
    assert (await store.migrate())["status"] == "up_to_date"
