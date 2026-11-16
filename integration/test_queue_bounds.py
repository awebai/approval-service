"""Operational retention/fairness through the real PostgreSQL store API."""

import pytest

from approval_service.store import StoreRefused


async def submit(store, key, number, *, created=1000, deadline=1500):
    return await store.prepare(
        f"{key}-{number}",
        f"digest-{key}-{number}",
        f"descriptor-{key}-{number}",
        "person",
        b"{}",
        created,
        deadline,
        organisation="example.test",
        requester_key=key,
    )


@pytest.mark.asyncio
async def test_descriptor_changes_do_not_reset_one_keys_pending_budget(store):
    for n in range(32):
        await submit(store, "one-key", n)
    with pytest.raises(StoreRefused, match="pending_limit"):
        await submit(store, "one-key", 32)
    await submit(store, "another-key", 0)


@pytest.mark.asyncio
async def test_pending_page_interleaves_keys_before_limiting(store):
    for key in range(5):
        for n in range(32):
            await submit(store, str(key), n, created=1000 + key)
    page = await store.pending("person", organisation="example.test", now=1100)
    assert len(page) == 128
    assert {r["requester_key"] for r in page[:5]} == {str(k) for k in range(5)}
    assert all(sum(r["requester_key"] == str(k) for r in page) >= 25 for k in range(5))


@pytest.mark.asyncio
async def test_old_terminal_requests_pruned_but_audit_and_recent_requests_survive(
    store,
):
    await submit(store, "old", 0)
    await store.refuse("old-0", "person", "denied", 1100, organisation="example.test")
    cutoff = 1100 + 30 * 86400
    await submit(store, "recent", 0, created=cutoff - 20, deadline=cutoff + 300)
    await store.cleanup(cutoff - 1)
    assert await store.audit("old-0", organisation="example.test", person_id="person")
    assert await store.poll(
        "old-0",
        "digest-old-0",
        "descriptor-old-0",
        cutoff - 1,
        organisation="example.test",
        person_id="person",
    )
    await store.cleanup(cutoff)
    assert (
        await store.db.fetch_one(
            "SELECT 1 FROM {{tables.approval_requests}} WHERE operation_id='old-0'"
        )
        is None
    )
    assert await store.audit("old-0", organisation="example.test", person_id="person")
    assert (await store.pending("person", organisation="example.test", now=cutoff))[0][
        "operation_id"
    ] == "recent-0"
