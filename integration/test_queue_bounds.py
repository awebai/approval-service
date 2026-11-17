"""Operational retention/fairness through the real PostgreSQL store API."""

import pytest

from approval_service.store import StoreRefused
from approval_service.verify import Refused


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
    from approval_service.ceremonies import Ceremonies

    from .test_ceremonies import active_port, login_assertion

    world, trust, requester = await active_port(store)
    ceremonies = Ceremonies(
        store, origin="https://approval.example.test", rp_id="approval.example.test"
    )
    options = await ceremonies.login_options()
    session = await ceremonies.finish_login(
        options["id"], login_assertion(world, options), world["user_handle"], trust
    )
    assert await ceremonies.deny(
        trust.person, "operation", session["session"], session["csrf"], trust, requester
    ) == {"state": "denied"}
    with pytest.raises(Refused, match="request_expired"):
        await ceremonies.deny(
            trust.person,
            "operation",
            session["session"],
            session["csrf"],
            trust,
            requester,
        )
    row = await store.db.fetch_one(
        "SELECT * FROM {{tables.approval_requests}} WHERE organisation=$1 AND person_id=$2 AND operation_id='operation'",
        trust.organisation,
        trust.person,
    )
    assert row["assertion"] is None and row["request_bytes"] is None
    audit_sql = "SELECT outcome FROM {{tables.approval_audit}} WHERE organisation=$1 AND person_id=$2 AND operation_id='operation'"
    cutoff = row["decided_at"] + 30 * 86400
    await submit(store, "recent", 0, created=cutoff - 20, deadline=cutoff + 300)
    await store.cleanup(cutoff - 1)
    assert await store.db.fetch_one(audit_sql, trust.organisation, trust.person) == {
        "outcome": "denied"
    }
    # This is an ordinary terminal row; enrollment confirmation stays retained.
    assert await store.poll(
        "operation",
        row["digest"],
        requester.commitment,
        cutoff - 1,
        organisation=trust.organisation,
        person_id=trust.person,
    )
    await store.cleanup(cutoff)
    assert (
        await store.db.fetch_one(
            "SELECT 1 FROM {{tables.approval_requests}} WHERE operation_id='operation'"
        )
        is None
    )
    assert await store.db.fetch_one(audit_sql, trust.organisation, trust.person) == {
        "outcome": "denied"
    }
    assert (await store.pending("person", organisation="example.test", now=cutoff))[0][
        "operation_id"
    ] == "recent-0"


@pytest.mark.asyncio
async def test_cleanup_removes_expired_sessions_and_challenges_but_keeps_enrollment(
    store,
):
    import time

    from approval_service.ceremonies import Ceremonies

    from .test_ceremonies import active_port, login_assertion

    world, trust, requester = await active_port(store)
    ceremonies = Ceremonies(
        store, origin="https://approval.example.test", rp_id="approval.example.test"
    )
    options = await ceremonies.login_options()
    session = await ceremonies.finish_login(
        options["id"], login_assertion(world, options), world["user_handle"], trust
    )
    await ceremonies.approval_options(
        trust.person, "operation", session["session"], session["csrf"], trust, requester
    )
    await store.cleanup(int(time.time()) + 31 * 86400)
    assert (
        await store.db.fetch_one(
            "SELECT count(*) AS n FROM {{tables.approval_sessions}}"
        )
    )["n"] == 0
    assert (
        await store.db.fetch_one(
            "SELECT count(*) AS n FROM {{tables.approval_challenges}}"
        )
    )["n"] == 0
    assert (
        await store.db.fetch_one(
            "SELECT count(*) AS n FROM {{tables.approval_enrollments}} WHERE state='active'"
        )
    )["n"] == 1
    assert (
        await store.db.fetch_one(
            "SELECT count(*) AS n FROM {{tables.approval_binding_versions}}"
        )
    )["n"] == 1
    assert (
        await store.db.fetch_one(
            "SELECT count(*) AS n FROM {{tables.approval_requests}} WHERE outcome='approved'"
        )
    )["n"] == 1
