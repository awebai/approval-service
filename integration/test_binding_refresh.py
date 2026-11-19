"""Real enrollment/SQL/signatures; current public Trust is an explicit input port.

This exercises the active-generation transaction, not registry controller rotation.
The joined holder journey separately supplies checked public authority.
"""

import asyncio
import copy
import json
import time
from dataclasses import replace

import pytest
from awid.did import did_from_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from receipts import assertion

from approval_service.binding_refresh import (
    BindingRefresher,
    RefreshFailure,
    RefreshRefused,
)
from approval_service.canonical import canonical
from approval_service.ceremonies import Ceremonies
from approval_service.encoding import encode
from approval_service.requester import AdmittedRequester
from approval_service.seams import commitment
from approval_service.verify import Refused, verify_historical
from approval_service.wire import domain

from .test_ceremonies import active_port, login_assertion
from .test_enrollment import ORIGIN, RP


def refresh_packet(previous, *, trust, issuer):
    body = {
        **copy.deepcopy(previous["binding"]),
        "issuer": trust.issuer,
        "certificate": trust.certificate,
    }
    binding = {
        "binding": body,
        "signature": encode(issuer.sign(domain("binding") + canonical(body))),
    }
    descriptor = {"kind": "identity", "id": trust.person, "key": trust.identity_key}
    packet = {
        "version": 1,
        "requester": descriptor,
        "previous_binding_commitment": commitment("binding_commitment", previous),
        "binding": binding,
        "id_chain": [{"checked_port": True}],
    }
    carrier = AdmittedRequester(
        canonical(descriptor), trust.identity_key, int(time.time())
    )
    return packet, carrier


async def enrollment_snapshot(store, *, trust):
    row = await store.db.fetch_one(
        """SELECT * FROM {{tables.approval_enrollments}}
        WHERE organisation=$1 AND person_id=$2""",
        trust.organisation,
        trust.person,
    )
    credentials = await store.db.fetch_all(
        """SELECT * FROM {{tables.approval_credentials}}
        WHERE organisation=$1 AND person_id=$2 ORDER BY credential_id""",
        trust.organisation,
        trust.person,
    )
    return dict(row), [dict(item) for item in credentials]


@pytest.mark.asyncio
async def test_current_issuer_refresh_restores_approval_without_registration_or_history_rewrite(
    store,
):
    world, old_trust, _ = await active_port(store)
    old_binding = world["receipt"]["binding"]
    world["receipt"]["assertion"] = assertion(
        world["private"],
        -7,
        world["request"],
        old_binding["binding"]["credentials"][0]["id"],
    )
    assert (
        verify_historical(
            world["receipt"], expected_request=world["request"], trust=old_trust
        ).person
        == old_trust.person
    )
    before, credentials = await enrollment_snapshot(store, trust=old_trust)
    issuer = Ed25519PrivateKey.generate()
    public = issuer.public_key().public_bytes_raw()
    trust = replace(
        old_trust,
        issuer=did_from_public_key(public),
        issuer_public_key=public,
        observed_at=int(time.time()),
    )
    with pytest.raises(Refused):
        verify_historical(
            world["receipt"], expected_request=world["request"], trust=trust
        )
    packet, carrier = refresh_packet(old_binding, trust=trust, issuer=issuer)
    refresher = BindingRefresher(store)
    answers = await asyncio.gather(
        *(refresher.refresh(packet, trust=trust, carrier=carrier) for _ in range(2))
    )
    assert answers[0] == answers[1]
    after, unchanged_credentials = await enrollment_snapshot(store, trust=trust)
    assert unchanged_credentials == credentials
    assert {k: v for k, v in after.items() if k not in {"binding_ref", "issuer"}} == {
        k: v for k, v in before.items() if k not in {"binding_ref", "issuer"}
    }
    assert after["issuer"] == packet["binding"]["binding"]["issuer"]
    retained = await store.db.fetch_one(
        "SELECT binding FROM {{tables.approval_binding_versions}} WHERE digest=$1",
        before["binding_ref"],
    )
    assert json.loads(retained["binding"]) == old_binding
    audit = await refresher.audit()
    assert len(audit) == 1
    assert audit[0]["actor_key"] == trust.identity_key
    assert audit[0]["previous_issuer"] == old_trust.issuer
    assert audit[0]["current_issuer"] == trust.issuer
    assert audit[0]["previous_binding_ref"] == before["binding_ref"]
    assert audit[0]["current_binding_ref"] == after["binding_ref"]
    live_receipt = {**world["receipt"], "binding": packet["binding"]}
    assert (
        verify_historical(
            live_receipt, expected_request=world["request"], trust=trust
        ).person
        == trust.person
    )
    # A real discoverable login still exercises the enrolled key after refresh.
    service = Ceremonies(store, origin=ORIGIN, rp_id=RP)
    world["receipt"] = live_receipt
    options = await service.login_options()
    proof = login_assertion(world, options)
    result = await service.finish_login(
        options["id"], proof, world["user_handle"], trust
    )
    assert result["session"] and result["csrf"]


@pytest.mark.asyncio
async def test_refresh_refuses_wrong_carrier_credentials_and_stale_generation_with_advice(
    store,
):
    world, trust, _ = await active_port(store)
    issuer = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
    packet, carrier = refresh_packet(
        world["receipt"]["binding"], trust=trust, issuer=issuer
    )
    refresher = BindingRefresher(store)
    before = await enrollment_snapshot(store, trust=trust)
    with pytest.raises(RefreshRefused) as refused:
        await refresher.refresh(
            packet, trust=trust, carrier=replace(carrier, key=trust.issuer)
        )
    assert refused.value.reason is RefreshFailure.REQUESTER
    assert refused.value.message
    changed = copy.deepcopy(packet)
    changed["binding"]["binding"]["credentials"][0]["id"] = encode(b"different key")
    changed["binding"]["signature"] = encode(
        issuer.sign(domain("binding") + canonical(changed["binding"]["binding"]))
    )
    with pytest.raises(RefreshRefused) as refused:
        await refresher.refresh(changed, trust=trust, carrier=carrier)
    assert refused.value.reason is RefreshFailure.CREDENTIAL_CHANGED
    stale = {**packet, "previous_binding_commitment": "sha256:" + "f" * 64}
    with pytest.raises(RefreshRefused) as refused:
        await refresher.refresh(stale, trust=trust, carrier=carrier)
    assert refused.value.reason is RefreshFailure.PREVIOUS_CHANGED
    assert await enrollment_snapshot(store, trust=trust) == before
    assert await refresher.audit() == []


async def blocked_backend(connection, *, blocker: int) -> int:
    """Barrier on an actual PostgreSQL lock waiter, without a timed sleep."""
    async with asyncio.timeout(10):
        while True:
            pid = await connection.fetchval(
                "SELECT pid FROM pg_stat_activity "
                "WHERE $1=ANY(pg_blocking_pids(pid)) AND application_name='awsign' "
                "ORDER BY pid LIMIT 1",
                blocker,
            )
            if pid is not None:
                return pid


@pytest.mark.asyncio
async def test_duplicate_refresh_waits_for_the_real_enrollment_lock_and_replays(store):
    import os

    import asyncpg

    world, original, _ = await active_port(store)
    issuer = Ed25519PrivateKey.generate()
    public = issuer.public_key().public_bytes_raw()
    trust = replace(
        original,
        issuer=did_from_public_key(public),
        issuer_public_key=public,
        observed_at=int(time.time()),
    )
    packet, carrier = refresh_packet(
        world["receipt"]["binding"], trust=trust, issuer=issuer
    )
    gate = await asyncpg.connect(os.environ["APPROVAL_TEST_DATABASE_URL"])
    tasks = []
    lock_key = await gate.fetchval("SELECT pg_backend_pid()")
    try:
        await gate.execute("SELECT pg_advisory_lock($1)", lock_key)
        # This private-schema trigger only pauses a real INSERT. Both refreshes
        # execute the unmodified product owner and its actual pooled transactions.
        await store.db.execute(
            f'''CREATE FUNCTION "{store.schema}".hold_refresh_audit() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN
                PERFORM pg_advisory_xact_lock({lock_key}); RETURN NEW;
            END; $$'''
        )
        await store.db.execute(
            f'''CREATE TRIGGER hold_refresh_audit BEFORE INSERT
            ON {{{{tables.approval_binding_refresh_audit}}}}
            FOR EACH ROW EXECUTE FUNCTION "{store.schema}".hold_refresh_audit()'''
        )
        refresher = BindingRefresher(store)
        tasks.append(
            asyncio.create_task(refresher.refresh(packet, trust=trust, carrier=carrier))
        )
        first = await blocked_backend(gate, blocker=lock_key)
        tasks.append(
            asyncio.create_task(refresher.refresh(packet, trust=trust, carrier=carrier))
        )
        second = await blocked_backend(gate, blocker=first)
        assert first != second
        await gate.execute("SELECT pg_advisory_unlock($1)", lock_key)
        async with asyncio.timeout(15):
            answers = await asyncio.gather(*tasks)
        assert answers[0] == answers[1]
        assert answers[0]["binding_commitment"] == commitment(
            "binding_commitment", packet["binding"]
        )
        assert len(await refresher.audit()) == 1
    finally:
        await gate.execute("SELECT pg_advisory_unlock_all()")
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await gate.close()


@pytest.mark.asyncio
async def test_every_installed_change_is_audited_when_an_issuer_returns_to_a_prior_key(
    store,
):
    world, original, _ = await active_port(store)
    first_issuer = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
    second_issuer = Ed25519PrivateKey.generate()
    refresher = BindingRefresher(store)
    binding = world["receipt"]["binding"]
    transitions = []
    for issuer in (second_issuer, first_issuer, second_issuer):
        public = issuer.public_key().public_bytes_raw()
        trust = replace(
            original,
            issuer=did_from_public_key(public),
            issuer_public_key=public,
            observed_at=int(time.time()),
        )
        packet, carrier = refresh_packet(binding, trust=trust, issuer=issuer)
        before = commitment("binding_commitment", binding)
        after = commitment("binding_commitment", packet["binding"])
        await refresher.refresh(packet, trust=trust, carrier=carrier)
        transitions.append((before, after))
        binding = packet["binding"]
    audit = await refresher.audit()
    assert [
        (row["previous_binding_ref"], row["current_binding_ref"]) for row in audit
    ] == transitions
    assert len({row["audit_id"] for row in audit}) == 3
    # An exact immediate replay is not another installed transition.
    await refresher.refresh(packet, trust=trust, carrier=carrier)
    assert await refresher.audit() == audit


@pytest.mark.asyncio
async def test_an_unchanged_binding_refresh_replays_without_duplicate_audit(store):
    world, trust, _ = await active_port(store)
    issuer = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
    packet, carrier = refresh_packet(
        world["receipt"]["binding"], trust=trust, issuer=issuer
    )
    refresher = BindingRefresher(store)
    first = await refresher.refresh(packet, trust=trust, carrier=carrier)
    second = await refresher.refresh(packet, trust=trust, carrier=carrier)
    assert first == second
    assert len(await refresher.audit()) == 1
