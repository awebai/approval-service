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
    assert {k: v for k, v in after.items() if k != "binding_ref"} == {
        k: v for k, v in before.items() if k != "binding_ref"
    }
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
