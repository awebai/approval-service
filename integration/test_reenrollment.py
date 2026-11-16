"""Real SQL isolation of pending replacement and current enrollment generations.

Public Trust is an explicit checked port, as in the enrollment component tests.
The joined registry journey supplies it through the real reader.
"""

import copy
import time
from dataclasses import replace

import pytest
from awid.did import did_from_public_key, generate_keypair
from awid.id_certificates import id_certificate_id, id_certificate_signing_bytes

from approval_service.canonical import canonical
from approval_service.ceremonies import Ceremonies
from approval_service.encoding import encode
from approval_service.enrollment import Enrollments, PublicIssuer
from approval_service.grading import EnrollmentGrading
from approval_service.seams import commitment
from approval_service.verify import Refused
from approval_service.wire import domain

from .test_ceremonies import login_assertion
from .test_enrollment import ORIGIN, RP, enroll_person, enrollment_world


def replacement_intent(trust, binding, *, purpose="replace_person_keys"):
    signed, issuer, _trust, caller, _w = enrollment_world()
    signed = copy.deepcopy(signed)
    i = signed["intent"]
    _seed, public = generate_keypair()
    i.update(
        purpose=purpose,
        person=trust.person,
        organisation=trust.organisation,
        identity_key=did_from_public_key(public),
        previous_binding_commitment=commitment("binding_commitment", binding),
    )
    c = i["pending_certificate"]["certificate"]
    c.update(
        id=trust.person,
        domain=trust.organisation,
        parent={"kind": "namespace", "id": trust.organisation},
    )
    c["issued_at"] = "2026-11-16T00:00:00Z"
    i["pending_certificate"]["signature"] = encode(
        issuer.sign(id_certificate_signing_bytes(c))
    )
    signed["signature"] = encode(
        issuer.sign(domain("enrollment_intent") + canonical(i))
    )
    after = replace(
        trust,
        certificate=id_certificate_id(c),
        identity_key=i["identity_key"],
        observed_at=int(time.time()),
    )
    return signed, issuer, caller, after


@pytest.mark.asyncio
async def test_pending_replacement_and_expiry_leave_the_active_generation_usable(store):
    w, trust, _caller, binding, creation, original = await enroll_person(store)
    w["receipt"].update(binding=binding, id_chain=creation["id_chain"])
    service = Enrollments(
        store, origin=ORIGIN, rp_id=RP, grading=EnrollmentGrading("passkey_only", None)
    )
    intent, _issuer, caller, _after = replacement_intent(trust, binding)
    public = PublicIssuer(trust.issuer, int(time.time()))
    pending = await service.start(
        intent, issuer=public, requester=caller, current=trust
    )
    assert pending["state"] == "pending"
    assert pending["locator"] != original["locator"]
    assert pending["public_key"]["user"]["id"] != original["public_key"]["user"]["id"]
    ceremonies = Ceremonies(store, origin=ORIGIN, rp_id=RP)
    options = await ceremonies.login_options()
    session = await ceremonies.finish_login(
        options["id"],
        login_assertion(w, options),
        original["public_key"]["user"]["id"],
        trust,
    )
    assert session["session"]
    # Expire only this pending attempt, through the actual service cleanup path.
    assert await service.cleanup(intent["intent"]["deadline"]) == 1
    options = await ceremonies.login_options()
    assert (
        await ceremonies.finish_login(
            options["id"],
            login_assertion(w, options),
            original["public_key"]["user"]["id"],
            trust,
        )
    )["session"]
    with pytest.raises(Refused, match="enrollment_not_found"):
        await service.browser_options(pending["locator"])


@pytest.mark.asyncio
async def test_active_recovery_requires_the_new_identity_key_to_be_current(store):
    _w, trust, _caller, binding, _creation, original = await enroll_person(store)
    service = Enrollments(
        store, origin=ORIGIN, rp_id=RP, grading=EnrollmentGrading("passkey_only", None)
    )
    intent, _issuer, caller, after = replacement_intent(
        trust, binding, purpose="enroll_person"
    )
    public = PublicIssuer(trust.issuer, int(time.time()))
    with pytest.raises(Refused, match="enrollment_identity_mismatch"):
        await service.start(intent, issuer=public, requester=caller, current=trust)
    pending = await service.start(
        intent, issuer=public, requester=caller, current=after
    )
    assert pending["state"] == "pending" and pending["locator"] != original["locator"]


async def pending_ceremony(service, intent, issuer, caller, w, *, current=None):
    from datetime import UTC, datetime

    from receipts import assertion
    from vendor import Vendor

    from approval_service.answers import assemble_receipt
    from approval_service.encoding import decode
    from approval_service.registration import check_registration

    from .test_enrollment import confirmation_request, sign_binding

    public = PublicIssuer(
        intent["intent"]["pending_certificate"]["certificate"]["issuer_key"],
        int(time.time()),
    )
    started = await service.start(
        intent, issuer=public, requester=caller, current=current
    )
    opened = await service.browser_options(started["locator"])
    raw, _ = Vendor().registration(
        challenge=decode(intent["intent"]["challenge"]),
        credential=w["receipt"]["binding"]["binding"]["credentials"][0],
    )
    await service.register(
        started["locator"], opened["csrf"], raw, {"credProps": {"rk": True}}
    )
    material = await service.material(intent, issuer=public, requester=caller)
    assert len(material["registrations"]) == 1
    entry = check_registration(
        material["registrations"][0]["registration"],
        expected_challenge=decode(intent["intent"]["challenge"]),
        origin=ORIGIN,
        rp_id=RP,
        snapshot=None,
        now=datetime.now(UTC),
    ).binding_entry()
    b = sign_binding(intent, issuer, [entry])
    r = confirmation_request(intent, b)
    body = {
        "version": 1,
        "intent": intent,
        "binding": b,
        "request_bytes": encode(canonical(r)),
        "admission": {"team_certificate": None, "id_chain": []},
    }
    assert (await service.confirm(body, issuer=public, requester=caller))[
        "state"
    ] == "pending"
    opened = await service.browser_options(started["locator"])
    options = await service.confirmation_options(started["locator"], opened["csrf"])
    await service.finish_confirmation(
        started["locator"],
        opened["csrf"],
        options["id"],
        assertion(w["private"], -7, r, entry["id"]),
        issuer=public,
    )
    answer = await service.confirm(body, issuer=public, requester=caller)
    c = assemble_receipt(
        canonical(r), answer, locator=started["locator"], intent=intent
    )
    return started, b, c, entry


async def approve_transition(store, actor, request, caller):
    import hashlib

    from receipts import assertion

    from approval_service.answers import assemble_receipt
    from approval_service.verify import verify_for_effect

    w, trust, binding, creation, started = actor
    w["receipt"].update(binding=binding, id_chain=creation["id_chain"])
    ceremonies = Ceremonies(store, origin=ORIGIN, rp_id=RP)
    options = await ceremonies.login_options()
    session = await ceremonies.finish_login(
        options["id"],
        login_assertion(w, options),
        started["public_key"]["user"]["id"],
        trust,
    )
    raw = canonical(request)
    locator = "transition-" + request["approver"]
    digest = hashlib.sha256(domain("request") + raw).hexdigest()
    await store.prepare(
        locator,
        digest,
        caller.commitment,
        trust.person,
        raw,
        int(time.time()),
        request["deadline"],
        organisation=trust.organisation,
    )
    options = await ceremonies.approval_options(
        trust.person, locator, session["session"], session["csrf"], trust, caller
    )
    await ceremonies.finish_approval(
        trust.person,
        locator,
        options["id"],
        assertion(
            w["private"], -7, request, binding["binding"]["credentials"][0]["id"]
        ),
        session["session"],
        session["csrf"],
        trust,
        caller,
    )
    selected = await store.poll(
        locator,
        digest,
        caller.commitment,
        int(time.time()),
        organisation=trust.organisation,
        person_id=trust.person,
    )
    answer = await store.decision_answer(selected, locator)
    receipt = assemble_receipt(raw, answer, locator=locator)
    checked = verify_for_effect(
        receipt,
        expected_request=request,
        presenter=request["requester"],
        now=int(time.time()),
        trust=trust,
        required_grade="passkey_uv",
        nonce_keys={"issuer": b"native-transition-enforcer-secret"},
    )
    assert checked.person == trust.person
    return receipt


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode,missing_history",
    [
        ("unbroken", False),
        ("assisted", False),
        ("recreated", False),
        ("recreated", True),
        ("assisted-retired-helper", False),
    ],
    ids=[
        "unbroken",
        "assisted",
        "recreated",
        "recreated-without-old-history",
        "retired-helper-refused",
    ],
)
async def test_real_replacement_activation_retires_only_the_old_generation(
    store, mode, missing_history
):
    import hmac
    import json

    from nacl.signing import SigningKey
    from receipts import fixture

    from approval_service.definitions import definition_ref

    retired_helper = mode == "assisted-retired-helper"
    if retired_helper:
        mode = "assisted"
    old_w, trust, _bootstrap, old_b, old_c, old_start = await enroll_person(store)
    before = await store.db.fetch_one(
        "SELECT evidence FROM {{tables.approval_enrollments}} WHERE enrollment_locator=$1",
        old_start["locator"],
    )
    old_e = json.loads(before["evidence"])
    if missing_history:
        # Missing public history is not a new authority source. Credentials
        # and sessions still come from the real enrollment path.
        await store.db.execute(
            "UPDATE {{tables.approval_enrollments}} SET evidence=NULL WHERE enrollment_locator=$1",
            old_start["locator"],
        )
    purpose = "enroll_person" if mode == "recreated" else "replace_person_keys"
    intent, issuer, caller, after = replacement_intent(trust, old_b, purpose=purpose)
    if mode == "unbroken":
        from approval_service.requester import AdmittedRequester

        original_requester = {
            "kind": "identity",
            "id": trust.person,
            "key": trust.identity_key,
        }
        intent["intent"]["requester"] = original_requester
        intent["signature"] = encode(
            issuer.sign(domain("enrollment_intent") + canonical(intent["intent"]))
        )
        caller = AdmittedRequester(
            canonical(original_requester), trust.identity_key, int(time.time())
        )
    service = Enrollments(
        store, origin=ORIGIN, rp_id=RP, grading=EnrollmentGrading("passkey_only", None)
    )
    new_w = fixture()
    started, b, c, entry = await pending_ceremony(
        service,
        intent,
        issuer,
        caller,
        new_w,
        current=after if mode == "recreated" else trust,
    )
    transition = {
        "mode": mode,
        "before": {
            "subject": old_e["evidence"]["subject"],
            "binding_commitment": commitment("binding_commitment", old_b),
        },
        "previous_evidence_commitment": None
        if missing_history
        else commitment("identity_evidence_commitment", old_e),
        "confirmation_receipt_commitment": commitment("receipt_commitment", c),
        "approval_receipt_commitment": None,
    }
    e = copy.deepcopy(old_e["evidence"])
    e.update(
        subject={
            "id": after.person,
            "certificate": after.certificate,
            "key": after.identity_key,
        },
        binding_commitment=commitment("binding_commitment", b),
        transition=transition,
    )
    value = {
        "version": 1,
        "intent": intent,
        "binding": b,
        "creation_receipt": c,
        "id_chain": c["id_chain"],
    }
    if mode == "recreated":
        e["creation"] = {
            "credential": entry["id"],
            "grade": entry["grade"],
            "receipt_commitment": commitment("receipt_commitment", c),
        }
        assert e["creation"] != old_e["evidence"]["creation"]
    else:
        actor = (old_w, trust, old_b, old_c, old_start)
        if mode == "assisted":
            helper_i, helper_issuer, helper_t, helper_caller, helper_w = (
                enrollment_world()
            )
            helper_seed = SigningKey(bytes([4]) * 32)
            from awid.did import stable_id_from_did_key

            helper_key = did_from_public_key(bytes(helper_seed.verify_key))
            person = stable_id_from_did_key(helper_key)
            hi = helper_i["intent"]
            hc = hi["pending_certificate"]["certificate"]
            hi.update(person=person, identity_key=helper_key)
            hc["id"] = person
            hi["pending_certificate"]["signature"] = encode(
                helper_issuer.sign(id_certificate_signing_bytes(hc))
            )
            helper_i["signature"] = encode(
                helper_issuer.sign(domain("enrollment_intent") + canonical(hi))
            )
            helper_t = replace(
                helper_t,
                person=person,
                identity_key=helper_key,
                certificate=id_certificate_id(hc),
            )
            hs, hb, hcpt, he = await pending_ceremony(
                service, helper_i, helper_issuer, helper_caller, helper_w
            )
            eb = {
                "version": 1,
                "kind": "human",
                "organisation": helper_t.organisation,
                "subject": {
                    "id": person,
                    "certificate": helper_t.certificate,
                    "key": helper_key,
                },
                "issuer": helper_t.issuer,
                "binding_commitment": commitment("binding_commitment", hb),
                "creation": {
                    "credential": he["id"],
                    "grade": he["grade"],
                    "receipt_commitment": commitment("receipt_commitment", hcpt),
                },
            }
            await service.activate(
                {
                    "version": 1,
                    "intent": helper_i,
                    "binding": hb,
                    "creation_receipt": hcpt,
                    "id_chain": hcpt["id_chain"],
                    "evidence": {
                        "evidence": eb,
                        "signature": encode(
                            helper_issuer.sign(
                                domain("identity_evidence") + canonical(eb)
                            )
                        ),
                    },
                },
                trust=helper_t,
                requester=helper_caller,
            )
            actor = (helper_w, helper_t, hb, hcpt, hs)
        r = {
            "version": 1,
            "purpose": "act_approval",
            "organisation": trust.organisation,
            "approver": actor[1].person,
            "requester": intent["intent"]["requester"],
            "enforcer": {"audience": "https://holder.example.test"},
            "definition": definition_ref("human.enrollment.replace"),
            "act": {
                "operation": "human.enrollment.replace",
                "target": {
                    "person": trust.person,
                    "before": {
                        "certificate": trust.certificate,
                        "identity_key": trust.identity_key,
                        "binding_commitment": commitment("binding_commitment", old_b),
                    },
                    "after": {
                        "certificate": after.certificate,
                        "identity_key": after.identity_key,
                        "binding_commitment": commitment("binding_commitment", b),
                    },
                    "continuity": mode,
                },
                "expected_revision": 1,
            },
            "not_before": int(time.time()) - 1,
            "deadline": int(time.time()) + 120,
            "nonce": {"kid": "issuer", "value": ""},
        }
        r["nonce"]["value"] = encode(
            hmac.digest(
                b"native-transition-enforcer-secret",
                domain("nonce") + canonical(r),
                "sha256",
            )
        )
        receipt = await approve_transition(store, actor, r, caller)
        value["transition_receipt"] = receipt
        transition["approval_receipt_commitment"] = commitment(
            "receipt_commitment", receipt
        )
        assert e["creation"] == old_e["evidence"]["creation"]
    value["evidence"] = {
        "evidence": e,
        "signature": encode(issuer.sign(domain("identity_evidence") + canonical(e))),
    }
    if retired_helper:
        # Retire the helper via a complete real recovery, not a flag/SQL seed.
        helper_after = await recover_actor(service, store, helper_t, hb)
        from receipts import assertion

        from approval_service.verify import verify_for_effect, verify_historical

        # The withdrawn authenticator can still make a genuine UV assertion
        # outside the service. Its valid signature must not restore assistance.
        receipt["assertion"] = assertion(
            helper_w["private"], -7, r, hb["binding"]["credentials"][0]["id"]
        )
        assert (
            verify_historical(receipt, expected_request=r, trust=helper_t).person
            == helper_t.person
        )
        with pytest.raises(Refused, match="binding_mismatch"):
            verify_for_effect(
                receipt,
                expected_request=r,
                presenter=r["requester"],
                now=int(time.time()),
                trust=helper_after,
                required_grade="passkey_uv",
                nonce_keys={"issuer": b"native-transition-enforcer-secret"},
            )
        transition["approval_receipt_commitment"] = commitment(
            "receipt_commitment", receipt
        )
        value["evidence"] = {
            "evidence": e,
            "signature": encode(
                issuer.sign(domain("identity_evidence") + canonical(e))
            ),
        }
        with pytest.raises(Refused, match="transition_receipt_unavailable"):
            await service.activate(value, trust=after, requester=caller)
        rows = await store.db.fetch_all(
            "SELECT state,enrollment_locator FROM {{tables.approval_enrollments}} WHERE organisation=$1 AND person_id=$2",
            trust.organisation,
            trust.person,
        )
        assert {row["enrollment_locator"]: row["state"] for row in rows} == {
            old_start["locator"]: "active",
            started["locator"]: "pending",
        }
        return
    if mode == "unbroken":
        from approval_service.canonical import parse
        from approval_service.encoding import decode

        assert parse(decode(c["request_bytes"]))["requester"] == original_requester
        assert intent["intent"]["requester"] == original_requester
        with pytest.raises(Refused, match="requester_mismatch"):
            await service.activate(value, trust=after, requester=caller)
        carrier = {"kind": "identity", "id": after.person, "key": after.identity_key}
        value["carrier"] = carrier
        caller = AdmittedRequester(
            canonical(carrier), after.identity_key, int(time.time())
        )
    assert (await service.activate(value, trust=after, requester=caller))[
        "state"
    ] == "active"
    assert (await service.activate(value, trust=after, requester=caller))[
        "state"
    ] == "active"
    rows = await store.db.fetch_all(
        "SELECT state,enrollment_locator FROM {{tables.approval_enrollments}} WHERE organisation=$1 AND person_id=$2",
        trust.organisation,
        trust.person,
    )
    assert {row["enrollment_locator"]: row["state"] for row in rows} == {
        old_start["locator"]: "retired",
        started["locator"]: "active",
    }
    ceremonies = Ceremonies(store, origin=ORIGIN, rp_id=RP)
    options = await ceremonies.login_options()
    with pytest.raises(Refused, match="credential_not_enrolled"):
        await ceremonies.finish_login(
            options["id"],
            login_assertion(old_w, options),
            old_start["public_key"]["user"]["id"],
            after,
        )
    new_w["receipt"].update(binding=b, id_chain=c["id_chain"])
    options = await ceremonies.login_options()
    assert (
        await ceremonies.finish_login(
            options["id"],
            login_assertion(new_w, options),
            started["public_key"]["user"]["id"],
            after,
        )
    )["session"]


async def recover_actor(service, store, trust, binding):
    """A real new generation makes the old helper credential withdrawn."""
    import json

    from receipts import fixture

    old = await store.db.fetch_one(
        "SELECT evidence FROM {{tables.approval_enrollments}} WHERE organisation=$1 AND person_id=$2 AND state='active'",
        trust.organisation,
        trust.person,
    )
    old_e = json.loads(old["evidence"])
    intent, issuer, caller, after = replacement_intent(
        trust, binding, purpose="enroll_person"
    )
    _started, b, c, entry = await pending_ceremony(
        service, intent, issuer, caller, fixture(), current=after
    )
    e = copy.deepcopy(old_e["evidence"])
    e.update(
        subject={
            "id": after.person,
            "certificate": after.certificate,
            "key": after.identity_key,
        },
        binding_commitment=commitment("binding_commitment", b),
        creation={
            "credential": entry["id"],
            "grade": entry["grade"],
            "receipt_commitment": commitment("receipt_commitment", c),
        },
        transition={
            "mode": "recreated",
            "before": {
                "subject": old_e["evidence"]["subject"],
                "binding_commitment": commitment("binding_commitment", binding),
            },
            "previous_evidence_commitment": commitment(
                "identity_evidence_commitment", old_e
            ),
            "confirmation_receipt_commitment": commitment("receipt_commitment", c),
            "approval_receipt_commitment": None,
        },
    )
    value = {
        "version": 1,
        "intent": intent,
        "binding": b,
        "creation_receipt": c,
        "id_chain": c["id_chain"],
        "evidence": {
            "evidence": e,
            "signature": encode(
                issuer.sign(domain("identity_evidence") + canonical(e))
            ),
        },
    }
    assert (await service.activate(value, trust=after, requester=caller))[
        "state"
    ] == "active"
    return after
