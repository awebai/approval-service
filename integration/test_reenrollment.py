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
        identity_key=did_from_public_key(public),
        previous_binding_commitment=commitment("binding_commitment", binding),
    )
    c = i["pending_certificate"]["certificate"]
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
