"""Real service-local enrollment/UV/state transitions on disposable PostgreSQL.

The issuer and committed Trust are explicit checked input ports here; the joined
journey supplies them from the real registry. No clock, authenticator verifier,
transaction or credential storage is replaced.
"""

import copy
import hashlib
import hmac
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from approval_service.canonical import canonical
from approval_service.definitions import definition_ref
from approval_service.encoding import decode, encode
from approval_service.enrollment import Enrollments, PublicIssuer
from approval_service.grading import EnrollmentGrading
from approval_service.registration import check_registration
from approval_service.requester import AdmittedRequester
from approval_service.seams import commitment
from approval_service.verify import Refused, Trust
from approval_service.wire import domain

sys.path.insert(0, str(Path(__file__).parents[1] / "tests"))
from receipts import assertion, fixture
from vendor import Vendor

ROOT = Path(__file__).parents[1]
ORIGIN = "https://approval.example.test"
RP = "approval.example.test"


def enrollment_world():
    case = json.loads((ROOT / "vectors/issuer-service-enrollment-v1.json").read_text())[
        "cases"
    ][0]
    intent = copy.deepcopy(case["intent"])
    now = int(time.time())
    i = intent["intent"]
    i.update(origin=ORIGIN, rp_id=RP, not_before=now - 1, deadline=now + 120)
    issuer = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
    intent["signature"] = encode(
        issuer.sign(domain("enrollment_intent") + canonical(i))
    )
    t = case["trust"]
    trust = Trust(
        **{**t, "observed_at": now, "issuer_public_key": decode(t["issuer_public_key"])}
    )
    caller = AdmittedRequester(canonical(i["requester"]), i["requester"]["key"], now)
    w = fixture()
    return intent, issuer, trust, caller, w


def sign_binding(intent, issuer, entries):
    from awid.id_certificates import id_certificate_id

    i = intent["intent"]
    b = {
        "version": 1,
        "organisation": i["organisation"],
        "person": i["person"],
        "certificate": id_certificate_id(i["pending_certificate"]["certificate"]),
        "identity_key": i["identity_key"],
        "issuer": i["pending_certificate"]["certificate"]["issuer_key"],
        "origin": i["origin"],
        "rp_id": i["rp_id"],
        "credentials": entries,
    }
    return {
        "binding": b,
        "signature": encode(issuer.sign(domain("binding") + canonical(b))),
    }


def confirmation_request(intent, binding):
    i = intent["intent"]
    r = {
        "version": 1,
        "purpose": "enrollment_confirmation",
        "organisation": i["organisation"],
        "approver": i["person"],
        "requester": i["requester"],
        "enforcer": {"audience": "https://holder.example.test"},
        "definition": definition_ref("enrollment.confirm"),
        "act": {
            "operation": "enrollment.confirm",
            "expected_revision": 0,
            "target": {
                "person": i["person"],
                "certificate": binding["binding"]["certificate"],
                "identity_key": i["identity_key"],
                "binding_commitment": commitment("binding_commitment", binding),
            },
        },
        "not_before": i["not_before"],
        "deadline": i["deadline"],
        "nonce": {"kid": "k1", "value": ""},
    }
    r["nonce"]["value"] = encode(
        hmac.digest(
            b"holder-owned-nonce-secret-for-test",
            domain("nonce") + canonical(r),
            "sha256",
        )
    )
    return r


async def enroll_person(store):
    intent, issuer, trust, caller, w = enrollment_world()
    service = Enrollments(
        store, origin=ORIGIN, rp_id=RP, grading=EnrollmentGrading("passkey_only", None)
    )
    public = PublicIssuer(trust.issuer, trust.observed_at)
    started = await service.start(intent, issuer=public, requester=caller)
    browser = await service.browser_options(started["locator"])
    assert browser["public_key"]["authenticatorSelection"]["residentKey"] == "required"
    assert (
        browser["public_key"]["authenticatorSelection"]["userVerification"]
        == "required"
    )
    registered, _ = Vendor().registration(
        challenge=decode(intent["intent"]["challenge"]),
        credential=w["receipt"]["binding"]["binding"]["credentials"][0],
    )
    ext = {"credProps": {"rk": True}}
    await service.register(started["locator"], browser["csrf"], registered, ext)
    material = await service.material(intent, issuer=public, requester=caller)
    raw = material["registrations"][0]["registration"]
    assert raw == registered
    checked = check_registration(
        raw,
        expected_challenge=decode(intent["intent"]["challenge"]),
        origin=ORIGIN,
        rp_id=RP,
        snapshot=None,
        now=datetime.now(UTC),
    )
    binding = sign_binding(intent, issuer, [checked.binding_entry()])
    r = confirmation_request(intent, binding)
    confirm = {
        "version": 1,
        "intent": intent,
        "binding": binding,
        "request_bytes": encode(canonical(r)),
        "admission": {"team_certificate": None, "id_chain": []},
    }
    pending = await service.confirm(confirm, issuer=public, requester=caller)
    assert pending["state"] == "pending"
    options = await service.confirmation_options(started["locator"], browser["csrf"])
    assert options["challenge"] == encode(
        hashlib.sha256(domain("request") + canonical(r)).digest()
    )
    proof = assertion(w["private"], -7, r, checked.credential_id)
    await service.finish_confirmation(
        started["locator"], browser["csrf"], options["id"], proof, issuer=public
    )
    approved = await service.confirm(confirm, issuer=public, requester=caller)
    assert approved["state"] == "approved"
    from approval_service.answers import assemble_receipt

    c = assemble_receipt(
        canonical(r), approved, locator=started["locator"], intent=intent
    )
    e = {
        "version": 1,
        "organisation": trust.organisation,
        "subject": {
            "id": trust.person,
            "certificate": trust.certificate,
            "key": trust.identity_key,
        },
        "issuer": trust.issuer,
        "binding_commitment": commitment("binding_commitment", binding),
        "creation": {
            "credential": checked.credential_id,
            "grade": checked.grade,
            "receipt_commitment": commitment("receipt_commitment", c),
        },
    }
    # Copy the already-pinned E header/fields; replace only its checked bindings.
    base = json.loads((ROOT / "vectors/issuer-service-enrollment-v1.json").read_text())[
        "cases"
    ][0]["activation"]["evidence"]["evidence"]
    e = {**base, **e}
    signed_e = {
        "evidence": e,
        "signature": encode(issuer.sign(domain("identity_evidence") + canonical(e))),
    }
    active = {
        "version": 1,
        "intent": intent,
        "binding": binding,
        "creation_receipt": c,
        "evidence": signed_e,
        "id_chain": c["id_chain"],
    }
    assert (await service.activate(active, trust=trust, requester=caller))[
        "state"
    ] == "active"
    return w, trust, caller, binding, c, started


@pytest.mark.asyncio
async def test_pending_registration_confirmation_and_committed_activation_are_distinct(
    store,
):
    _w, trust, _caller, binding, c, _started = await enroll_person(store)
    row = await store.db.fetch_one(
        "SELECT state,identity_key FROM {{tables.approval_enrollments}} WHERE person_id=$1",
        trust.person,
    )
    assert row == {"state": "active", "identity_key": trust.identity_key}
    assert c["binding"] == binding
    assert c["assertion"]["id"] == binding["binding"]["credentials"][0]["id"]
    assert c["id_chain"]


@pytest.mark.asyncio
async def test_registration_requires_original_browser_token_and_discoverability(store):
    intent, _issuer, trust, caller, _w = enrollment_world()
    service = Enrollments(
        store, origin=ORIGIN, rp_id=RP, grading=EnrollmentGrading("passkey_only", None)
    )
    started = await service.start(
        intent, issuer=PublicIssuer(trust.issuer, trust.observed_at), requester=caller
    )
    browser = await service.browser_options(started["locator"])
    registered, _ = Vendor().registration(
        challenge=decode(intent["intent"]["challenge"])
    )
    for csrf, extensions, code in [
        ("wrong", {"credProps": {"rk": True}}, "csrf_invalid"),
        (
            browser["csrf"],
            {"credProps": {"rk": False}},
            "discoverable_credential_required",
        ),
    ]:
        with pytest.raises(Refused, match=code):
            await service.register(started["locator"], csrf, registered, extensions)
    assert await store.db.fetch_one(
        "SELECT count(*) AS n FROM {{tables.approval_credentials}}"
    ) == {"n": 0}
    assert (
        await store.db.fetch_one("SELECT state FROM {{tables.approval_enrollments}}")
    )["state"] == "pending"


@pytest.mark.asyncio
async def test_issuer_cannot_upgrade_the_services_private_registration_grade(store):
    intent, issuer, trust, caller, _w = enrollment_world()
    service = Enrollments(
        store, origin=ORIGIN, rp_id=RP, grading=EnrollmentGrading("passkey_only", None)
    )
    public = PublicIssuer(trust.issuer, trust.observed_at)
    started = await service.start(intent, issuer=public, requester=caller)
    browser = await service.browser_options(started["locator"])
    registered, _ = Vendor().registration(
        challenge=decode(intent["intent"]["challenge"])
    )
    await service.register(
        started["locator"], browser["csrf"], registered, {"credProps": {"rk": True}}
    )
    checked = check_registration(
        registered,
        expected_challenge=decode(intent["intent"]["challenge"]),
        origin=ORIGIN,
        rp_id=RP,
        snapshot=None,
        now=datetime.now(UTC),
    )
    entry = {
        **checked.binding_entry(),
        "grade": "certified_hardware",
        "snapshot": "sha256:" + "a" * 64,
    }
    binding = sign_binding(intent, issuer, [entry])
    r = confirmation_request(intent, binding)
    body = {
        "version": 1,
        "intent": intent,
        "binding": binding,
        "request_bytes": encode(canonical(r)),
        "admission": {"team_certificate": None, "id_chain": []},
    }
    with pytest.raises(Refused, match="binding_credential_mismatch"):
        await service.confirm(body, issuer=public, requester=caller)
    assert await store.db.fetch_one(
        "SELECT count(*) AS n FROM {{tables.approval_requests}}"
    ) == {"n": 0}
