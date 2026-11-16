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
from approval_service.requester import AdmittedRequester, KeyObservation
from approval_service.seams import commitment
from approval_service.verify import Refused, Trust
from approval_service.wire import domain

sys.path.insert(0, str(Path(__file__).parents[1] / "tests"))
from receipts import assertion, fixture
from vendor import Vendor

ROOT = Path(__file__).parents[1]
ORIGIN = "https://approval.example.test"
RP = "approval.example.test"


def enrollment_world(*, lifetime=120):
    case = json.loads((ROOT / "vectors/issuer-service-enrollment-v1.json").read_text())[
        "cases"
    ][0]
    intent = copy.deepcopy(case["intent"])
    now = int(time.time())
    i = intent["intent"]
    i.update(origin=ORIGIN, rp_id=RP, not_before=now - 1, deadline=now + lifetime)
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


def creation_status(intent):
    """Explicit checked not-committed input port, like this fixture's Trust."""
    i = intent["intent"]
    return KeyObservation(i["person"], i["identity_key"], False, int(time.time()))


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


async def confirmed_person(
    store,
    *,
    lifetime=120,
    later=False,
    service_grading=None,
    issuer_grading=None,
    vendor=None,
):
    intent, issuer, trust, caller, w = enrollment_world(lifetime=lifetime)
    service = Enrollments(
        store,
        origin=ORIGIN,
        rp_id=RP,
        grading=service_grading or EnrollmentGrading("passkey_only", None),
    )
    public = PublicIssuer(trust.issuer, trust.observed_at)
    if later:
        from dataclasses import replace

        trust = replace(trust, namespace_issuer=trust.issuer)
        i = intent["intent"]
        i.update(
            purpose="enroll_existing_person",
            requester={
                "kind": "identity",
                "id": trust.person,
                "key": trust.identity_key,
            },
        )
        intent["signature"] = encode(
            issuer.sign(domain("enrollment_intent") + canonical(i))
        )
        caller = AdmittedRequester(
            canonical(i["requester"]), trust.identity_key, trust.observed_at
        )
    started = await service.start(
        intent,
        issuer=public,
        requester=caller,
        current=trust if later else None,
        observation=creation_status(intent),
    )
    browser = await service.browser_options(started["locator"])
    assert browser["public_key"]["authenticatorSelection"]["residentKey"] == "required"
    assert (
        browser["public_key"]["authenticatorSelection"]["userVerification"]
        == "required"
    )
    registered, _ = (vendor or Vendor()).registration(
        challenge=decode(intent["intent"]["challenge"]),
        credential=w["receipt"]["binding"]["binding"]["credentials"][0],
    )
    ext = {"credProps": {"rk": True}}
    await service.register(started["locator"], browser["csrf"], registered, ext)
    material = await service.material(
        intent, issuer=public, requester=caller, current=trust if later else None
    )
    raw = material["registrations"][0]["registration"]
    assert raw == registered
    checked = check_registration(
        raw,
        expected_challenge=decode(intent["intent"]["challenge"]),
        origin=ORIGIN,
        rp_id=RP,
        snapshot=issuer_grading,
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
    pending = await service.confirm(
        confirm, issuer=public, requester=caller, current=trust if later else None
    )
    assert pending["state"] == "pending"
    # A newly opened page has no original token. Refresh from the bearer locator
    # after the issuer has done its independent work; never repeat registration.
    previous_csrf = browser["csrf"]
    browser = await service.browser_options(started["locator"])
    assert browser["csrf"] != previous_csrf
    options = await service.confirmation_options(started["locator"], browser["csrf"])
    assert options["challenge"] == encode(
        hashlib.sha256(domain("request") + canonical(r)).digest()
    )
    proof = assertion(w["private"], -7, r, checked.credential_id)
    await service.finish_confirmation(
        started["locator"], browser["csrf"], options["id"], proof, issuer=public
    )
    approved = await service.confirm(
        confirm, issuer=public, requester=caller, current=trust if later else None
    )
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
    if later:
        e.pop("creation")
        e.update(
            kind="human_enrolled_later",
            enrollment={
                "credential": checked.credential_id,
                "grade": checked.grade,
                "since": int(time.time()),
                "confirmation_receipt_commitment": commitment("receipt_commitment", c),
            },
        )
    signed_e = {
        "evidence": e,
        "signature": encode(
            issuer.sign(
                domain("later_enrollment_evidence" if later else "identity_evidence")
                + canonical(e)
            )
        ),
    }
    active = {
        "version": 1,
        "intent": intent,
        "binding": binding,
        "creation_receipt": c,
        "evidence": signed_e,
        "id_chain": c["id_chain"],
    }
    if later:
        active["version"] = 2
        active["confirmation_receipt"] = active.pop("creation_receipt")
    return {
        "service": service,
        "intent": intent,
        "issuer": issuer,
        "trust": trust,
        "caller": caller,
        "world": w,
        "binding": binding,
        "receipt": c,
        "started": started,
        "activation": active,
    }


async def enroll_person(store):
    confirmed = await confirmed_person(store)
    assert (
        await confirmed["service"].activate(
            confirmed["activation"],
            trust=confirmed["trust"],
            requester=confirmed["caller"],
        )
    )["state"] == "active"
    return tuple(
        confirmed[k]
        for k in ("world", "trust", "caller", "binding", "receipt", "started")
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("approved", [False, True], ids=["unconfirmed", "confirmed"])
async def test_pending_sweep_retains_only_approved_confirmation_for_30_days(
    store, approved
):
    if approved:
        context = await confirmed_person(store)
        service, intent, started = (
            context[k] for k in ("service", "intent", "started")
        )
    else:
        intent, _issuer, trust, caller, _w = enrollment_world()
        service = Enrollments(
            store,
            origin=ORIGIN,
            rp_id=RP,
            grading=EnrollmentGrading("passkey_only", None),
        )
        started = await service.start(
            intent,
            issuer=PublicIssuer(trust.issuer, trust.observed_at),
            requester=caller,
            observation=creation_status(intent),
        )
    deadline = intent["intent"]["deadline"]
    assert await service.cleanup(deadline - 1) == 0
    # Expiring raw assertion delivery must not erase the durable approval outcome.
    await store.cleanup(deadline)
    if approved:
        assert await service.cleanup(deadline) == 0
        assert await service.cleanup(deadline + 30 * 86400 - 1) == 0
        assert await store.db.fetch_one(
            "SELECT state FROM {{tables.approval_enrollments}} WHERE enrollment_locator=$1",
            started["locator"],
        ) == {"state": "pending"}
        assert await store.db.fetch_one(
            "SELECT outcome,assertion,request_bytes FROM {{tables.approval_requests}} WHERE operation_id=$1",
            started["locator"],
        ) == {"outcome": "approved", "assertion": None, "request_bytes": None}
    assert await service.cleanup(deadline + (30 * 86400 if approved else 0)) == 1
    for table in (
        "approval_enrollments",
        "approval_credentials",
        "approval_binding_versions",
    ):
        assert await store.db.fetch_one(
            "SELECT count(*) AS n FROM {{tables." + table + "}}"
        ) == {"n": 0}


@pytest.mark.asyncio
async def test_new_start_replaces_confirmed_generation_after_original_deadline(store):
    import asyncio
    import secrets

    context = await confirmed_person(store, lifetime=3)
    old = context["started"]["locator"]
    deadline = context["intent"]["intent"]["deadline"]
    await asyncio.sleep(max(0, deadline - time.time()) + 0.05)
    assert await context["service"].cleanup(int(time.time())) == 0
    retry = copy.deepcopy(context["intent"])
    retry["intent"].update(
        not_before=int(time.time()) - 1,
        deadline=int(time.time()) + 120,
        challenge=encode(secrets.token_bytes(32)),
    )
    retry["signature"] = encode(
        context["issuer"].sign(domain("enrollment_intent") + canonical(retry["intent"]))
    )
    started = await context["service"].start(
        retry,
        issuer=PublicIssuer(context["trust"].issuer, int(time.time())),
        requester=context["caller"],
        observation=creation_status(retry),
    )
    assert started["locator"] != old
    assert await store.db.fetch_all(
        "SELECT enrollment_locator,state FROM {{tables.approval_enrollments}}"
    ) == [{"enrollment_locator": started["locator"], "state": "pending"}]
    assert await store.db.fetch_one(
        "SELECT count(*) AS n FROM {{tables.approval_credentials}}"
    ) == {"n": 0}
    assert await store.db.fetch_one(
        "SELECT count(*) AS n FROM {{tables.approval_binding_versions}}"
    ) == {"n": 0}
    assert await store.db.fetch_one(
        "SELECT outcome,assertion FROM {{tables.approval_requests}} WHERE operation_id=$1",
        old,
    ) == {"outcome": "approved", "assertion": None}


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
        intent,
        issuer=PublicIssuer(trust.issuer, trust.observed_at),
        requester=caller,
        observation=creation_status(intent),
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
    started = await service.start(
        intent, issuer=public, requester=caller, observation=creation_status(intent)
    )
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


def intent_for_organisation(intent, issuer, organisation):
    from awid.id_certificates import id_certificate_signing_bytes

    changed = copy.deepcopy(intent)
    i = changed["intent"]
    i["organisation"] = organisation
    i["requester"] = {**i["requester"], "namespace": organisation}
    certificate = i["pending_certificate"]["certificate"]
    certificate["domain"] = organisation
    certificate["parent"]["id"] = organisation
    i["pending_certificate"]["signature"] = encode(
        issuer.sign(id_certificate_signing_bytes(certificate))
    )
    changed["signature"] = encode(
        issuer.sign(domain("enrollment_intent") + canonical(i))
    )
    return changed


@pytest.mark.asyncio
async def test_foreign_organisation_cannot_reserve_another_organisations_person_id(
    store,
):
    intent, issuer, trust, caller, _w = enrollment_world()
    service = Enrollments(
        store, origin=ORIGIN, rp_id=RP, grading=EnrollmentGrading("passkey_only", None)
    )
    foreign = intent_for_organisation(intent, issuer, "other.example")
    foreign_caller = AdmittedRequester(
        canonical(foreign["intent"]["requester"]), caller.key, caller.observed_at
    )
    first = await service.start(
        foreign,
        issuer=PublicIssuer(trust.issuer, trust.observed_at),
        requester=foreign_caller,
        observation=creation_status(foreign),
    )
    second = await service.start(
        intent,
        issuer=PublicIssuer(trust.issuer, trust.observed_at),
        requester=caller,
        observation=creation_status(intent),
    )
    assert first["locator"] != second["locator"]
    rows = await store.db.fetch_all(
        "SELECT organisation,person_id FROM {{tables.approval_enrollments}} ORDER BY organisation"
    )
    assert rows == [
        {"organisation": trust.organisation, "person_id": trust.person},
        {"organisation": "other.example", "person_id": trust.person},
    ]


@pytest.mark.asyncio
async def test_pending_enrollment_refuses_more_than_24_hours_and_expired_attempt_retries(
    store,
):
    import asyncio

    intent, issuer, trust, caller, _w = enrollment_world()
    service = Enrollments(
        store, origin=ORIGIN, rp_id=RP, grading=EnrollmentGrading("passkey_only", None)
    )
    public = PublicIssuer(trust.issuer, trust.observed_at)
    long = copy.deepcopy(intent)
    long["intent"]["deadline"] = long["intent"]["not_before"] + 86401
    long["signature"] = encode(
        issuer.sign(domain("enrollment_intent") + canonical(long["intent"]))
    )
    with pytest.raises(Refused, match="enrollment_lifetime_invalid"):
        await service.start(
            long, issuer=public, requester=caller, observation=creation_status(long)
        )
    assert await store.db.fetch_one(
        "SELECT count(*) AS n FROM {{tables.approval_enrollments}}"
    ) == {"n": 0}
    short = copy.deepcopy(intent)
    short["intent"]["deadline"] = int(time.time()) + 3
    short["signature"] = encode(
        issuer.sign(domain("enrollment_intent") + canonical(short["intent"]))
    )
    old = await service.start(
        short, issuer=public, requester=caller, observation=creation_status(short)
    )
    await asyncio.sleep(max(0, short["intent"]["deadline"] - time.time()) + 0.05)
    retry = await service.start(
        intent, issuer=public, requester=caller, observation=creation_status(intent)
    )
    assert retry["locator"] != old["locator"]
    assert (
        await store.db.fetch_one(
            "SELECT count(*) AS n FROM {{tables.approval_enrollments}}"
        )
    )["n"] == 1
