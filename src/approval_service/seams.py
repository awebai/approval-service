"""Pure first-path seam codecs. Public evidence/permissions stay with callers.

No network, service key, org key custody, database, or effect is implemented
here. HTTP consumers must obtain current admission evidence independently and
check original bounds again after awaits, before a state-changing transaction.
"""

from __future__ import annotations

import hashlib
import hmac

from awid.did import public_key_from_did
from awid.id_certificates import (
    IDCertificateError,
    id_certificate_id,
    verify_ed25519,
    verify_id_certificate,
)
from jsonschema import ValidationError
from nacl.signing import SigningKey

from .canonical import canonical, parse
from .definitions import check_definition
from .encoding import decode, encode
from .verify import Refused, _check_nonce, verify_for_effect, verify_historical
from .wire import SCHEMA, domain, validate, validate_site


def commitment(kind, value):
    return "sha256:" + hashlib.sha256(domain(kind) + canonical(value)).hexdigest()


def _signature(key, signature, preimage):
    try:
        verify_ed25519(key, preimage, decode(signature))
    except (IDCertificateError, ValueError, TypeError) as exc:
        raise Refused("signature_invalid") from exc


def http_authorization(body, *, seed, requester, origin, purpose, issued_at):
    """The caller signs a canonical request, never an arbitrary URL or alias."""
    if public_key_from_did(requester["key"]) != bytes(SigningKey(seed).verify_key):
        raise Refused("requester_mismatch")
    value = parse(body)
    proof = {
        "version": 1,
        "purpose": purpose,
        "requester": requester,
        "origin": origin,
        "method": "POST",
        "path": SCHEMA["x-http"]["routes"][purpose],
        "issued_at": issued_at,
        "body_sha256": hashlib.sha256(canonical(value)).hexdigest(),
    }
    validate("http_proof", proof)
    signed = {
        "proof": proof,
        "signature": encode(
            SigningKey(seed).sign(domain("http_request") + canonical(proof)).signature
        ),
    }
    return "Awsign " + encode(canonical(signed))


def check_http(authorization, body, *, requester, origin, method, path, purpose, now):
    try:
        if (
            not isinstance(authorization, str)
            or len(authorization) > SCHEMA["x-http"]["max_header_bytes"]
            or not authorization.startswith("Awsign ")
        ):
            raise Refused("http_authorization_invalid")
        raw = decode(authorization[7:])
        packet = parse(raw)
        validate("http_authorization", packet)
        if raw != canonical(packet):
            raise Refused("http_authorization_noncanonical")
        p = packet["proof"]
        if canonical(p["requester"]) != canonical(requester):
            raise Refused("requester_mismatch")
        if (p["origin"], p["method"], p["path"], p["purpose"]) != (
            origin,
            method,
            path,
            purpose,
        ):
            raise Refused("http_binding_mismatch")
        if method != "POST" or path != SCHEMA["x-http"]["routes"].get(purpose):
            raise Refused("http_binding_mismatch")
        if (
            type(now) is not int
            or not 0 <= now - p["issued_at"] <= SCHEMA["x-http"]["freshness_seconds"]
        ):
            raise Refused("http_expired")
        body_value = parse(body)
        digest = hashlib.sha256(canonical(body_value)).hexdigest()
        if not hmac.compare_digest(digest, p["body_sha256"]):
            raise Refused("http_body_mismatch")
        preimage = domain("http_request") + canonical(p)
        _signature(requester["key"], packet["signature"], preimage)
        return {
            "key": requester["key"],
            "requester": requester,
            "issued_at": p["issued_at"],
            "preimage": preimage,
            "body": body_value,
        }
    except Refused:
        raise
    except (ValueError, KeyError, TypeError, ValidationError) as exc:
        raise Refused("http_invalid") from exc


def check_enrollment_intent(
    signed, *, issuer_key, requester, origin, rp_id, now, trust=None
):
    """issuer_key is checked public issuer authority, never taken from signed.

    For creation, a proposed identity_key is not yet bound by public identity
    status: an ID certificate contains no subject key. Existing-person
    enrollment requires current committed Trust here; pending creation needs
    committed Trust at activation. Active-person recovery additionally requires
    that new key already current when the service starts the recovery. Pending is not active authority.
    """
    return _check_enrollment_intent(
        signed,
        issuer_key=issuer_key,
        requester=requester,
        origin=origin,
        rp_id=rp_id,
        now=now,
        live=True,
        trust=trust,
    )


def _check_enrollment_intent(
    signed, *, issuer_key, requester, origin, rp_id, now, live, trust=None
):
    try:
        validate("enrollment_intent", signed)
        body = signed["intent"]
        if canonical(body["requester"]) != canonical(requester):
            raise Refused("requester_mismatch")
        if (body["origin"], body["rp_id"]) != (origin, rp_id):
            raise Refused("origin_invalid")
        validate_site(origin, rp_id)
        if live and (
            type(now) is not int or not body["not_before"] <= now < body["deadline"]
        ):
            raise Refused("enrollment_expired")
        if len(decode(body["challenge"])) != 32:
            raise Refused("enrollment_challenge_invalid")
        certificate = body["pending_certificate"]
        c = certificate["certificate"]
        later = body["purpose"] == "enroll_existing_person"
        # An existing certificate can be witnessed under an earlier controller
        # epoch. The caller's SDK-checked current Trust, not this signature alone,
        # establishes that its exact certificate is still admitted.
        certificate_key = c["issuer_key"] if later else issuer_key
        verify_id_certificate(certificate, issuer_key=certificate_key)
        if (c["id"], c["domain"], c["kind"], c["issuer_key"]) != (
            body["person"],
            body["organisation"],
            "human",
            certificate_key,
        ):
            raise Refused("enrollment_certificate_mismatch")
        if later:
            if trust is None or not 0 <= now - trust.observed_at <= 60:
                raise Refused("identity_unavailable")
            if (
                trust.person,
                trust.organisation,
                trust.identity_key,
                trust.certificate,
                trust.issuer,
            ) != (
                body["person"],
                body["organisation"],
                body["identity_key"],
                id_certificate_id(c),
                issuer_key,
            ):
                raise Refused("enrollment_identity_mismatch")
            if requester != {
                "kind": "identity",
                "id": trust.person,
                "key": trust.identity_key,
            }:
                raise Refused("requester_mismatch")
        public_key_from_did(body["identity_key"])
        preimage = domain("enrollment_intent") + canonical(body)
        _signature(issuer_key, signed["signature"], preimage)
        return {
            "person": body["person"],
            "certificate": id_certificate_id(c),
            "identity_key": body["identity_key"],
            "state": "pending",
            "locator": commitment("enrollment_locator", signed),
            "preimage": preimage,
        }
    except Refused:
        raise
    except (ValueError, KeyError, TypeError, ValidationError) as exc:
        raise Refused("enrollment_invalid") from exc


def check_activation_carrier(value, *, requester, trust):
    """Only the original requester or the exact current target person carries activation.

    This checked carrier never replaces the original requester in I or C and
    grants no session, receipt recovery or effect permission.
    """
    i = value["intent"]["intent"]
    if (trust.person, trust.organisation, trust.identity_key) != (
        i["person"],
        i["organisation"],
        i["identity_key"],
    ):
        raise Refused("enrollment_identity_mismatch")
    original = i["requester"]
    carrier = value.get("carrier", original)
    if canonical(requester) != canonical(carrier):
        raise Refused("requester_mismatch")
    if (
        carrier.get("kind") == "identity"
        and carrier.get("id") == i["person"]
        and carrier.get("key") != trust.identity_key
    ):
        raise Refused("requester_mismatch")
    if canonical(carrier) != canonical(original):
        expected = {
            "kind": "identity",
            "id": value["intent"]["intent"]["person"],
            "key": trust.identity_key,
        }
        if canonical(carrier) != canonical(expected) or trust.person != expected["id"]:
            raise Refused("requester_mismatch")
    return original


def check_activation(
    value,
    *,
    issuer_key,
    requester,
    origin,
    rp_id,
    now,
    trust,
    previous=None,
    transition_trust=None,
):
    """Activation requires independently checked COMMITTED public identity.

    A valid pending intent/B/creation proof alone remains pending. The public
    Trust is acquired through read_trust; it is not parsed from this payload.
    The issuer's nonce consumption/application rule is outside this service.
    Once evidence exists this is observation, not a new enrollment ceremony:
    intent and saved confirmation deadlines do not expire committed evidence.
    """
    try:
        validate("enrollment_activation", value)
        original = value["intent"]["intent"]["requester"]
        pending = _check_enrollment_intent(
            value["intent"],
            issuer_key=issuer_key,
            requester=original,
            origin=origin,
            rp_id=rp_id,
            now=now,
            live=False,
            trust=trust,
        )
        if (
            type(now) is not int
            or trust is None
            or not 0 <= now - trust.observed_at <= 60
        ):
            raise Refused("identity_unavailable")
        if (trust.person, trust.certificate, trust.identity_key, trust.issuer) != (
            pending["person"],
            pending["certificate"],
            pending["identity_key"],
            issuer_key,
        ):
            raise Refused("enrollment_identity_mismatch")
        check_activation_carrier(value, requester=requester, trust=trust)
        later = value["version"] == 2
        if later and (
            "previous_binding_commitment" not in value["intent"]["intent"]
            and value["intent"]["intent"]["purpose"] != "enroll_existing_person"
        ):
            raise Refused("enrollment_purpose_mismatch")
        c = value["confirmation_receipt"] if later else value["creation_receipt"]
        if canonical(c["binding"]) != canonical(value["binding"]):
            raise Refused("binding_mismatch")
        checked, bh, _r = _creation_assertion(
            c, requester=original, origin=origin, now=now, trust=trust, live=False
        )
        b = value["binding"]["binding"]
        if canonical(value["id_chain"]) != canonical(c["id_chain"]):
            raise Refused("identity_chain_mismatch")
        # The caller's read_trust validated this chain against public status.
        if not any(
            canonical(item)
            == canonical(value["intent"]["intent"]["pending_certificate"])
            for item in value["id_chain"]
        ):
            raise Refused("identity_chain_mismatch")
        evidence = value["evidence"]
        e = evidence["evidence"]
        if later:
            from .statements import _check_statement

            _check_statement(evidence, trust)
        else:
            _signature(
                issuer_key,
                evidence["signature"],
                domain("identity_evidence") + canonical(e),
            )
            expected_subject = {
                "id": trust.person,
                "certificate": trust.certificate,
                "key": trust.identity_key,
            }
            if (
                canonical(e["subject"]) != canonical(expected_subject)
                or e["organisation"] != trust.organisation
                or e["issuer"] != issuer_key
            ):
                raise Refused("evidence_subject_mismatch")
        new_creation = {
            "credential": checked.credential,
            "grade": checked.grade,
            "receipt_commitment": commitment("receipt_commitment", c),
        }
        if e["binding_commitment"] != bh:
            raise Refused("evidence_binding_mismatch")
        if later:
            from .statements import _match_confirmation

            _match_confirmation(e, c, checked, bh)
        if (
            "previous_binding_commitment" in value["intent"]["intent"]
            or "transition" in e
        ):
            from .lifecycle import check_lifecycle

            check_lifecycle(
                value,
                previous=previous,
                transition_trust=transition_trust,
                new_creation=new_creation,
            )
        elif not later and (
            e["creation"] != new_creation
            or value["intent"]["intent"]["purpose"] != "enroll_person"
        ):
            raise Refused("evidence_binding_mismatch")
        if (b["origin"], b["rp_id"]) != (origin, rp_id):
            raise Refused("origin_invalid")
        return {"person": trust.person, "state": "active", "binding_commitment": bh}
    except Refused:
        raise
    except (ValueError, KeyError, TypeError, ValidationError) as exc:
        raise Refused("activation_invalid") from exc


def read_needs_human(value, *, requester, origin, now, status):
    try:
        validate("needs_human", value)
        if status != SCHEMA["x-enforcer"]["needs_human_status"]:
            raise Refused("http_status_invalid")
        if value["approval_origin"] != origin:
            raise Refused("origin_invalid")
        raw = decode(value["request_bytes"])
        r = parse(raw)
        validate("request", r)
        check_definition(r)
        if raw != canonical(r):
            raise Refused("request_mismatch")
        if r["purpose"] != "act_approval":
            raise Refused("purpose_invalid")
        if canonical(r["requester"]) != canonical(requester):
            raise Refused("requester_mismatch")
        if type(now) is not int or not r["not_before"] <= now < r["deadline"]:
            raise Refused("request_expired")
        if value["digest"] != hashlib.sha256(domain("request") + raw).hexdigest():
            raise Refused("request_digest_mismatch")
        return r
    except Refused:
        raise
    except (ValueError, KeyError, TypeError, ValidationError) as exc:
        raise Refused("needs_human_invalid") from exc


def check_presentation(
    value,
    *,
    expected_request,
    presenter,
    origin,
    now,
    trust,
    required_grade,
    nonce_keys,
):
    try:
        validate("presentation", value)
        if decode(value["request_bytes"]) != canonical(expected_request):
            raise Refused("request_mismatch")
        result = verify_for_effect(
            value["receipt"],
            expected_request=expected_request,
            presenter=presenter,
            now=now,
            trust=trust,
            required_grade=required_grade,
            nonce_keys=nonce_keys,
        )
        if result.origin != origin:
            raise Refused("origin_invalid")
        return result
    except Refused:
        raise
    except (ValueError, KeyError, TypeError, ValidationError) as exc:
        raise Refused("presentation_invalid") from exc


def make_needs_human(request, *, origin):
    check_definition(request)
    if request["purpose"] != "act_approval":
        raise Refused("purpose_invalid")
    raw = canonical(request)
    return SCHEMA["x-enforcer"]["needs_human_status"], {
        "version": 1,
        "status": "needs_human",
        "approval_origin": origin,
        "request_bytes": encode(raw),
        "digest": hashlib.sha256(domain("request") + raw).hexdigest(),
    }


def _creation_assertion(receipt, *, requester, origin, now, trust, live=True):
    validate("receipt", receipt)
    request = parse(decode(receipt["request_bytes"]))
    check_definition(request)
    if request["purpose"] != "enrollment_confirmation":
        raise Refused("purpose_invalid")
    if canonical(request["requester"]) != canonical(requester):
        raise Refused("requester_mismatch")
    if live and not request["not_before"] <= now < request["deadline"]:
        raise Refused("request_expired")
    checked = verify_historical(receipt, expected_request=request, trust=trust)
    if checked.origin != origin:
        raise Refused("origin_invalid")
    bh = commitment("binding_commitment", receipt["binding"])
    target = request["act"]["target"]
    if (
        target["person"],
        target["certificate"],
        target["identity_key"],
        target["binding_commitment"],
    ) != (trust.person, trust.certificate, trust.identity_key, bh):
        raise Refused("creation_target_mismatch")
    return checked, bh, request


def check_creation_proof(
    receipt,
    *,
    intent,
    issuer_key,
    requester,
    origin,
    rp_id,
    now,
    pending_trust,
    nonce_keys,
):
    """Issuer-only confirmation check; service activation remains pending.

    pending_trust combines the exact signed certificate/key with independently
    checked CURRENT issuer authority and its observation time. For existing
    people it is committed public Trust; for creation it does not claim public
    registration. The issuer still owns authorization and nonce consumption.
    """
    try:
        pending = check_enrollment_intent(
            intent,
            issuer_key=issuer_key,
            requester=requester,
            origin=origin,
            rp_id=rp_id,
            now=now,
            trust=pending_trust,
        )
        trust = pending_trust
        if trust is None or not 0 <= now - trust.observed_at <= 60:
            raise Refused("issuer_unavailable")
        if (trust.person, trust.certificate, trust.identity_key, trust.issuer) != (
            pending["person"],
            pending["certificate"],
            pending["identity_key"],
            issuer_key,
        ):
            raise Refused("enrollment_identity_mismatch")
        checked, bh, request = _creation_assertion(
            receipt, requester=requester, origin=origin, now=now, trust=trust
        )
        _check_nonce(request, nonce_keys)
        return {
            "person": trust.person,
            "state": "pending",
            "binding_commitment": bh,
            "credential": checked.credential,
            "grade": checked.grade,
            "digest": checked.digest,
        }
    except Refused:
        raise
    except (ValueError, KeyError, TypeError, ValidationError) as exc:
        raise Refused("creation_invalid") from exc
