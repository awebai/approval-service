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
from .encoding import decode, encode
from .verify import Refused, verify_for_effect, verify_historical
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


def check_enrollment_intent(signed, *, issuer_key, requester, origin, rp_id, now):
    """issuer_key is checked public issuer authority, never taken from signed."""
    try:
        validate("enrollment_intent", signed)
        body = signed["intent"]
        if canonical(body["requester"]) != canonical(requester):
            raise Refused("requester_mismatch")
        if (body["origin"], body["rp_id"]) != (origin, rp_id):
            raise Refused("origin_invalid")
        validate_site(origin, rp_id)
        if type(now) is not int or not body["not_before"] <= now < body["deadline"]:
            raise Refused("enrollment_expired")
        if len(decode(body["challenge"])) != 32:
            raise Refused("enrollment_challenge_invalid")
        certificate = body["pending_certificate"]
        c = certificate["certificate"]
        verify_id_certificate(certificate, issuer_key=issuer_key)
        if (c["id"], c["domain"], c["kind"], c["issuer_key"]) != (
            body["person"],
            body["organisation"],
            "human",
            issuer_key,
        ):
            raise Refused("enrollment_certificate_mismatch")
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


def check_activation(value, *, issuer_key, requester, origin, rp_id, now, trust):
    """Activation requires independently checked COMMITTED public identity.

    A valid pending intent/B/creation proof alone remains pending. The public
    Trust is acquired through read_trust; it is not parsed from this payload.
    The issuer's nonce consumption/application rule is outside this service.
    """
    try:
        validate("enrollment_activation", value)
        pending = check_enrollment_intent(
            value["intent"],
            issuer_key=issuer_key,
            requester=requester,
            origin=origin,
            rp_id=rp_id,
            now=now,
        )
        if trust is None or not 0 <= now - trust.observed_at <= 60:
            raise Refused("identity_unavailable")
        if (trust.person, trust.certificate, trust.identity_key, trust.issuer) != (
            pending["person"],
            pending["certificate"],
            pending["identity_key"],
            issuer_key,
        ):
            raise Refused("enrollment_identity_mismatch")
        c = value["creation_receipt"]
        raw = decode(c["request_bytes"])
        r = parse(raw)
        validate("request", r)
        if r["purpose"] != "enrollment_confirmation":
            raise Refused("purpose_invalid")
        if not r["not_before"] <= now < r["deadline"]:
            raise Refused("request_expired")
        if canonical(c["binding"]) != canonical(value["binding"]):
            raise Refused("binding_mismatch")
        checked = verify_historical(c, expected_request=r, trust=trust)
        if checked.origin != origin:
            raise Refused("origin_invalid")
        b = value["binding"]["binding"]
        bh = commitment("binding_commitment", value["binding"])
        target = r["act"].get("target", {})
        if (
            target.get("person"),
            target.get("certificate"),
            target.get("identity_key"),
            target.get("binding_commitment"),
        ) != (trust.person, trust.certificate, trust.identity_key, bh):
            raise Refused("creation_target_mismatch")
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
        if e["binding_commitment"] != bh or e["creation"] != {
            "credential": checked.credential,
            "grade": checked.grade,
            "receipt_commitment": commitment("receipt_commitment", c),
        }:
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
    validate("request", request)
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
