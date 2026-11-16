"""Closed service answers and requester-owned receipt assembly.

These readers report state; they do not authorize an enforcer effect. Saved
proof can be assembled/checked historically after a live request's deadline.
"""

import hashlib

from jsonschema import ValidationError

from .canonical import canonical, parse
from .encoding import decode, encode
from .seams import commitment
from .verify import Refused
from .wire import SCHEMA, validate


class ServiceError(Refused):
    def __init__(self, code, status):
        super().__init__(code)
        self.http_status = status


def read_answer(kind, body, *, status, request_bytes=None, intent=None, locator=None):
    try:
        if status >= 400:
            validate("service_error", body)
            raise ServiceError(body["error"]["code"], status)
        if status not in SCHEMA["x-answer-status"][kind]:
            raise Refused("service_response_invalid")
        validate(kind + "_answer", body)
        if locator is not None and body["locator"] != locator:
            raise Refused("locator_mismatch")
        if kind in ("submit", "poll", "cancel", "enrollment_confirm"):
            if request_bytes is None:
                raise Refused("request_mismatch")
            r = parse(request_bytes)
            validate("request", r)
            if canonical(r) != request_bytes:
                raise Refused("request_mismatch")
            digest = hashlib.sha256(
                SCHEMA["x-domains"]["request"].encode() + request_bytes
            ).hexdigest()
            if body["digest"] != digest:
                raise Refused("request_digest_mismatch")
            if body["deadline"] != r["deadline"]:
                raise Refused("deadline_mismatch")
            expected = (
                "enrollment_confirmation"
                if kind == "enrollment_confirm"
                else "act_approval"
            )
            if r["purpose"] != expected:
                raise Refused("purpose_invalid")
        if kind.startswith("enrollment_"):
            validate("enrollment_intent", intent)
            if body["locator"] != commitment("enrollment_locator", intent):
                raise Refused("locator_mismatch")
            i = intent["intent"]
            if kind == "enrollment_confirm" and (
                r["approver"] != i["person"]
                or r["organisation"] != i["organisation"]
                or canonical(r["requester"]) != canonical(i["requester"])
                or r["not_before"] < i["not_before"]
                or r["deadline"] > i["deadline"]
            ):
                raise Refused("enrollment_intent_mismatch")
            if kind == "enrollment_activate":
                if body["person"] != i["person"]:
                    raise Refused("person_mismatch")
            elif kind != "enrollment_confirm" and body["deadline"] != i["deadline"]:
                raise Refused("deadline_mismatch")
            if kind == "enrollment_start":
                p = body["public_key"]
                if p["challenge"] != i["challenge"] or p["rp"]["id"] != i["rp_id"]:
                    raise Refused("enrollment_challenge_invalid")
                if (
                    p["user"]["name"] != i["person"]
                    or p["user"]["displayName"] != i["person"]
                    or len(decode(p["user"]["id"])) != 32
                ):
                    raise Refused("enrollment_user_invalid")
                algorithms = SCHEMA["$defs"]["credential"]["properties"]["algorithm"][
                    "enum"
                ]
                if p["pubKeyCredParams"] != [
                    {"type": "public-key", "alg": a} for a in algorithms
                ]:
                    raise Refused("service_response_invalid")
        return body
    except Refused:
        raise
    except (ValueError, TypeError, KeyError, ValidationError) as exc:
        raise Refused("service_response_invalid") from exc


def assemble_receipt(request_bytes, answer, *, locator, status=200, intent=None):
    kind = "enrollment_confirm" if intent is not None else "poll"
    read_answer(
        kind,
        answer,
        status=status,
        request_bytes=request_bytes,
        intent=intent,
        locator=locator,
    )
    state = answer["state"]
    if state != "approved":
        raise Refused(
            {
                "pending": "approval_pending",
                "denied": "approval_denied",
                "cancelled": "approval_cancelled",
                "expired": "request_expired",
            }[state]
        )
    bundle = answer["approval"]
    if bundle is None:
        raise Refused("receipt_unavailable")
    receipt = {"version": 1, "request_bytes": encode(request_bytes), **bundle}
    validate("receipt", receipt)
    return receipt


def read_answer_json(kind, raw, **context):
    try:
        return read_answer(kind, parse(raw), **context)
    except Refused:
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise Refused("service_response_invalid") from exc


def read_enrollment_request(
    kind, body, *, intent, issuer_key, requester, origin, rp_id, now, trust=None
):
    # Admission evidence is checked by the HTTP layer from THIS frozen body.
    # B's grades also have to equal the service's private registered rows there.
    from .definitions import check_definition
    from .seams import _signature, check_enrollment_intent
    from .verify import _key
    from .wire import domain

    try:
        validate(kind + "_request", body)
        if canonical(body["intent"]) != canonical(intent):
            raise Refused("enrollment_intent_mismatch")
        pending = check_enrollment_intent(
            intent,
            issuer_key=issuer_key,
            requester=requester,
            origin=origin,
            rp_id=rp_id,
            now=now,
            trust=trust,
        )
        if kind == "enrollment_material":
            return pending
        if kind != "enrollment_confirm":
            raise Refused("enrollment_request_invalid")
        signed = body["binding"]
        b = signed["binding"]
        i = intent["intent"]
        if (
            b["person"],
            b["organisation"],
            b["certificate"],
            b["identity_key"],
            b["issuer"],
            b["origin"],
            b["rp_id"],
        ) != (
            pending["person"],
            i["organisation"],
            pending["certificate"],
            pending["identity_key"],
            issuer_key,
            origin,
            rp_id,
        ):
            raise Refused("binding_mismatch")
        _signature(issuer_key, signed["signature"], domain("binding") + canonical(b))
        seen_ids = set()
        seen_keys = set()
        for c in b["credentials"]:
            key = decode(c["key"])
            _key(key, c["algorithm"])
            if c["id"] in seen_ids or key in seen_keys:
                raise Refused("credential_key_invalid")
            seen_ids.add(c["id"])
            seen_keys.add(key)
        raw = decode(body["request_bytes"])
        r = parse(raw)
        check_definition(r)
        if raw != canonical(r):
            raise Refused("request_mismatch")
        if r["purpose"] != "enrollment_confirmation":
            raise Refused("purpose_invalid")
        if canonical(r["requester"]) != canonical(requester):
            raise Refused("requester_mismatch")
        if r["approver"] != i["person"] or r["organisation"] != i["organisation"]:
            raise Refused("person_mismatch")
        if (
            not i["not_before"]
            <= r["not_before"]
            <= now
            < r["deadline"]
            <= i["deadline"]
        ):
            raise Refused("request_expired")
        target = r["act"]["target"]
        expected = {
            "person": pending["person"],
            "certificate": pending["certificate"],
            "identity_key": pending["identity_key"],
            "binding_commitment": commitment("binding_commitment", signed),
        }
        if target != expected:
            raise Refused("creation_target_mismatch")
        return {
            **pending,
            "digest": hashlib.sha256(domain("request") + raw).hexdigest(),
        }
    except Refused:
        raise
    except (ValueError, TypeError, KeyError, ValidationError) as exc:
        raise Refused("enrollment_request_invalid") from exc
