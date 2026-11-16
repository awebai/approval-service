"""Issuer enrollment claims and optional historical confirmation proof.

Trust is independently checked by the caller. This does not authorize an
effect, establish currentness, or turn issuer time/grade into witnessed facts.
"""

import copy

from jsonschema import ValidationError

from .canonical import canonical, parse
from .encoding import decode
from .verify import Refused
from .wire import SCHEMA, domain, validate


def statement_definition(name):
    try:
        value = copy.deepcopy(SCHEMA["x-statement-definitions"][name])
    except KeyError as exc:
        raise Refused("statement_unavailable") from exc
    value["body_schema"] = copy.deepcopy(SCHEMA["$defs"][value["body_schema"]])
    value["signature_domain"] = SCHEMA["x-domains"][value["signature_domain"]]
    return value


def _check_statement(statement, trust):
    from .seams import _signature

    e = statement.get("evidence") if isinstance(statement, dict) else None
    if not isinstance(e, dict) or type(e.get("version")) is not int:
        raise Refused("enrollment_evidence_invalid")
    if e.get("version") != 1 or e.get("kind") != "human_enrolled_later":
        raise Refused("enrollment_evidence_unsupported")
    try:
        validate("later_enrollment_evidence", statement)
    except (TypeError, ValueError, ValidationError) as exc:
        raise Refused("enrollment_evidence_invalid") from exc
    _signature(
        trust.issuer,
        statement["signature"],
        domain("later_enrollment_evidence") + canonical(e),
    )
    if (
        e["subject"]
        != {
            "id": trust.person,
            "certificate": trust.certificate,
            "key": trust.identity_key,
        }
        or e["organisation"] != trust.organisation
        or e["issuer"] != trust.issuer
    ):
        raise Refused("evidence_subject_mismatch")
    return e


def _match_confirmation(e, receipt, checked, binding_commitment):
    from .seams import commitment

    f = e["enrollment"]
    receipt_commitment = commitment("receipt_commitment", receipt)
    if (
        e["binding_commitment"] != binding_commitment
        or f["credential"] != checked.credential
        or f["grade"] != checked.grade
        or f["confirmation_receipt_commitment"] != receipt_commitment
        or (
            "transition" in e
            and e["transition"]["confirmation_receipt_commitment"] != receipt_commitment
        )
    ):
        raise Refused("evidence_binding_mismatch")


def verify_enrollment_evidence(statement, *, trust, receipt=None):
    """Authenticate issuer facts; check the actual proof only when supplied.

    No live ceremony deadline is applied to saved evidence. since and grade
    remain issuer statements, even when the credential assertion is checked.
    """
    from .seams import _creation_assertion

    e = _check_statement(statement, trust)
    f = e["enrollment"]
    result = {
        "person": trust.person,
        "credential": f["credential"],
        "grade": f["grade"],
        "since": f["since"],
        "proof_status": "not_presented",
    }
    if receipt is not None:
        try:
            validate("receipt", receipt)
            request = parse(decode(receipt["request_bytes"]))
            validate("request", request)
        except (ValueError, TypeError, KeyError, ValidationError) as exc:
            raise Refused("enrollment_proof_invalid") from exc
        checked, bh, _ = _creation_assertion(
            receipt,
            requester=request["requester"],
            origin=receipt["binding"]["binding"]["origin"],
            now=0,
            trust=trust,
            live=False,
        )
        _match_confirmation(e, receipt, checked, bh)
        result["proof_status"] = "checked"
    return result
