"""Enrollment transition evidence over independently checked prior state.

The issuer/enforcer decides permission and consumes its nonce at the effect.
These historical checks establish exact artifacts, not permission for an effect.
Previous state and transition Trust are checked ports, never receipt trust roots.
"""

from .canonical import canonical, parse
from .encoding import decode
from .verify import Refused, verify_historical
from .wire import domain, validate


def check_lifecycle(value, *, previous, transition_trust, new_creation):
    from .definitions import check_definition
    from .seams import _signature, commitment

    if previous is None:
        raise Refused("enrollment_previous_unavailable")
    trust = previous["trust"]
    signed_b, signed_e = previous["binding"], previous["evidence"]
    supplied = value.get("previous_evidence")
    if supplied is not None:
        if signed_e is not None and canonical(supplied) != canonical(signed_e):
            raise Refused("transition_before_mismatch")
        signed_e = supplied
    validate("binding", signed_b)
    b = signed_b["binding"]
    e = None if signed_e is None else signed_e["evidence"]
    expected_subject = {
        "id": trust.person,
        "certificate": trust.certificate,
        "key": trust.identity_key,
    }
    if (
        b["person"],
        b["organisation"],
        b["identity_key"],
        b["certificate"],
        b["issuer"],
    ) != (
        trust.person,
        trust.organisation,
        trust.identity_key,
        trust.certificate,
        trust.issuer,
    ):
        raise Refused("binding_mismatch")
    _signature(trust.issuer, signed_b["signature"], domain("binding") + canonical(b))
    before_hash = commitment("binding_commitment", signed_b)
    if signed_e is not None:
        validate("creation_evidence", signed_e)
        _signature(
            trust.issuer,
            signed_e["signature"],
            domain("identity_evidence") + canonical(e),
        )
        if (
            e["subject"] != expected_subject
            or e["binding_commitment"] != before_hash
            or e["organisation"] != trust.organisation
            or e["issuer"] != trust.issuer
        ):
            raise Refused("evidence_subject_mismatch")
    i = value["intent"]["intent"]
    after_b = value["binding"]["binding"]
    after_e = value["evidence"]["evidence"]
    t = after_e.get("transition")
    if t is None:
        raise Refused("transition_mode_invalid")
    if signed_e is None and t["mode"] != "recreated":
        raise Refused("enrollment_previous_unavailable")
    if (
        i.get("previous_binding_commitment") != before_hash
        or t["before"]
        != {"subject": expected_subject, "binding_commitment": before_hash}
        or t["previous_evidence_commitment"]
        != (
            None
            if signed_e is None
            else commitment("identity_evidence_commitment", signed_e)
        )
    ):
        raise Refused("transition_before_mismatch")
    if (after_b["person"], after_b["organisation"]) != (
        trust.person,
        trust.organisation,
    ) or after_b["identity_key"] == trust.identity_key:
        raise Refused("enrollment_identity_mismatch")
    if t["confirmation_receipt_commitment"] != commitment(
        "receipt_commitment", value["creation_receipt"]
    ):
        raise Refused("evidence_binding_mismatch")
    if i["purpose"] == "enroll_person":
        if (
            t["mode"] != "recreated"
            or t["approval_receipt_commitment"] is not None
            or "transition_receipt" in value
        ):
            raise Refused("transition_mode_invalid")
        # A recovery is a new creation event after a break. No old grade survives.
        if after_e["creation"] != new_creation:
            raise Refused("evidence_binding_mismatch")
        return
    if t["mode"] not in ("unbroken", "assisted"):
        raise Refused("transition_mode_invalid")
    if e is None:
        raise Refused("enrollment_previous_unavailable")
    if after_e["creation"] != e["creation"]:
        raise Refused("creation_changed")
    receipt = value.get("transition_receipt")
    if receipt is None or transition_trust is None:
        raise Refused("transition_receipt_unavailable")
    if t["approval_receipt_commitment"] != commitment("receipt_commitment", receipt):
        raise Refused("transition_receipt_mismatch")
    r = parse(decode(receipt["request_bytes"]))
    check_definition(r)
    checked = verify_historical(receipt, expected_request=r, trust=transition_trust)
    same = checked.person == trust.person
    if (t["mode"] == "unbroken") != same:
        raise Refused("transition_approver_mismatch")
    if same and canonical(receipt["binding"]) != canonical(signed_b):
        raise Refused("binding_mismatch")
    after_target = {
        "certificate": after_b["certificate"],
        "identity_key": after_b["identity_key"],
        "binding_commitment": after_e["binding_commitment"],
    }
    before_target = {
        "certificate": trust.certificate,
        "identity_key": trust.identity_key,
        "binding_commitment": before_hash,
    }
    expected = {
        "person": trust.person,
        "before": before_target,
        "after": after_target,
        "continuity": t["mode"],
    }
    if (
        r["purpose"] != "act_approval"
        or r["definition"]["id"] != "human.enrollment.replace"
        or r["organisation"] != trust.organisation
        or r["act"]["target"] != expected
    ):
        raise Refused("transition_target_mismatch")
