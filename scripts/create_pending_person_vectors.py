"""Exact pending-person ownership scope, independent expected refusals."""

import copy
import json
from dataclasses import asdict
from pathlib import Path

from nacl.signing import SigningKey

from approval_service.canonical import canonical
from approval_service.encoding import encode
from approval_service.requester import KeyObservation
from approval_service.wire import domain

root = Path(__file__).resolve().parents[1]
out = root / "vectors/pending-person-v1.json"
if out.exists():
    raise SystemExit("refuse to overwrite vectors")
c = json.loads((root / "vectors/later-enrollment-v1.json").read_text())["cases"][0]
i = copy.deepcopy(c["activation"]["intent"])
i["intent"]["purpose"] = "enroll_person"


def sign(i):
    i["signature"] = encode(
        SigningKey(bytes([1]) * 32)
        .sign(domain("enrollment_intent") + canonical(i["intent"]))
        .signature
    )


sign(i)
base = {
    "intent": i,
    "descriptor": c["requester"],
    "issuer_key": c["issuer_key"],
    "origin": c["origin"],
    "rp_id": c["rp_id"],
    "now": 1100,
    "observation": asdict(
        KeyObservation(c["trust"]["person"], c["trust"]["identity_key"], False, 1100)
    ),
    "accept": True,
}
cases = []
for purpose in [
    "enrollment_start",
    "enrollment_material",
    "enrollment_confirm",
    "enrollment_activate",
    "holder_binding",
    "holder_finish",
    "holder_activate",
]:
    cases.append(
        {**copy.deepcopy(base), "id": "pending-" + purpose, "purpose": purpose}
    )
for fault in ["other_intent", "act_route", "noncurrent_key", "admin_carrier"]:
    t = copy.deepcopy(base)
    t.update(
        id="pending-refuse-" + fault,
        purpose="enrollment_start",
        accept=False,
        expected_error="requester_mismatch",
    )
    if fault == "other_intent":
        t["intent"]["intent"]["person"] = "did:aw:another-person"
        sign(t["intent"])
    elif fault == "act_route":
        t.update(purpose="submit", expected_error="enrollment_scope_invalid")
    elif fault == "noncurrent_key":
        t["observation"]["current_key"] = "another-current-key"
    else:
        t["descriptor"] = {
            "kind": "namespace_controller",
            "namespace": "customer.example",
            "key": c["issuer_key"],
        }
    cases.append(t)
out.write_text(json.dumps({"version": 1, "cases": cases}, indent=2) + "\n")
