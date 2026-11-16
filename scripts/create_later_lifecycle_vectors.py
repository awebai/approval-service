"""New later-profile lifecycle cases; existing creation corpus stays unchanged."""

import copy
import hashlib
import json
from pathlib import Path

from nacl.signing import SigningKey

from approval_service.canonical import canonical
from approval_service.encoding import encode
from approval_service.wire import domain

root = Path(__file__).resolve().parents[1]
out = root / "vectors/later-lifecycle-v1.json"
if out.exists():
    raise SystemExit("refuse to overwrite vectors")
key = SigningKey(bytes([1]) * 32)


def signed(body):
    return {
        "evidence": body,
        "signature": encode(
            key.sign(domain("later_enrollment_evidence") + canonical(body)).signature
        ),
    }


def commitment(kind, value):
    return "sha256:" + hashlib.sha256(domain(kind) + canonical(value)).hexdigest()


def later(body, receipt):
    body = copy.deepcopy(body)
    body["kind"] = "human_enrolled_later"
    body.pop("creation")
    credential = next(
        e
        for e in receipt["binding"]["binding"]["credentials"]
        if e["id"] == receipt["assertion"]["id"]
    )
    body["enrollment"] = {
        "credential": credential["id"],
        "grade": credential["grade"],
        "since": 1001,
        "confirmation_receipt_commitment": commitment("receipt_commitment", receipt),
    }
    return signed(body)


cases = []
for old in json.loads((root / "vectors/enrollment-lifecycle-v1.json").read_text())[
    "cases"
]:
    if not old["accept"]:
        continue
    c = copy.deepcopy(old)
    c["id"] = "later-" + c["id"]
    for t in [c["trust"], c["previous"]["trust"]]:
        t["namespace_issuer"] = c["issuer_key"]
    p = c["previous"]
    if p["evidence"] is not None:
        p["evidence"] = later(p["evidence"]["evidence"], c["previous_creation_receipt"])
    a = c["activation"]
    a["version"] = 2
    if "previous_evidence" in a:
        a["previous_evidence"] = later(
            a["previous_evidence"]["evidence"], c["previous_creation_receipt"]
        )
    a["confirmation_receipt"] = a.pop("creation_receipt")
    e = later(a["evidence"]["evidence"], a["confirmation_receipt"])["evidence"]
    previous = a.get("previous_evidence", p["evidence"])
    e["transition"]["previous_evidence_commitment"] = (
        None
        if previous is None
        else commitment("identity_evidence_commitment", previous)
    )
    a["evidence"] = signed(e)
    cases.append(c)
    bad = copy.deepcopy(c)
    bad["id"] += "-different-confirmation"
    bad["accept"] = False
    bad["expected_error"] = "evidence_binding_mismatch"
    e = bad["activation"]["evidence"]["evidence"]
    e["transition"]["confirmation_receipt_commitment"] = "sha256:" + "0" * 64
    bad["activation"]["evidence"] = signed(e)
    cases.append(bad)
out.write_text(json.dumps({"version": 1, "cases": cases}, indent=2) + "\n")
