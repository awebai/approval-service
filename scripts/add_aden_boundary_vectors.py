"""Review G1 and refusal-code regressions, without overwriting the old corpus."""

import copy
import json
from pathlib import Path

from approval_service.encoding import encode

root = Path(__file__).resolve().parents[1]
out = root / "vectors/enrollment-boundaries-v1.json"
if out.exists():
    raise SystemExit("refuse to overwrite vectors")
later = json.loads((root / "vectors/later-enrollment-v1.json").read_text())["cases"][0]
creation = next(
    c
    for c in json.loads(
        (root / "vectors/issuer-service-enrollment-v1.json").read_text()
    )["cases"]
    if c["accept"] and c["phase"] == "activation"
)
cases = []
for kind, base in [("creation", creation), ("later", later)]:
    for fault in [
        "empty",
        "no_certificate",
        "not_object",
        "no_issuer_key",
        "issuer_key_not_string",
        "challenge",
        "request_bytes",
    ]:
        c = copy.deepcopy(base)
        c.update(id=kind + "-" + fault, accept=False)
        a = c["activation"]
        i = a["intent"]["intent"]
        if fault == "empty":
            i["pending_certificate"] = {}
        elif fault == "no_certificate":
            i["pending_certificate"].pop("certificate")
        elif fault == "not_object":
            i["pending_certificate"]["certificate"] = []
        elif fault == "no_issuer_key":
            i["pending_certificate"]["certificate"].pop("issuer_key")
        elif fault == "issuer_key_not_string":
            i["pending_certificate"]["certificate"]["issuer_key"] = 17
        elif fault == "challenge":
            i["challenge"] = "A"
        else:
            a["confirmation_receipt" if kind == "later" else "creation_receipt"][
                "request_bytes"
            ] = encode(b"not-json")
        c["expected_error"] = (
            "activation_invalid"
            if fault in ["empty", "no_certificate", "not_object", "request_bytes"]
            else "enrollment_invalid"
        )
        if fault != "request_bytes":
            c["expected_intent_error"] = "enrollment_invalid"
        cases.append(c)
out.write_text(json.dumps({"version": 1, "cases": cases}, indent=2) + "\n")
