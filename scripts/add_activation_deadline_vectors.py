"""Append deadline-boundary cases without changing any signed proof bytes.

Activation observes already committed identity/evidence; binding, material and
confirmation remain live enrollment operations. Expected outcomes follow the
coordinator's c687f1f8 / Antares 3a5f03f0 ruling, not a verifier invocation.
"""

import copy
import json
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "vectors/issuer-service-enrollment-v1.json"
corpus = json.loads(path.read_text())
cases = corpus["cases"]
if any(c["id"].startswith("activation-deadline-") for c in cases):
    raise SystemExit("refuse to append activation deadline cases twice")

base = next(c for c in cases if c["id"] == "activation-valid")
for name, now, fault, error in [
    ("exact", 1300, None, None),
    ("past-confirmation", 2000, None, None),
    ("stale-trust", 2000, "stale", "identity_unavailable"),
    ("missing-trust", 2000, "no-trust", "identity_unavailable"),
    ("missing-evidence", 2000, "no-evidence", "activation_invalid"),
    ("changed-intent", 2000, "intent", "signature_invalid"),
    ("changed-assertion", 2000, "assertion", "assertion_invalid"),
]:
    c = copy.deepcopy(base)
    c.update(id="activation-deadline-" + name, now=now, accept=error is None)
    c["trust"]["observed_at"] = now
    if fault == "stale":
        c["trust"]["observed_at"] = now - 61
    elif fault == "no-trust":
        c["trust"] = None
    elif fault == "no-evidence":
        c["activation"]["evidence"] = None
    elif fault == "intent":
        challenge = c["activation"]["intent"]["intent"]["challenge"]
        c["activation"]["intent"]["intent"]["challenge"] = (
            ("A" if challenge[0] != "A" else "B") + challenge[1:]
        )
    elif fault == "assertion":
        c["activation"]["creation_receipt"]["assertion"]["signature"] = "AA"
    if error:
        c["expected_error"] = error
    cases.append(c)

for kind in ("enrollment_material", "enrollment_confirm"):
    c = copy.deepcopy(next(c for c in cases if c["id"] == kind + "-request"))
    c.update(
        id=kind + "-after-deadline",
        now=c["intent"]["intent"]["deadline"],
        accept=False,
        expected_error="enrollment_expired",
    )
    cases.append(c)

# This existing expired activation also has stale public Trust. It still
# refuses, now at that live authority boundary rather than the intent clock.
old = next(c for c in cases if c["id"] == "expired-intent")
assert old["expected_error"] == "enrollment_expired"
old["expected_error"] = "identity_unavailable"
path.write_text(json.dumps(corpus, indent=2, ensure_ascii=False) + "\n")
