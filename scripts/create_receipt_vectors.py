"""Freeze real software-authenticator signatures; NEVER auto-refreeze in tests."""

import copy
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tests"))
from receipts import b64, fixture, resign

out = root / "vectors/receipts.json"
if out.exists():
    raise SystemExit("refuse to overwrite frozen vectors")
cases = []


def add(name, w, accept, now=1100, required_grade="passkey_uv"):
    status = {**w["status"], "issuer_public_key": b64(w["status"]["issuer_public_key"])}
    cases.append(
        {
            "id": name,
            "receipt": w["receipt"],
            "request": w["request"],
            "trust": status,
            "nonce_key": b64(w["secret"]),
            "now": now,
            "required_grade": required_grade,
            "presenter": w["request"]["requester"],
            "accept": accept,
        }
    )


for algorithm in (-7, -8, -257):
    add("algorithm-" + str(algorithm), fixture(algorithm), True)
for packaging in ("carried", "dropped", "superseded"):
    for expired in (False, True):
        w = fixture()
        later = copy.deepcopy(w["receipt"]["binding"]["binding"])
        later.update(
            identity_key="identity-key-after", certificate="sha256:" + "c" * 64
        )
        w["status"].update(
            identity_key=later["identity_key"],
            certificate=later["certificate"],
            observed_at=1301 if expired else 1100,
        )
        if packaging == "dropped":
            later["credentials"][0]["id"] = b64(b"another-key")
        if packaging != "superseded":
            w["receipt"]["binding"] = resign(w, later)
        add(
            packaging + ("-expired" if expired else "-current"),
            w,
            packaging == "carried" and not expired,
            now=1301 if expired else 1100,
        )
w = fixture()
w["receipt"]["assertion"]["signature"] = b64(b"bad")
add("changed-signature", w, False)
w = fixture()
b = w["receipt"]["binding"]["binding"]
other = copy.deepcopy(b["credentials"][0])
other.update(
    id=b64(b"other"), grade="certified_hardware", snapshot="sha256:" + "d" * 64
)
b["credentials"].append(other)
w["receipt"]["binding"] = resign(w, b)
add(
    "different-key-hardware-cannot-upgrade",
    w,
    False,
    required_grade="certified_hardware",
)
out.write_text(
    json.dumps(
        {
            "version": 1,
            "note": "Real software-authenticator assertions. No private identity/passkey keys retained. Non-production fixed nonce secret is a vector input. These cases do not qualify hardware or registry.",
            "cases": cases,
        },
        indent=2,
    )
    + "\n"
)
