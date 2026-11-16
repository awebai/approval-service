"""Append the three activation-only carrier vectors, preserving earlier cases.

The original I/C bytes and requester do not change. Each HTTP proof is signed
by the named carrier; a valid signature is not sufficient activation authority.
"""

import copy
import hashlib
import json
from pathlib import Path

from awid.did import did_key_from_signing_key, stable_id_from_did_key
from nacl.signing import SigningKey

from approval_service.canonical import canonical
from approval_service.encoding import encode
from approval_service.wire import SCHEMA, domain

root = Path(__file__).resolve().parents[1]
p = root / "vectors/issuer-service-enrollment-v1.json"
v = json.loads(p.read_text())
if any(c["id"].startswith("activation-carrier-") for c in v["cases"]):
    raise SystemExit("refuse to append carrier vectors twice")
base = next(c for c in v["cases"] if c.get("accept") and c.get("phase") == "activation")
for name, n, same, accept in [
    ("current-person", 2, True, True),
    ("noncurrent-key", 7, True, False),
    ("different-person", 4, False, False),
]:
    c = copy.deepcopy(base)
    key = did_key_from_signing_key(bytes([n]) * 32)
    presenter = {
        "kind": "identity",
        "id": c["expected_person"] if same else stable_id_from_did_key(key),
        "key": key,
    }
    c.update(id="activation-carrier-" + name, presenter=presenter, accept=accept)
    c["activation"]["carrier"] = presenter
    if not accept:
        c["expected_error"] = "requester_mismatch"
    proof = {
        "version": 1,
        "purpose": "enrollment_activate",
        "requester": presenter,
        "origin": c["origin"],
        "method": "POST",
        "path": SCHEMA["x-http"]["routes"]["enrollment_activate"],
        "issued_at": c["now"],
        "body_sha256": hashlib.sha256(canonical(c["activation"])).hexdigest(),
    }
    packet = {
        "proof": proof,
        "signature": encode(
            SigningKey(bytes([n]) * 32)
            .sign(domain("http_request") + canonical(proof))
            .signature
        ),
    }
    c["activation_authorization"] = "Awsign " + encode(canonical(packet))
    v["cases"].append(c)
p.write_text(json.dumps(v, indent=2, ensure_ascii=False) + "\n")
