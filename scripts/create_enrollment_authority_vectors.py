"""K1: actual-person issuer OR checked namespace controller, never a B anchor.

Reuse the immutable public-chain/status corpus, and sign new real approval
receipts with public TEST keys. No verifier chooses the expected outcomes.
"""

import copy
import hashlib
import hmac
import json
import sys
from pathlib import Path

from awid.did import did_key_from_signing_key, stable_id_from_did_key
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from receipts import assertion, b64, canon, fixture

path = ROOT / "vectors/enrollment-authority-v1.json"
if path.exists():
    raise SystemExit("refuse to overwrite enrollment-authority corpus")
source = json.loads((ROOT / "vectors/trust.json").read_text())["cases"]
schema = json.loads((ROOT / "src/approval_service/data/format-v1.json").read_text())
domains = schema["x-domains"]
w = fixture()
cases = []
for name, source_name, signer_seed, accepted in [
    ("human-issued-person-controller-binding", "current-child-human", 1, True),
    ("unrelated-key-binding", "current-child-human", 9, False),
    ("foreign-controller-binding", "current-child-human", 8, False),
    ("self-asserted-binding-key", "current-child-human", 17, False),
    ("namespace-parent-unchanged", "current-root-human", 1, True),
]:
    c = copy.deepcopy(next(c for c in source if c["id"] == source_name))
    signer = SigningKey(bytes([signer_seed]) * 32)
    issuer = did_key_from_signing_key(bytes(signer))
    b = copy.deepcopy(w["receipt"]["binding"]["binding"])
    b.update(
        person=c["person"],
        organisation=c["organisation"],
        identity_key=c["identity_key"],
        certificate=c["expected_certificate"],
        issuer=issuer,
    )
    binding = {
        "binding": b,
        "signature": b64(signer.sign(domains["binding"].encode() + canon(b)).signature),
    }
    r = copy.deepcopy(w["request"])
    definition = schema["x-act-definitions"]["human.add"]
    target_key = did_key_from_signing_key(bytes([37]) * 32)
    r.update(
        organisation=c["organisation"],
        approver=c["person"],
        requester={"kind": "identity", "id": c["person"], "key": c["identity_key"]},
        definition={
            "id": "human.add",
            "version": 1,
            "sha256": hashlib.sha256(canon(definition)).hexdigest(),
        },
        act={
            "operation": "human.add",
            "target": {
                "person": stable_id_from_did_key(target_key),
                "certificate": "sha256:" + "a" * 64,
                "identity_key": target_key,
            },
            "expected_revision": 1,
        },
        not_before=c["now"] - 1,
        deadline=c["now"] + 300,
    )
    r["nonce"]["value"] = ""
    r["nonce"]["value"] = b64(
        hmac.digest(w["secret"], domains["nonce"].encode() + canon(r), "sha256")
    )
    receipt = {
        "version": 1,
        "request_bytes": b64(canon(r)),
        "binding": binding,
        "id_chain": c["chain"],
        "assertion": assertion(w["private"], -7, r, b["credentials"][0]["id"]),
    }
    c.update(
        id=name,
        accept=accepted,
        request=r,
        receipt=receipt,
        nonce_key=b64(w["secret"]),
        expected_namespace_issuer=did_key_from_signing_key(bytes([1]) * 32),
    )
    if not accepted:
        c["expected_error"] = "binding_mismatch"
    cases.append(c)
path.write_text(
    json.dumps(
        {
            "version": 1,
            "source": "trust.json public status/chain inputs; new real Ed25519 and ES256 signatures, public test seeds",
            "cases": cases,
        },
        indent=2,
    )
    + "\n"
)
