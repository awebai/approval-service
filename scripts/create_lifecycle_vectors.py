"""Freeze lifecycle inputs with actual public-test signatures; never overwrite.

Expected outcomes are explicit, independent of the verifier under test.
"""

import copy
import hashlib
import hmac
import json
import sys
from pathlib import Path

import cbor2
from awid.did import did_key_from_signing_key
from awid.id_certificates import id_certificate_id, id_certificate_signing_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from nacl.signing import SigningKey

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tests"))
from receipts import fixture, canon, b64

out = root / "vectors/enrollment-lifecycle-v1.json"
if out.exists():
    raise SystemExit("refuse to overwrite frozen lifecycle vectors")
schema = json.loads((root / "src/approval_service/data/format-v1.json").read_text())
base = next(
    c
    for c in json.loads(
        (root / "vectors/issuer-service-enrollment-v1.json").read_text()
    )["cases"]
    if c["accept"] and c["phase"] == "activation"
)
issuer = SigningKey(bytes([1]) * 32)


def prefix(k):
    return schema["x-domains"][k].encode()


def digest(k, v):
    return "sha256:" + hashlib.sha256(prefix(k) + canon(v)).hexdigest()


def sign(field, k, v):
    return {
        field: copy.deepcopy(v),
        "signature": b64(issuer.sign(prefix(k) + canon(v)).signature),
    }


def assertion(r, private, credential):
    client = canon(
        {
            "type": "webauthn.get",
            "challenge": b64(hashlib.sha256(prefix("request") + canon(r)).digest()),
            "origin": base["origin"],
            "crossOrigin": False,
        }
    )
    auth = hashlib.sha256(base["rp_id"].encode()).digest() + bytes([5]) + bytes(4)
    return {
        "id": credential,
        "client_data_json": b64(client),
        "authenticator_data": b64(auth),
        "signature": b64(
            private.sign(
                auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())
            )
        ),
    }


def reference(id):
    d = schema["x-act-definitions"][id]
    return {
        "id": id,
        "version": d["version"],
        "sha256": hashlib.sha256(canon(d)).hexdigest(),
    }


def resign_request(r):
    r["nonce"]["value"] = ""
    r["nonce"]["value"] = b64(
        hmac.digest(
            b"issuer-owned-lifecycle-test-secret", prefix("nonce") + canon(r), "sha256"
        )
    )
    return r


def world(mode):
    c = copy.deepcopy(base)
    c["id"] = "lifecycle-" + mode
    c["expected_state"] = "active"
    c.pop("expected_intent_preimage", None)
    c.pop("expected_locator", None)
    old = copy.deepcopy(base["activation"])
    c["previous"] = {
        "binding": old["binding"],
        "evidence": old["evidence"],
        "trust": copy.deepcopy(base["trust"]),
    }
    i = c["intent"]["intent"]
    i["purpose"] = "enroll_person" if mode == "recreated" else "replace_person_keys"
    i["previous_binding_commitment"] = digest("binding_commitment", old["binding"])
    i["identity_key"] = did_key_from_signing_key(bytes([7]) * 32)
    cert = i["pending_certificate"]["certificate"]
    cert["issued_at"] = "1970-01-01T00:16:41Z"
    i["pending_certificate"] = {
        "certificate": cert,
        "signature": b64(issuer.sign(id_certificate_signing_bytes(cert)).signature),
    }
    c["intent"] = sign("intent", "enrollment_intent", i)
    c["trust"].update(
        identity_key=i["identity_key"], certificate=id_certificate_id(cert)
    )
    b = copy.deepcopy(old["binding"]["binding"])
    b.update(identity_key=i["identity_key"], certificate=id_certificate_id(cert))
    private = ec.derive_private_key(17, ec.SECP256R1())
    n = private.public_key().public_numbers()
    entry = copy.deepcopy(b["credentials"][0])
    entry.update(
        id=b64(bytes([17]) * 32),
        key=b64(
            cbor2.dumps(
                {
                    1: 2,
                    3: -7,
                    -1: 1,
                    -2: n.x.to_bytes(32, "big"),
                    -3: n.y.to_bytes(32, "big"),
                }
            )
        ),
        grade="passkey_uv",
        snapshot=None,
    )
    b["credentials"] = [entry]
    binding = sign("binding", "binding", b)
    r = json.loads(
        __import__("base64").urlsafe_b64decode(
            old["creation_receipt"]["request_bytes"] + "=="
        )
    )
    r["act"]["target"].update(
        certificate=b["certificate"],
        identity_key=b["identity_key"],
        binding_commitment=digest("binding_commitment", binding),
    )
    resign_request(r)
    creation = {
        "version": 1,
        "request_bytes": b64(canon(r)),
        "assertion": assertion(r, private, entry["id"]),
        "binding": binding,
        "id_chain": [i["pending_certificate"]],
    }
    e = copy.deepcopy(old["evidence"]["evidence"])
    e["subject"].update(certificate=b["certificate"], key=b["identity_key"])
    e["binding_commitment"] = digest("binding_commitment", binding)
    before = {
        "subject": copy.deepcopy(old["evidence"]["evidence"]["subject"]),
        "binding_commitment": digest("binding_commitment", old["binding"]),
    }
    t = {
        "mode": mode,
        "before": before,
        "previous_evidence_commitment": digest(
            "identity_evidence_commitment", old["evidence"]
        ),
        "confirmation_receipt_commitment": digest("receipt_commitment", creation),
        "approval_receipt_commitment": None,
    }
    value = {
        "version": 1,
        "intent": c["intent"],
        "binding": binding,
        "creation_receipt": creation,
        "id_chain": creation["id_chain"],
    }
    if mode == "recreated":
        e["creation"] = {
            "credential": entry["id"],
            "grade": entry["grade"],
            "receipt_commitment": digest("receipt_commitment", creation),
        }
        c["transition_trust"] = None
    else:
        target = {
            "person": b["person"],
            "before": {
                "certificate": before["subject"]["certificate"],
                "identity_key": before["subject"]["key"],
                "binding_commitment": before["binding_commitment"],
            },
            "after": {
                "certificate": b["certificate"],
                "identity_key": b["identity_key"],
                "binding_commitment": e["binding_commitment"],
            },
            "continuity": mode,
        }
        tr = copy.deepcopy(r)
        tr.update(
            purpose="act_approval",
            requester=c["requester"],
            approver=b["person"],
            definition=reference("human.enrollment.replace"),
        )
        tr["act"] = {
            "operation": "human.enrollment.replace",
            "target": target,
            "expected_revision": 1,
        }
        resign_request(tr)
        cb = copy.deepcopy(old["binding"])
        chain = copy.deepcopy(old["creation_receipt"]["id_chain"])
        priv = fixture()["private"]
        c["transition_trust"] = copy.deepcopy(base["trust"])
        if mode == "assisted":
            key = SigningKey(bytes([4]) * 32)
            helper = __import__(
                "awid.did", fromlist=["stable_id_from_did_key"]
            ).stable_id_from_did_key(did_key_from_signing_key(bytes(key)))
            cb["binding"]["person"] = helper
            cb["binding"]["identity_key"] = did_key_from_signing_key(bytes(key))
            hc = copy.deepcopy(chain[0]["certificate"])
            hc["id"] = helper
            cb["binding"]["certificate"] = id_certificate_id(hc)
            chain = [
                {
                    "certificate": hc,
                    "signature": b64(
                        issuer.sign(id_certificate_signing_bytes(hc)).signature
                    ),
                }
            ]
            cb = sign("binding", "binding", cb["binding"])
            tr["approver"] = helper
            c["transition_trust"].update(
                person=helper,
                identity_key=cb["binding"]["identity_key"],
                certificate=cb["binding"]["certificate"],
            )
            resign_request(tr)
        receipt = {
            "version": 1,
            "request_bytes": b64(canon(tr)),
            "binding": cb,
            "id_chain": chain,
            "assertion": assertion(tr, priv, cb["binding"]["credentials"][0]["id"]),
        }
        value["transition_receipt"] = receipt
        t["approval_receipt_commitment"] = digest("receipt_commitment", receipt)
    e["transition"] = t
    value["evidence"] = sign("evidence", "identity_evidence", e)
    c["activation"] = value
    return c


cases = [world(mode) for mode in ("unbroken", "assisted", "recreated")]


def fault(base, name, code, change):
    c = copy.deepcopy(base)
    c.update(id=name, accept=False, expected_error=code)
    change(c)
    cases.append(c)


def evidence_change(c, change):
    e = c["activation"]["evidence"]["evidence"]
    change(e)
    c["activation"]["evidence"] = sign("evidence", "identity_evidence", e)


fault(
    cases[0],
    "replacement-cannot-raise-creation-grade",
    "creation_changed",
    lambda c: evidence_change(
        c, lambda e: e["creation"].update(grade="certified_hardware")
    ),
)
fault(
    cases[0],
    "replacement-before-key-mismatch",
    "transition_before_mismatch",
    lambda c: evidence_change(
        c,
        lambda e: e["transition"]["before"]["subject"].update(
            key=c["trust"]["identity_key"]
        ),
    ),
)
fault(
    cases[0],
    "replacement-history-mismatch",
    "transition_before_mismatch",
    lambda c: evidence_change(
        c,
        lambda e: e["transition"].update(
            previous_evidence_commitment="sha256:" + "0" * 64
        ),
    ),
)
fault(
    cases[0],
    "replacement-receipt-unavailable",
    "transition_receipt_unavailable",
    lambda c: c["activation"].pop("transition_receipt"),
)
fault(
    cases[1],
    "helper-cannot-be-labelled-unbroken",
    "transition_approver_mismatch",
    lambda c: evidence_change(c, lambda e: e["transition"].update(mode="unbroken")),
)
fault(
    cases[2],
    "recovery-must-record-the-break",
    "transition_mode_invalid",
    lambda c: evidence_change(c, lambda e: e["transition"].update(mode="unbroken")),
)
fault(
    cases[2],
    "recovery-cannot-carry-the-old-creation",
    "evidence_binding_mismatch",
    lambda c: evidence_change(
        c,
        lambda e: e.update(
            creation=copy.deepcopy(c["previous"]["evidence"]["evidence"]["creation"])
        ),
    ),
)
fault(
    cases[2],
    "recovery-current-key-mismatch",
    "enrollment_identity_mismatch",
    lambda c: c["trust"].update(identity_key=c["previous"]["trust"]["identity_key"]),
)
out.write_text(
    json.dumps({"version": 1, "cases": cases}, indent=2, ensure_ascii=False) + "\n"
)
print(f"{len(cases)} frozen lifecycle cases")
