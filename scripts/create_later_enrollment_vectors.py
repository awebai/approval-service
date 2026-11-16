"""Proposed later-enrollment vectors; real signatures, public test keys.

Expected outcomes are explicit. This generator never calls the seam checker
and refuses to overwrite its corpus. Trust is an independently checked port.
"""

import copy
import hashlib
import hmac
import json
import sys
from pathlib import Path

from awid.did import did_key_from_signing_key, stable_id_from_did_key
from awid.id_certificates import id_certificate_id, id_certificate_signing_bytes
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from receipts import assertion, b64, canon, fixture

path = ROOT / "vectors/later-enrollment-v1.json"
if path.exists():
    raise SystemExit("refuse to overwrite later-enrollment corpus")
schema = json.loads((ROOT / "src/approval_service/data/format-v1.json").read_text())
domains = schema["x-domains"]
domains = {**domains, "later_enrollment_evidence": "aweb.human-enrollment-evidence/1\n"}
issuer, old_issuer, person_key = (SigningKey(bytes([n]) * 32) for n in (1, 9, 2))


def did(key):
    return did_key_from_signing_key(bytes(key))


def signed(key, purpose, field, value):
    return {
        field: copy.deepcopy(value),
        "signature": b64(key.sign(domains[purpose].encode() + canon(value)).signature),
    }


def commitment(purpose, value):
    return (
        "sha256:" + hashlib.sha256(domains[purpose].encode() + canon(value)).hexdigest()
    )


w = fixture()
w2 = fixture()
person = stable_id_from_did_key(did(person_key))
requester = {"kind": "identity", "id": person, "key": did(person_key)}


def construction(
    certificate_signer=issuer, person_signer=person_key, alternative_credential=False
):
    person_key = person_signer
    person = stable_id_from_did_key(did(person_key))
    requester = {"kind": "identity", "id": person, "key": did(person_key)}
    cert = {
        "v": 1,
        "type": "aweb.id-certificate",
        "id": person,
        "domain": "customer.example",
        "parent": {"kind": "namespace", "id": "customer.example"},
        "kind": "human",
        "issuer_key": did(certificate_signer),
        "issued_at": "1970-01-01T00:01:40Z",
    }
    certificate = {
        "certificate": cert,
        "signature": b64(
            certificate_signer.sign(id_certificate_signing_bytes(cert)).signature
        ),
    }
    cid = id_certificate_id(cert)
    b = copy.deepcopy(w["receipt"]["binding"]["binding"])
    b.update(
        person=person, certificate=cid, identity_key=did(person_key), issuer=did(issuer)
    )
    if alternative_credential:
        extra = copy.deepcopy(w2["receipt"]["binding"]["binding"]["credentials"][0])
        extra["id"] = b64(b"second-enrolled-credential")
        b["credentials"].append(extra)
    binding = signed(issuer, "binding", "binding", b)
    intent = signed(
        issuer,
        "enrollment_intent",
        "intent",
        {
            "version": 1,
            "purpose": "enroll_existing_person",
            "organisation": "customer.example",
            "person": person,
            "pending_certificate": certificate,
            "identity_key": did(person_key),
            "requester": requester,
            "origin": b["origin"],
            "rp_id": b["rp_id"],
            "challenge": b64(bytes([17]) * 32),
            "not_before": 1000,
            "deadline": 1300,
        },
    )
    definition = schema["x-act-definitions"]["enrollment.confirm"]
    r = copy.deepcopy(w["request"])
    r.update(
        purpose="enrollment_confirmation",
        approver=person,
        requester=requester,
        enforcer={"audience": "urn:awsign:test:holder"},
        definition={
            "id": definition["id"],
            "version": 1,
            "sha256": hashlib.sha256(canon(definition)).hexdigest(),
        },
        act={
            "operation": "enrollment.confirm",
            "target": {
                "person": person,
                "certificate": cid,
                "identity_key": did(person_key),
                "binding_commitment": commitment("binding_commitment", binding),
            },
            "expected_revision": 1,
        },
    )
    r["nonce"]["value"] = ""
    r["nonce"]["value"] = b64(
        hmac.digest(w["secret"], domains["nonce"].encode() + canon(r), "sha256")
    )
    credential = b["credentials"][0]
    receipt = {
        "version": 1,
        "request_bytes": b64(canon(r)),
        "binding": binding,
        "id_chain": [certificate],
        "assertion": assertion(
            w2["private"] if alternative_credential else w["private"],
            -7,
            r,
            b["credentials"][-1]["id"] if alternative_credential else credential["id"],
        ),
    }
    e = {
        "version": 1,
        "kind": "human_enrolled_later",
        "organisation": b["organisation"],
        "subject": {"id": person, "certificate": cid, "key": did(person_key)},
        "issuer": did(issuer),
        "binding_commitment": commitment("binding_commitment", binding),
        "enrollment": {
            "credential": credential["id"],
            "grade": credential["grade"],
            "since": 1100,
            "confirmation_receipt_commitment": commitment(
                "receipt_commitment", receipt
            ),
        },
    }
    return {
        "issuer_key": did(issuer),
        "requester": requester,
        "origin": b["origin"],
        "rp_id": b["rp_id"],
        "now": 1100,
        "trust": {
            "person": person,
            "organisation": b["organisation"],
            "certificate": cid,
            "identity_key": did(person_key),
            "issuer": did(issuer),
            "issuer_public_key": b64(bytes(issuer.verify_key)),
            "namespace_issuer": did(issuer),
            "observed_at": 1100,
        },
        "activation": {
            "version": 2,
            "intent": intent,
            "binding": binding,
            "confirmation_receipt": receipt,
            "evidence": signed(issuer, "later_enrollment_evidence", "evidence", e),
            "id_chain": [certificate],
        },
    }


base = construction()
cases = []


def case(name, *, error=None, value=None, edit=None, resign=False):
    c = copy.deepcopy(base if value is None else value)
    c.update(id=name, accept=error is None)
    if edit:
        edit(c)
    if resign:
        e = c["activation"]["evidence"]["evidence"]
        c["activation"]["evidence"] = signed(
            issuer, "later_enrollment_evidence", "evidence", e
        )
        i = c["activation"]["intent"]["intent"]
        c["activation"]["intent"] = signed(issuer, "enrollment_intent", "intent", i)
    if error:
        c["expected_error"] = error
    cases.append(c)


case("existing-person-activates")
case("earlier-controller-certificate", value=construction(old_issuer))
case(
    "controller-is-not-person",
    error="requester_mismatch",
    edit=lambda c: c.update(
        requester={
            "kind": "namespace_controller",
            "namespace": "customer.example",
            "key": did(issuer),
        }
    ),
)
case(
    "other-person-is-not-requester",
    error="requester_mismatch",
    edit=lambda c: c.update(
        requester={
            "kind": "identity",
            "id": stable_id_from_did_key(did(old_issuer)),
            "key": did(old_issuer),
        }
    ),
)
case(
    "foreign-namespace",
    error="enrollment_identity_mismatch",
    edit=lambda c: c["trust"].update(organisation="other.example"),
)
case(
    "different-committed-certificate",
    error="enrollment_identity_mismatch",
    edit=lambda c: c["trust"].update(certificate="sha256:" + "f" * 64),
)
case(
    "stale-current-status",
    error="identity_unavailable",
    edit=lambda c: c["trust"].update(observed_at=1039),
)
case(
    "later-evidence-with-creation-intent",
    error="enrollment_purpose_mismatch",
    edit=lambda c: c["activation"]["intent"]["intent"].update(purpose="enroll_person"),
    resign=True,
)
case(
    "later-statement-cannot-be-creation",
    error="activation_invalid",
    edit=lambda c: c["activation"]["evidence"]["evidence"].update(kind="human"),
    resign=True,
)
case(
    "no-creation-member",
    error="activation_invalid",
    edit=lambda c: c["activation"]["evidence"]["evidence"].update(creation={}),
    resign=True,
)
case(
    "wrong-enrollment-grade",
    error="evidence_binding_mismatch",
    edit=lambda c: c["activation"]["evidence"]["evidence"]["enrollment"].update(
        grade="certified_hardware"
    ),
    resign=True,
)
case(
    "wrong-binding-commitment",
    error="evidence_binding_mismatch",
    edit=lambda c: c["activation"]["evidence"]["evidence"].update(
        binding_commitment="sha256:" + "f" * 64
    ),
    resign=True,
)
case(
    "negative-issuer-time",
    error="activation_invalid",
    edit=lambda c: c["activation"]["evidence"]["evidence"]["enrollment"].update(
        since=-1
    ),
    resign=True,
)
case(
    "saved-confirmation-after-deadline",
    edit=lambda c: (c.update(now=1400), c["trust"].update(observed_at=1400)),
)
case(
    "statement-names-another-confirmation",
    error="evidence_binding_mismatch",
    edit=lambda c: c["activation"]["evidence"]["evidence"]["enrollment"].update(
        confirmation_receipt_commitment="sha256:" + "f" * 64
    ),
    resign=True,
)
case(
    "confirmation-by-another-credential",
    error="evidence_binding_mismatch",
    value=construction(alternative_credential=True),
)
cases[-1]["confirmation_trust"] = copy.deepcopy(cases[-1]["trust"])
other_person = construction(person_signer=old_issuer)
case(
    "confirmation-for-another-person",
    error="binding_mismatch",
    edit=lambda c: c["activation"].update(
        confirmation_receipt=other_person["activation"]["confirmation_receipt"]
    ),
)
cases[-1]["confirmation_trust"] = other_person["trust"]

path.write_text(
    json.dumps(
        {
            "version": 1,
            "scope": "Checked public Trust ports; raw assertion and issuer signatures are real. No registry acquisition/effect claim.",
            "cases": cases,
        },
        indent=2,
    )
    + "\n"
)
