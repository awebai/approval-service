"""Proposed new definitions: shared bytes and genuine signatures, no registry claim.

Expected outcomes are written here, not obtained by calling the verifier.
Refuse to overwrite the corpus. Existing definition and wire bytes stay fixed.
"""

import copy
import hashlib
import hmac
import json
import sys
from pathlib import Path

from awid.did import did_from_public_key, stable_id_from_did_key
from nacl.signing import SigningKey

from approval_service.canonical import canonical
from approval_service.encoding import encode
from approval_service.wire import SCHEMA, domain

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tests"))
from receipts import assertion, fixture

path = root / "vectors/organisation-actions-v1.json"
if path.exists():
    raise SystemExit("refuse to overwrite a corpus")
w = fixture()
issuer_key = did_from_public_key(w["issuer"].public_key().public_bytes_raw())
person_key = did_from_public_key(bytes(SigningKey(bytes.fromhex("8a" * 32)).verify_key))
person = stable_id_from_did_key(person_key)
subject = stable_id_from_did_key(
    did_from_public_key(bytes(SigningKey(bytes.fromhex("9b" * 32)).verify_key))
)
binding = w["receipt"]["binding"]["binding"]
binding.update(person=person, identity_key=person_key, issuer=issuer_key)
w["receipt"]["binding"]["signature"] = encode(
    w["issuer"].sign(domain("binding") + canonical(binding))
)
w["status"].update(person=person, identity_key=person_key, issuer=issuer_key)
trust = {**w["status"], "issuer_public_key": encode(w["status"]["issuer_public_key"])}
cases = []


def base(identifier):
    definition = SCHEMA["x-act-definitions"][identifier]
    r = copy.deepcopy(w["request"])
    r.update(
        approver=person,
        requester={"kind": "identity", "id": person, "key": person_key},
        definition={
            "id": identifier,
            "version": 1,
            "sha256": hashlib.sha256(canonical(definition)).hexdigest(),
        },
        enforcer={"audience": "https://cloud.example.test"},
    )
    target = {"organisation": "admitting.example", "person": subject, "role": "member"}
    if identifier.endswith("change"):
        target = {
            "organisation": "admitting.example",
            "action": "organisation.human.add",
            "before": {"service": binding["origin"], "level": "passkey"},
            "after": {"service": None, "level": "none"},
        }
    r["act"] = {"operation": identifier, "target": target, "expected_revision": 7}
    return r


def case(identifier, name, *, edit=None, error=None, phase="definition"):
    r = base(identifier)
    if edit:
        edit(r)
    c = {"id": name, "phase": phase, "accept": error is None, "request": r}
    if error:
        c["expected_error"] = error
    if phase == "receipt":
        r["nonce"]["value"] = ""
        r["nonce"]["value"] = encode(
            hmac.digest(w["secret"], domain("nonce") + canonical(r), "sha256")
        )
        c.update(
            receipt={
                "version": 1,
                "request_bytes": encode(canonical(r)),
                "binding": copy.deepcopy(w["receipt"]["binding"]),
                "id_chain": [],
                "assertion": assertion(
                    w["private"], -7, r, binding["credentials"][0]["id"]
                ),
            },
            trust=trust,
            presenter=r["requester"],
            nonce_key=encode(w["secret"]),
            now=1100,
            required_grade="passkey_uv",
            expected_person=person,
        )
    cases.append(c)
    return c


for identifier in ("organisation.person.admit", "organisation.human_approval.change"):
    short = identifier.split(".")[-1]
    case(identifier, short + "-typed-act")
    case(identifier, short + "-home-bound-real-proof", phase="receipt")
    for field in ("email", "name"):
        case(
            identifier,
            short + "-private-" + field,
            error="definition_invalid",
            edit=lambda r, f=field: r["act"]["target"].update({f: "private value"}),
        )
    case(
        identifier,
        short + "-domain-newline",
        error="definition_invalid",
        edit=lambda r: r["act"]["target"].update(organisation="admitting.example\n"),
    )
    for bad in (None, [], {}, True, "private prose\napproved"):
        field = "role" if short == "admit" else "action"
        case(
            identifier,
            short + "-" + field + "-" + str(len(cases)),
            error="definition_invalid",
            edit=lambda r, f=field, b=bad: r["act"]["target"].update({f: b}),
        )
case(
    "organisation.person.admit",
    "person-newline",
    error="definition_invalid",
    edit=lambda r: r["act"]["target"].update(person=subject + "\n"),
)
for side in ("before", "after"):
    for field, bad in (
        ("level", {}),
        ("level", "email"),
        ("service", "https://safe.example\n"),
    ):
        case(
            "organisation.human_approval.change",
            side + "-" + field + "-" + str(len(cases)),
            error="definition_invalid",
            edit=lambda r, s=side, f=field, b=bad: r["act"]["target"][s].update({f: b}),
        )

case(
    "organisation.person.admit",
    "person-malformed-stable-id",
    error="definition_invalid",
    edit=lambda r: r["act"]["target"].update(person="did:aw:abc"),
)

for identifier, name, error, edit in (
    (
        "organisation.person.admit",
        "admission-role-changed-after-approval",
        "request_mismatch",
        lambda c: c["request"]["act"]["target"].update(role="admin"),
    ),
    (
        "organisation.human_approval.change",
        "policy-service-changed-after-approval",
        "request_mismatch",
        lambda c: c["request"]["act"]["target"]["after"].update(
            service="https://different.example.test"
        ),
    ),
    (
        "organisation.person.admit",
        "expired-admission",
        "request_expired",
        lambda c: c.update(now=1300),
    ),
    (
        "organisation.human_approval.change",
        "old-level-still-required",
        "grade_insufficient",
        lambda c: c.update(required_grade="certified_hardware"),
    ),
    (
        "organisation.person.admit",
        "different-presenter",
        "requester_mismatch",
        lambda c: c["presenter"].update(key="wrong-key"),
    ),
):
    c = case(identifier, name, phase="receipt")
    c.update(accept=False, expected_error=error)
    # Presentation identity is an independent observed caller, not an alias to R.
    c["presenter"] = copy.deepcopy(c["presenter"])
    edit(c)

path.write_text(json.dumps({"version": 1, "cases": cases}, indent=2) + "\n")
print(len(cases), "proposed cases written")
