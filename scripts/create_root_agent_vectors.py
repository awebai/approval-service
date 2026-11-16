"""Root-agent receipt and grant cases. Real signatures, public test keys. Real signatures, test keys.

This generator never calls the seam to select an expected result. Refuse to
overwrite a corpus. Root/person histories are explicitly independently checked
SDK/lifecycle input ports, not authority inferred from a receipt or export.
"""

import copy
import hashlib
import hmac
import json
import sys
from pathlib import Path

from awid.did import (
    did_from_public_key,
    did_key_from_signing_key,
    stable_id_from_did_key,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from approval_service.canonical import canonical
from approval_service.encoding import encode
from approval_service.wire import SCHEMA, domain

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tests"))
from receipts import assertion, fixture

path = root / "vectors/root-agent-v1.json"
if path.exists():
    raise SystemExit("refuse to overwrite root-agent corpus")

w = fixture()
issuer = did_from_public_key(
    w["issuer"].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
)
person_key = did_key_from_signing_key(bytes([2]) * 32)
person = stable_id_from_did_key(person_key)
root_key = did_key_from_signing_key(bytes([3]) * 32)
root_id = stable_id_from_did_key(root_key)
rotated_key = did_key_from_signing_key(bytes([4]) * 32)
new_person_key = did_key_from_signing_key(bytes([5]) * 32)
binding = copy.deepcopy(w["receipt"]["binding"])
binding["binding"].update(person=person, identity_key=person_key, issuer=issuer)
binding["signature"] = encode(
    w["issuer"].sign(domain("binding") + canonical(binding["binding"]))
)
trust = {
    **w["status"],
    "person": person,
    "identity_key": person_key,
    "issuer": issuer,
    "issuer_public_key": encode(w["status"]["issuer_public_key"]),
}
definition = SCHEMA["x-act-definitions"]["agent.root.authorize"]
ref = {
    "id": definition["id"],
    "version": 1,
    "sha256": hashlib.sha256(canonical(definition)).hexdigest(),
}


def signed(r, *, secret=w["secret"]):
    r["nonce"]["value"] = ""
    r["nonce"]["value"] = encode(
        hmac.digest(secret, domain("nonce") + canonical(r), "sha256")
    )
    return {
        "version": 1,
        "request_bytes": encode(canonical(r)),
        "binding": copy.deepcopy(binding),
        "id_chain": [],
        "assertion": assertion(
            w["private"], -7, r, binding["binding"]["credentials"][0]["id"]
        ),
    }


request = copy.deepcopy(w["request"])
request.update(
    approver=person,
    requester={"kind": "identity", "id": person, "key": person_key},
    enforcer={"audience": "https://holder.customer.example"},
    definition=ref,
)
request["act"] = {
    "operation": "agent.root.authorize",
    "target": {
        "person": person,
        "root_id": root_id,
        "root_key": root_key,
        "mode": "issue",
        "teams": ["agents:customer.example", "workers:customer.example"],
    },
    "expected_revision": 7,
}
receipt = signed(request)
base = {
    "phase": "live",
    "accept": True,
    "request": request,
    "presentation": {
        "version": 1,
        "request_bytes": encode(canonical(request)),
        "receipt": receipt,
    },
    "proof": {"version": 1, "receipt": receipt},
    "trust": trust,
    "root": {"id": root_id, "current_key": root_key, "continuous_keys": [root_key]},
    "parent_person": person,
    "continuity": {
        "from_key": person_key,
        "current_key": person_key,
        "mode": "unbroken",
        "since": 1000,
    },
    "now": 1100,
    "presenter": copy.deepcopy(request["requester"]),
    "nonce_key": encode(w["secret"]),
    "origin": "https://approval.example.test",
    "audience": request["enforcer"]["audience"],
    "enforcer_kind": "key_holder",
    "owned_teams": [
        "agents:customer.example",
        "workers:customer.example",
        "extra:customer.example",
    ],
    "revision": 7,
    "required_grade": "passkey_uv",
    "expected": {
        "person": person,
        "root_id": root_id,
        "root_key": root_key,
        "mode": "issue",
        "teams": request["act"]["target"]["teams"],
        "status": "checked",
        "enforcer": request["enforcer"]["audience"],
    },
}
cases = []


def case(name, *, phase="live", error=None, edit=None, resign=False):
    c = copy.deepcopy(base)
    c.update(id=name, phase=phase, accept=error is None)
    if phase == "historical":
        c["expected"].update(status="approved", continuity="unbroken", since=1000)
    if edit:
        edit(c)
    if resign:
        r = c["request"]
        receipt = signed(r)
        c["presentation"] = {
            "version": 1,
            "request_bytes": encode(canonical(r)),
            "receipt": receipt,
        }
        c["proof"] = {"version": 1, "receipt": receipt}
    if error:
        c["expected_error"] = error
        c.pop("expected")
    cases.append(c)
    return c


case("holder-issue-two-teams")
c = case("cloud-adopt-existing-root", resign=False)
c["request"]["act"]["target"]["mode"] = "adopt"
c["expected"]["mode"] = "adopt"
c["enforcer_kind"] = "cloud_key_process"
c["request"]["enforcer"]["audience"] = "https://cloud.customer.example"
c["audience"] = c["request"]["enforcer"]["audience"]
c["expected"]["enforcer"] = c["audience"]
c["presentation"]["receipt"] = signed(c["request"])
c["presentation"]["request_bytes"] = encode(canonical(c["request"]))
c["proof"]["receipt"] = copy.deepcopy(c["presentation"]["receipt"])
for name, teams in [
    ("replace-team-list", ["workers:customer.example"]),
    ("empty-list-withdraws", []),
]:
    c = case(name)
    c["previous_teams"] = ["agents:customer.example", "workers:customer.example"]
    c["request"]["act"]["target"]["teams"] = teams
    c["expected"]["teams"] = teams
    c["presentation"]["receipt"] = signed(c["request"])
    c["presentation"]["request_bytes"] = encode(canonical(c["request"]))
c = case("aw-evidence-only-empty-teams")
c["enforcer_kind"] = "aw"
c["audience"] = "urn:awsign:aw:customer.example"
c["request"]["enforcer"]["audience"] = c["audience"]
c["expected"]["enforcer"] = c["audience"]
c["request"]["act"]["target"]["teams"] = []
c["expected"]["teams"] = []
c["presentation"]["receipt"] = signed(c["request"])
c["presentation"]["request_bytes"] = encode(canonical(c["request"]))

case(
    "aw-refuses-any-team",
    error="root_teams_not_supported",
    edit=lambda c: c.update(enforcer_kind="aw"),
)
case(
    "unowned-team",
    error="root_team_not_owned",
    edit=lambda c: c.update(owned_teams=["agents:customer.example"]),
)
case(
    "wrong-audience",
    error="root_enforcer_mismatch",
    edit=lambda c: c.update(audience="https://other.customer.example"),
)
case(
    "stale-revision",
    error="root_revision_mismatch",
    edit=lambda c: c.update(revision=8),
)
case(
    "unknown-enforcer-kind",
    error="root_enforcer_invalid",
    edit=lambda c: c.update(enforcer_kind="application"),
)
case("expired-live-receipt", error="request_expired", edit=lambda c: c.update(now=1300))
case(
    "stale-person-status",
    error="status_unavailable",
    edit=lambda c: c["trust"].update(observed_at=1039),
)
case(
    "wrong-presenter",
    error="requester_mismatch",
    edit=lambda c: c["presenter"].update(key=rotated_key),
)
case(
    "invented-enforcer-nonce",
    error="nonce_invalid",
    edit=lambda c: c.update(nonce_key=encode(b"wrong-enforcer-secret")),
)

for name, field, value, error in [
    (
        "wrong-person",
        "person",
        stable_id_from_did_key(new_person_key),
        "root_person_mismatch",
    ),
    (
        "wrong-root-id",
        "root_id",
        stable_id_from_did_key(rotated_key),
        "root_identity_mismatch",
    ),
    ("wrong-root-key", "root_key", rotated_key, "root_key_discontinuous"),
    (
        "foreign-team",
        "teams",
        ["agents:sibling.example"],
        "root_team_organisation_mismatch",
    ),
    ("duplicate-team", "teams", ["agents:customer.example"] * 2, "definition_invalid"),
    ("wildcard-team", "teams", ["*:customer.example"], "definition_invalid"),
    ("noncanonical-team", "teams", ["Agents:Customer.example"], "definition_invalid"),
    ("unknown-mode", "mode", "spawn", "definition_invalid"),
    (
        "too-many-teams",
        "teams",
        [f"team-{i}:customer.example" for i in range(129)],
        "definition_invalid",
    ),
]:
    case(
        name,
        error=error,
        edit=lambda c, field=field, value=value: c["request"]["act"]["target"].update(
            {field: value}
        ),
        resign=True,
    )

case(
    "root-key-rotated-continuously",
    edit=lambda c: c["root"].update(
        current_key=rotated_key, continuous_keys=[root_key, rotated_key]
    ),
)
case(
    "root-key-rotation-broken",
    error="root_key_discontinuous",
    edit=lambda c: c["root"].update(
        current_key=rotated_key, continuous_keys=[rotated_key]
    ),
)
case(
    "root-history-missing",
    error="root_history_unavailable",
    edit=lambda c: c["root"].update(continuous_keys=[]),
)

for name, enforcer in [
    ("historical-holder", "key_holder"),
    ("historical-cloud", "cloud_key_process"),
    ("historical-aw", "aw"),
]:
    c = case(name, phase="historical")
    c["enforcer_kind"] = enforcer
    audience = {
        "key_holder": "https://holder.customer.example",
        "cloud_key_process": "https://cloud.customer.example",
        "aw": "urn:awsign:aw:customer.example",
    }[enforcer]
    c["request"]["enforcer"]["audience"] = audience
    if enforcer == "aw":
        c["request"]["act"]["target"]["teams"] = []
        c["expected"]["teams"] = []
    c["proof"]["receipt"] = signed(c["request"])
    c["expected"]["enforcer"] = audience
    # Historical verification checks what was approved, not an enforcer grant.
    c["now"] = 2000
case("historical-after-expiry", phase="historical", edit=lambda c: c.update(now=9000))
case(
    "historical-rotated-root",
    phase="historical",
    edit=lambda c: c["root"].update(
        current_key=rotated_key, continuous_keys=[root_key, rotated_key]
    ),
)
case(
    "historical-root-discontinuity",
    phase="historical",
    error="root_key_discontinuous",
    edit=lambda c: c["root"].update(
        current_key=rotated_key, continuous_keys=[rotated_key]
    ),
)
case(
    "historical-not-person-root-link",
    phase="historical",
    error="root_person_mismatch",
    edit=lambda c: c.update(parent_person=stable_id_from_did_key(rotated_key)),
)
case(
    "historical-proof-unsupported",
    phase="historical",
    error="root_proof_unsupported",
    edit=lambda c: c["proof"].update(version=2),
)
case(
    "historical-proof-unknown-field",
    phase="historical",
    error="root_proof_invalid",
    edit=lambda c: c["proof"].update(statement={}),
)
case(
    "historical-history-wrong-key",
    phase="historical",
    error="root_history_unavailable",
    edit=lambda c: c["continuity"].update(from_key=rotated_key),
)
for mode, status in [
    ("unbroken", "approved"),
    ("assisted", "approval_predates_break"),
    ("recreated", "approval_predates_break"),
    ("unknown", "continuity_unknown"),
]:
    c = case("person-key-change-" + mode, phase="historical")
    c["continuity"].update(
        current_key=new_person_key, mode=mode, since=None if mode == "unknown" else 1200
    )
    c["expected"].update(status=status, continuity=mode, since=c["continuity"]["since"])

case(
    "historical-malformed-request-bytes",
    phase="historical",
    error="root_proof_invalid",
    edit=lambda c: c["proof"]["receipt"].update(request_bytes="AA"),
)
case(
    "historical-altered-assertion",
    phase="historical",
    error="assertion_invalid",
    edit=lambda c: c["proof"]["receipt"]["assertion"].update(signature="AA"),
)
for suffix, fault, error in [
    ("keeps-id-and-key", None, None),
    ("changed-id", "root_id", "root_identity_mismatch"),
    ("changed-key", "root_key", "root_key_discontinuous"),
]:

    def edit_adoption(c, fault=fault):
        c["request"]["act"]["target"]["mode"] = "adopt"
        c["expected"]["mode"] = "adopt"
        if fault == "root_id":
            c["request"]["act"]["target"][fault] = stable_id_from_did_key(rotated_key)
        elif fault == "root_key":
            c["request"]["act"]["target"][fault] = rotated_key

    case("adopt-" + suffix, error=error, edit=edit_adoption, resign=True)

path.write_text(
    json.dumps(
        {
            "version": 1,
            "trust_boundary": "root histories and person continuity are independently checked SDK/lifecycle/as-of ports; never taken from the receipt",
            "cases": cases,
        },
        indent=2,
    )
    + "\n"
)
