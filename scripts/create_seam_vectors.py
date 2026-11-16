"""Freeze real signatures at the three seams. Public TEST keys, never production.

No product seam verifier is imported by this generator. Existing canonical,
ID and cryptographic primitives supply the bytes; expected results are explicit.
Refuse to overwrite any corpus. Consumers MUST NOT regenerate while testing.
"""

import copy
import hashlib
import hmac
import json
import sys
from pathlib import Path

from awid.did import did_key_from_signing_key, stable_id_from_did_key
from awid.id_certificates import id_certificate_id, id_certificate_signing_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from nacl.signing import SigningKey

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tests"))
from receipts import b64, canon, fixture

outputs = [
    root / "vectors" / n
    for n in (
        "requester-service-v1.json",
        "issuer-service-enrollment-v1.json",
        "enforcer-requester-v1.json",
    )
]
if any(p.exists() for p in outputs):
    raise SystemExit("refuse to overwrite frozen seam vectors")
S = json.loads((root / "src/approval_service/data/format-v1.json").read_text())


def domain(n):
    return S["x-domains"][n].encode()


def hashof(n, value):
    return "sha256:" + hashlib.sha256(domain(n) + canon(value)).hexdigest()


def key(n):
    return SigningKey(bytes([n]) * 32)


issuer = key(1)
person_key = key(2)
other = key(3)


def did(k):
    return did_key_from_signing_key(bytes(k))


person = stable_id_from_did_key(did(person_key))
org = "customer.example"
origin = "https://awsign.com"
requester = {"kind": "identity", "id": person, "key": did(person_key)}
controller = {"kind": "namespace_controller", "namespace": org, "key": did(issuer)}


def sign(k, n, field, body):
    return {
        field: copy.deepcopy(body),
        "signature": b64(k.sign(domain(n) + canon(body)).signature),
    }


def idcert():
    c = {
        "v": 1,
        "type": "aweb.id-certificate",
        "id": person,
        "domain": org,
        "parent": {"kind": "namespace", "id": org},
        "kind": "human",
        "issuer_key": did(issuer),
        "issued_at": "1970-01-01T00:16:40Z",
    }
    return {
        "certificate": c,
        "signature": b64(issuer.sign(id_certificate_signing_bytes(c)).signature),
    }


certificate = idcert()
cid = id_certificate_id(certificate["certificate"])
second_key = key(4)
second_person = stable_id_from_did_key(did(second_key))
second_certificate_body = copy.deepcopy(certificate["certificate"])
second_certificate_body["id"] = second_person
second_cid = id_certificate_id(second_certificate_body)
w = fixture()
credential = w["receipt"]["binding"]["binding"]["credentials"][0]
binding_body = {
    "version": 1,
    "organisation": org,
    "person": person,
    "certificate": cid,
    "identity_key": did(person_key),
    "issuer": did(issuer),
    "origin": origin,
    "rp_id": "awsign.com",
    "credentials": [credential],
}
binding = sign(issuer, "binding", "binding", binding_body)
trust = {
    "person": person,
    "organisation": org,
    "identity_key": did(person_key),
    "certificate": cid,
    "issuer": did(issuer),
    "issuer_public_key": b64(bytes(issuer.verify_key)),
    "observed_at": 1100,
}
secret = b"enforcer-test-secret-not-a-production-key"


def request(purpose="act_approval"):
    r = copy.deepcopy(w["request"])
    r.update(
        purpose=purpose,
        organisation=org,
        approver=person,
        requester=controller if purpose == "enrollment_confirmation" else requester,
        enforcer={"audience": "urn:awsign:test:keyholder"},
    )
    identifier = "human.add" if purpose == "act_approval" else "enrollment.confirm"
    definition = S["x-act-definitions"][identifier]
    r["definition"] = {
        "id": identifier,
        "version": 1,
        "sha256": hashlib.sha256(canon(definition)).hexdigest(),
    }
    target = (
        {"person": person, "certificate": cid, "identity_key": did(person_key)}
        if purpose == "enrollment_confirmation"
        else {
            "person": second_person,
            "certificate": second_cid,
            "identity_key": did(second_key),
        }
    )
    r["act"] = {"operation": identifier, "target": target, "expected_revision": 1}
    r["nonce"] = {"kid": "k1", "value": ""}
    r["nonce"]["value"] = b64(hmac.digest(secret, domain("nonce") + canon(r), "sha256"))
    return r


r = request()
raw = canon(r)
digest = hashlib.sha256(domain("request") + raw).hexdigest()


def assertion(req):
    client = canon(
        {
            "type": "webauthn.get",
            "challenge": b64(hashlib.sha256(domain("request") + canon(req)).digest()),
            "origin": origin,
            "crossOrigin": False,
        }
    )
    auth = hashlib.sha256(b"awsign.com").digest() + bytes([5]) + b"\0" * 4
    signature = w["private"].sign(
        auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())
    )
    return {
        "id": credential["id"],
        "client_data_json": b64(client),
        "authenticator_data": b64(auth),
        "signature": b64(signature),
    }


def receipt(req):
    return {
        "version": 1,
        "request_bytes": b64(canon(req)),
        "binding": binding,
        "id_chain": [certificate],
        "assertion": assertion(req),
    }


# 1. Authenticated submission/poll/cancel. Public status is a separate live port.
http_cases = []


def httpcase(name, purpose, body, who=requester, k=person_key, accept=True, **changes):
    proof = {
        "version": 1,
        "purpose": purpose,
        "requester": who,
        "origin": origin,
        "method": "POST",
        "path": S["x-http"]["routes"][purpose],
        "issued_at": 1100,
        "body_sha256": hashlib.sha256(canon(body)).hexdigest(),
    }
    signed = sign(k, "http_request", "proof", proof)
    case = {
        "id": name,
        "accept": accept,
        "body": b64(canon(body)),
        "authorization": "Awsign " + b64(canon(signed)),
        "expected_requester": who,
        "origin": origin,
        "method": "POST",
        "path": proof["path"],
        "purpose": purpose,
        "now": 1100,
        "expected_preimage": b64(domain("http_request") + canon(proof)),
        "expected_requester_key": who["key"],
    }
    case.update(changes)
    http_cases.append(case)
    return case


admission = {"team_certificate": None, "id_chain": [certificate]}
httpcase(
    "submit-exact-key-and-bytes",
    "submit",
    {"version": 1, "request_bytes": b64(raw), "admission": admission},
)
httpcase(
    "poll-same-descriptor",
    "poll",
    {
        "version": 1,
        "locator": "pending-selection",
        "digest": digest,
        "admission": admission,
    },
)
httpcase(
    "cancel-same-descriptor",
    "cancel",
    {
        "version": 1,
        "locator": "pending-selection",
        "digest": digest,
        "admission": admission,
    },
)
for fault in [
    "wrong-key",
    "wrong-body",
    "wrong-origin",
    "wrong-path",
    "wrong-method",
    "wrong-purpose",
    "changed-descriptor",
    "too-old",
    "future",
    "padded-token",
    "duplicate-header-packet",
    "unknown-field",
]:
    c = copy.deepcopy(http_cases[0])
    c.update(id=fault, accept=False)
    if fault == "wrong-key":
        packet = json.loads(
            __import__("base64").urlsafe_b64decode(
                c["authorization"][7:] + "=" * (-len(c["authorization"][7:]) % 4)
            )
        )
        packet["signature"] = b64(
            other.sign(domain("http_request") + canon(packet["proof"])).signature
        )
        c["authorization"] = "Awsign " + b64(canon(packet))
    elif fault == "wrong-body":
        c["body"] = b64(
            canon(
                {"version": 1, "request_bytes": b64(raw + b" "), "admission": admission}
            )
        )
    elif fault == "wrong-origin":
        c["origin"] = "https://other.example"
    elif fault == "wrong-path":
        c["path"] = "/v1/requests/poll"
    elif fault == "wrong-method":
        c["method"] = "GET"
    elif fault == "wrong-purpose":
        c["purpose"] = "poll"
    elif fault == "changed-descriptor":
        c["expected_requester"] = {
            **requester,
            "id": stable_id_from_did_key(did(other)),
        }
    elif fault == "too-old":
        c["now"] = 1161
    elif fault == "future":
        c["now"] = 1099
    elif fault == "padded-token":
        c["authorization"] += "="
    elif fault == "duplicate-header-packet":
        data = __import__("base64").urlsafe_b64decode(
            c["authorization"][7:] + "=" * (-len(c["authorization"][7:]) % 4)
        )
        c["authorization"] = "Awsign " + b64(data[:-1] + b',"signature":"x"}')
    else:
        packet = json.loads(
            __import__("base64").urlsafe_b64decode(
                c["authorization"][7:] + "=" * (-len(c["authorization"][7:]) % 4)
            )
        )
        packet["extra"] = "refused"
        c["authorization"] = "Awsign " + b64(canon(packet))
    http_cases.append(c)
c = copy.deepcopy(http_cases[0])
c.update(id="oldest-allowed-boundary", now=1160)
http_cases.append(c)

# 2. Issuer intent -> pending registration -> issuer binding/creation -> observed activation.
intent_body = {
    "version": 1,
    "purpose": "enroll_person",
    "organisation": org,
    "person": person,
    "pending_certificate": certificate,
    "identity_key": did(person_key),
    "requester": controller,
    "origin": origin,
    "rp_id": "awsign.com",
    "challenge": b64(bytes([17]) * 32),
    "not_before": 1000,
    "deadline": 1300,
}
intent = sign(issuer, "enrollment_intent", "intent", intent_body)
httpcase(
    "controller-bootstrap-enrollment",
    "enrollment_start",
    {
        "version": 1,
        "intent": intent,
        "admission": {"team_certificate": None, "id_chain": []},
    },
    who=controller,
    k=issuer,
)
confirmation = request("enrollment_confirmation")
confirmation["act"]["target"]["binding_commitment"] = hashof(
    "binding_commitment", binding
)
confirmation["nonce"]["value"] = ""
confirmation["nonce"]["value"] = b64(
    hmac.digest(secret, domain("nonce") + canon(confirmation), "sha256")
)
creation = receipt(confirmation)
ebody = {
    "version": 1,
    "kind": "human",
    "organisation": org,
    "subject": {"id": person, "certificate": cid, "key": did(person_key)},
    "issuer": did(issuer),
    "binding_commitment": hashof("binding_commitment", binding),
    "creation": {
        "credential": credential["id"],
        "grade": credential["grade"],
        "receipt_commitment": hashof("receipt_commitment", creation),
    },
}
evidence = sign(issuer, "identity_evidence", "evidence", ebody)
activation = {
    "version": 1,
    "intent": intent,
    "binding": binding,
    "creation_receipt": creation,
    "evidence": evidence,
    "id_chain": [certificate],
}
httpcase(
    "controller-presents-activation",
    "enrollment_activate",
    activation,
    who=controller,
    k=issuer,
)
enrollment_cases = []
for phase in ["intent", "pending", "activation"]:
    enrollment_cases.append(
        {
            "id": phase + "-valid",
            "phase": phase,
            "accept": True,
            "intent": intent,
            "activation": activation,
            "issuer_key": did(issuer),
            "requester": controller,
            "origin": origin,
            "rp_id": "awsign.com",
            "now": 1100,
            "trust": trust,
            "expected_person": person,
            "expected_locator": hashof("enrollment_locator", intent),
            "expected_intent_preimage": b64(
                domain("enrollment_intent") + canon(intent_body)
            ),
            "expected_state": "active" if phase == "activation" else "pending",
        }
    )
activation_base = copy.deepcopy(enrollment_cases[-1])
for fault in [
    "wrong-issuer",
    "wrong-requester",
    "wrong-origin",
    "expired-intent",
    "missing-public-identity",
    "expired-status",
    "wrong-public-key",
    "changed-binding",
    "missing-evidence",
    "evidence-subject-mismatch",
    "evidence-receipt-mismatch",
    "confirmation-target-mismatch",
    "malformed-creation-request",
    "unsupported-definition-version",
    "confirmation-requester-mismatch",
]:
    c = copy.deepcopy(activation_base)
    c.update(id=fault, accept=False)
    if fault == "unsupported-definition-version":
        req = copy.deepcopy(confirmation)
        req["definition"]["version"] = 2
        c["activation"]["creation_receipt"]["request_bytes"] = b64(canon(req))
    elif fault == "confirmation-requester-mismatch":
        req = copy.deepcopy(confirmation)
        req["requester"] = requester
        req["nonce"]["value"] = ""
        req["nonce"]["value"] = b64(
            hmac.digest(secret, domain("nonce") + canon(req), "sha256")
        )
        cc = receipt(req)
        c["activation"]["creation_receipt"] = cc
        eb = copy.deepcopy(ebody)
        eb["creation"]["receipt_commitment"] = hashof("receipt_commitment", cc)
        c["activation"]["evidence"] = sign(issuer, "identity_evidence", "evidence", eb)
        c["expected_error"] = "requester_mismatch"
    elif fault == "malformed-creation-request":
        c["activation"]["creation_receipt"]["request_bytes"] = b64(b"{}")
    elif fault == "wrong-issuer":
        c["issuer_key"] = did(other)
    elif fault == "wrong-requester":
        c["requester"] = requester
    elif fault == "wrong-origin":
        c["origin"] = "https://other.example"
    elif fault == "expired-intent":
        c["now"] = 1300
    elif fault == "missing-public-identity":
        c["trust"] = None
    elif fault == "expired-status":
        c["trust"]["observed_at"] = 1039
    elif fault == "wrong-public-key":
        c["trust"]["identity_key"] = did(other)
    elif fault == "changed-binding":
        c["activation"]["binding"]["binding"]["credentials"][0]["id"] = b64(b"changed")
    elif fault == "missing-evidence":
        c["activation"]["evidence"] = None
    elif fault in ["evidence-subject-mismatch", "evidence-receipt-mismatch"]:
        body = c["activation"]["evidence"]["evidence"]
        if fault == "evidence-subject-mismatch":
            body["subject"]["key"] = did(other)
        else:
            body["creation"]["receipt_commitment"] = "sha256:" + "0" * 64
        c["activation"]["evidence"] = sign(
            issuer, "identity_evidence", "evidence", body
        )
    else:
        req = copy.deepcopy(confirmation)
        req["act"]["target"]["binding_commitment"] = "sha256:" + "0" * 64
        cc = receipt(req)
        c["activation"]["creation_receipt"] = cc
        eb = copy.deepcopy(ebody)
        eb["creation"]["receipt_commitment"] = hashof("receipt_commitment", cc)
        c["activation"]["evidence"] = sign(issuer, "identity_evidence", "evidence", eb)
    enrollment_cases.append(c)

# The second-person enrollment is requested by the already active first person,
# while the org controller remains the issuer. It is pending until its own
# registration, creation proof and committed public identity exist.
second_intent_body = copy.deepcopy(intent_body)
second_certificate = {
    "certificate": second_certificate_body,
    "signature": b64(
        issuer.sign(id_certificate_signing_bytes(second_certificate_body)).signature
    ),
}
second_intent_body.update(
    person=second_person,
    pending_certificate=second_certificate,
    identity_key=did(second_key),
    requester=requester,
    challenge=b64(bytes([18]) * 32),
)
second_intent = sign(issuer, "enrollment_intent", "intent", second_intent_body)
enrollment_cases.append(
    {
        "id": "first-person-requests-second-enrollment",
        "phase": "intent",
        "accept": True,
        "intent": second_intent,
        "activation": activation,
        "issuer_key": did(issuer),
        "requester": requester,
        "origin": origin,
        "rp_id": "awsign.com",
        "now": 1100,
        "trust": None,
        "expected_person": second_person,
        "expected_locator": hashof("enrollment_locator", second_intent),
        "expected_intent_preimage": b64(
            domain("enrollment_intent") + canon(second_intent_body)
        ),
        "expected_state": "pending",
    }
)

# The issuer checks creation BEFORE a public person exists. Checking the
# assertion/nonce does not activate the pending service enrollment.
creation_base = copy.deepcopy(
    next(c for c in enrollment_cases if c["id"] == "activation-valid")
)
for fault in ["valid", "wrong-nonce", "wrong-presenter", "expired"]:
    c = copy.deepcopy(creation_base)
    c.update(
        expected_credential=credential["id"],
        expected_grade=credential["grade"],
        expected_digest=hashlib.sha256(
            domain("request") + canon(confirmation)
        ).hexdigest(),
        id="issuer-creation-" + fault,
        phase="creation",
        accept=fault == "valid",
        expected_state="pending",
        nonce_key=b64(secret),
        trust_source="current issuer plus exact pending certificate; not current person membership",
    )
    if fault == "wrong-nonce":
        c["nonce_key"] = b64(b"other-secret")
        c["expected_error"] = "nonce_invalid"
    elif fault == "wrong-presenter":
        c["presenter"] = {**controller, "key": did(person_key)}
        c["expected_error"] = "requester_mismatch"
    elif fault == "expired":
        c["now"] = 1300
        c["expected_error"] = "enrollment_expired"
    enrollment_cases.append(c)

# 3. Enforcer's challenge answer -> exact requester presentation and live proof.
needs = {
    "version": 1,
    "status": "needs_human",
    "approval_origin": origin,
    "request_bytes": b64(raw),
    "digest": digest,
}
presentation = {"version": 1, "request_bytes": b64(raw), "receipt": receipt(r)}
base = {
    "http_status": 428,
    "expected_approver_person": person,
    "expected_target_person": second_person,
    "phase": "needs_human",
    "accept": True,
    "needs_human": needs,
    "presentation": presentation,
    "request": r,
    "presenter": requester,
    "trust": trust,
    "nonce_key": b64(secret),
    "origin": origin,
    "now": 1100,
    "required_grade": "passkey_uv",
    "expected_digest": digest,
}
enforcer_cases = [
    dict(copy.deepcopy(base), id="needs-human-exact-R"),
    dict(copy.deepcopy(base), id="presentation-exact-caller", phase="presentation"),
]
for fault in [
    "changed-R",
    "wrong-digest",
    "wrong-service",
    "different-presenter",
    "expired",
    "wrong-nonce-secret",
    "binding-origin-not-allowed",
    "creation-is-not-effect",
    "wrong-http-status",
]:
    c = copy.deepcopy(enforcer_cases[1])
    c.update(id=fault, accept=False)
    if fault == "wrong-http-status":
        c["phase"] = "needs_human"
        c["http_status"] = 200
    elif fault == "changed-R":
        c["presentation"]["request_bytes"] = b64(raw + b" ")
    elif fault == "wrong-digest":
        c["phase"] = "needs_human"
        c["needs_human"]["digest"] = "0" * 64
    elif fault == "wrong-service":
        c["phase"] = "needs_human"
        c["needs_human"]["approval_origin"] = "https://other.example"
    elif fault == "different-presenter":
        c["presenter"] = {**requester, "key": did(other)}
    elif fault == "expired":
        c["now"] = 1300
    elif fault == "wrong-nonce-secret":
        c["nonce_key"] = b64(b"other-secret")
    elif fault == "binding-origin-not-allowed":
        c["origin"] = "https://other.example"
    else:
        c["request"] = confirmation
        c["presentation"] = {
            "version": 1,
            "request_bytes": b64(canon(confirmation)),
            "receipt": creation,
        }
    enforcer_cases.append(c)
for name, error in [
    ("unknown-definition", "definition_unavailable"),
    ("unexpected-act-field", "definition_invalid"),
]:
    c = copy.deepcopy(enforcer_cases[0])
    c.update(id=name, accept=False, expected_error=error)
    changed = c["request"]
    if name == "unknown-definition":
        changed["definition"]["id"] = "unbundled"
    else:
        changed["act"]["uncovered_default"] = "refuse"
    changed_raw = canon(changed)
    c["needs_human"]["request_bytes"] = b64(changed_raw)
    c["needs_human"]["digest"] = hashlib.sha256(
        domain("request") + changed_raw
    ).hexdigest()
    enforcer_cases.append(c)

EXPECTED_ERRORS = {
    "unsupported-definition-version": "definition_invalid",
    "wrong-key": "signature_invalid",
    "wrong-body": "http_body_mismatch",
    "wrong-origin": "origin_invalid",
    "wrong-path": "http_binding_mismatch",
    "wrong-method": "http_binding_mismatch",
    "wrong-purpose": "http_binding_mismatch",
    "changed-descriptor": "requester_mismatch",
    "too-old": "http_expired",
    "future": "http_expired",
    "padded-token": "http_invalid",
    "duplicate-header-packet": "http_invalid",
    "unknown-field": "http_invalid",
    "wrong-issuer": "enrollment_invalid",
    "wrong-requester": "requester_mismatch",
    "expired-intent": "enrollment_expired",
    "missing-public-identity": "identity_unavailable",
    "expired-status": "identity_unavailable",
    "wrong-public-key": "enrollment_identity_mismatch",
    "changed-binding": "issuer_signature_invalid",
    "missing-evidence": "activation_invalid",
    "evidence-subject-mismatch": "evidence_subject_mismatch",
    "evidence-receipt-mismatch": "evidence_binding_mismatch",
    "confirmation-target-mismatch": "creation_target_mismatch",
    "malformed-creation-request": "definition_invalid",
    "confirmation-requester-mismatch": "requester_mismatch",
    "issuer-creation-wrong-nonce": "nonce_invalid",
    "issuer-creation-wrong-presenter": "requester_mismatch",
    "issuer-creation-expired": "enrollment_expired",
    "changed-R": "request_mismatch",
    "wrong-digest": "request_digest_mismatch",
    "wrong-service": "origin_invalid",
    "different-presenter": "requester_mismatch",
    "expired": "request_expired",
    "wrong-nonce-secret": "nonce_invalid",
    "binding-origin-not-allowed": "origin_invalid",
    "creation-is-not-effect": "purpose_invalid",
    "wrong-http-status": "http_status_invalid",
    "unknown-definition": "definition_unavailable",
    "unexpected-act-field": "definition_invalid",
}
for case in http_cases:
    if case["accept"]:
        case.update(
            test_signing_seed=b64(
                bytes(
                    issuer
                    if case["expected_requester"]["kind"] == "namespace_controller"
                    else person_key
                )
            ),
            signed_at=1100,
        )

for path, cases, scope in zip(
    outputs,
    [http_cases, enrollment_cases, enforcer_cases],
    ["requester-service", "issuer-service-enrollment", "enforcer-requester"],
    strict=True,
):
    for case in cases:
        if not case["accept"]:
            case["expected_error"] = (
                "http_binding_mismatch"
                if scope == "requester-service" and case["id"] == "wrong-origin"
                else EXPECTED_ERRORS[case["id"]]
            )
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "scope": scope,
                "source": "Synthetic exact signed bytes for the first self-custody add-human path. Test keys are public fixtures. Pure cryptographic seam inputs, not live registry, browser, custody or effect qualification.",
                "cases": cases,
            },
            indent=2,
        )
        + "\n"
    )
    print(path.name, len(cases))
