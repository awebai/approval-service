"""Append explicit service answers; NEVER overwrite existing signed seam cases."""

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

import cbor2
from awid.id_certificates import id_certificate_id, id_certificate_signing_bytes
from nacl.signing import SigningKey

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tests"))
from vendor import NOW, Vendor


def canon(x):
    return json.dumps(
        x, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode()


def b64(x):
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()


def raw(x):
    return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))


paths = {
    name: root / "vectors" / (name + "-v1.json")
    for name in ["requester-service", "issuer-service-enrollment", "enforcer-requester"]
}
files = {n: json.loads(p.read_text()) for n, p in paths.items()}
if any(
    c.get("phase") in ("answer", "enrollment-request")
    for v in files.values()
    for c in v["cases"]
):
    raise SystemExit("refuse to replace answer vectors")
schema = json.loads((root / "src/approval_service/data/format-v1.json").read_text())
domains = schema["x-domains"]


def commitment(n, v):
    return "sha256:" + hashlib.sha256(domains[n].encode() + canon(v)).hexdigest()


enforcer = next(
    c
    for c in files["enforcer-requester"]["cases"]
    if c["id"] == "presentation-exact-caller"
)
activation = next(
    c
    for c in files["issuer-service-enrollment"]["cases"]
    if c["id"] == "activation-valid"
)["activation"]
r = enforcer["request"]
rbytes = canon(r)
digest = enforcer["expected_digest"]
receipt = enforcer["presentation"]["receipt"]
locator = "request-locator-1"
intent = activation["intent"]
il = commitment("enrollment_locator", intent)
cr = activation["creation_receipt"]
crbytes = raw(cr["request_bytes"])
crq = json.loads(crbytes)
cd = hashlib.sha256(domains["request"].encode() + crbytes).hexdigest()


def bundle(c):
    return {k: copy.deepcopy(c[k]) for k in ["assertion", "binding", "id_chain"]}


def answer_case(
    file,
    name,
    kind,
    answer,
    *,
    status=200,
    request_bytes=None,
    i=None,
    loc=None,
    accept=True,
    error=None,
    mode="read",
    expected_receipt=None,
    **extra,
):
    c = {
        "id": name,
        "phase": "answer",
        "kind": kind,
        "answer": b64(canon(answer)),
        "response_status": status,
        "request_bytes": b64(request_bytes) if request_bytes is not None else None,
        "intent": i,
        "locator": loc,
        "accept": accept,
        "mode": mode,
    }
    if error:
        c["expected_error"] = error
    if expected_receipt is not None:
        c["expected_receipt_bytes"] = b64(canon(expected_receipt))
    c.update(extra)
    files[file]["cases"].append(c)
    return c


summary = {
    "version": 1,
    "locator": locator,
    "digest": digest,
    "deadline": r["deadline"],
    "state": "pending",
}
answer_case(
    "requester-service",
    "submit-new-pending",
    "submit",
    summary,
    status=202,
    request_bytes=rbytes,
)
answer_case(
    "requester-service",
    "submit-existing-pending",
    "submit",
    summary,
    status=200,
    request_bytes=rbytes,
    loc=locator,
)
for state in [
    "pending",
    "approved",
    "denied",
    "cancelled",
    "expired",
    "approved-erased",
]:
    body = {
        **summary,
        "state": "approved" if state == "approved-erased" else state,
        "approval": bundle(receipt) if state == "approved" else None,
    }
    answer_case(
        "requester-service",
        "poll-" + state,
        "poll",
        body,
        request_bytes=rbytes,
        loc=locator,
    )
    errors = {
        "pending": "approval_pending",
        "denied": "approval_denied",
        "cancelled": "approval_cancelled",
        "expired": "request_expired",
        "approved-erased": "receipt_unavailable",
    }
    answer_case(
        "requester-service",
        "assemble-poll-" + state,
        "poll",
        body,
        request_bytes=rbytes,
        loc=locator,
        mode="assemble",
        accept=state == "approved",
        error=errors.get(state),
        expected_receipt=receipt if state == "approved" else None,
    )
for state in ["cancelled", "approved"]:
    answer_case(
        "requester-service",
        "cancel-" + state,
        "cancel",
        {**summary, "state": state},
        request_bytes=rbytes,
        loc=locator,
    )
for fault in [
    "wrong-locator",
    "wrong-digest",
    "changed-deadline",
    "unexpected-field",
    "bundle-on-denial",
    "unrecognized-success-status",
    "duplicate-answer-member",
]:
    body = {**summary, "state": "approved", "approval": bundle(receipt)}
    status = 200
    error = "service_response_invalid"
    if fault == "wrong-locator":
        body["locator"] = "other"
        error = "locator_mismatch"
    elif fault == "wrong-digest":
        body["digest"] = "0" * 64
        error = "request_digest_mismatch"
    elif fault == "changed-deadline":
        body["deadline"] += 1
        error = "deadline_mismatch"
    elif fault == "unexpected-field":
        body["request_bytes"] = b64(rbytes)
    elif fault == "bundle-on-denial":
        body["state"] = "denied"
    elif fault == "unrecognized-success-status":
        status = 204
    c = answer_case(
        "requester-service",
        "answer-" + fault,
        "poll",
        body,
        status=status,
        request_bytes=rbytes,
        loc=locator,
        accept=False,
        error=error,
    )
    if fault == "duplicate-answer-member":
        c["answer"] = b64(canon(body)[:-1] + b',"state":"approved"}')
answer_case(
    "requester-service",
    "service-cancel-forbidden-code",
    "cancel",
    {"version": 1, "error": {"code": "requester_mismatch"}},
    status=403,
    request_bytes=rbytes,
    loc=locator,
    accept=False,
    error="requester_mismatch",
    expected_http_status=403,
)

# Exact issuer intent tied WebAuthn options, with no credential enumeration.
options = {
    "challenge": intent["intent"]["challenge"],
    "rp": {"id": "awsign.com", "name": "awsign"},
    "user": {
        "id": b64(bytes([23]) * 32),
        "name": intent["intent"]["person"],
        "displayName": intent["intent"]["person"],
    },
    "pubKeyCredParams": [{"type": "public-key", "alg": a} for a in [-7, -8, -257]],
    "authenticatorSelection": {
        "residentKey": "required",
        "requireResidentKey": True,
        "userVerification": "required",
    },
    "attestation": "direct",
    "extensions": {"credProps": True},
    "timeout": 120000,
}
start = {
    "version": 1,
    "locator": il,
    "deadline": intent["intent"]["deadline"],
    "state": "pending",
    "public_key": options,
}
answer_case(
    "issuer-service-enrollment",
    "enrollment-start-answer",
    "enrollment_start",
    start,
    status=201,
    i=intent,
    loc=il,
)
for fault in [
    "non-discoverable",
    "changed-challenge",
    "changed-person",
    "changed-deadline",
]:
    body = copy.deepcopy(start)
    error = "service_response_invalid"
    if fault == "non-discoverable":
        body["public_key"]["authenticatorSelection"]["residentKey"] = "preferred"
    elif fault == "changed-challenge":
        body["public_key"]["challenge"] = b64(bytes([99]) * 32)
        error = "enrollment_challenge_invalid"
    elif fault == "changed-person":
        body["public_key"]["user"]["name"] = "other"
        error = "enrollment_user_invalid"
    else:
        body["deadline"] += 1
        error = "deadline_mismatch"
    answer_case(
        "issuer-service-enrollment",
        "start-answer-" + fault,
        "enrollment_start",
        body,
        status=201,
        i=intent,
        loc=il,
        accept=False,
        error=error,
    )
# Material and confirm bodies are authenticated under the intent's requester.
admission = {"team_certificate": None, "id_chain": []}
confirm_request = {
    "version": 1,
    "intent": intent,
    "binding": activation["binding"],
    "request_bytes": cr["request_bytes"],
    "admission": admission,
}
for kind, body in [
    ("enrollment_material", {"version": 1, "intent": intent, "admission": admission}),
    ("enrollment_confirm", confirm_request),
]:
    c = {
        "id": kind + "-request",
        "phase": "enrollment-request",
        "kind": kind,
        "body": body,
        "intent": intent,
        "issuer_key": intent["intent"]["pending_certificate"]["certificate"][
            "issuer_key"
        ],
        "requester": intent["intent"]["requester"],
        "origin": "https://awsign.com",
        "rp_id": "awsign.com",
        "now": 1100,
        "accept": True,
        "expected_person": intent["intent"]["person"],
        "expected_state": "pending",
    }
    files["issuer-service-enrollment"]["cases"].append(c)
    if kind == "enrollment_confirm":
        bad = copy.deepcopy(c)
        bad.update(
            id="confirmation-body-unknown-field",
            accept=False,
            expected_error="enrollment_request_invalid",
        )
        bad["body"]["extra"] = "refuse"
        files["issuer-service-enrollment"]["cases"].append(bad)
for state in ["pending", "approved", "expired", "approved-erased"]:
    body = {
        "version": 1,
        "locator": il,
        "digest": cd,
        "deadline": crq["deadline"],
        "state": "approved" if state == "approved-erased" else state,
        "approval": bundle(cr) if state == "approved" else None,
    }
    answer_case(
        "issuer-service-enrollment",
        "confirm-answer-" + state,
        "enrollment_confirm",
        body,
        request_bytes=crbytes,
        i=intent,
        loc=il,
    )
    if state in ["approved", "approved-erased"]:
        answer_case(
            "issuer-service-enrollment",
            "assemble-confirm-" + state,
            "enrollment_confirm",
            body,
            request_bytes=crbytes,
            i=intent,
            loc=il,
            mode="assemble",
            accept=state == "approved",
            error=None if state == "approved" else "receipt_unavailable",
            expected_receipt=cr if state == "approved" else None,
        )
answer_case(
    "issuer-service-enrollment",
    "activation-answer",
    "enrollment_activate",
    {
        "version": 1,
        "locator": il,
        "person": intent["intent"]["person"],
        "state": "active",
    },
    i=intent,
    loc=il,
)
# Synthetic vendor; independently checkable raw create -> exact B entry. No FIDO data.
mi = copy.deepcopy(intent)
ib = mi["intent"]
now = int(NOW.timestamp())
ib.update(not_before=now - 1, deadline=now + 300)
cert = ib["pending_certificate"]["certificate"]
cert["issued_at"] = "2026-11-15T20:59:59Z"
issuer = SigningKey(bytes([1]) * 32)
ib["pending_certificate"]["signature"] = b64(
    issuer.sign(id_certificate_signing_bytes(cert)).signature
)
mi["signature"] = b64(
    issuer.sign(domains["enrollment_intent"].encode() + canon(ib)).signature
)
ml = commitment("enrollment_locator", mi)
registration, _ = Vendor().registration(
    challenge=raw(ib["challenge"]), origin=ib["origin"], rp_id=ib["rp_id"]
)
auth = cbor2.loads(raw(registration["attestation_object"]))["authData"]
n = int.from_bytes(auth[53:55], "big")
public_key = auth[55 + n :]
entry = {
    "id": registration["id"],
    "key": b64(public_key),
    "algorithm": -7,
    "grade": "passkey_uv",
    "snapshot": None,
    "grade_policy": json.loads(
        (root / "src/approval_service/data/mds-policy-v1.json").read_text()
    )["id"],
}
mb = copy.deepcopy(activation["binding"]["binding"])
mb["certificate"] = id_certificate_id(cert)
mb["credentials"] = [entry]
signed_b = {
    "binding": mb,
    "signature": b64(issuer.sign(domains["binding"].encode() + canon(mb)).signature),
}
material = {
    "version": 1,
    "locator": ml,
    "deadline": ib["deadline"],
    "state": "pending",
    "registrations": [
        {
            "registration": registration,
            "client_extension_results": {"credProps": {"rk": True}},
        }
    ],
}
answer_case(
    "issuer-service-enrollment",
    "material-answer-raw-create-to-binding",
    "enrollment_material",
    material,
    i=mi,
    loc=ml,
    registration_binding=signed_b,
    registration_now=now,
)
answer_case(
    "issuer-service-enrollment",
    "material-answer-not-ready",
    "enrollment_material",
    {**material, "registrations": []},
    i=mi,
    loc=ml,
)
bad = copy.deepcopy(material)
bad["registrations"][0]["client_extension_results"]["credProps"]["rk"] = False
answer_case(
    "issuer-service-enrollment",
    "material-answer-non-discoverable",
    "enrollment_material",
    bad,
    i=mi,
    loc=ml,
    accept=False,
    error="service_response_invalid",
)

# A valid second original intent cannot select an unrelated confirmation R.
mixed = {
    "version": 1,
    "locator": ml,
    "digest": cd,
    "deadline": crq["deadline"],
    "state": "approved",
    "approval": bundle(cr),
}
answer_case(
    "issuer-service-enrollment",
    "confirm-answer-mixed-original-intent",
    "enrollment_confirm",
    mixed,
    request_bytes=crbytes,
    i=mi,
    loc=ml,
    accept=False,
    error="enrollment_intent_mismatch",
)

# Poll/cancel bodies retain the requester-owned original R. Re-sign only these
# HTTP headers; existing receipt/intent/assertion signatures stay unchanged.
for c in files["requester-service"]["cases"]:
    if c.get("phase") == "answer" or c["id"] not in (
        "poll-same-descriptor",
        "cancel-same-descriptor",
    ):
        continue
    body = json.loads(raw(c["body"]))
    body["request_bytes"] = b64(rbytes)
    c["body"] = b64(canon(body))
    packet = json.loads(raw(c["authorization"][7:]))
    packet["proof"]["body_sha256"] = hashlib.sha256(canon(body)).hexdigest()
    pre = domains["http_request"].encode() + canon(packet["proof"])
    packet["signature"] = b64(SigningKey(bytes([2]) * 32).sign(pre).signature)
    c["authorization"] = "Awsign " + b64(canon(packet))
    c["expected_preimage"] = b64(pre)
for name, path in paths.items():
    path.write_text(json.dumps(files[name], indent=2) + "\n")
    print(name, len(files[name]["cases"]))
