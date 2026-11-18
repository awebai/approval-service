"""Offline approval proof checks; no organisation signing or effect authority.

Trust is supplied by the caller's independently authenticated public observations.
It is never reconstructed from receipt-supplied keys. Live callers still own the
current rule, membership and the nonce/effect transaction.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import StrEnum

import cbor2
from aweb_naapp.webauthn import (
    AssertionFailure,
    AssertionRefused,
    BackupPolicy,
    VerifiedAssertion,
    verify_assertion,
)
from awid.did import public_key_from_did
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import ValidationError
from nacl.bindings import crypto_core_ed25519_is_valid_point

from .canonical import InvalidJSON, canonical, parse
from .cbor import decode_map
from .encoding import EncodingError, decode
from .wire import domain, validate, validate_site

REQUEST_PREFIX = domain("request")
BINDING_PREFIX = domain("binding")
NONCE_PREFIX = domain("nonce")


class CredentialGrade(StrEnum):
    PASSKEY = "passkey_uv"
    HARDWARE = "certified_hardware"


GRADES = {CredentialGrade.PASSKEY: 0, CredentialGrade.HARDWARE: 1}


class Refused(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Trust:
    person: str
    organisation: str
    identity_key: str
    certificate: str
    issuer: str
    issuer_public_key: bytes
    observed_at: int
    namespace_issuer: str | None = None


@dataclass(frozen=True)
class CheckedApproval:
    person: str
    identity_key: str
    credential: str
    grade: str
    digest: str
    origin: str
    deadline: int


@dataclass(frozen=True)
class CheckedReceipt:
    request: dict
    approval: CheckedApproval
    assertion: VerifiedAssertion


def _closed(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields.split()):
        raise Refused("invalid_shape")


def _integer(value):
    return type(value) is int and value >= 0


def _key(raw, algorithm):
    try:
        key = decode_map(raw)
    except (cbor2.CBORDecodeError, ValueError) as exc:
        raise Refused("credential_key_invalid") from exc
    if (
        not isinstance(key, dict)
        or any(type(k) is not int for k in key)
        or type(key.get(1)) is not int
        or (algorithm in (-7, -8) and type(key.get(-1)) is not int)
        or type(key.get(3)) is not int
        or key.get(3) != algorithm
    ):
        raise Refused("credential_key_invalid")
    negatives = {k for k in key if isinstance(k, int) and k < 0}
    valid = False
    if algorithm == -7:
        valid = (
            key.get(1) == 2
            and key.get(-1) == 1
            and negatives == {-1, -2, -3}
            and all(
                isinstance(key.get(k), bytes) and len(key[k]) == 32 for k in (-2, -3)
            )
        )
        if valid:
            try:
                ec.EllipticCurvePublicNumbers(
                    int.from_bytes(key[-2]), int.from_bytes(key[-3]), ec.SECP256R1()
                ).public_key()
            except ValueError:
                valid = False
    elif algorithm == -8:
        valid = (
            key.get(1) == 1
            and key.get(-1) == 6
            and negatives == {-1, -2}
            and isinstance(key.get(-2), bytes)
            and len(key[-2]) == 32
            and crypto_core_ed25519_is_valid_point(key[-2])
        )
    elif algorithm == -257:
        n, e = key.get(-1), key.get(-2)
        valid = (
            key.get(1) == 3
            and negatives == {-1, -2}
            and isinstance(n, bytes)
            and isinstance(e, bytes)
            and n[:1] != b"\0"
            and e == b"\x01\x00\x01"
            and 2048 <= int.from_bytes(n).bit_length() <= 8192
        )
    if not valid:
        raise Refused("credential_key_invalid")


def verify_binding(signed_binding: dict, *, trust: Trust) -> dict:
    """Check current issuer authority and exact person binding, without an assertion.

    README.md:30-34,148-155 and protocol.md:900-908 select the issuer from checked
    public authority, including the namespace controller for later enrollment.
    """
    _closed(signed_binding, "binding signature")
    b = signed_binding["binding"]
    _closed(
        b,
        "version organisation person certificate identity_key issuer origin rp_id credentials",
    )
    if b["version"] != 1 or (
        b["person"],
        b["organisation"],
        b["identity_key"],
        b["certificate"],
    ) != (
        trust.person,
        trust.organisation,
        trust.identity_key,
        trust.certificate,
    ):
        raise Refused("binding_mismatch")
    issuer_public_key = trust.issuer_public_key
    if b["issuer"] != trust.issuer:
        if not trust.namespace_issuer or b["issuer"] != trust.namespace_issuer:
            raise Refused("binding_mismatch")
        try:
            issuer_public_key = public_key_from_did(trust.namespace_issuer)
        except (ValueError, TypeError) as exc:
            raise Refused("issuer_key_invalid") from exc
    if len(issuer_public_key) != 32 or not crypto_core_ed25519_is_valid_point(
        issuer_public_key
    ):
        raise Refused("issuer_key_invalid")
    try:
        Ed25519PublicKey.from_public_bytes(issuer_public_key).verify(
            decode(signed_binding["signature"]), BINDING_PREFIX + canonical(b)
        )
    except (InvalidSignature, ValueError) as exc:
        raise Refused("issuer_signature_invalid") from exc
    try:
        validate_site(b["origin"], b["rp_id"])
    except ValidationError as exc:
        raise Refused("origin_invalid") from exc
    return b


def _verify(receipt, *, expected_request, trust, sign_count: int = 0) -> CheckedReceipt:
    canonical(receipt)
    validate("receipt", receipt)
    if receipt["version"] != 1 or not isinstance(receipt["id_chain"], list):
        raise Refused("version_invalid")
    raw = decode(receipt["request_bytes"])
    request = parse(raw)
    if raw != canonical(request) or raw != canonical(expected_request):
        raise Refused("request_mismatch")
    validate("request", request)
    if request["version"] != 1 or request["purpose"] not in (
        "act_approval",
        "enrollment_confirmation",
    ):
        raise Refused("purpose_invalid")
    if (
        request["approver"] != trust.person
        or request["organisation"] != trust.organisation
    ):
        raise Refused("person_mismatch")
    if (
        not _integer(request["not_before"])
        or not _integer(request["deadline"])
        or request["deadline"] <= request["not_before"]
    ):
        raise Refused("deadline_invalid")
    b = verify_binding(receipt["binding"], trust=trust)
    a = receipt["assertion"]
    _closed(a, "id client_data_json authenticator_data signature")
    selected = None
    ids = set()
    if not isinstance(b["credentials"], list) or not 1 <= len(b["credentials"]) <= 8:
        raise Refused("credentials_invalid")
    for credential in b["credentials"]:
        _closed(credential, "id key algorithm grade snapshot grade_policy")
        cid = decode(credential["id"])
        if cid in ids:
            raise Refused("duplicate_credential")
        ids.add(cid)
        if credential["grade"] not in GRADES:
            raise Refused("grade_invalid")
        if credential["grade"] == "certified_hardware" and (
            not isinstance(credential["snapshot"], str)
            or not credential["snapshot"].startswith("sha256:")
            or len(credential["snapshot"]) != 71
        ):
            raise Refused("snapshot_invalid")
        key = decode(credential["key"])
        _key(key, credential["algorithm"])
        if cid == decode(a["id"]):
            selected = credential
    if selected is None:
        raise Refused("credential_not_enrolled")
    digest = hashlib.sha256(REQUEST_PREFIX + raw).digest()
    proof = {
        "id": a["id"],
        "rawId": a["id"],
        "type": "public-key",
        "response": {
            "clientDataJSON": a["client_data_json"],
            "authenticatorData": a["authenticator_data"],
            "signature": a["signature"],
        },
    }
    for field in ("client_data_json", "authenticator_data", "signature"):
        decode(a[field])
    try:
        assertion = verify_assertion(
            proof,
            expected_challenge=digest,
            expected_rp_id=b["rp_id"],
            expected_origin=b["origin"],
            credential_id=decode(selected["id"]),
            public_key=decode(selected["key"]),
            sign_count=sign_count,
            backup_policy=(
                BackupPolicy.FORBIDDEN
                if selected["grade"] == CredentialGrade.HARDWARE
                else BackupPolicy.ALLOWED
            ),
        )
    except AssertionRefused as error:
        if error.reason is AssertionFailure.COUNTER_NOT_ADVANCED:
            raise Refused("approval_assertion_invalid") from error
        raise Refused(error.reason.value) from error
    approval = CheckedApproval(
        person=trust.person,
        identity_key=trust.identity_key,
        credential=selected["id"],
        grade=selected["grade"],
        digest=digest.hex(),
        origin=b["origin"],
        deadline=request["deadline"],
    )
    return CheckedReceipt(request=request, approval=approval, assertion=assertion)


def verify_historical(receipt, *, expected_request, trust):
    """Check raw proof under explicit as-of trust, without live effect permission."""
    try:
        return _verify(receipt, expected_request=expected_request, trust=trust).approval
    except (InvalidJSON, EncodingError, ValidationError) as exc:
        raise Refused("invalid_encoding") from exc


def verify_receipt_with_counter(
    receipt, *, expected_request, trust: Trust, sign_count: int
) -> CheckedReceipt:
    """One signed proof check; the service supplies its locked counter.

    The state owner checks deadlines and consumes the challenge at the effect.
    Portable callers keep verify_historical and its explicit as-of trust.
    """
    try:
        return _verify(
            receipt,
            expected_request=expected_request,
            trust=trust,
            sign_count=sign_count,
        )
    except (InvalidJSON, EncodingError, ValidationError) as error:
        raise Refused("invalid_encoding") from error


def verify_for_effect(
    receipt, *, expected_request, trust, now, required_grade, presenter, nonce_keys
):
    """Checked bindings only; the enforcer owns rule/member/effect authority."""
    try:
        verified = _verify(receipt, expected_request=expected_request, trust=trust)
        request = verified.request
        result = verified.approval
        if request["purpose"] != "act_approval":
            raise Refused("purpose_invalid")
        if not _integer(now) or not request["not_before"] <= now < request["deadline"]:
            raise Refused("request_expired")
        if not _integer(trust.observed_at) or not 0 <= now - trust.observed_at <= 60:
            raise Refused("status_unavailable")
        if canonical(presenter) != canonical(request["requester"]):
            raise Refused("requester_mismatch")
        if (
            required_grade not in GRADES
            or GRADES[result.grade] < GRADES[required_grade]
        ):
            raise Refused("grade_insufficient")
        _check_nonce(request, nonce_keys)
        return result
    except (InvalidJSON, EncodingError, ValidationError) as exc:
        raise Refused("invalid_encoding") from exc


def _check_nonce(request, nonce_keys):
    nonce = request["nonce"]
    _closed(nonce, "kid value")
    secret = nonce_keys.get(nonce["kid"])
    if not secret:
        raise Refused("nonce_invalid")
    core = {**request, "nonce": {"kid": nonce["kid"], "value": ""}}
    expected = hmac.digest(secret, NONCE_PREFIX + canonical(core), "sha256")
    if not hmac.compare_digest(decode(nonce["value"]), expected):
        raise Refused("nonce_invalid")
