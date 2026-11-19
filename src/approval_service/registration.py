"""The same private registration verifier for the service AND the ID issuer.

The issuer supplies the fresh exact-enrollment challenge. Both parties check
this SAME create response; the issuer checks it before claiming hardware in B.
Registration is pending data, never LOGIN, activation or application authority.
Raw attestation is private; binding_entry exports no device certificate/AAGUID.
"""

from __future__ import annotations

import base64
import io
import uuid
from dataclasses import dataclass, field

import cbor2
from aweb_naapp.webauthn import ClientDataType, verify_client_data
from aweb_naapp.webauthn_cbor import read_cbor_item
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.x509.oid import NameOID, ObjectIdentifier
from jsonschema import ValidationError
from OpenSSL import crypto
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ
from webauthn import verify_registration_response
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import COSEAlgorithmIdentifier

from .encoding import decode, encode
from .metadata import POLICY
from .verify import Refused, _key
from .wire import SCHEMA, validate, validate_site

AAGUID_OID = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")
FIRMWARE_OID = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.5")
ENTERPRISE_SERIAL_OID = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.2")


def require_supported_entry(assessed, declared):
    """An issuer may grade down; one independently checked key cannot grade up.

    Each party has already checked its own pinned snapshot at registration.
    Hardware snapshots may differ; their hashes are evidence, not key identity.
    The service retains its original assessment rather than overwriting it.
    """
    if (
        {k: v for k, v in assessed.items() if k not in ("grade", "snapshot")}
        != {k: v for k, v in declared.items() if k not in ("grade", "snapshot")}
        or declared["grade"] not in ("passkey_uv", assessed["grade"])
        or (declared["grade"] == "passkey_uv" and declared["snapshot"] is not None)
        or (declared["grade"] == "certified_hardware" and not declared["snapshot"])
    ):
        raise Refused("binding_credential_mismatch")


@dataclass(frozen=True)
class RegisteredCredential:
    credential_id: str
    public_key: bytes
    algorithm: int
    sign_count: int
    grade: str
    snapshot: str | None
    client_data_json: bytes = field(repr=False)

    def binding_entry(self):
        return {
            "id": self.credential_id,
            "key": encode(self.public_key),
            "algorithm": self.algorithm,
            "grade": self.grade,
            "snapshot": self.snapshot,
            "grade_policy": POLICY["id"],
        }


def _authenticator(raw, credential_id):
    if not isinstance(raw, bytes) or len(raw) < 55:
        raise Refused("registration_authenticator_invalid")
    flags = raw[32]
    if flags & 0x45 != 0x45 or (flags & 0x10 and not flags & 0x08):
        raise Refused("registration_uv_required")
    length = int.from_bytes(raw[53:55])
    end = 55 + length
    if not length or end >= len(raw) or raw[55:end] != decode(credential_id):
        raise Refused("registration_credential_mismatch")
    stream = io.BytesIO(raw[end:])
    value = read_cbor_item(stream)
    consumed = stream.tell()
    if not isinstance(value, dict) or type(value.get(3)) is not int:
        raise Refused("credential_key_invalid")
    algorithm = value[3]
    key = raw[end : end + consumed]
    _key(key, algorithm)
    if flags & 0x80:
        extensions = read_cbor_item(stream)
        if not isinstance(extensions, dict):
            raise Refused("registration_extensions_invalid")
    if stream.tell() != len(raw) - end:
        raise Refused("registration_authenticator_trailing")
    return key, algorithm, str(uuid.UUID(bytes=raw[37:53])), flags


def _der(value, spec):
    decoded, tail = der_decoder.decode(value, asn1Spec=spec)
    if tail or der_encoder.encode(decoded) != value:
        raise Refused("attestation_extension_invalid")
    return decoded


def _model_extensions(certificate, aaguid):
    matched = False
    firmware = None
    for ext in certificate.extensions:
        if ext.oid == ENTERPRISE_SERIAL_OID:
            raise Refused("enterprise_attestation_refused")
        if ext.oid == AAGUID_OID and aaguid is not None:
            value = bytes(_der(ext.value.value, univ.OctetString()))
            if ext.critical or value != uuid.UUID(aaguid).bytes:
                raise Refused("attestation_aaguid_mismatch")
            matched = True
        if ext.oid == FIRMWARE_OID and aaguid is not None:
            firmware = int(_der(ext.value.value, univ.Integer()))
            if ext.critical or firmware < 0:
                raise Refused("attestation_extension_invalid")
    return matched, firmware


def _packed(certificate):
    # WebAuthn 3 §8.2.1. Unique enterprise device data is never admitted.
    if certificate.version != x509.Version.v3:
        raise Refused("attestation_certificate_invalid")
    for oid in (
        NameOID.COUNTRY_NAME,
        NameOID.ORGANIZATION_NAME,
        NameOID.ORGANIZATIONAL_UNIT_NAME,
        NameOID.COMMON_NAME,
    ):
        values = certificate.subject.get_attributes_for_oid(oid)
        if len(values) != 1 or not values[0].value:
            raise Refused("attestation_certificate_invalid")
    country = certificate.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
    if (
        len(country) != 2
        or not country.isascii()
        or not country.isalpha()
        or country != country.upper()
    ):
        raise Refused("attestation_certificate_invalid")
    if (
        certificate.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[
            0
        ].value
        != "Authenticator Attestation"
    ):
        raise Refused("attestation_certificate_invalid")
    if certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER):
        raise Refused("identifying_attestation_refused")
    if certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise Refused("attestation_certificate_invalid")


def _hardware(snapshot, entry, chain, aaguid, firmware, has_aaguid, fmt, now):
    if snapshot is None or entry is None or not chain:
        return False
    statement = entry.get("metadataStatement", {})
    if not set(statement.get("attestationTypes", [])).intersection(
        {"basic_full", "attca"}
    ):
        return False
    roots = statement.get("attestationRootCertificates", [])
    if not roots:
        return False
    try:
        store = crypto.X509Store()
        store.set_time(now)
        for encoded in roots:
            root = base64.b64decode(encoded, validate=True)
            store.add_cert(crypto.load_certificate(crypto.FILETYPE_ASN1, root))
        context = crypto.X509StoreContext(
            store,
            crypto.load_certificate(crypto.FILETYPE_ASN1, chain[0]),
            [crypto.load_certificate(crypto.FILETYPE_ASN1, c) for c in chain[1:]],
        )
        context.verify_certificate()
        verified = [
            crypto.dump_certificate(crypto.FILETYPE_ASN1, c)
            for c in context.get_verified_chain()
        ]
        # An AAGUID-less certificate can identify a model only if its MDS
        # root is model-specific. Pure bounded snapshot lookup, no I/O loop.
        if not has_aaguid:
            root = base64.b64encode(verified[-1]).decode()
            models = {
                e.get("aaguid") or e.get("aaid") or str(i)
                for i, e in enumerate(snapshot.entries)
                if root
                in e.get("metadataStatement", {}).get("attestationRootCertificates", [])
            }
            if models != {aaguid}:
                return False
        return (
            snapshot.model(
                aaguid,
                now=now,
                attestation_chain=verified,
                authenticator_version=firmware,
            )
            is not None
        )
    except (ValueError, TypeError, crypto.Error, crypto.X509StoreContextError):
        return False


def check_registration(
    response,
    *,
    expected_challenge,
    origin,
    rp_id,
    snapshot,
    now,
    hardware_grading=False,
):
    """Validate raw create bytes and assess only the actual registered key.

    `snapshot` is the caller's independently loaded, pinned MDS input, NEVER
    metadata supplied by the enrollment service to an issuer. Hardware chain
    failures cannot become hardware. A valid software/untrusted
    attestation remains passkey grade. Invalid UP/UV/signature/binding refuses.
    """
    try:
        validate_site(origin, rp_id)
        validate("registration", response)
        client = decode(response["client_data_json"])
        raw = decode(response["attestation_object"])
        verify_client_data(
            client,
            expected_type=ClientDataType.REGISTRATION,
            expected_challenge=expected_challenge,
            expected_origin=origin,
        )
        stream = io.BytesIO(raw)
        obj = read_cbor_item(stream)
        if (
            stream.tell() != len(raw)
            or not isinstance(obj, dict)
            or set(obj) != {"fmt", "authData", "attStmt"}
        ):
            raise Refused("registration_attestation_invalid")
        fmt = obj["fmt"]
        if fmt not in SCHEMA["x-registration-attestation-formats"]:
            raise Refused("attestation_profile_unsupported")
        stmt = obj["attStmt"]
        if not isinstance(fmt, str) or not isinstance(stmt, dict):
            raise Refused("registration_attestation_invalid")
        key, algorithm, aaguid, flags = _authenticator(obj["authData"], response["id"])
        chain = stmt.get("x5c", [])
        if (
            not isinstance(chain, list)
            or len(chain) > 8
            or any(not isinstance(c, bytes) or len(c) > 65536 for c in chain)
        ):
            raise Refused("attestation_chain_invalid")
        if chain and (snapshot is not None or hardware_grading):
            if snapshot is None:
                raise Refused("snapshot_unavailable")
            if now >= snapshot.next_update:
                raise Refused("snapshot_expired")
            if now >= snapshot.valid_until:
                raise Refused("snapshot_validation_expired")
        certificates = [x509.load_der_x509_certificate(c) for c in chain]
        has_aaguid = False
        firmware = None
        for i, c in enumerate(certificates):
            matched, version = _model_extensions(c, aaguid if i == 0 else None)
            if i == 0:
                has_aaguid, firmware = matched, version
        if fmt == "none" and stmt:
            raise Refused("registration_attestation_invalid")
        if fmt == "packed" and certificates:
            _packed(certificates[0])
        verified = verify_registration_response(
            credential={
                "id": response["id"],
                "rawId": response["id"],
                "type": "public-key",
                "response": {
                    "clientDataJSON": response["client_data_json"],
                    "attestationObject": response["attestation_object"],
                },
            },
            expected_challenge=expected_challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            require_user_presence=True,
            require_user_verification=True,
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.EDDSA,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ],
        )
        if verified.credential_id != decode(response["id"]):
            raise Refused("registration_credential_mismatch")
        entry = snapshot.by_aaguid.get(aaguid) if snapshot is not None else None
        hardware = not flags & 0x18 and _hardware(
            snapshot, entry, chain, aaguid, firmware, has_aaguid, fmt, now
        )
        return RegisteredCredential(
            response["id"],
            key,
            algorithm,
            verified.sign_count,
            "certified_hardware" if hardware else "passkey_uv",
            "sha256:" + snapshot.digest if hardware else None,
            client,
        )
    except Refused:
        raise
    except (
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        OverflowError,
        cbor2.CBORDecodeError,
        WebAuthnException,
        ValidationError,
        PyAsn1Error,
        x509.ExtensionNotFound,
        x509.DuplicateExtension,
        UnsupportedAlgorithm,
        InvalidSignature,
    ) as exc:
        # Parse/crypto failures are named, preserving the original cause for the
        # private caller; no raw response is put in this error or a log field.
        raise Refused("registration_invalid") from exc
