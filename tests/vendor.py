"""Synthetic test vendor, with actual X509/CRL/JWT/registration signatures.

This exercises classification under a supplied test trust anchor. It is NOT
FIDO data, a physical authenticator or a hardware qualification receipt.
"""

import base64
import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from functools import lru_cache

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from pyasn1.codec.der.encoder import encode as der
from pyasn1.type import univ
from receipts import fixture

from approval_service.canonical import canonical
from approval_service.encoding import decode, encode
from approval_service.metadata import load_snapshot

NOW = datetime(2026, 11, 15, 21, tzinfo=UTC)
AAGUID = "00000000-0000-4000-8000-000000000001"
OTHER_AAGUID = "00000000-0000-4000-8000-000000000002"


def certificate(
    subject,
    key,
    *,
    issuer=None,
    issuer_key=None,
    ca=False,
    san=None,
    aaguid=None,
    firmware=None,
    now=NOW,
):
    issuer = issuer or subject
    issuer_key = issuer_key or key
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=730))
    )
    builder = (
        builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=1 if ca else None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=isinstance(key, rsa.RSAPrivateKey) and not ca,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    if aaguid:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"),
                der(univ.OctetString(uuid.UUID(aaguid).bytes)),
            ),
            critical=False,
        )
    if firmware is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                ObjectIdentifier("1.3.6.1.4.1.45724.1.1.5"), der(univ.Integer(firmware))
            ),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


@lru_cache(maxsize=1)
def metadata_signer(now):
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Test metadata root")]
    )
    root = certificate(root_name, root_key, ca=True, now=now)
    signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer = certificate(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test metadata signer")]),
        signer_key,
        issuer=root.subject,
        issuer_key=root_key,
        san="mds.fidoalliance.org",
        now=now,
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root.subject)
        .last_update(now - timedelta(days=1))
        .next_update(now + timedelta(days=7))
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    return root, signer, signer_key, crl


def signed_metadata(entries, *, sequence=1, next_update=None, now=NOW):
    root, signer, key, crl = metadata_signer(now)
    header = {
        "alg": "RS256",
        "x5c": [base64.b64encode(signer.public_bytes(Encoding.DER)).decode()],
    }
    body = {
        "no": sequence,
        "nextUpdate": (next_update or now + timedelta(days=1)).strftime("%Y-%m-%d"),
        "entries": entries,
    }
    preimage = (
        encode(canonical(header)).encode() + b"." + encode(canonical(body)).encode()
    )
    blob = (
        preimage
        + b"."
        + encode(key.sign(preimage, padding.PKCS1v15(), hashes.SHA256())).encode()
    )
    root_der = root.public_bytes(Encoding.DER)
    return {
        "blob": blob,
        "root_der": root_der,
        "crls": [crl.public_bytes(Encoding.DER)],
        "blob_sha256": hashlib.sha256(blob).hexdigest(),
        "root_sha256": hashlib.sha256(root_der).hexdigest(),
        "minimum_sequence": 1,
        "now": now,
    }


class Vendor:
    def __init__(self, *, now=NOW):
        self.now = now
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Test vendor batch root")]
        )
        self.root = certificate(self.root_name, self.root_key, ca=True, now=now)
        self.batch_key = ec.generate_private_key(ec.SECP256R1())
        self.subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test vendor"),
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"
                ),
                x509.NameAttribute(NameOID.COMMON_NAME, "Shared test batch"),
            ]
        )

    def entry(self, aaguid=AAGUID):
        return {
            "aaguid": aaguid,
            "metadataStatement": {
                "attestationTypes": ["basic_full"],
                "attestationRootCertificates": [
                    base64.b64encode(self.root.public_bytes(Encoding.DER)).decode()
                ],
            },
            "statusReports": [
                {
                    "status": "FIDO_CERTIFIED_L1",
                    "effectiveDate": "2026-01-01",
                    "authenticatorVersion": 1,
                }
            ],
        }

    def batch(self, *, aaguid=AAGUID, firmware=10, root_vendor=None):
        issuer = root_vendor or self
        return certificate(
            self.subject,
            self.batch_key,
            issuer=issuer.root.subject,
            issuer_key=issuer.root_key,
            aaguid=aaguid,
            firmware=firmware,
            now=self.now,
        )

    def registration(
        self,
        *,
        batch=None,
        be=False,
        backed_up=False,
        challenge=None,
        credential=None,
        origin="https://approval.example.test",
        rp_id="approval.example.test",
    ):
        batch = batch or self.batch()
        entry = (
            credential or fixture()["receipt"]["binding"]["binding"]["credentials"][0]
        )
        cid = decode(entry["id"])
        challenge = (
            challenge
            if challenge is not None
            else b"issuer-owned-test-enrollment-nonce"
        )
        client = canonical(
            {
                "type": "webauthn.create",
                "challenge": encode(challenge),
                "origin": origin,
                "crossOrigin": False,
            }
        )
        auth = (
            hashlib.sha256(rp_id.encode("ascii")).digest()
            + bytes([0x45 | (8 if be else 0) | (16 if backed_up else 0)])
            + b"\0" * 4
            + uuid.UUID(AAGUID).bytes
            + len(cid).to_bytes(2, "big")
            + cid
            + decode(entry["key"])
        )
        sig = self.batch_key.sign(
            auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())
        )
        obj = {
            "fmt": "packed",
            "authData": auth,
            "attStmt": {
                "alg": -7,
                "sig": sig,
                "x5c": [batch.public_bytes(Encoding.DER)],
            },
        }
        return {
            "id": entry["id"],
            "client_data_json": encode(client),
            "attestation_object": encode(cbor2.dumps(obj)),
        }, challenge

    def snapshot(self, entries=None):
        return load_snapshot(**signed_metadata(entries or [self.entry()], now=self.now))
