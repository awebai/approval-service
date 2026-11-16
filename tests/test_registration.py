"""Actual signed software registrations and a synthetic vendor hardware branch.

Synthetic attestation proves the classification logic, not physical hardware.
"""

import hashlib
import uuid

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from receipts import fixture
from vendor import AAGUID, NOW, OTHER_AAGUID, Vendor

from approval_service.canonical import canonical
from approval_service.encoding import decode, encode
from approval_service.registration import check_registration
from approval_service.verify import Refused


@pytest.fixture(scope="module")
def snapshot():
    return Vendor().snapshot()


def registration(algorithm=-7, fmt="packed", *, uv=True, be=False):
    w = fixture(algorithm)
    entry = w["receipt"]["binding"]["binding"]["credentials"][0]
    cid = decode(entry["id"])
    key = decode(entry["key"])
    challenge = b"real-registration-challenge-32byte"
    client = canonical(
        {
            "type": "webauthn.create",
            "challenge": encode(challenge),
            "origin": "https://approval.example.test",
            "crossOrigin": False,
        }
    )
    # A listed model's AAGUID cannot make this software key hardware.
    aaguid = uuid.UUID(AAGUID).bytes
    auth = (
        hashlib.sha256(b"approval.example.test").digest()
        + bytes([0x41 | (4 if uv else 0) | (8 if be else 0)])
        + b"\0" * 4
        + aaguid
        + len(cid).to_bytes(2, "big")
        + cid
        + key
    )
    signed = auth + hashlib.sha256(client).digest()
    if algorithm == -7:
        sig = w["private"].sign(signed, ec.ECDSA(hashes.SHA256()))
    elif algorithm == -8:
        sig = w["private"].sign(signed)
    else:
        sig = w["private"].sign(signed, padding.PKCS1v15(), hashes.SHA256())
    obj = {
        "fmt": fmt,
        "authData": auth,
        "attStmt": {} if fmt == "none" else {"alg": algorithm, "sig": sig},
    }
    return (
        {
            "id": entry["id"],
            "client_data_json": encode(client),
            "attestation_object": encode(cbor2.dumps(obj)),
        },
        challenge,
        w,
        obj,
    )


def check(response, challenge, snapshot):
    return check_registration(
        response,
        expected_challenge=challenge,
        origin="https://approval.example.test",
        rp_id="approval.example.test",
        snapshot=snapshot,
        now=NOW,
    )


@pytest.mark.parametrize("algorithm", [-7, -8, -257])
@pytest.mark.parametrize("fmt", ["none", "packed"])
def test_real_software_registration_never_inherits_metadata_hardware_grade(
    snapshot, algorithm, fmt
):
    response, challenge, w, _obj = registration(algorithm, fmt)
    result = check(response, challenge, snapshot)
    assert result.grade == "passkey_uv"
    assert result.snapshot is None
    assert result.algorithm == algorithm
    assert result.credential_id == response["id"]
    assert result.public_key == decode(
        w["receipt"]["binding"]["binding"]["credentials"][0]["key"]
    )
    public = result.binding_entry()
    assert set(public) == {
        "id",
        "key",
        "algorithm",
        "grade",
        "snapshot",
        "grade_policy",
    }
    assert "attestation" not in str(public)


@pytest.mark.parametrize(
    "fault",
    [
        "uv",
        "challenge",
        "origin",
        "cross_origin",
        "duplicate",
        "credential_id",
        "rp_hash",
        "signature",
        "cbor_tail",
        "private_key",
    ],
)
def test_bad_registration_or_uv_never_enters_pending_enrollment(snapshot, fault):
    response, challenge, w, obj = registration(uv=fault != "uv")
    if fault == "challenge":
        challenge = b"other"
    elif fault == "origin":
        client = __import__("json").loads(decode(response["client_data_json"]))
        client["origin"] = "https://foreign.example.test"
        response["client_data_json"] = encode(canonical(client))
    elif fault == "cross_origin":
        client = __import__("json").loads(decode(response["client_data_json"]))
        client["crossOrigin"] = True
        response["client_data_json"] = encode(canonical(client))
    elif fault == "duplicate":
        response["client_data_json"] = encode(
            decode(response["client_data_json"])[:-1]
            + b',"origin":"https://approval.example.test"}'
        )
    elif fault == "credential_id":
        response["id"] = encode(b"other")
    elif fault == "rp_hash":
        obj["authData"] = b"a" * 32 + obj["authData"][32:]
    elif fault == "signature":
        obj["attStmt"]["sig"] = b"broken"
    elif fault == "cbor_tail":
        response["attestation_object"] = encode(
            decode(response["attestation_object"]) + cbor2.dumps({})
        )
    elif fault == "private_key":
        raw = decode(w["receipt"]["binding"]["binding"]["credentials"][0]["key"])
        key = cbor2.loads(raw)
        key[-4] = b"private"
        obj["authData"] = obj["authData"][: -len(raw)] + cbor2.dumps(key)
    if fault not in ("cbor_tail",):
        if fault != "signature":
            obj["attStmt"]["sig"] = w["private"].sign(
                obj["authData"]
                + hashlib.sha256(decode(response["client_data_json"])).digest(),
                ec.ECDSA(hashes.SHA256()),
            )
        response["attestation_object"] = encode(cbor2.dumps(obj))
    with pytest.raises(Refused):
        check(response, challenge, snapshot)


@pytest.mark.parametrize("enterprise", [False, True])
def test_real_x509_enterprise_marker_refuses_while_untrusted_batch_is_only_passkey(
    snapshot, enterprise
):
    from datetime import timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID, ObjectIdentifier

    response, challenge, w, obj = registration()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Software test issuer"),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"
            ),
            x509.NameAttribute(NameOID.COMMON_NAME, "Disposable test batch"),
        ]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(w["private"].public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if enterprise:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                ObjectIdentifier("1.3.6.1.4.1.45724.1.1.2"), b"\x04\x10unique-device-01"
            ),
            critical=False,
        )
    obj["attStmt"]["x5c"] = [
        builder.sign(w["private"], hashes.SHA256()).public_bytes(Encoding.DER)
    ]
    response["attestation_object"] = encode(cbor2.dumps(obj))
    if enterprise:
        with pytest.raises(Refused, match="enterprise_attestation_refused"):
            check(response, challenge, snapshot)
    else:
        result = check(response, challenge, snapshot)
        assert result.grade == "passkey_uv" and result.snapshot is None


@pytest.mark.parametrize("attestation_type", ["basic_full", "attca"])
def test_synthetic_vendor_exercises_the_complete_hardware_classification(
    attestation_type,
):
    vendor = Vendor()
    response, challenge = vendor.registration()
    entry = vendor.entry()
    entry["metadataStatement"]["attestationTypes"] = [attestation_type]
    result = check(response, challenge, vendor.snapshot([entry]))
    assert result.grade == "certified_hardware"
    assert result.snapshot is not None
    assert result.binding_entry()["snapshot"] == result.snapshot


@pytest.mark.parametrize(
    "fault",
    [
        "other-model-extension",
        "other-entry-root",
        "shared-root-no-aaguid",
        "firmware-below",
        "withdrawal",
        "withdrawal-newer-firmware",
        "this-batch-withdrawal",
        "backup-eligible",
        "backed-up",
        "attestation-type",
    ],
)
def test_synthetic_vendor_hardware_near_misses(fault):
    import base64

    from cryptography.hazmat.primitives.serialization import Encoding

    vendor = Vendor()
    entry = vendor.entry()
    entries = [entry]
    kwargs = {}
    batch = None
    if fault == "other-model-extension":
        batch = vendor.batch(aaguid=OTHER_AAGUID)
    elif fault == "other-entry-root":
        other = Vendor()
        entries.append(other.entry(OTHER_AAGUID))
        batch = vendor.batch(root_vendor=other)
    elif fault == "shared-root-no-aaguid":
        entries.append(vendor.entry(OTHER_AAGUID))
        batch = vendor.batch(aaguid=None)
    elif fault == "firmware-below":
        entry["statusReports"][0]["authenticatorVersion"] = 11
    elif fault.startswith("withdrawal"):
        report = {"status": "USER_VERIFICATION_BYPASS", "effectiveDate": "2026-01-02"}
        if fault == "withdrawal-newer-firmware":
            report["authenticatorVersion"] = 20
        entry["statusReports"].append(report)
    elif fault == "this-batch-withdrawal":
        batch = vendor.batch()
        entry["statusReports"].append(
            {
                "status": "ATTESTATION_KEY_COMPROMISE",
                "batchCertificate": base64.b64encode(
                    batch.public_bytes(Encoding.DER)
                ).decode(),
            }
        )
    elif fault == "backup-eligible":
        kwargs["be"] = True
    elif fault == "backed-up":
        kwargs.update(be=True, backed_up=True)
    elif fault == "attestation-type":
        entry["metadataStatement"]["attestationTypes"] = ["basic_surrogate"]
    response, challenge = vendor.registration(batch=batch, **kwargs)
    if fault == "other-model-extension":
        with pytest.raises(Refused, match="attestation_aaguid_mismatch"):
            check(response, challenge, vendor.snapshot(entries))
    else:
        result = check(response, challenge, vendor.snapshot(entries))
        assert result.grade == "passkey_uv" and result.snapshot is None


def test_model_specific_root_accepts_a_batch_without_aaguid_extension():
    vendor = Vendor()
    response, challenge = vendor.registration(batch=vendor.batch(aaguid=None))
    assert check(response, challenge, vendor.snapshot()).grade == "certified_hardware"


def test_withdrawal_for_another_batch_does_not_revoke_this_batch():
    import base64

    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    from vendor import certificate

    vendor = Vendor()
    other = certificate(
        vendor.subject,
        ec.generate_private_key(ec.SECP256R1()),
        issuer=vendor.root.subject,
        issuer_key=vendor.root_key,
        aaguid=AAGUID,
        firmware=10,
    )
    entry = vendor.entry()
    entry["statusReports"].append(
        {
            "status": "ATTESTATION_KEY_COMPROMISE",
            "batchCertificate": base64.b64encode(
                other.public_bytes(Encoding.DER)
            ).decode(),
        }
    )
    response, challenge = vendor.registration()
    assert (
        check(response, challenge, vendor.snapshot([entry])).grade
        == "certified_hardware"
    )


def test_expired_snapshot_refuses_instead_of_permanently_downgrading_creation():
    from datetime import timedelta

    vendor = Vendor()
    response, challenge = vendor.registration()
    with pytest.raises(Refused, match="snapshot_expired"):
        check_registration(
            response,
            expected_challenge=challenge,
            origin="https://approval.example.test",
            rp_id="approval.example.test",
            snapshot=vendor.snapshot(),
            now=NOW + timedelta(days=2),
        )


def test_explicit_passkey_only_enrollment_needs_no_metadata():
    vendor = Vendor()
    response, challenge = vendor.registration()
    assert check(response, challenge, None).grade == "passkey_uv"


def test_loaded_snapshot_cannot_outlive_its_verified_revocation_inputs():
    from datetime import timedelta

    from vendor import signed_metadata

    from approval_service.metadata import load_snapshot

    vendor = Vendor()
    snapshot = load_snapshot(
        **signed_metadata([vendor.entry()], next_update=NOW + timedelta(days=14))
    )
    response, challenge = vendor.registration()
    with pytest.raises(Refused, match="snapshot_validation_expired"):
        check_registration(
            response,
            expected_challenge=challenge,
            origin="https://approval.example.test",
            rp_id="approval.example.test",
            snapshot=snapshot,
            now=NOW + timedelta(days=8),
        )
