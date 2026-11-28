"""Explicit withdrawals in signed synthetic metadata."""

import base64
import hashlib
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.serialization import Encoding
from vendor import AAGUID, NOW, OTHER_AAGUID, Vendor, signed_metadata

from approval_service.metadata import MetadataRefused, load_snapshot


@pytest.mark.parametrize(
    "scope, matches",
    [
        ("unscoped", True),
        ("batchCertificate", True),
        ("certificate", True),
        ("different_batch", False),
        ("other_model", False),
        ("future", False),
    ],
)
def test_effective_withdrawal_matches_verified_model_or_certificate(scope, matches):
    vendor = Vendor()
    entry = vendor.entry()
    leaf = vendor.batch().public_bytes(Encoding.DER)
    root = vendor.root.public_bytes(Encoding.DER)
    report = {"status": "ATTESTATION_KEY_COMPROMISE", "authenticatorVersion": 20}
    if scope == "batchCertificate":
        report[scope] = base64.b64encode(leaf).decode()
    elif scope == "certificate":
        report[scope] = base64.b64encode(root).decode()
    elif scope == "different_batch":
        unrelated = vendor.batch().public_bytes(Encoding.DER)
        report["batchCertificate"] = base64.b64encode(unrelated).decode()
    elif scope == "future":
        report["effectiveDate"] = (NOW + timedelta(days=1)).date().isoformat()
    entry["statusReports"].append(report)
    snapshot = load_snapshot(
        **signed_metadata([entry], next_update=NOW + timedelta(days=4))
    )
    fingerprints = {hashlib.sha256(der).digest() for der in (leaf, root)}

    assert (
        snapshot.has_effective_withdrawal(
            OTHER_AAGUID if scope == "other_model" else AAGUID,
            now=NOW,
            certificate_hashes=fingerprints,
        )
        is matches
    )
    if scope == "future":
        assert snapshot.has_effective_withdrawal(
            AAGUID, now=NOW + timedelta(days=1), certificate_hashes=fingerprints
        )


@pytest.mark.parametrize("field", ["effectiveDate", "batchCertificate"])
def test_malformed_withdrawal_is_not_reported_as_healthy(field):
    vendor = Vendor()
    entry = vendor.entry()
    entry["statusReports"].append({"status": "REVOKED", field: "!"})
    snapshot = vendor.snapshot([entry])
    with pytest.raises(MetadataRefused, match="metadata_withdrawal_invalid"):
        snapshot.has_effective_withdrawal(AAGUID, now=NOW, certificate_hashes=set())
