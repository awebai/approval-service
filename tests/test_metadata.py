"""Real cryptography under a synthetic metadata trust anchor; no FIDO blob."""

import hashlib
from datetime import timedelta

import pytest
from vendor import AAGUID, NOW, Vendor, signed_metadata

from approval_service.metadata import MetadataRefused, load_snapshot


def inputs():
    return signed_metadata([Vendor().entry()])


def test_signed_metadata_chain_signature_crl_and_sequence():
    snapshot = load_snapshot(**inputs())
    assert snapshot.sequence == 1
    assert len(snapshot.entries) == 1


@pytest.mark.parametrize(
    "fault", ["blob_pin", "root_pin", "signature", "rollback", "expired", "missing_crl"]
)
def test_untrusted_or_stale_snapshot_never_grades_hardware(fault):
    kwargs = inputs()
    if fault == "blob_pin":
        kwargs["blob_sha256"] = "0" * 64
    elif fault == "root_pin":
        kwargs["root_sha256"] = "0" * 64
    elif fault == "signature":
        raw = bytearray(kwargs["blob"])
        raw[-20] = ord("A") if raw[-20] != ord("A") else ord("B")
        kwargs["blob"] = bytes(raw)
        kwargs["blob_sha256"] = hashlib.sha256(raw).hexdigest()
    elif fault == "rollback":
        kwargs["minimum_sequence"] = 2
    elif fault == "expired":
        kwargs["now"] = NOW + timedelta(days=2)
    else:
        kwargs["crls"] = []
    with pytest.raises(MetadataRefused):
        load_snapshot(**kwargs)


def test_model_certification_requires_its_attested_firmware_scope():
    vendor = Vendor()
    entry = vendor.entry()
    entry["statusReports"][0]["authenticatorVersion"] = 10
    snapshot = vendor.snapshot([entry])
    assert snapshot.model(AAGUID, now=NOW, authenticator_version=10) is not None
    assert snapshot.model(AAGUID, now=NOW, authenticator_version=9) is None
    assert snapshot.model(AAGUID, now=NOW, authenticator_version=None) is None
