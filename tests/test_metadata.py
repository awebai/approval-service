"""A real signed public FIDO snapshot, not a mocked metadata response."""

import gzip
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from approval_service.metadata import MetadataRefused, load_snapshot

DATA = Path(__file__).parent / "data/mds"
NOW = datetime(2026, 11, 15, 21, tzinfo=UTC)


def inputs():
    manifest = json.loads((DATA / "manifest.json").read_text())
    return {
        "blob": gzip.decompress((DATA / "blob.jwt.gz").read_bytes()),
        "root_der": (DATA / "root-r46.der").read_bytes(),
        "crls": [(DATA / n).read_bytes() for n in manifest["crls"]],
        "blob_sha256": manifest["blob_sha256"],
        "root_sha256": manifest["root_sha256"],
        "minimum_sequence": 301,
        "now": NOW,
    }


def test_actual_fido_blob_chain_signature_crls_and_dated_sequence():
    snapshot = load_snapshot(**inputs())
    assert snapshot.sequence == 301
    assert snapshot.next_update == datetime(2026, 12, 1, tzinfo=UTC)
    assert len(snapshot.entries) == 537


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
        kwargs["minimum_sequence"] = 302
    elif fault == "expired":
        kwargs["now"] = datetime(2026, 12, 2, tzinfo=UTC)
    else:
        kwargs["crls"] = []
    with pytest.raises(MetadataRefused):
        load_snapshot(**kwargs)


def test_model_certification_requires_its_attested_firmware_scope():
    snapshot = load_snapshot(**inputs())
    model = "9eb7eabc-9db5-49a1-b6c3-555a802093f4"
    # This actual snapshot's L2 certificate starts at firmware 329476.
    assert snapshot.model(model, now=NOW, authenticator_version=329476) is not None
    assert snapshot.model(model, now=NOW, authenticator_version=329475) is None
    assert snapshot.model(model, now=NOW, authenticator_version=None) is None
