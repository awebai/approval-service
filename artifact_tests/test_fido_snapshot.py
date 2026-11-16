"""A real signed public FIDO snapshot, not a mocked metadata response."""

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from approval_service.metadata import MetadataRefused, load_snapshot
from approval_service.metadata_cache import default_manifest, fetch_and_pin

CACHE = Path(os.environ["APPROVAL_MDS_CACHE"])
NOW = datetime(2026, 11, 15, 21, tzinfo=UTC)


def inputs():
    manifest = default_manifest()
    # The exact downloaded files remain outside Git. This is the same cache
    # verification used at runtime, with an explicit historical as-of clock.
    fetch_and_pin(CACHE, manifest=manifest, now=NOW)
    artifacts = manifest["artifacts"]

    def raw(spec):
        return (CACHE / (spec["sha256"] + ".artifact")).read_bytes()

    return {
        "blob": raw(artifacts["blob"]),
        "root_der": raw(artifacts["root"]),
        "crls": [raw(spec) for spec in artifacts["crls"]],
        "blob_sha256": artifacts["blob"]["sha256"],
        "root_sha256": artifacts["root"]["sha256"],
        "minimum_sequence": manifest["minimum_sequence"],
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
