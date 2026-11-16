"""The operator's hardware choice must not silently become passkey-only."""

from datetime import timedelta

import pytest
from test_metadata_cache import manifest
from vendor import NOW, Vendor

from approval_service.grading import EnrollmentGrading
from approval_service.metadata_cache import CacheRefused
from approval_service.verify import Refused


def test_mode_is_explicit_and_hardware_requires_a_cache(tmp_path):
    with pytest.raises(ValueError, match="grading_mode_invalid"):
        EnrollmentGrading.load(mode="", cache_dir=tmp_path / "cache", now=NOW)
    with pytest.raises(ValueError, match="hardware_cache_required"):
        EnrollmentGrading.load(mode="hardware", now=NOW)


def test_loading_failure_never_reaches_passkey_only(transport, tmp_path):
    config = manifest(transport)
    config["artifacts"]["blob"]["sha256"] = "0" * 64
    with pytest.raises(CacheRefused, match="artifact_pin_mismatch"):
        EnrollmentGrading.load(
            mode="hardware", cache_dir=tmp_path / "cache", manifest=config, now=NOW
        )


def test_configured_hardware_stays_required_after_load_and_time_passes(
    transport, tmp_path
):
    vendor = Vendor()
    config = manifest(transport, entries=[vendor.entry()])
    grading = EnrollmentGrading.load(
        mode="hardware", cache_dir=tmp_path / "cache", manifest=config, now=NOW
    )
    response, challenge = vendor.registration()
    args = {
        "expected_challenge": challenge,
        "origin": "https://approval.example.test",
        "rp_id": "approval.example.test",
    }
    assert grading.check(response, **args, now=NOW).grade == "certified_hardware"
    with pytest.raises(Refused, match="snapshot_expired"):
        grading.check(response, **args, now=NOW + timedelta(days=2))
    assert grading.status(now=NOW + timedelta(days=2))["enrollment_ready"] is False


def test_operator_can_explicitly_choose_passkey_only_without_cache_or_network():
    grading = EnrollmentGrading.load(mode="passkey_only", now=NOW)
    response, challenge = Vendor().registration()
    assert (
        grading.check(
            response,
            expected_challenge=challenge,
            origin="https://approval.example.test",
            rp_id="approval.example.test",
            now=NOW,
        ).grade
        == "passkey_uv"
    )
    assert grading.status(now=NOW) == {
        "mode": "passkey_only",
        "enrollment_ready": True,
        "metadata": None,
    }


def test_operator_warning_starts_seven_days_before_deadline(transport, tmp_path):
    config = manifest(transport)
    grading = EnrollmentGrading.load(
        mode="hardware", cache_dir=tmp_path / "cache", manifest=config, now=NOW
    )
    status = grading.status(now=NOW)
    assert status["enrollment_ready"] is True
    assert status["metadata"]["warning"] == "metadata_expiring"
    assert status["metadata"]["seconds_remaining"] > 0
    assert (
        grading.status(now=NOW + timedelta(days=2))["metadata"]["warning"]
        == "metadata_expired"
    )


def test_warning_uses_earlier_revocation_deadline_and_not_only_blob_date():
    from vendor import signed_metadata

    from approval_service.metadata import load_snapshot

    snapshot = load_snapshot(
        **signed_metadata([Vendor().entry()], next_update=NOW + timedelta(days=14))
    )
    grading = EnrollmentGrading("hardware", snapshot)
    health = grading.status(now=NOW + timedelta(days=1))["metadata"]
    assert health["valid_until"] == (NOW + timedelta(days=7)).isoformat()
    assert (
        health["next_update"] == (NOW + timedelta(days=14)).replace(hour=0).isoformat()
    )
    assert health["warning"] == "metadata_expiring"
    assert grading.status(now=NOW + timedelta(days=8))["enrollment_ready"] is False


def test_hardware_policy_cannot_be_created_without_loaded_input():
    with pytest.raises(Refused, match="snapshot_unavailable"):
        EnrollmentGrading("hardware", None)
