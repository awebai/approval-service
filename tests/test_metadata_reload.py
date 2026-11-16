"""A running grader installs verified reviewed pins without weakening policy."""

import copy
import hashlib
import json
from datetime import timedelta

import pytest
from test_metadata_cache import manifest
from vendor import NOW, Vendor, signed_metadata

from approval_service.grading import EnrollmentGrading
from approval_service.verify import Refused


def renew(transport, config, entries):
    newer = signed_metadata(entries, sequence=2, next_update=NOW + timedelta(days=6))
    config = copy.deepcopy(config)
    config["minimum_sequence"] = 2
    config["artifacts"]["blob"]["url"] = transport[0] + "/2/blob"
    config["artifacts"]["blob"]["sha256"] = hashlib.sha256(newer["blob"]).hexdigest()
    transport[1]["/2/blob"] = newer["blob"]
    return config


def test_verified_manifest_reloads_after_startup_without_a_second_registration(
    transport, tmp_path
):
    vendor = Vendor()
    config = manifest(transport, entries=[vendor.entry()])
    path = tmp_path / "pin.json"
    path.write_text(json.dumps(config))
    grading = EnrollmentGrading.load(
        mode="hardware", cache_dir=tmp_path / "cache", manifest_path=path, now=NOW
    )
    response, challenge = vendor.registration()
    later = NOW + timedelta(days=2)
    with pytest.raises(Refused, match="snapshot_expired"):
        grading.check(
            response,
            expected_challenge=challenge,
            origin="https://approval.example.test",
            rp_id="approval.example.test",
            now=later,
        )
    path.write_text(json.dumps(renew(transport, config, [vendor.entry()])))
    assert grading.refresh(now=later) is True
    assert grading.status(now=later)["metadata"]["sequence"] == 2
    assert (
        grading.check(
            response,
            expected_challenge=challenge,
            origin="https://approval.example.test",
            rp_id="approval.example.test",
            now=later,
        ).grade
        == "certified_hardware"
    )
    count = len(transport[2])
    assert grading.refresh(now=later) is False
    assert len(transport[2]) == count


def test_bad_replacement_keeps_only_the_still_valid_old_snapshot(transport, tmp_path):
    vendor = Vendor()
    config = manifest(transport, entries=[vendor.entry()])
    path = tmp_path / "pin.json"
    path.write_text(json.dumps(config))
    grading = EnrollmentGrading.load(
        mode="hardware", cache_dir=tmp_path / "cache", manifest_path=path, now=NOW
    )
    bad = renew(transport, config, [vendor.entry()])
    bad["artifacts"]["blob"]["sha256"] = "0" * 64
    path.write_text(json.dumps(bad))
    with pytest.raises(ValueError):
        grading.refresh(now=NOW)
    assert grading.status(now=NOW)["metadata"]["sequence"] == 1
    assert (
        grading.status(now=NOW)["metadata"]["reload_error"] == "metadata_reload_failed"
    )
    response, challenge = vendor.registration()
    assert (
        grading.check(
            response,
            expected_challenge=challenge,
            origin="https://approval.example.test",
            rp_id="approval.example.test",
            now=NOW,
        ).grade
        == "certified_hardware"
    )
    with pytest.raises(Refused, match="snapshot_expired"):
        grading.check(
            response,
            expected_challenge=challenge,
            origin="https://approval.example.test",
            rp_id="approval.example.test",
            now=NOW + timedelta(days=2),
        )


def test_rollback_never_replaces_the_current_grader(transport, tmp_path):
    vendor = Vendor()
    old = manifest(transport, entries=[vendor.entry()])
    path = tmp_path / "pin.json"
    path.write_text(json.dumps(old))
    grading = EnrollmentGrading.load(
        mode="hardware", cache_dir=tmp_path / "cache", manifest_path=path, now=NOW
    )
    path.write_text(json.dumps(renew(transport, old, [vendor.entry()])))
    assert grading.refresh(now=NOW)
    path.write_text(json.dumps(old))
    with pytest.raises(ValueError):
        grading.refresh(now=NOW)
    assert grading.status(now=NOW)["metadata"]["sequence"] == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("replacement", ["shape", "unlisted_exception"])
async def test_process_watcher_observes_pin_changes_and_stops_cleanly(
    transport, tmp_path, replacement
):
    import asyncio

    from approval_service.grading import watch_metadata

    vendor = Vendor()
    old = manifest(transport, entries=[vendor.entry()])
    path = tmp_path / "pin.json"
    path.write_text(json.dumps(old))
    grading = EnrollmentGrading.load(
        mode="hardware", cache_dir=tmp_path / "cache", manifest_path=path, now=NOW
    )
    async with watch_metadata(grading, interval=0.02):
        # A malformed operator file does not kill the watcher.
        bad = copy.deepcopy(old)
        bad["artifacts"]["blob"].update(
            url="https://localhost:invalid/blob", sha256="f" * 64
        )
        path.write_text("[]" if replacement == "shape" else json.dumps(bad))
        deadline = asyncio.get_running_loop().time() + 3
        while (
            grading._reload_error is None
            and asyncio.get_running_loop().time() < deadline
        ):
            await asyncio.sleep(0.01)
        assert grading._reload_error == "metadata_reload_failed"
        # Restore an already verified manifest. This lifecycle test does not
        # depend on the historical vendor CRL being current on the host clock;
        # replacement verification/installation is covered above with as-of NOW.
        path.write_text(json.dumps(old))
        deadline = asyncio.get_running_loop().time() + 3
        while (
            grading._reload_error is not None
            and asyncio.get_running_loop().time() < deadline
        ):
            await asyncio.sleep(0.01)
        assert grading._reload_error is None
    path.unlink()
    await asyncio.sleep(0.04)
    assert grading._reload_error is None


@pytest.mark.asyncio
async def test_service_lifespan_owns_the_shared_metadata_worker(transport, tmp_path):
    import asyncio

    from approval_service.http import create_app

    config = manifest(transport)
    path = tmp_path / "pin.json"
    path.write_text(json.dumps(config))
    grading = EnrollmentGrading.load(
        mode="hardware", cache_dir=tmp_path / "cache", manifest_path=path, now=NOW
    )
    app = create_app(
        None,
        public=None,
        origin="https://approval.example.test",
        rp_id="approval.example.test",
        grading=grading,
    )
    before = asyncio.all_tasks()
    async with app.router.lifespan_context(app):
        workers = asyncio.all_tasks() - before
        assert len(workers) == 1
        assert not next(iter(workers)).done()
    assert all(worker.done() for worker in workers)
