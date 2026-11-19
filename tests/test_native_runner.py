"""The package owner collects every caller and refuses absent preparation."""

import os
import subprocess
import sys


def runner_environment():
    environment = dict(os.environ)
    for name in (
        "APPROVAL_TEST_DATABASE_URL",
        "APPROVAL_TEST_REDIS_URL",
        "APPROVAL_TEST_COREDNS_BINARY",
        "APPROVAL_AWID_SOURCE",
        "PYTHONPATH",
        "PYTHONHOME",
        "AWID_SERVICE_TOKEN",
    ):
        environment.pop(name, None)
    return environment


def test_package_collect_target_includes_units_and_real_database_callers():
    result = subprocess.run(
        ["make", "collect"],
        env=runner_environment(),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    selected = set(result.stdout.splitlines())
    assert {
        "tests/test_binding_refresh_transport.py::test_current_person_can_cover_the_additive_binding_refresh_route",
        "integration/test_binding_refresh.py::test_duplicate_refresh_waits_for_the_real_enrollment_lock_and_replays",
        "integration/test_binding_refresh_registry.py::test_refresh_budget_follows_the_signing_key_across_changed_identity_claims",
    } <= selected


def test_native_runner_refuses_missing_resources_before_starting_any_tests():
    result = subprocess.run(
        [sys.executable, "scripts/run_integration.py"],
        env=runner_environment(),
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 1
    assert result.stderr.strip().endswith(
        "RuntimeError: Missing disposable integration resource: APPROVAL_TEST_DATABASE_URL"
    )
    assert result.stdout == ""
