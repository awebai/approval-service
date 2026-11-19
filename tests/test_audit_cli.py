"""Installed operator command refusals give a usable final retry before DB access."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

RETRY = "Next: run awsign audit-binding-refreshes --after 0 --limit 100."


@pytest.mark.parametrize(
    "arguments,diagnostic",
    [
        (
            ["serve", "--after", "1"],
            "--after and --limit belong to audit-binding-refreshes",
        ),
        (
            ["migrate", "--limit", "1"],
            "--after and --limit belong to audit-binding-refreshes",
        ),
        (["audit-binding-refreshes", "--after", "-1"], "--after must be nonnegative"),
        (
            ["audit-binding-refreshes", "--limit", "0"],
            "--limit must be between 1 and 1000",
        ),
        (
            ["audit-binding-refreshes", "--limit", "1001"],
            "--limit must be between 1 and 1000",
        ),
    ],
)
def test_audit_argument_refusal_ends_with_a_valid_retry_before_database_access(
    arguments, diagnostic
):
    environment = dict(os.environ)
    environment.pop("AWSIGN_DATABASE_URL", None)
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [str(Path(sys.executable).with_name("awsign")), *arguments],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 2, result.stderr
    assert diagnostic in result.stderr
    assert result.stderr.strip().endswith(RETRY)
    assert "AWSIGN_DATABASE_URL" not in result.stderr


@pytest.mark.parametrize("command", ["serve", "migrate", "audit-binding-refreshes"])
def test_existing_operator_command_help_does_not_need_database_access(command):
    result = subprocess.run(
        [str(Path(sys.executable).with_name("awsign")), command, "--help"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert "--after" in result.stdout and "--limit" in result.stdout
