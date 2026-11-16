"""Run the real service/registry controls on an operator-provided disposable stack.

This creates no VM/container/database server. The placement supplies private
PostgreSQL/Redis, the frozen AWID checkout and the environment below.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

AWEB_REVISION = "686abcfc971bebe5de34674e7a61bcf0b6d7bb6a"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--collect-only", action="store_true")
    parser.add_argument("--junitxml", default="/tmp/awsign-service.xml")
    args = parser.parse_args()
    source = Path(os.environ["APPROVAL_AWID_SOURCE"]).resolve()
    root = source.parent.parent
    selected = subprocess.check_output(
        ["git", "rev-parse", "HEAD:awid/src"], cwd=root, text=True
    ).strip()
    expected = subprocess.check_output(
        ["git", "rev-parse", AWEB_REVISION + ":awid/src"], cwd=root, text=True
    ).strip()
    if selected != expected or not (source / "awid_service").is_dir():
        raise RuntimeError(
            "AWID source does not match the frozen post-deletion revision"
        )
    if subprocess.check_output(
        ["git", "diff", "--name-only", "HEAD", "--", "awid/src"], cwd=root, text=True
    ).strip():
        raise RuntimeError("Frozen AWID source has tracked modifications")
    if not args.collect_only:
        for name in ("APPROVAL_TEST_DATABASE_URL", "APPROVAL_TEST_REDIS_URL"):
            if not os.environ.get(name):
                raise RuntimeError("Missing disposable integration resource: " + name)
        if os.environ.get("AWID_SERVICE_TOKEN"):
            raise RuntimeError("Native quotas must not use a trusted-service token")
    env = {
        **os.environ,
        "PYTHONPATH": str(source),
        "AWID_RATE_LIMIT_BACKEND": "redis",
        # Library-mode AWID also reads its normal process settings. They name
        # the same disposable services as the explicitly supplied infrastructure.
        "AWID_DATABASE_URL": os.environ.get("APPROVAL_TEST_DATABASE_URL", ""),
        "AWID_REDIS_URL": os.environ.get("APPROVAL_TEST_REDIS_URL", ""),
    }
    command = [sys.executable, "-m", "pytest", "-q", "integration"]
    if args.collect_only:
        command.append("--collect-only")
    else:
        command.append("--junitxml=" + args.junitxml)
    return subprocess.call(command, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
