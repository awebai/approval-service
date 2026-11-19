"""Run the real service/registry controls on an operator-provided disposable stack.

This creates no VM/container/database server. The placement supplies private
PostgreSQL/Redis, CoreDNS and the frozen installed dependencies.
"""

import argparse
import asyncio
import os
import subprocess
import sys
from pathlib import Path

import awid
import awid_service
from awid.external_registry import SystemHostResolver


async def require_private_test_hostname() -> None:
    """The real private-hostname guard requires the runner's normal OS mapping."""
    addresses = set(await SystemHostResolver().resolve_all("signer.example.com"))
    if addresses != {"127.0.0.1"}:
        raise RuntimeError(
            "Configure the disposable runner's normal resolver so signer.example.com "
            "resolves only to 127.0.0.1 before running integration; "
            "the private-hostname guard must not be bypassed."
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--collect-only", action="store_true")
    parser.add_argument("--junitxml", default="/tmp/awsign-service.xml")
    args = parser.parse_args()
    source = Path(awid.__file__).resolve().parent.parent
    environment_root = Path(sys.prefix).resolve()
    for module in (awid, awid_service):
        if not Path(module.__file__).resolve().is_relative_to(environment_root):
            raise RuntimeError("AWID must come from this service's frozen environment")
    if not args.collect_only:
        for name in (
            "APPROVAL_TEST_DATABASE_URL",
            "APPROVAL_TEST_REDIS_URL",
            "APPROVAL_TEST_COREDNS_BINARY",
        ):
            if not os.environ.get(name):
                raise RuntimeError("Missing disposable integration resource: " + name)
        asyncio.run(require_private_test_hostname())
        if os.environ.get("AWID_SERVICE_TOKEN"):
            raise RuntimeError("Native quotas must not use a trusted-service token")
    env = {
        **os.environ,
        # The native provenance control checks the actual installed package root.
        "APPROVAL_AWID_SOURCE": str(source),
        "AWID_RATE_LIMIT_BACKEND": "redis",
        # Library-mode AWID also reads its normal process settings. They name
        # the same disposable services as the explicitly supplied infrastructure.
        "AWID_DATABASE_URL": os.environ.get("APPROVAL_TEST_DATABASE_URL", ""),
        "AWID_REDIS_URL": os.environ.get("APPROVAL_TEST_REDIS_URL", ""),
    }
    command = [sys.executable, "-m", "pytest", "-q", "tests", "integration"]
    if args.collect_only:
        command.append("--collect-only")
    else:
        command.append("--junitxml=" + args.junitxml)
    return subprocess.call(command, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
