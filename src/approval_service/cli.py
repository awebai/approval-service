"""Process entry point. Database migration is an explicit operator command."""

import argparse
import asyncio
import json
import logging
import os
import time
from enum import StrEnum
from pathlib import Path

logger = logging.getLogger(__name__)

import uvicorn
from awid.registry import RegistryClient

from .binding_refresh import BindingRefresher
from .grading import EnrollmentGrading
from .http import create_app
from .public import PublicReader
from .store import Store


AUDIT_RETRY = "Next: run awsign audit-binding-refreshes --after 0 --limit 100."


class OperatorCommand(StrEnum):
    MIGRATE = "migrate"
    SERVE = "serve"
    AUDIT_BINDING_REFRESHES = "audit-binding-refreshes"


def server_config(app, *, bind, port, trusted_proxy_ips):
    return uvicorn.Config(
        app,
        host=bind,
        port=port,
        access_log=False,
        log_level="info",
        proxy_headers=True,
        forwarded_allow_ips=trusted_proxy_ips,
    )


async def operate(args):
    store = Store(
        os.environ["AWSIGN_DATABASE_URL"],
        schema=os.environ.get("AWSIGN_DATABASE_SCHEMA", "awsign"),
        min_connections=1,
        max_connections=int(os.environ.get("AWSIGN_DATABASE_POOL_MAX", "10")),
    )
    await store.connect()
    try:
        if args.command == OperatorCommand.MIGRATE:
            await store.migrate()
            return
        # Refuse startup without the current schema; a server never applies it.
        await store.require_current_schema()
        if args.command == OperatorCommand.AUDIT_BINDING_REFRESHES:
            rows = await BindingRefresher(store).audit(
                after=0 if args.after is None else args.after,
                limit=100 if args.limit is None else args.limit,
            )
            print(json.dumps(rows))
            return
        origin = os.environ.get("AWSIGN_ORIGIN", "https://awsign.com")
        rp_id = os.environ.get("AWSIGN_RP_ID", "awsign.com")
        grading = await asyncio.to_thread(
            EnrollmentGrading.load,
            mode=os.environ.get("AWSIGN_GRADING", "hardware"),
            manifest_path=os.environ.get("AWSIGN_MDS_MANIFEST"),
            cache_dir=Path(
                os.environ.get(
                    "AWSIGN_MDS_CACHE", str(Path.home() / ".cache/awsign/mds")
                )
            ),
        )
        registry = RegistryClient(
            registry_url=os.environ.get("AWID_REGISTRY_URL", "https://api.awid.ai")
        )
        if not callable(getattr(registry, "get_team_certificate_status_fresh", None)):
            raise TypeError(
                "This AWID SDK lacks the public exact-certificate status reader; install the post-adcl.2 AWID release"
            )
        app = create_app(
            store,
            public=PublicReader(registry),
            origin=origin,
            rp_id=rp_id,
            grading=grading,
            requests_per_ip=int(
                os.environ.get("AWSIGN_REQUESTS_PER_IP_PER_MINUTE", "600")
            ),
        )

        async def cleanup():
            while True:
                await asyncio.sleep(30)
                try:
                    now = int(time.time())
                    await store.cleanup(now)
                    await app.state.enrollments.cleanup(now)
                except Exception as error:  # noqa: BLE001 — keep the bounded expiry worker alive, log no parameters.
                    logger.error(
                        "awsign expiry cleanup failed (%s)", type(error).__name__
                    )

        worker = asyncio.create_task(cleanup())
        try:
            await uvicorn.Server(
                server_config(
                    app,
                    bind=args.bind,
                    port=args.port,
                    trusted_proxy_ips=os.environ.get(
                        "AWSIGN_TRUSTED_PROXY_IPS", "127.0.0.1,::1"
                    ),
                )
            ).serve()
        finally:
            worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)
    finally:
        await store.close()


def main():
    parser = argparse.ArgumentParser(prog="awsign")
    parser.add_argument("command", type=OperatorCommand, choices=list(OperatorCommand))
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8030)
    parser.add_argument(
        "--after", type=int, help="audit-binding-refreshes: last audit ID"
    )
    parser.add_argument(
        "--limit", type=int, help="audit-binding-refreshes: maximum rows (1..1000)"
    )
    args = parser.parse_args()
    if args.command is not OperatorCommand.AUDIT_BINDING_REFRESHES and (
        args.after is not None or args.limit is not None
    ):
        parser.error(
            f"--after and --limit belong to audit-binding-refreshes. {AUDIT_RETRY}"
        )
    if args.after is not None and args.after < 0:
        parser.error(f"--after must be nonnegative. {AUDIT_RETRY}")
    if args.limit is not None and not 1 <= args.limit <= 1000:
        parser.error(f"--limit must be between 1 and 1000. {AUDIT_RETRY}")
    asyncio.run(operate(args))
