"""Native main-AWID certificate admission. Requires an isolated PG/Redis placement.

Import main's actual awid/src via PYTHONPATH. SQL creates only the disposable
team projection; real signed HTTP registers/revokes certificates and reads status.
No domain verifier, auth, status response, rate limiter or HTTP client is replaced.
"""

from __future__ import annotations

import asyncio
import base64
import os
import socket
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import uvicorn
from awid.db_config import build_database_config
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, sign_message
from awid_service.db import AwidDatabaseInfra
from awid_service.main import create_app
from pgdbm import AsyncDatabaseManager
from redis.asyncio import Redis

from approval_service.requester import read_team_member
from approval_service.verify import Refused


@asynccontextmanager
async def listener(app, *, config=None):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    server = uvicorn.Server(
        config
        or uvicorn.Config(app, log_level="warning", access_log=False, lifespan="on")
    )
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                    raise AssertionError("registry did not start")
                await asyncio.sleep(0.01)
        host = "localhost" if server.config.is_ssl else "127.0.0.1"
        scheme = "https" if server.config.is_ssl else "http"
        yield f"{scheme}://{host}:{sock.getsockname()[1]}", server
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, 10)
        finally:
            sock.close()


@pytest.mark.asyncio
async def test_main_public_exact_status_admits_private_local_and_global_members_then_refuses_revocation():
    import awid.registry
    import awid_service

    source = Path(os.environ["APPROVAL_AWID_SOURCE"]).resolve()
    assert Path(awid.registry.__file__).resolve().is_relative_to(source)
    assert Path(awid_service.__file__).resolve().is_relative_to(source)
    assert callable(
        getattr(RegistryClient, "get_team_certificate_status_fresh", None)
    ), "requires actual post-adcl.2 main SDK"
    assert os.environ.get("AWID_RATE_LIMIT_BACKEND", "redis") == "redis"
    assert not os.environ.get("AWID_SERVICE_TOKEN"), "no trusted-service quota bypass"
    config = build_database_config(
        connection_string=os.environ["APPROVAL_TEST_DATABASE_URL"],
        min_connections=2,
        max_connections=5,
    )
    pool = await AsyncDatabaseManager.create_shared_pool(config)
    schema = "approval_registry_" + uuid4().hex
    infra = AwidDatabaseInfra(schema=schema)
    domain = "customer.example.test"
    name = "private-" + uuid4().hex[:12]
    team_id = name + ":" + domain
    controller, public = generate_keypair()
    team_key = did_from_public_key(public)
    redis = Redis.from_url(os.environ["APPROVAL_TEST_REDIS_URL"], decode_responses=True)
    try:
        await redis.ping()
        await infra.initialize(shared_pool=pool)
        manager = infra.get_manager("aweb")
        await manager.execute(
            "INSERT INTO {{tables.teams}} (domain,name,team_did_key,visibility) VALUES($1,$2,$3,'private')",
            domain,
            name,
            team_key,
        )
        app = create_app(db_infra=infra, redis=redis)
        async with listener(app) as (origin, _server):
            assert "Redis" in type(app.state.rate_limiter).__name__
            registry = RegistryClient(registry_url=origin)
            async with httpx.AsyncClient() as observer:
                private = await observer.get(
                    origin + f"/v1/namespaces/{domain}/teams/{name}"
                )
                assert private.status_code == 403
            for scope in ("local", "global"):
                private_key, public_key = generate_keypair()
                did = did_from_public_key(public_key)
                stable = None
                if scope == "global":
                    await registry.register_did(did, private_key)
                    stable = stable_id_from_did_key(did)
                cert_id = str(uuid4())
                cert = {
                    "version": 1,
                    "certificate_id": cert_id,
                    "team_id": team_id,
                    "team_did_key": team_key,
                    "member_did_key": did,
                    "alias": scope,
                    "identity_scope": scope,
                }
                if stable:
                    cert["member_did_aw"] = stable
                cert["signature"] = sign_message(controller, canonical_json_bytes(cert))
                header = base64.b64encode(canonical_json_bytes(cert)).decode()
                await registry.register_team_certificate(
                    domain,
                    name,
                    team_controller_signing_key=controller,
                    certificate_id=cert_id,
                    member_did_key=did,
                    member_did_aw=stable,
                    member_address=None,
                    alias=scope,
                    identity_scope=scope,
                    certificate=header,
                )
                descriptor = {
                    "kind": "team_member",
                    "team_id": team_id,
                    "certificate_id": cert_id,
                    "key": did,
                }
                result = await read_team_member(
                    registry, descriptor, organisation=domain, certificate_header=header
                )
                assert result.descriptor_bytes == canonical_json_bytes(descriptor)
                assert result.key == did
                with pytest.raises(Refused, match="namespace_mismatch"):
                    await read_team_member(
                        registry,
                        descriptor,
                        organisation="sibling.example.test",
                        certificate_header=header,
                    )
                await registry.revoke_team_certificate(
                    domain,
                    name,
                    team_controller_signing_key=controller,
                    certificate_id=cert_id,
                )
                with pytest.raises(Refused, match="inactive"):
                    await read_team_member(
                        registry,
                        descriptor,
                        organisation=domain,
                        certificate_header=header,
                    )
            missing = {**descriptor, "certificate_id": str(uuid4())}
            with pytest.raises(Refused):
                await read_team_member(
                    registry, missing, organisation=domain, certificate_header=header
                )
    finally:
        await redis.aclose()
        cleanup_manager = AsyncDatabaseManager(pool=pool, schema=schema)
        await cleanup_manager.execute('DROP SCHEMA IF EXISTS "' + schema + '" CASCADE')
        await infra.close()
        await pool.close()
