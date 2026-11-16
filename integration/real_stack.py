"""Real disposable AWID, authoritative CoreDNS and local TLS transports.

DNS uses the resolver's supported configuration, not a verifier replacement.
No production namespace, service token, DNS bypass or mocked read is used.
"""

from __future__ import annotations

import asyncio
import os
import socket
import ssl
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

import dns.asyncresolver
import uvicorn
from awid.db_config import build_database_config
from awid.did import did_from_public_key
from awid.registry import RegistryClient
from awid_service.db import AwidDatabaseInfra
from awid_service.main import create_app
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pgdbm import AsyncDatabaseManager
from redis.asyncio import Redis

from .test_requester_registry import listener


@asynccontextmanager
async def dns_zone(directory, controllers):
    binary = Path(os.environ["APPROVAL_TEST_COREDNS_BINARY"]).resolve()
    version = await asyncio.to_thread(
        subprocess.check_output, [str(binary), "-version"], text=True
    )
    assert version.startswith("CoreDNS-1.12.0")
    directory.mkdir()
    zone = directory / "example.test.zone"
    zone.write_text(
        "$ORIGIN example.test.\n@ 1 IN SOA ns.example.test. hostmaster.example.test. (1 60 60 60 1)\n@ 1 IN NS ns.example.test.\nns 1 IN A 127.0.0.1\n"
        + "".join(
            f'_awid.{domain}. 1 IN TXT "awid=v1; controller={did_from_public_key(public)};"\n'
            for domain, (_private, public) in controllers.items()
        )
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    corefile = directory / "Corefile"
    corefile.write_text(
        f".:{port} {{\n bind 127.0.0.1\n file {zone} example.test\n log\n errors\n}}\n"
    )
    # Configure the real process resolver; DNS verification itself is unchanged.
    resolver = dns.asyncresolver.get_default_resolver()
    saved = (resolver.nameservers, resolver.port, resolver.timeout, resolver.lifetime)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = port
    resolver.timeout = 1
    resolver.lifetime = 2
    log = (directory / "dns.log").open("wb")
    process = await asyncio.create_subprocess_exec(
        str(binary), "-conf", str(corefile), stdout=log, stderr=log
    )
    try:
        async with asyncio.timeout(5):
            while True:
                if process.returncode is not None:
                    raise RuntimeError("CoreDNS refused the private zone")
                try:
                    answers = await resolver.resolve(
                        "_awid." + next(iter(controllers)), "TXT"
                    )
                    assert answers
                    break
                except dns.exception.DNSException:
                    await asyncio.sleep(0.025)
        yield
    finally:
        resolver.nameservers, resolver.port, resolver.timeout, resolver.lifetime = saved
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 5)
            except TimeoutError:
                process.kill()
                await process.wait()
        log.close()


@asynccontextmanager
async def registry_stack(directory, controllers):
    assert not os.environ.get("AWID_SKIP_DNS_VERIFY")
    assert not os.environ.get("AWID_SERVICE_TOKEN")
    config = build_database_config(
        connection_string=os.environ["APPROVAL_TEST_DATABASE_URL"],
        min_connections=1,
        max_connections=5,
    )
    pool = await AsyncDatabaseManager.create_shared_pool(config)
    schema = "approval_http_registry_" + uuid4().hex
    infra = AwidDatabaseInfra(schema=schema)
    redis = Redis.from_url(os.environ["APPROVAL_TEST_REDIS_URL"], decode_responses=True)
    try:
        await redis.ping()
        await infra.initialize(shared_pool=pool)
        app = create_app(db_infra=infra, redis=redis)
        async with (
            dns_zone(directory / "dns", controllers),
            listener(app, registry_public_origin=True) as (origin, _server),
        ):
            registry = RegistryClient(registry_url=origin)
            assert registry._domain_verifier is None
            for domain, (private, public) in controllers.items():
                await registry.register_namespace(
                    domain, did_from_public_key(public), private
                )
            yield registry
    finally:
        await redis.aclose()
        manager = AsyncDatabaseManager(pool=pool, schema=schema)
        await manager.execute('DROP SCHEMA "' + schema + '" CASCADE')
        await infra.close()
        await pool.close()


def tls_config(app, directory):
    """Actual HTTPS for secure session cookies; the browser journey pins its RP."""
    from vendor import Vendor, certificate

    vendor = Vendor()
    key = vendor.batch_key
    leaf = certificate(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost")]),
        key,
        issuer=vendor.root.subject,
        issuer_key=vendor.root_key,
        san="localhost",
    )
    certfile = directory / "tls-cert.pem"
    keyfile = directory / "tls-key.pem"
    certfile.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    keyfile.chmod(0o600)
    context = ssl.create_default_context(
        cadata=vendor.root.public_bytes(serialization.Encoding.PEM).decode()
    )
    return uvicorn.Config(
        app,
        log_level="warning",
        access_log=False,
        ssl_certfile=str(certfile),
        ssl_keyfile=str(keyfile),
    ), context
