"""Real HTTPS download and X509/CRL/JWT checks under a synthetic vendor CA."""

import hashlib
import json
import ssl
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from vendor import NOW, Vendor, certificate, signed_metadata

from approval_service.metadata import MetadataRefused
from approval_service.metadata_cache import CacheRefused, fetch_and_pin


@pytest.fixture
def transport(tmp_path, monkeypatch):
    # The actual httpx TLS stack trusts this test CA through its normal OS/env
    # interface. Neither transport nor metadata verification is replaced.
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test HTTPS CA")])
    ca = certificate(name, key, ca=True)
    server_key = ec.generate_private_key(ec.SECP256R1())
    leaf = certificate(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]),
        server_key,
        issuer=ca.subject,
        issuer_key=key,
        san="localhost",
    )
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path = tmp_path / "server.pem"
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path = tmp_path / "server.key"
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_path))
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1")
    payloads = {}
    paths = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            paths.append(self.path)
            raw = payloads[self.path]
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://localhost:{server.server_port}", payloads, paths
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def manifest(transport, *, sequence=1):
    origin, payloads, _paths = transport
    inputs = signed_metadata([Vendor().entry()], sequence=sequence)

    def artifact(name, raw):
        path = f"/{sequence}/{name}"
        payloads[path] = raw
        return {
            "url": origin + path,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "max_bytes": 1048576,
        }

    return {
        "version": 1,
        "minimum_sequence": 1,
        "artifacts": {
            "blob": artifact("blob", inputs["blob"]),
            "root": artifact("root", inputs["root_der"]),
            "crls": [artifact("crl", inputs["crls"][0])],
        },
    }


def test_download_pin_verify_then_reuse_private_disk_cache(transport, tmp_path):
    config = manifest(transport)
    cache = tmp_path / "outside-cache"
    result = fetch_and_pin(cache, manifest=config, now=NOW)
    assert result.sequence == 1 and len(result.entries) == 1
    assert len(transport[2]) == 3
    assert stat.S_IMODE(cache.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in cache.iterdir())
    # Every cache hit still verifies hashes, signature, chain and CRLs. No GET.
    assert fetch_and_pin(cache, manifest=config, now=NOW).digest == result.digest
    assert len(transport[2]) == 3
    assert json.loads((cache / "installed-sequence.json").read_text()) == {
        "sequence": 1
    }


def test_download_must_match_the_pin_before_cache_installation(transport, tmp_path):
    config = manifest(transport)
    config["artifacts"]["blob"]["sha256"] = "0" * 64
    cache = tmp_path / "outside-cache"
    with pytest.raises(CacheRefused, match="artifact_pin_mismatch"):
        fetch_and_pin(cache, manifest=config, now=NOW)
    assert not list(cache.glob("*.artifact"))
    assert not (cache / "installed-sequence.json").exists()


def test_corrupted_cached_bytes_are_not_replaced_by_a_network_fallback(
    transport, tmp_path
):
    config = manifest(transport)
    cache = tmp_path / "outside-cache"
    fetch_and_pin(cache, manifest=config, now=NOW)
    (cache / (config["artifacts"]["blob"]["sha256"] + ".artifact")).write_bytes(
        b"changed"
    )
    with pytest.raises(CacheRefused, match="artifact_pin_mismatch"):
        fetch_and_pin(cache, manifest=config, now=NOW)
    assert len(transport[2]) == 3


def test_installed_sequence_prevents_later_operator_manifest_rollback(
    transport, tmp_path
):
    cache = tmp_path / "outside-cache"
    higher = manifest(transport, sequence=2)
    assert fetch_and_pin(cache, manifest=higher, now=NOW).sequence == 2
    lower = manifest(transport, sequence=1)
    with pytest.raises(MetadataRefused):
        fetch_and_pin(cache, manifest=lower, now=NOW)
    assert json.loads((cache / "installed-sequence.json").read_text()) == {
        "sequence": 2
    }


def test_repository_cache_and_public_cache_refused_before_any_fetch(tmp_path):
    from approval_service import metadata_cache

    repository = Path(metadata_cache.__file__).resolve().parents[2]
    with pytest.raises(CacheRefused, match="cache_must_be_outside_repository"):
        fetch_and_pin(repository / "mds-cache")
    tmp_path.chmod(0o755)
    with pytest.raises(CacheRefused, match="cache_permissions"):
        fetch_and_pin(tmp_path)
