"""Real HTTPS download and X509/CRL/JWT checks under a synthetic vendor CA."""

import ssl
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from vendor import certificate


@pytest.fixture
def transport(tmp_path, monkeypatch):
    # The actual httpx TLS stack trusts this test CA through its normal OS/env
    # interface. Neither transport nor metadata verification is replaced.
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test HTTPS CA")])
    now = datetime.now(UTC)
    ca = certificate(name, key, ca=True, now=now)
    server_key = ec.generate_private_key(ec.SECP256R1())
    leaf = certificate(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]),
        server_key,
        issuer=ca.subject,
        issuer_key=key,
        san="localhost",
        now=now,
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
            raw = payloads.get(self.path)
            if raw is None:
                self.send_response(404)
                self.end_headers()
                return
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
