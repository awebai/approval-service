"""Real software-authenticator assertions; not hardware/registry qualification."""

import base64
import copy
import hashlib
import hmac
import json

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

PREFIX = b"aweb.human-approval-request/1\n"
BINDING_PREFIX = b"aweb.human-enrollment-binding/1\n"
NONCE_PREFIX = b"aweb.human-approval-nonce/1\n"


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def canon(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode()


def fixture(algorithm=-7):
    issuer = ed25519.Ed25519PrivateKey.generate()
    if algorithm == -7:
        private = ec.generate_private_key(ec.SECP256R1())
        n = private.public_key().public_numbers()
        cose = {
            1: 2,
            3: -7,
            -1: 1,
            -2: n.x.to_bytes(32, "big"),
            -3: n.y.to_bytes(32, "big"),
        }
    elif algorithm == -8:
        private = ed25519.Ed25519PrivateKey.generate()
        cose = {1: 1, 3: -8, -1: 6, -2: private.public_key().public_bytes_raw()}
    else:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        n = private.public_key().public_numbers()
        cose = {1: 3, 3: -257, -1: n.n.to_bytes(256, "big"), -2: n.e.to_bytes(3, "big")}
    credential = {
        "id": b64(b"credential-for-person-p"),
        "key": b64(cbor2.dumps(cose)),
        "algorithm": algorithm,
        "grade": "passkey_uv",
        "snapshot": None,
        "grade_policy": "uv-v1",
    }
    binding = {
        "version": 1,
        "organisation": "customer.example",
        "person": "did:aw:person-p",
        "certificate": "sha256:" + "a" * 64,
        "identity_key": "identity-key-before",
        "issuer": "issuer-key",
        "origin": "https://approval.example.test",
        "rp_id": "approval.example.test",
        "credentials": [credential],
    }
    request = {
        "version": 1,
        "purpose": "act_approval",
        "organisation": "customer.example",
        "approver": "did:aw:person-p",
        "requester": {
            "kind": "identity",
            "id": "did:aw:agent-a",
            "key": "requester-key",
        },
        "enforcer": {"audience": "https://secrets.example.test"},
        "definition": {"id": "secrets.read-write", "version": 1, "sha256": "b" * 64},
        "act": {
            "resource": "vault/key",
            "rights": ["read", "write"],
            "expected_revision": 1,
        },
        "not_before": 1000,
        "deadline": 1300,
        "nonce": {"kid": "k1", "value": ""},
    }
    secret = b"enforcer-only-secret-32-bytes-long"
    request["nonce"]["value"] = b64(
        hmac.digest(secret, NONCE_PREFIX + canon(request), "sha256")
    )
    signed = {
        "binding": binding,
        "signature": b64(issuer.sign(BINDING_PREFIX + canon(binding))),
    }
    receipt = {
        "version": 1,
        "request_bytes": b64(canon(request)),
        "binding": signed,
        "id_chain": [],
        "assertion": assertion(private, algorithm, request, credential["id"]),
    }
    status = {
        "person": binding["person"],
        "organisation": binding["organisation"],
        "identity_key": binding["identity_key"],
        "certificate": binding["certificate"],
        "issuer": binding["issuer"],
        "issuer_public_key": issuer.public_key().public_bytes_raw(),
        "observed_at": 1100,
    }
    return {
        "request": request,
        "receipt": receipt,
        "status": status,
        "secret": secret,
        "issuer": issuer,
        "private": private,
        "algorithm": algorithm,
    }


def assertion(
    private,
    algorithm,
    request,
    credential_id,
    *,
    uv=True,
    origin="https://approval.example.test",
):
    challenge = hashlib.sha256(PREFIX + canon(request)).digest()
    client = canon(
        {
            "type": "webauthn.get",
            "challenge": b64(challenge),
            "origin": origin,
            "crossOrigin": False,
        }
    )
    auth = (
        hashlib.sha256(b"approval.example.test").digest()
        + bytes([5 if uv else 1])
        + b"\0" * 4
    )
    signed = auth + hashlib.sha256(client).digest()
    if algorithm == -7:
        sig = private.sign(signed, ec.ECDSA(hashes.SHA256()))
    elif algorithm == -8:
        sig = private.sign(signed)
    else:
        sig = private.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    return {
        "id": credential_id,
        "client_data_json": b64(client),
        "authenticator_data": b64(auth),
        "signature": b64(sig),
    }


def resign(world, binding):
    return {
        "binding": copy.deepcopy(binding),
        "signature": b64(world["issuer"].sign(BINDING_PREFIX + canon(binding))),
    }


def signed_client(world, make_client):
    """Sign exact caller-chosen client bytes, including adversarial encodings."""
    challenge=hashlib.sha256(PREFIX+canon(world["request"])).digest()
    client=make_client({"type":"webauthn.get","challenge":b64(challenge),"origin":world["receipt"]["binding"]["binding"]["origin"],"crossOrigin":False})
    auth=hashlib.sha256(b"approval.example.test").digest()+bytes([5])+b"\0"*4
    sig=world["private"].sign(auth+hashlib.sha256(client).digest(),ec.ECDSA(hashes.SHA256()))
    world["receipt"]["assertion"]={"id":world["receipt"]["assertion"]["id"],"client_data_json":b64(client),"authenticator_data":b64(auth),"signature":b64(sig)}
