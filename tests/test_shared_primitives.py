"""Consume the exact shared published fixtures; approval artifacts keep their codec."""

import base64
import hashlib
import json
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from approval_service.canonical import canonical
from approval_service.encoding import encode
from approval_service.seams import _signature
from approval_service.verify import Refused

DATA = Path(__file__).parents[1] / "vectors/shared-primitives"


def test_shared_fixture_bytes_match_their_owner_pin():
    manifest = json.loads((DATA / "provenance.json").read_text())
    for name, source in manifest["files"].items():
        assert (
            hashlib.sha256((DATA / name).read_bytes()).hexdigest() == source["sha256"]
        )


def test_common_canonical_and_key_order_cases():
    corpus = json.loads((DATA / "canonical-json-v1.json").read_text())
    for case in corpus["cases"] + corpus["code_point_key_order_cases"]:
        assert canonical(case["value"]).hex() == case["canonical_hex"], case["name"]


def test_common_message_payload_and_signature_bytes():
    corpus = json.loads((DATA / "message-signing-v1.json").read_text())
    for case in corpus:
        raw = canonical(case["message"])
        assert raw.decode() == case["canonical_payload"]
        signed = SigningKey(bytes.fromhex(case["signing_seed_hex"])).sign(raw).signature
        assert signed == base64.b64decode(case["signature_b64"] + "==")
        _signature(case["signing_did_key"], encode(signed), raw)


def test_common_ed25519_cases_through_the_approval_signature_adapter():
    corpus = json.loads((DATA / "signature-primitives-v1.json").read_text())
    for case in corpus["cases"]:
        if case["name"] != "raw-standard" and not case["name"].startswith("ed25519-"):
            # Message-family text spellings do not select approval's wire codec.
            continue
        raw_signature = base64.b64decode(case["signature"] + "==")
        if case["expected"]["python"] == "verified":
            _signature(case["did_key"], encode(raw_signature), case["payload"].encode())
        else:
            with pytest.raises(Refused):
                _signature(
                    case["did_key"], encode(raw_signature), case["payload"].encode()
                )
