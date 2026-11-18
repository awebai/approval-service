"""Freeze real signed receipts that distinguish exact client-data member names."""

import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tests"))
from receipts import b64, canon, fixture, signed_client

target = root / "vectors/client-data-members.json"
if target.exists():
    raise SystemExit("refuse to overwrite frozen client-data vectors")

cases = []
for name, changes, accept in [
    ("ordinary", {}, True),
    (
        "cross-origin-cannot-be-overridden",
        {"crossOrigin": True, "CROSSORIGIN": False},
        False,
    ),
    (
        "wrong-origin-cannot-be-overridden",
        {"origin": "https://other.example", "Origin": "https://approval.example.test"},
        False,
    ),
    (
        "wrong-type-cannot-be-overridden",
        {"type": "webauthn.create", "Type": "webauthn.get"},
        False,
    ),
    ("unknown-origin-case-is-ignored", {"Origin": "https://other.example"}, True),
    ("unknown-cross-origin-case-is-ignored", {"CROSSORIGIN": True}, True),
    (
        "unknown-challenge-case-is-ignored",
        {"Challenge": b64(b"different challenge")},
        True,
    ),
]:
    world = fixture()
    signed_client(
        world,
        lambda original, changes=changes: json.dumps(
            {**original, **changes}, separators=(",", ":")
        ).encode(),
    )
    cases.append(
        {
            "id": name,
            "receipt": world["receipt"],
            "request": world["request"],
            "trust": {
                **world["status"],
                "issuer_public_key": b64(world["status"]["issuer_public_key"]),
            },
            "nonce_key": b64(world["secret"]),
            "now": 1100,
            "required_grade": "passkey_uv",
            "presenter": world["request"]["requester"],
            "accept": accept,
        }
    )

target.write_bytes(canon({"cases": cases}) + b"\n")
