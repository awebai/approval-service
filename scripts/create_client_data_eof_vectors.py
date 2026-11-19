"""Real signed receipts retain the entire clientDataJSON document boundary."""

import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tests"))
from receipts import b64, canon, fixture, signed_client

target = root / "vectors/client-data-eof.json"
if target.exists():
    raise SystemExit("refuse to overwrite existing signed client-data vectors")

cases = []
for name, suffix, accept in [
    ("trailing-whitespace", b" \n\t", True),
    ("second-json-value", b" {}", False),
    ("trailing-garbage", b" garbage", False),
]:
    world = fixture()
    signed_client(world, lambda value, suffix=suffix: canon(value) + suffix)
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
