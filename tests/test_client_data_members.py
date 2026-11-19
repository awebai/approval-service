"""Both portable verifiers read the same original, cryptographically signed bytes."""

import json
from pathlib import Path

import pytest

from approval_service.encoding import decode
from approval_service.verify import Refused, Trust, verify_for_effect

CASES = (
    json.loads(
        (Path(__file__).parents[1] / "vectors/client-data-members.json").read_text()
    )["cases"]
    + json.loads(
        (Path(__file__).parents[1] / "vectors/client-data-eof.json").read_text()
    )["cases"]
)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_signed_client_data_members(case):
    trust = {
        **case["trust"],
        "issuer_public_key": decode(case["trust"]["issuer_public_key"]),
    }
    kwargs = {
        "expected_request": case["request"],
        "trust": Trust(**trust),
        "now": case["now"],
        "required_grade": case["required_grade"],
        "presenter": case["presenter"],
        "nonce_keys": {"k1": decode(case["nonce_key"])},
    }
    if case["accept"]:
        assert verify_for_effect(case["receipt"], **kwargs).person == trust["person"]
    else:
        with pytest.raises(Refused, match="assertion_invalid"):
            verify_for_effect(case["receipt"], **kwargs)
