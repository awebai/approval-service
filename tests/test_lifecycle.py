"""Cross-language lifecycle vectors: original facts, exact proofs and recovery.

Previous enrollment and transition Trust are independently checked input ports.
They are never derived from the receipt's self-supplied keys.
"""

import copy
import json
from pathlib import Path

import pytest

from approval_service.encoding import decode
from approval_service.seams import check_activation
from approval_service.verify import Refused, Trust

CASES = json.loads(
    (Path(__file__).parents[1] / "vectors/enrollment-lifecycle-v1.json").read_text()
)["cases"]


def trust(value):
    return (
        None
        if value is None
        else Trust(**{**value, "issuer_public_key": decode(value["issuer_public_key"])})
    )


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_lifecycle_shared_construction(case):
    previous = copy.deepcopy(case["previous"])
    previous["trust"] = trust(previous["trust"])

    def run():
        return check_activation(
            case["activation"],
            issuer_key=case["issuer_key"],
            requester=case["requester"],
            origin=case["origin"],
            rp_id=case["rp_id"],
            now=case["now"],
            trust=trust(case["trust"]),
            previous=previous,
            transition_trust=trust(case["transition_trust"]),
        )

    if case["accept"]:
        assert run()["state"] == "active"
    else:
        with pytest.raises(Refused) as error:
            run()
        assert error.value.code == case["expected_error"]


def test_previous_creation_receipts_are_real_checked_constructions():
    from approval_service.canonical import parse
    from approval_service.verify import verify_historical

    for case in CASES:
        if case["accept"]:
            c = case["previous_creation_receipt"]
            checked = verify_historical(
                c,
                expected_request=parse(decode(c["request_bytes"])),
                trust=trust(case["previous"]["trust"]),
            )
            assert checked.person == case["previous"]["trust"]["person"]
