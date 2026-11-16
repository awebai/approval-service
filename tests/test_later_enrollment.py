"""The later profile must not turn enrollment into a creation claim."""

import json
from pathlib import Path

import pytest

from approval_service.encoding import decode
from approval_service.seams import check_activation
from approval_service.verify import Refused, Trust

CASES = json.loads(
    (Path(__file__).parents[1] / "vectors/later-enrollment-v1.json").read_text()
)["cases"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_later_enrollment_shared(case):
    trust = Trust(
        **{
            **case["trust"],
            "issuer_public_key": decode(case["trust"]["issuer_public_key"]),
        }
    )

    def run():
        return check_activation(
            case["activation"],
            issuer_key=case["issuer_key"],
            requester=case["requester"],
            origin=case["origin"],
            rp_id=case["rp_id"],
            now=case["now"],
            trust=trust,
        )

    if case["accept"]:
        assert run()["state"] == "active"
    else:
        with pytest.raises(Refused) as error:
            run()
        assert error.value.code == case["expected_error"]
