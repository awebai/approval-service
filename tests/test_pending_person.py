"""A pending person's possession is scoped to their exact enrollment only."""

import json
from pathlib import Path

import pytest

from approval_service.requester import KeyObservation, admit_enrollment_target
from approval_service.verify import Refused

CASES = json.loads(
    (Path(__file__).parents[1] / "vectors/pending-person-v1.json").read_text()
)["cases"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_pending_person_scope(case):
    c = case

    def run():
        return admit_enrollment_target(
            c["intent"],
            c["descriptor"],
            issuer_key=c["issuer_key"],
            observation=KeyObservation(**c["observation"]),
            origin=c["origin"],
            rp_id=c["rp_id"],
            now=c["now"],
            purpose=c["purpose"],
        )

    if c["accept"]:
        assert run().key == c["descriptor"]["key"]
    else:
        with pytest.raises(Refused) as error:
            run()
        assert error.value.code == c["expected_error"]
