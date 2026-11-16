"""Both binding issuers come from SDK-checked public authority, never B."""

import json
from pathlib import Path

import pytest

from approval_service.encoding import decode
from approval_service.trust import PublicObservation, derive_trust
from approval_service.verify import Refused, verify_for_effect

CASES = json.loads(
    (Path(__file__).parents[1] / "vectors/enrollment-authority-v1.json").read_text()
)["cases"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_checked_namespace_controller_is_a_binding_candidate(case):
    c = case
    trust = derive_trust(
        c["chain"],
        person=c["person"],
        identity_key=c["identity_key"],
        organisation=c["organisation"],
        observation=PublicObservation(
            c["status"], c["namespace_authority"], c["acquired_at"], c["age_seconds"]
        ),
        now=c["now"],
    )

    def run():
        return verify_for_effect(
            c["receipt"],
            expected_request=c["request"],
            trust=trust,
            now=c["now"],
            required_grade="passkey_uv",
            presenter=c["request"]["requester"],
            nonce_keys={"k1": decode(c["nonce_key"])},
        )

    if c["accept"]:
        assert run().person == c["person"]
        assert trust.namespace_issuer == c["expected_namespace_issuer"]
    else:
        with pytest.raises(Refused) as error:
            run()
        assert error.value.code == c["expected_error"]
