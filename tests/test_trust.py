"""Actual public ID signatures/logs; independent status inputs, not a live registry."""

import json
from pathlib import Path

import pytest

from approval_service.encoding import encode
from approval_service.trust import PublicObservation, derive_trust
from approval_service.verify import Refused, verify_historical

CASES = json.loads((Path(__file__).parents[1] / "vectors/trust.json").read_text())[
    "cases"
]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_public_chain_and_original_status_age_to_trust(case):
    observation = PublicObservation(
        case["status"],
        case["namespace_authority"],
        case["acquired_at"],
        case["age_seconds"],
    )

    def check():
        return derive_trust(
            case["chain"],
            person=case["person"],
            identity_key=case["identity_key"],
            organisation=case["organisation"],
            observation=observation,
            now=case["now"],
        )

    if not case["accept"]:
        with pytest.raises(Refused):
            check()
    else:
        result = check()
        assert result.person == case["person"]
        assert result.organisation == case["organisation"]
        assert result.identity_key == case["identity_key"]
        assert result.certificate == case["expected_certificate"]
        assert result.issuer == case["expected_issuer"]
        assert encode(result.issuer_public_key) == case["expected_issuer_key"]
        assert result.observed_at == case["acquired_at"] - case["age_seconds"]
        if "offered_receipt" in case:
            assert case["receipt_accept"] is False
            with pytest.raises(Refused, match="binding_mismatch"):
                verify_historical(
                    case["offered_receipt"],
                    expected_request=case["offered_request"],
                    trust=result,
                )
        # The same observation does not become younger when used again.
        with pytest.raises(Refused):
            derive_trust(
                case["chain"],
                person=case["person"],
                identity_key=case["identity_key"],
                organisation=case["organisation"],
                observation=observation,
                now=case["acquired_at"] + 61,
            )
