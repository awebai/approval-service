"""Actual public ID signatures/logs; independent status inputs, not a live registry."""

import json
from pathlib import Path

import pytest

from approval_service.trust import PublicObservation, derive_trust
from approval_service.verify import Refused

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
        assert (
            result.certificate.startswith("sha256:") and len(result.certificate) == 71
        )
        assert len(result.issuer_public_key) == 32
        assert result.observed_at == case["acquired_at"] - case["age_seconds"]
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
