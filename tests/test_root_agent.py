"""The root seam consumes checked SDK/lifecycle ports, never receipt trust roots."""

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from approval_service.encoding import decode
from approval_service.root_agent import (
    PersonContinuity,
    RootIdentity,
    check_root_agent_presentation,
    verify_root_agent_proof,
)
from approval_service.verify import Refused, Trust

CASES = json.loads(
    (Path(__file__).parents[1] / "vectors/root-agent-v1.json").read_text()
)["cases"]


@pytest.mark.parametrize(
    "case", [c for c in CASES if c["phase"] != "prepare-read"], ids=lambda c: c["id"]
)
def test_root_agent_shared_cases(case):
    trust = Trust(
        **{
            **case["trust"],
            "issuer_public_key": decode(case["trust"]["issuer_public_key"]),
        }
    )
    root = RootIdentity(**case["root"])

    def run():
        if case["phase"] == "historical":
            return verify_root_agent_proof(
                case["proof"],
                root=root,
                parent_person=case["parent_person"],
                trust=trust,
                continuity=PersonContinuity(**case["continuity"]),
            )
        return check_root_agent_presentation(
            case["presentation"],
            expected_request=case["request"],
            root=root,
            parent_person=case["parent_person"],
            trust=trust,
            now=case["now"],
            presenter=case["presenter"],
            required_grade=case["required_grade"],
            nonce_keys={"k1": decode(case["nonce_key"])},
            origin=case["origin"],
            audience=case["audience"],
            enforcer_kind=case["enforcer_kind"],
            owned_teams=case["owned_teams"],
            revision=case["revision"],
        )

    if not case["accept"]:
        with pytest.raises(Refused) as error:
            run()
        assert error.value.code == case["expected_error"]
    else:
        result = asdict(run())
        result["teams"] = list(result["teams"])
        assert {k: result[k] for k in case["expected"]} == case["expected"]
        if "previous_teams" in case:
            # The checked target is a full replacement, never an additive union.
            assert result["teams"] == case["expected"]["teams"]


@pytest.mark.parametrize(
    "case", [c for c in CASES if c["phase"] == "prepare-read"], ids=lambda c: c["id"]
)
def test_revision_is_read_from_enforcer_built_prepare(case):
    from approval_service.canonical import canonical
    from approval_service.seams import read_needs_human

    request = read_needs_human(
        case["needs_human"],
        requester=case["presenter"],
        origin=case["origin"],
        now=case["now"],
        status=428,
    )
    assert canonical(request) == canonical(case["request"])
    assert request["act"]["expected_revision"] == case["revision"]
