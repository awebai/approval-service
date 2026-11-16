"""Shared exact seam bytes and real signatures, not live HTTP/registry effects."""

import json
from pathlib import Path

import pytest

from approval_service.canonical import canonical
from approval_service.encoding import decode
from approval_service.seams import (
    check_activation,
    check_enrollment_intent,
    check_http,
    check_presentation,
    http_authorization,
    make_needs_human,
    read_needs_human,
)
from approval_service.verify import Refused, Trust

ROOT = Path(__file__).parents[1] / "vectors"


def corpus(name):
    return json.loads((ROOT / (name + "-v1.json")).read_text())["cases"]


def trust(value):
    return (
        None
        if value is None
        else Trust(**{**value, "issuer_public_key": decode(value["issuer_public_key"])})
    )


def outcome(case, call):
    if case["accept"]:
        return call()
    with pytest.raises(Refused):
        call()


@pytest.mark.parametrize("case", corpus("requester-service"), ids=lambda c: c["id"])
def test_requester_service_shared_bytes(case):
    result = outcome(
        case,
        lambda: check_http(
            case["authorization"],
            decode(case["body"]),
            requester=case["expected_requester"],
            origin=case["origin"],
            method=case["method"],
            path=case["path"],
            purpose=case["purpose"],
            now=case["now"],
        ),
    )
    if case["accept"]:
        assert result["key"] == case["expected_requester_key"]
        assert result["preimage"] == decode(case["expected_preimage"])
        assert (
            http_authorization(
                decode(case["body"]),
                seed=decode(case["test_signing_seed"]),
                requester=case["expected_requester"],
                origin=case["origin"],
                purpose=case["purpose"],
                issued_at=case["signed_at"],
            )
            == case["authorization"]
        )


@pytest.mark.parametrize(
    "case", corpus("issuer-service-enrollment"), ids=lambda c: c["id"]
)
def test_issuer_service_enrollment_shared_construction(case):
    def run():
        checked = check_enrollment_intent(
            case["intent"],
            issuer_key=case["issuer_key"],
            requester=case["requester"],
            origin=case["origin"],
            rp_id=case["rp_id"],
            now=case["now"],
        )
        assert checked["locator"] == case["expected_locator"]
        assert checked["preimage"] == decode(case["expected_intent_preimage"])
        if case["phase"] == "activation":
            return check_activation(
                case["activation"],
                issuer_key=case["issuer_key"],
                requester=case["requester"],
                origin=case["origin"],
                rp_id=case["rp_id"],
                now=case["now"],
                trust=trust(case["trust"]),
            )
        return checked

    result = outcome(case, run)
    if case["accept"]:
        assert result["person"] == case["expected_person"]
        assert result["state"] == case["expected_state"]


@pytest.mark.parametrize("case", corpus("enforcer-requester"), ids=lambda c: c["id"])
def test_enforcer_requester_shared_exchange(case):
    def run():
        if case["phase"] == "needs_human":
            result = read_needs_human(
                case["needs_human"],
                requester=case["presenter"],
                origin=case["origin"],
                now=case["now"],
                status=case["http_status"],
            )
            assert canonical(result) == canonical(case["request"])
            status, body = make_needs_human(result, origin=case["origin"])
            assert status == case["http_status"]
            assert canonical(body) == canonical(case["needs_human"])
            return case["needs_human"]["digest"]
        return check_presentation(
            case["presentation"],
            expected_request=case["request"],
            presenter=case["presenter"],
            origin=case["origin"],
            now=case["now"],
            trust=trust(case["trust"]),
            required_grade=case["required_grade"],
            nonce_keys={"k1": decode(case["nonce_key"])},
        ).digest

    result = outcome(case, run)
    if case["accept"]:
        assert result == case["expected_digest"]
        assert case["request"]["approver"] == case["expected_approver_person"]
        assert (
            case["request"]["act"]["target"]["person"] == case["expected_target_person"]
        )
        assert case["expected_approver_person"] != case["expected_target_person"]
