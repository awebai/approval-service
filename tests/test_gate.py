"""Organisation policy and the reusable gate, with genuine signed seam proofs."""

import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest

from approval_service.encoding import decode
from approval_service.gate import Gate, Policy
from approval_service.verify import Refused, Trust

ACTION = "organisation.human.add"
CASE = next(
    case
    for case in json.loads(
        (Path(__file__).parents[1] / "vectors/enforcer-requester-v1.json").read_text()
    )["cases"]
    if case["id"] == "presentation-exact-caller"
)


def configured(level="passkey"):
    return Policy.from_section({"service": CASE["origin"], "require": {ACTION: level}})


def gate(policy=None, **kwargs):
    return Gate(
        policy or configured(),
        organisation=CASE["request"]["organisation"],
        audience=CASE["request"]["enforcer"]["audience"],
        **kwargs,
    )


def inputs():
    return {
        "request": copy.deepcopy(CASE["request"]),
        "presentation": copy.deepcopy(CASE["presentation"]),
        "presenter": copy.deepcopy(CASE["presenter"]),
        "trust": Trust(
            **{
                **CASE["trust"],
                "issuer_public_key": decode(CASE["trust"]["issuer_public_key"]),
            }
        ),
        "now": CASE["now"],
        "nonce_keys": {"k1": decode(CASE["nonce_key"])},
    }


def test_missing_and_empty_policy_proceed_without_receipt_or_trust():
    for section in (None, {}, {"require": {}}):
        assert gate(Policy.from_section(section)).evaluate(ACTION) is None


@pytest.mark.parametrize(
    "section",
    [
        {"service": "http://insecure.test", "require": {ACTION: "passkey"}},
        {"require": {ACTION: "passkey"}},
        {"service": CASE["origin"], "require": {ACTION: "email"}},
        {"service": CASE["origin"], "require": {ACTION: "unknown"}},
        {"service": CASE["origin"], "require": {"invented.action": "passkey"}},
        {"service": CASE["origin"], "require": {ACTION: None}},
        {"service": CASE["origin"], "require": [], "extra": True},
        {"enabled": False},
        [],
    ],
)
def test_invalid_configuration_never_becomes_off(section):
    with pytest.raises(Refused, match="human_approval_invalid"):
        Policy.from_section(section)


def test_unknown_declared_action_refuses_even_without_requirements():
    with pytest.raises(Refused, match="approval_action_unknown"):
        gate(Policy.from_section(None)).evaluate("invented.action")


def test_existing_packet_and_checked_bindings_are_unchanged():
    assert gate().evaluate(ACTION, request=CASE["request"]) == (
        428,
        CASE["needs_human"],
    )
    checked = gate().evaluate(ACTION, **inputs())
    assert checked.digest == CASE["expected_digest"]
    assert checked.grade == "passkey_uv"


def test_current_policy_raise_refuses_a_genuine_weaker_receipt():
    with pytest.raises(Refused, match="grade_insufficient"):
        gate(configured("hardware")).evaluate(ACTION, **inputs())


@pytest.mark.parametrize(
    "fault", ["organisation", "audience", "requester", "target", "expired", "stale"]
)
def test_effect_boundary_checks_current_authority_and_bindings(fault):
    value = inputs()
    if fault == "organisation":
        value["request"]["organisation"] = "elsewhere.test"
    elif fault == "audience":
        value["request"]["enforcer"]["audience"] = "https://other.test"
    elif fault == "requester":
        value["presenter"]["key"] = "other"
    elif fault == "target":
        value["request"]["act"]["target"]["person"] = "other"
    elif fault == "expired":
        value["now"] = value["request"]["deadline"]
    else:
        value["trust"] = replace(value["trust"], observed_at=value["now"] - 61)
    with pytest.raises(Refused):
        gate().evaluate(ACTION, **value)


def test_policy_does_not_follow_mutation_of_the_loaded_mapping():
    value = {"service": CASE["origin"], "require": {ACTION: "hardware"}}
    policy = Policy.from_section(value)
    value["require"].clear()
    with pytest.raises(Refused, match="grade_insufficient"):
        gate(policy).evaluate(ACTION, **inputs())


@pytest.mark.parametrize("field", ["act", "definition"])
@pytest.mark.parametrize("bad", [None, [], "not-an-object"])
def test_malformed_expected_request_is_a_named_refusal(field, bad):
    value = copy.deepcopy(CASE["request"])
    value[field] = bad
    with pytest.raises(Refused):
        gate().evaluate(ACTION, request=value)
