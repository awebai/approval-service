"""New organisation effects: real receipts retain the approver's home binding."""

import copy
import hmac
import json
from pathlib import Path

import pytest
from receipts import assertion, fixture

from approval_service.canonical import canonical
from approval_service.definitions import check_definition, definition_ref
from approval_service.encoding import decode, encode
from approval_service.gate import Gate, Policy
from approval_service.verify import Refused, Trust, verify_for_effect
from approval_service.wire import domain

ACTION = "organisation.human.add"
ADMIT = "organisation.person.admit"
CHANGE = "organisation.human_approval.change"
ORG = "company.example"
PERSON = "did:aw:hrCg7FYuHsoU5tqQ8r5JMUDHudr"


def policy(level="passkey", service="https://approval.example.test"):
    return Policy.from_section({"service": service, "require": {ACTION: level}})


def effect(identifier=ADMIT, *, target=None):
    world = fixture()
    r = world["request"]
    r["definition"] = definition_ref(identifier)
    r["enforcer"] = {"audience": "https://cloud.example.test"}
    r["requester"] = {
        "kind": "identity",
        "id": r["approver"],
        "key": world["status"]["identity_key"],
    }
    r["act"] = {
        "operation": identifier,
        "target": target or {"organisation": ORG, "person": PERSON, "role": "member"},
        "expected_revision": 7,
    }
    r["nonce"]["value"] = ""
    r["nonce"]["value"] = encode(
        hmac.digest(world["secret"], domain("nonce") + canonical(r), "sha256")
    )
    world["receipt"]["request_bytes"] = encode(canonical(r))
    world["receipt"]["assertion"] = assertion(
        world["private"], -7, r, world["receipt"]["assertion"]["id"]
    )
    return Gate(policy(), organisation=ORG, audience=r["enforcer"]["audience"]), {
        "request": r,
        "presentation": {
            "version": 1,
            "request_bytes": encode(canonical(r)),
            "receipt": world["receipt"],
        },
        "presenter": r["requester"],
        "trust": Trust(**world["status"]),
        "now": 1100,
        "nonce_keys": {"k1": world["secret"]},
    }


def test_admission_keeps_home_binding_and_compares_the_effect_organisation():
    gate, value = effect()
    assert value["request"]["organisation"] != ORG
    assert value["presentation"]["receipt"]["binding"]["binding"]["organisation"] != ORG
    assert gate.evaluate(ACTION, request=value["request"])[0] == 428
    result = gate.evaluate(ACTION, **value)
    assert result.person == value["trust"].person
    assert result.grade == "passkey_uv"


def test_admitting_organisation_must_equal_the_policy_organisation():
    gate, value = effect(
        target={"organisation": "other.example", "person": PERSON, "role": "member"}
    )
    with pytest.raises(Refused, match="approval_act_mismatch"):
        gate.evaluate(ACTION, **value)


def test_receipt_still_requires_the_approvers_verified_home():
    gate, value = effect()
    value["request"]["organisation"] = ORG
    with pytest.raises(Refused):
        gate.evaluate(ACTION, **value)


@pytest.mark.parametrize(
    "field,bad",
    [
        ("person", "did:aw:abc"),
        ("person", PERSON + "\nAdministrator approved"),
        ("organisation", ORG + "\n"),
        ("role", "member\nowner"),
        ("email", "private@example.test"),
        ("name", "Private name"),
    ],
)
def test_admission_fields_are_typed_identifiers_never_prose(field, bad):
    _, value = effect()
    value["request"]["act"]["target"][field] = bad
    with pytest.raises(Refused, match="definition_invalid"):
        check_definition(value["request"])


@pytest.mark.parametrize(
    "next_policy,expected",
    [
        (None, [ACTION]),
        (policy("passkey"), []),
        (policy("hardware"), []),
        (policy("passkey", "https://new.example.test"), [ACTION]),
    ],
)
def test_policy_change_approval_comes_from_the_old_policy(next_policy, expected):
    old = policy()
    new = next_policy or Policy.from_section(None)
    assert old.changes_requiring_approval(new) == tuple(expected)
    assert Policy.from_section(None).changes_requiring_approval(new) == ()
    assert policy("hardware").changes_requiring_approval(policy()) == (ACTION,)


def test_policy_change_receipt_binds_before_after_and_revision_at_old_level():
    target = {
        "organisation": ORG,
        "action": ACTION,
        "before": {"service": "https://approval.example.test", "level": "passkey"},
        "after": {"service": None, "level": "none"},
    }
    gate, value = effect(CHANGE, target=target)
    new = Policy.from_section(None)
    result = gate.evaluate_policy_change(ACTION, new, revision=7, **value)
    assert result.grade == "passkey_uv"
    for changed in ("before", "after", "revision", "action"):
        wrong = copy.deepcopy(value)
        if changed == "revision":
            revision = 8
        else:
            revision = 7
            wrong["request"]["act"]["target"][changed] = (
                "team.human.add"
                if changed == "action"
                else {"service": None, "level": "none"}
            )
            if changed == "after":
                wrong["request"]["act"]["target"][changed] = target["before"]
        with pytest.raises(Refused, match="approval_policy_mismatch"):
            gate.evaluate_policy_change(ACTION, new, revision=revision, **wrong)


def test_policy_raise_proceeds_without_any_receipt_but_cloud_must_check_available_approvers():
    gate = Gate(
        Policy.from_section(None),
        organisation=ORG,
        audience="https://cloud.example.test",
    )
    assert gate.evaluate_policy_change(ACTION, policy(), revision=0) is None


def test_policy_change_is_not_an_admission_receipt():
    gate, value = effect()
    with pytest.raises(Refused, match="approval_policy_mismatch"):
        gate.evaluate_policy_change(
            ACTION, Policy.from_section(None), revision=7, **value
        )


def test_lowering_cannot_use_the_new_weaker_level():
    old, new = policy("hardware"), policy("passkey")
    target = old.change_target(ACTION, new, organisation=ORG)
    _, value = effect(CHANGE, target=target)
    gate = Gate(
        old, organisation=ORG, audience=value["request"]["enforcer"]["audience"]
    )
    with pytest.raises(Refused, match="grade_insufficient"):
        gate.evaluate_policy_change(ACTION, new, revision=7, **value)


def test_new_actions_do_not_change_old_definition_hashes():
    assert (
        definition_ref("human.add")["sha256"]
        == "f911038c3328c857c01e4fadcd5462cb5a03f5815895888a9a7a718adbe31a86"
    )
    assert (
        definition_ref("enrollment.confirm")["sha256"]
        == "95eb9dd6c9c88c8d2aa5d47a056069b99521ebdde3b6fe991b69abeb422e7660"
    )


def _shared_cases():
    return json.loads(
        (Path(__file__).parents[1] / "vectors/organisation-actions-v1.json").read_text()
    )["cases"]


@pytest.mark.parametrize("case", _shared_cases(), ids=lambda c: c["id"])
def test_organisation_shared_bytes(case):
    def run():
        check_definition(case["request"])
        if case["phase"] != "receipt":
            return
        trust = Trust(
            **{
                **case["trust"],
                "issuer_public_key": decode(case["trust"]["issuer_public_key"]),
            }
        )
        result = verify_for_effect(
            case["receipt"],
            expected_request=case["request"],
            trust=trust,
            now=case["now"],
            required_grade=case["required_grade"],
            presenter=case["presenter"],
            nonce_keys={"k1": decode(case["nonce_key"])},
        )
        assert result.person == case["expected_person"]

    if not case["accept"]:
        with pytest.raises(Refused) as error:
            run()
        assert error.value.code == case["expected_error"]
    else:
        run()
