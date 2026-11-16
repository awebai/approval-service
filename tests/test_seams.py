"""Shared exact seam bytes and real signatures, not live HTTP/registry effects."""

import json
from pathlib import Path

import pytest

from approval_service.canonical import canonical
from approval_service.encoding import decode
from approval_service.seams import (
    check_activation,
    check_creation_proof,
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
    return [
        c
        for c in json.loads((ROOT / (name + "-v1.json")).read_text())["cases"]
        if c.get("phase") not in ("answer", "enrollment-request")
    ]


def trust(value):
    return (
        None
        if value is None
        else Trust(**{**value, "issuer_public_key": decode(value["issuer_public_key"])})
    )


def outcome(case, call):
    if case["accept"]:
        return call()
    with pytest.raises(Refused) as failure:
        call()
    assert failure.value.code == case["expected_error"]
    if "expected_http_status" in case:
        assert failure.value.http_status == case["expected_http_status"]


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
        if case["phase"] == "creation":
            return check_creation_proof(
                case["activation"]["creation_receipt"],
                intent=case["intent"],
                issuer_key=case["issuer_key"],
                requester=case.get("presenter", case["requester"]),
                origin=case["origin"],
                rp_id=case["rp_id"],
                now=case["now"],
                pending_trust=trust(case["trust"]),
                nonce_keys={"k1": decode(case["nonce_key"])},
            )
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
        if case["phase"] == "creation":
            assert result["credential"] == case["expected_credential"]
            assert result["grade"] == case["expected_grade"]
            assert result["digest"] == case["expected_digest"]


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


def test_published_definition_hashes_are_literal_immutable_pins():
    from approval_service.definitions import definition_ref
    from approval_service.wire import SCHEMA

    pins = json.loads((ROOT / "definition-hashes-v1.json").read_text())
    definitions = SCHEMA["x-act-definitions"].values()
    assert set(pins) == {f"{d['id']}@{d['version']}" for d in definitions}
    for item in definitions:
        expected = pins[f"{item['id']}@{item['version']}"]
        assert definition_ref(item["id"])["sha256"] == expected


def _answer_cases():
    return [
        case
        for name in (
            "requester-service",
            "issuer-service-enrollment",
            "enforcer-requester",
        )
        for case in json.loads((ROOT / (name + "-v1.json")).read_text())["cases"]
        if case.get("phase") == "answer"
    ]


@pytest.mark.parametrize("case", _answer_cases(), ids=lambda c: c["id"])
def test_service_answers_and_exact_receipt_assembly(case):
    from datetime import UTC, datetime

    from approval_service.answers import assemble_receipt, read_answer_json
    from approval_service.canonical import parse
    from approval_service.registration import check_registration

    def run():
        original = (
            decode(case["request_bytes"]) if case["request_bytes"] is not None else None
        )
        context = {
            "status": case["response_status"],
            "request_bytes": original,
            "intent": case["intent"],
            "locator": case["locator"],
        }
        answer = read_answer_json(case["kind"], decode(case["answer"]), **context)
        if case["mode"] == "assemble":
            receipt = assemble_receipt(
                original,
                answer,
                locator=case["locator"],
                status=case["response_status"],
                intent=case["intent"],
            )
            assert canonical(receipt) == decode(case["expected_receipt_bytes"])
        if "registration_binding" in case:
            registered = answer["registrations"][0]["registration"]
            checked = check_registration(
                registered,
                expected_challenge=decode(case["intent"]["intent"]["challenge"]),
                origin=case["intent"]["intent"]["origin"],
                rp_id=case["intent"]["intent"]["rp_id"],
                snapshot=None,
                now=datetime.fromtimestamp(case["registration_now"], UTC),
            )
            assert (
                checked.binding_entry()
                == case["registration_binding"]["binding"]["credentials"][0]
            )
            # The raw create response is retained byte-for-byte for the issuer.
            assert (
                registered
                == parse(decode(case["answer"]))["registrations"][0]["registration"]
            )
        return answer

    try:
        outcome(case, run)
    except Refused as error:
        raise AssertionError(error.code) from error


def _enrollment_request_cases():
    return [
        case
        for case in json.loads(
            (ROOT / "issuer-service-enrollment-v1.json").read_text()
        )["cases"]
        if case.get("phase") == "enrollment-request"
    ]


@pytest.mark.parametrize("case", _enrollment_request_cases(), ids=lambda c: c["id"])
def test_material_and_confirmation_bodies(case):
    from approval_service.answers import read_enrollment_request

    result = outcome(
        case,
        lambda: read_enrollment_request(
            case["kind"],
            case["body"],
            intent=case["intent"],
            issuer_key=case["issuer_key"],
            requester=case["requester"],
            origin=case["origin"],
            rp_id=case["rp_id"],
            now=case["now"],
        ),
    )
    if case["accept"]:
        assert result["person"] == case["expected_person"]
        assert result["state"] == "pending"
