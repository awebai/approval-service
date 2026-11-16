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


def test_statement_and_optional_raw_proof_have_independent_results():
    from approval_service.statements import verify_enrollment_evidence

    case = CASES[0]
    trust = Trust(
        **{
            **case["trust"],
            "issuer_public_key": decode(case["trust"]["issuer_public_key"]),
        }
    )
    statement = case["activation"]["evidence"]
    claimed = verify_enrollment_evidence(statement, trust=trust)
    assert claimed["proof_status"] == "not_presented"
    assert claimed["since"] == statement["evidence"]["enrollment"]["since"]
    checked = verify_enrollment_evidence(
        statement, receipt=case["activation"]["confirmation_receipt"], trust=trust
    )
    assert checked["proof_status"] == "checked"
    assert checked["grade"] == "passkey_uv"
    assert "creation" not in checked


def test_statement_definition_includes_the_schema_and_issuer_time_claim():
    import hashlib

    from approval_service.canonical import canonical
    from approval_service.statements import statement_definition

    definition = statement_definition("human_enrolled_later")
    pins = json.loads(
        (Path(__file__).parents[1] / "vectors/statement-hashes-v1.json").read_text()
    )
    assert (
        hashlib.sha256(canonical(definition)).hexdigest()
        == pins["human.enrolled_later@1"]
    )
    assert "not a registry-witnessed time" in definition["meaning"]


def test_other_confirmation_neighbors_are_genuinely_signed_proofs():
    from approval_service.canonical import parse
    from approval_service.verify import verify_historical

    for case in CASES:
        if "confirmation_trust" in case:
            value = case["confirmation_trust"]
            trust = Trust(
                **{**value, "issuer_public_key": decode(value["issuer_public_key"])}
            )
            receipt = case["activation"]["confirmation_receipt"]
            verify_historical(
                receipt,
                expected_request=parse(decode(receipt["request_bytes"])),
                trust=trust,
            )
