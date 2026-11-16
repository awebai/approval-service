"""Each grader checks the same real attestation under its own pinned snapshot."""

import copy
from datetime import UTC, datetime, timedelta

import pytest
from vendor import Vendor, signed_metadata

from approval_service.grading import EnrollmentGrading
from approval_service.metadata import load_snapshot
from approval_service.registration import require_supported_entry
from approval_service.verify import Refused


def assessments():
    vendor = Vendor()
    now = datetime.now(UTC)
    first = load_snapshot(
        **{
            **signed_metadata([vendor.entry()], next_update=now + timedelta(days=7)),
            "now": now,
        }
    )
    second = load_snapshot(
        **{
            **signed_metadata(
                [vendor.entry()], sequence=2, next_update=now + timedelta(days=8)
            ),
            "now": now,
        }
    )
    raw, challenge = vendor.registration()

    def check(mode, snapshot):
        return (
            EnrollmentGrading(mode, snapshot)
            .check(
                raw,
                expected_challenge=challenge,
                origin="https://approval.example.test",
                rp_id="approval.example.test",
                now=now,
            )
            .binding_entry()
        )

    return (
        check("hardware", first),
        check("hardware", second),
        check("passkey_only", None),
    )


def test_weaker_issuer_grade_and_an_independent_hardware_snapshot_are_supported():
    service, issuer, passkey = assessments()
    assert service["grade"] == issuer["grade"] == "certified_hardware"
    assert service["snapshot"] != issuer["snapshot"]
    assert passkey["grade"] == "passkey_uv"
    require_supported_entry(service, issuer)
    require_supported_entry(service, passkey)
    require_supported_entry(passkey, passkey)
    with pytest.raises(Refused, match="binding_credential_mismatch"):
        require_supported_entry(passkey, issuer)


@pytest.mark.parametrize(
    "field,value", [("id", "other"), ("key", "other"), ("alg", -8)]
)
def test_one_registered_key_cannot_lend_its_assessment_to_another(field, value):
    service, issuer, _ = assessments()
    altered = copy.deepcopy(issuer)
    altered[field] = value
    with pytest.raises(Refused, match="binding_credential_mismatch"):
        require_supported_entry(service, altered)
