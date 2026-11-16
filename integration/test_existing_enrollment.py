"""Real PG/registration/UV: later enrollment does not become ID creation.

This component fixture supplies explicit checked public ports. The joined HTTP
journey obtains those ports from the actual registry; no verifier or storage
is replaced here.
"""

import time

import pytest

from approval_service.enrollment import Enrollments, PublicIssuer
from approval_service.grading import EnrollmentGrading
from approval_service.requester import KeyObservation
from approval_service.statements import verify_enrollment_evidence
from approval_service.verify import Refused

from .test_enrollment import (
    ORIGIN,
    RP,
    confirmed_person,
    enrollment_world,
)


@pytest.mark.asyncio
async def test_existing_person_activates_with_later_statement_and_raw_proof(store):
    w = await confirmed_person(store, later=True)
    result = await w["service"].activate(
        w["activation"], trust=w["trust"], requester=w["caller"]
    )
    assert result["state"] == "active"
    row = await store.db.fetch_one(
        "SELECT state,evidence FROM {{tables.approval_enrollments}} WHERE enrollment_locator=$1",
        w["started"]["locator"],
    )
    assert row["state"] == "active"
    e = w["activation"]["evidence"]
    assert e["evidence"]["kind"] == "human_enrolled_later"
    assert "creation" not in e["evidence"]
    checked = verify_enrollment_evidence(e, trust=w["trust"], receipt=w["receipt"])
    assert checked["proof_status"] == "checked"


@pytest.mark.asyncio
async def test_new_creation_start_cannot_relabel_a_committed_person(store):
    intent, _issuer, trust, caller, _ = enrollment_world()
    service = Enrollments(
        store, origin=ORIGIN, rp_id=RP, grading=EnrollmentGrading("passkey_only", None)
    )
    observation = KeyObservation(
        trust.person, trust.identity_key, True, int(time.time())
    )
    with pytest.raises(Refused, match="enrollment_creation_committed"):
        await service.start(
            intent,
            issuer=PublicIssuer(trust.issuer, trust.observed_at),
            requester=caller,
            observation=observation,
        )
    rows = await store.db.fetch_all(
        "SELECT person_id FROM {{tables.approval_enrollments}}"
    )
    assert rows == []
