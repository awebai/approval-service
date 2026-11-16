"""Issuer and service independently grade the same signed vendor registration."""

from datetime import UTC, datetime, timedelta

import pytest
from vendor import Vendor, signed_metadata

from approval_service.grading import EnrollmentGrading
from approval_service.metadata import load_snapshot
from approval_service.verify import Refused

from .test_enrollment import confirmed_person


@pytest.mark.asyncio
@pytest.mark.parametrize("issuer_hardware", [False, True])
async def test_independent_grading_can_activate_a_weaker_or_different_snapshot(
    store, issuer_hardware
):
    vendor = Vendor()
    now = datetime.now(UTC)
    service_snapshot = load_snapshot(
        **{
            **signed_metadata([vendor.entry()], next_update=now + timedelta(days=7)),
            "now": now,
        }
    )
    issuer_snapshot = (
        load_snapshot(
            **{
                **signed_metadata(
                    [vendor.entry()], sequence=2, next_update=now + timedelta(days=8)
                ),
                "now": now,
            }
        )
        if issuer_hardware
        else None
    )
    p = await confirmed_person(
        store,
        vendor=vendor,
        service_grading=EnrollmentGrading("hardware", service_snapshot),
        issuer_grading=issuer_snapshot,
    )
    result = await p["service"].activate(
        p["activation"], trust=p["trust"], requester=p["caller"]
    )
    assert result["state"] == "active"
    entry = p["binding"]["binding"]["credentials"][0]
    assert entry["grade"] == ("certified_hardware" if issuer_hardware else "passkey_uv")
    if issuer_hardware:
        assert entry["snapshot"] != service_snapshot.digest


@pytest.mark.asyncio
async def test_issuer_cannot_upgrade_beyond_the_services_assessment(store):
    vendor = Vendor()
    now = datetime.now(UTC)
    issuer_snapshot = load_snapshot(
        **{
            **signed_metadata([vendor.entry()], next_update=now + timedelta(days=7)),
            "now": now,
        }
    )
    with pytest.raises(Refused, match="binding_credential_mismatch"):
        await confirmed_person(store, vendor=vendor, issuer_grading=issuer_snapshot)
