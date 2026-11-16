"""Admission to a pending list, never authority to perform an application act.

The public registry key here is for this admission check ONLY. An enforcer's
membership/role decision uses the team key it has admitted independently.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

from awid.team_certificate import TeamCertificateError, check_team_certificate
from awid.team_ids import build_team_id, parse_team_id
from jsonschema import ValidationError

from .canonical import canonical
from .verify import Refused
from .wire import validate


@dataclass(frozen=True)
class CertificateObservation:
    # These path selectors are set by the trusted reader, not by response JSON.
    team_id: str
    certificate_id: str
    status: dict | None
    acquired_at: int


@dataclass(frozen=True)
class AdmittedRequester:
    descriptor_bytes: bytes
    key: str
    observed_at: int

    @property
    def commitment(self):
        return hashlib.sha256(self.descriptor_bytes).hexdigest()


def admit_team_member(
    descriptor, *, organisation, certificate_header, observation, now
):
    """A valid global member admitted to this org's team may ask, too."""
    try:
        validate("requester", descriptor)
        if descriptor["kind"] != "team_member":
            raise Refused("requester_kind_invalid")
        if (
            type(now) is not int
            or type(observation.acquired_at) is not int
            or not 0 <= now - observation.acquired_at <= 60
        ):
            raise Refused("requester_status_unavailable")
        team_id = descriptor["team_id"]
        domain, name = parse_team_id(team_id)
        if build_team_id(domain, name) != team_id or domain != organisation:
            raise Refused("requester_namespace_mismatch")
        if (observation.team_id, observation.certificate_id) != (
            team_id,
            descriptor["certificate_id"],
        ):
            raise Refused("requester_status_mismatch")
        status = observation.status
        if not isinstance(status, dict) or status.get("team_id") != team_id:
            raise Refused("requester_status_unavailable")
        if (
            status.get("status") != "active"
            or status.get("revoked_at", "missing") is not None
        ):
            raise Refused("requester_certificate_inactive")
        certificate = check_team_certificate(
            certificate_header,
            subject_did_key=descriptor["key"],
            team_did_key=status["team_did_key"],
            revoked_certificate_ids=set(),
            registered_certificate_ids={descriptor["certificate_id"]},
        )
        if certificate["team_id"] != team_id:
            raise Refused("requester_certificate_mismatch")
        return AdmittedRequester(
            canonical(descriptor), descriptor["key"], observation.acquired_at
        )
    except Refused:
        raise
    except (
        ValueError,
        TypeError,
        KeyError,
        ValidationError,
        TeamCertificateError,
    ) as exc:
        raise Refused("requester_certificate_invalid") from exc


async def read_team_member(registry, descriptor, *, organisation, certificate_header):
    """One public exact status read. Requires the post-adcl.2 AWID SDK method.

    No GET team, private team credential, protection field or registry override.
    SDK 0.5.40rc1 remains pinned until the recorded next release supplies this
    public method; tests use the actual main SDK source, never a fake response.
    """
    try:
        validate("requester", descriptor)
        if descriptor["kind"] != "team_member":
            raise Refused("requester_kind_invalid")
        domain, name = parse_team_id(descriptor["team_id"])
        if (
            domain != organisation
            or build_team_id(domain, name) != descriptor["team_id"]
        ):
            raise Refused("requester_namespace_mismatch")
        # Stamp before the awaited read so its time cannot renew observation age.
        acquired = int(time.time())
        status = await registry.get_team_certificate_status_fresh(
            domain, name, descriptor["certificate_id"]
        )
        observation = CertificateObservation(
            descriptor["team_id"], descriptor["certificate_id"], status, acquired
        )
        return admit_team_member(
            descriptor,
            organisation=organisation,
            certificate_header=certificate_header,
            observation=observation,
            now=int(time.time()),
        )
    except (ValidationError, ValueError, KeyError, TypeError) as exc:
        if isinstance(exc, Refused):
            raise
        raise Refused("requester_invalid") from exc
