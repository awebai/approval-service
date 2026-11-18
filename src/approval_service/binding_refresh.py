"""Current-issuer re-signing of an active binding, preserving its enrollment."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from enum import StrEnum

from .canonical import canonical
from .http_errors import AdvisedRefused
from .requester import AdmittedRequester
from .seams import commitment
from .store import Store
from .verify import Refused, Trust, verify_binding
from .wire import validate


class EnrollmentState(StrEnum):
    ACTIVE = "active"


class RequesterKind(StrEnum):
    IDENTITY = "identity"


class RefreshFailure(StrEnum):
    REQUEST_INVALID = "binding_refresh_request_invalid"
    AUTHORIZATION = "binding_refresh_authorization_invalid"
    SITE_CHANGED = "binding_refresh_site_changed"
    REQUESTER = "requester_mismatch"
    UNAVAILABLE = "identity_unavailable"
    NOT_ACTIVE = "binding_refresh_enrollment_not_found"
    PREVIOUS_CHANGED = "binding_refresh_state_changed"
    CREDENTIAL_CHANGED = "binding_refresh_credential_changed"
    PROOF_INVALID = "binding_refresh_proof_invalid"


REFRESH_ADVICE = {
    RefreshFailure.REQUEST_INVALID: "Use the complete packet returned by the issuer's refresh command; do not edit its fields.",
    RefreshFailure.AUTHORIZATION: "Sign this exact refresh packet with the person's current identity key for this approval-service origin and route.",
    RefreshFailure.SITE_CHANGED: "A refresh cannot move an enrollment to a new approval-service origin or RP. Use the documented enrollment procedure.",
    RefreshFailure.REQUESTER: "Run binding refresh with this person's own current identity key.",
    RefreshFailure.UNAVAILABLE: "Check the person's current registry status, then retry binding refresh.",
    RefreshFailure.NOT_ACTIVE: "There is no active enrollment to refresh. Use the enrollment command for this ID.",
    RefreshFailure.PREVIOUS_CHANGED: "Use the current binding from the last successful refresh, then ask the issuer to refresh again.",
    RefreshFailure.CREDENTIAL_CHANGED: "A refresh cannot replace keys or change their grade or site. Keep the existing enrollment; use the documented recovery procedure if keys were lost.",
    RefreshFailure.PROOF_INVALID: "Ask the person's current certificate issuer or namespace controller to re-sign the existing binding; do not register new approval keys.",
}


class RefreshRefused(AdvisedRefused):
    def __init__(self, reason: RefreshFailure):
        super().__init__(reason=reason, advice=REFRESH_ADVICE[reason])


def check_refresh_carrier(
    packet: dict, *, trust: Trust, carrier: AdmittedRequester
) -> None:
    """Only the current person carries this update; no pending or admin admission."""
    expected = {
        "kind": RequesterKind.IDENTITY,
        "id": trust.person,
        "key": trust.identity_key,
    }
    if (
        packet["requester"] != expected
        or carrier.descriptor_bytes != canonical(expected)
        or carrier.key != trust.identity_key
    ):
        raise RefreshRefused(RefreshFailure.REQUESTER)
    now = int(time.time())
    if any(
        not 0 <= now - observed <= 60
        for observed in (trust.observed_at, carrier.observed_at)
    ):
        raise RefreshRefused(RefreshFailure.UNAVAILABLE)


def check_refresh_replacement(previous: dict, candidate: dict, *, trust: Trust) -> None:
    """README.md:148-155 permits re-signing, not another registration ceremony.

    The original credential declarations and person key are immutable here;
    only checked current issuer authority and certificate may be renewed.
    """
    validate("binding", previous)
    try:
        body = verify_binding(candidate, trust=trust)
    except Refused as error:
        raise RefreshRefused(RefreshFailure.PROOF_INVALID) from error
    expected = {
        **previous["binding"],
        "issuer": body["issuer"],
        "certificate": trust.certificate,
    }
    if canonical(body) != canonical(expected):
        raise RefreshRefused(RefreshFailure.CREDENTIAL_CHANGED)


@dataclass(frozen=True)
class BindingRefresher:
    store: Store

    async def refresh(
        self, packet: dict, *, trust: Trust, carrier: AdmittedRequester
    ) -> dict:
        validate("binding_refresh_request", packet)
        check_refresh_carrier(packet, trust=trust, carrier=carrier)
        new_ref = commitment("binding_commitment", packet["binding"])
        previous_ref = packet["previous_binding_commitment"]
        async with self.store.transaction() as connection:
            row = await connection.fetch_one(
                """SELECT e.*,v.binding AS current_binding
                FROM {{tables.approval_enrollments}} e
                JOIN {{tables.approval_binding_versions}} v ON v.digest=e.binding_ref
                    AND v.organisation=e.organisation AND v.person_id=e.person_id
                WHERE e.organisation=$1 AND e.person_id=$2 AND e.state=$3
                FOR UPDATE OF e""",
                trust.organisation,
                trust.person,
                EnrollmentState.ACTIVE,
            )
            check_refresh_carrier(packet, trust=trust, carrier=carrier)
            if row is None:
                raise RefreshRefused(RefreshFailure.NOT_ACTIVE)
            old = json.loads(row["current_binding"])
            check_refresh_replacement(old, packet["binding"], trust=trust)
            if row["binding_ref"] == new_ref and previous_ref != new_ref:
                recorded = await connection.fetch_one(
                    """SELECT actor_key FROM {{tables.approval_binding_refresh_audit}}
                    WHERE organisation=$1 AND person_id=$2 AND previous_binding_ref=$3
                        AND current_binding_ref=$4""",
                    trust.organisation,
                    trust.person,
                    previous_ref,
                    new_ref,
                )
                if recorded is not None and recorded["actor_key"] == carrier.key:
                    check_refresh_carrier(packet, trust=trust, carrier=carrier)
                    return self._answer(trust=trust, binding_ref=new_ref)
            if row["binding_ref"] != previous_ref:
                raise RefreshRefused(RefreshFailure.PREVIOUS_CHANGED)
            await self._install(
                connection,
                row=row,
                packet=packet,
                trust=trust,
                carrier=carrier,
                previous=old,
                binding_ref=new_ref,
            )
            check_refresh_carrier(packet, trust=trust, carrier=carrier)
            return self._answer(trust=trust, binding_ref=new_ref)

    async def _install(
        self,
        connection,
        *,
        row: dict,
        packet: dict,
        trust: Trust,
        carrier: AdmittedRequester,
        previous: dict,
        binding_ref: str,
    ) -> None:
        await connection.execute(
            """INSERT INTO {{tables.approval_binding_versions}}
            (digest,person_id,binding,id_chain,organisation,enrollment_locator)
            VALUES($1,$2,$3::jsonb,$4::jsonb,$5,$6) ON CONFLICT DO NOTHING""",
            binding_ref,
            trust.person,
            json.dumps(packet["binding"]),
            json.dumps(packet["id_chain"]),
            trust.organisation,
            row["enrollment_locator"],
        )
        check_refresh_carrier(packet, trust=trust, carrier=carrier)
        await connection.execute(
            """UPDATE {{tables.approval_enrollments}} SET binding_ref=$1,certificate=$2
            WHERE organisation=$3 AND person_id=$4 AND enrollment_locator=$5""",
            binding_ref,
            trust.certificate,
            trust.organisation,
            trust.person,
            row["enrollment_locator"],
        )
        await connection.execute(
            """INSERT INTO {{tables.approval_binding_refresh_audit}}
            (organisation,person_id,actor_key,previous_binding_ref,current_binding_ref,
                previous_issuer,current_issuer,recorded_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING""",
            trust.organisation,
            trust.person,
            carrier.key,
            row["binding_ref"],
            binding_ref,
            previous["binding"]["issuer"],
            packet["binding"]["binding"]["issuer"],
            int(time.time()),
        )

    @staticmethod
    def _answer(*, trust: Trust, binding_ref: str) -> dict:
        return {
            "version": 1,
            "person": trust.person,
            "state": EnrollmentState.ACTIVE,
            "binding_commitment": binding_ref,
        }

    async def audit(self, *, after: int = 0, limit: int = 100) -> list[dict]:
        if (
            type(after) is not int
            or after < 0
            or type(limit) is not int
            or not 1 <= limit <= 1000
        ):
            raise ValueError("audit bounds must be nonnegative after and limit 1..1000")
        return await self.store.db.fetch_all(
            """SELECT audit_id,organisation,person_id,actor_key,previous_binding_ref,
            current_binding_ref,previous_issuer,current_issuer,recorded_at
            FROM {{tables.approval_binding_refresh_audit}} WHERE audit_id>$1
            ORDER BY audit_id LIMIT $2""",
            after,
            limit,
        )
