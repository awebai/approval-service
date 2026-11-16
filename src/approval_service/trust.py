"""One public ID-chain/status-to-Trust path, shared by service and enforcers.

PublicObservation is trusted acquisition data, NEVER an object read from a
receipt or submitted HTTP body. The carrier supplies only signed certificates.
The existing AWID verifier remains the owner of ID/DNS/log semantics.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass

from awid.did import public_key_from_did
from awid.id_certificates import IDChainEvidence, id_certificate_id, verify_id_chain

from .verify import Refused, Trust


@dataclass(frozen=True)
class PublicObservation:
    status: dict
    namespace_authority: dict
    acquired_at: int
    age_seconds: float | None


def derive_trust(chain, *, person, identity_key, organisation, observation, now):
    """Check independently acquired public data; never renew its original age."""
    try:
        if (
            type(now) is not int
            or type(observation.acquired_at) is not int
            or now < observation.acquired_at
            or observation.acquired_at < 0
        ):
            raise Refused("status_unavailable")
        age = observation.age_seconds
        if type(age) not in (int, float) or not math.isfinite(age) or age < 0:
            raise Refused("status_unavailable")
        total_age = age + now - observation.acquired_at
        if total_age > 60:
            raise Refused("status_unavailable")
        if not isinstance(chain, list) or not chain:
            raise Refused("identity_chain_required")
        evidence = IDChainEvidence(
            observation.status, observation.namespace_authority, total_age
        )
        bundle = {"v": 1, "type": "aweb.id-chain", "certificates": chain}
        checked = verify_id_chain(
            bundle,
            subject={"id": person, "did_key": identity_key},
            evidence=evidence,
            domain=organisation,
        )
        if checked["identity_valid"] is not True:
            raise Refused("identity_" + checked["reason"])
        if checked["kind"] != "human" or checked["human_id"] != person:
            raise Refused("approver_not_person")
        # The chain verifier has checked every status row, log, certificate,
        # revocation and namespace delegation against independently obtained DNS.
        certificate = chain[-1]["certificate"]
        parent = certificate["parent"]
        status = observation.status
        if parent["kind"] == "namespace":
            issuer = status["namespace"]["epochs"][-1]["did_key"]
        elif parent["id"].startswith("did:key:"):
            issuer = parent["id"]
        else:
            row = next(r for r in status["identities"] if r["id"] == parent["id"])
            issuer = row["key_history"][-1]["entry"]["new_did_key"]
        observed_at = observation.acquired_at - math.ceil(age)
        if observed_at < 0:
            raise Refused("status_unavailable")
        return Trust(
            person,
            organisation,
            identity_key,
            id_certificate_id(certificate),
            issuer,
            public_key_from_did(issuer),
            observed_at,
        )
    except Refused:
        raise
    except (
        ValueError,
        TypeError,
        KeyError,
        LookupError,
        StopIteration,
        OverflowError,
    ) as exc:
        raise Refused("identity_trust_invalid") from exc


async def read_trust(registry, chain, *, person, identity_key, organisation):
    """Use the configured AWID public resolver; no caller-provided status route.

    A long-lived SDK CachedRegistryClient may serve a <=60s cached observation;
    its reported original age is retained. No protected/freshness extension or
    mutation is involved. Registry failures remain unavailable, never legacy.
    """
    bundle = {"v": 1, "type": "aweb.id-chain", "certificates": chain}
    evidence = await registry.id_chain_evidence(
        bundle, {"id": person, "did_key": identity_key}, domain=organisation
    )
    acquired = int(time.time())
    observation = PublicObservation(
        evidence.status, evidence.namespace_authority, acquired, evidence.age_seconds
    )
    return derive_trust(
        chain,
        person=person,
        identity_key=identity_key,
        organisation=organisation,
        observation=observation,
        now=acquired,
    )
