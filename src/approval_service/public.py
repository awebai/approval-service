"""Configured public AWID reads for requester admission and issuer authority.

Admission never authorizes an effect. Every cached result retains its original
observation time. No network origin comes from a submitted receipt or request.
"""

from __future__ import annotations

import logging
import math
import time
from collections import OrderedDict
from functools import wraps

from awid.dns_verify import DnsVerificationError
from awid.id_certificates import (
    IDCertificateError,
    namespace_authority_valid,
    status_request,
    verify_id_certificate,
    verify_id_chain,
)
from awid.registry import DIDKeyNotFoundError, RegistryError
from httpx import HTTPError

from .canonical import canonical
from .enrollment import PublicIssuer
from .requester import (
    AdmittedRequester,
    KeyObservation,
    admit_enrollment_target,
    read_team_member,
)
from .trust import read_trust
from .verify import Refused

logger = logging.getLogger(__name__)


def public_errors(method):
    @wraps(method)
    async def checked(*args, **kwargs):
        try:
            return await method(*args, **kwargs)
        except Refused:
            raise
        except (RegistryError, DnsVerificationError, HTTPError, OSError) as exc:
            status = getattr(exc, "status_code", None)
            logger.warning(
                "public registry read failed: type=%s status=%s code=%s",
                type(exc).__name__,
                status,
                getattr(exc, "code", None),
            )
            code = (
                "status_unavailable"
                if status is None or status == 429 or status >= 500
                else "public_evidence_invalid"
            )
            raise Refused(code) from exc
        except (IDCertificateError, ValueError, TypeError, KeyError) as exc:
            raise Refused("public_evidence_invalid") from exc

    return checked


class PublicReader:
    def __init__(self, registry, *, cache_size=1024):
        self.registry = registry
        self._cache = OrderedDict()
        self._cache_size = cache_size

    async def _cached(self, key, read):
        old = self._cache.get(key)
        now = int(time.time())
        if old is not None and 0 <= now - old.observed_at <= 60:
            self._cache.move_to_end(key)
            return old
        self._cache.pop(key, None)
        value = await read()
        if not 0 <= int(time.time()) - value.observed_at <= 60:
            raise Refused("status_unavailable")
        self._cache[key] = value
        while len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)
        return value

    @public_errors
    async def person(self, chain, *, person, identity_key, organisation):
        return await self._cached(
            ("person", person, identity_key, organisation, canonical(chain)),
            lambda: read_trust(
                self.registry,
                chain,
                person=person,
                identity_key=identity_key,
                organisation=organisation,
            ),
        )

    @public_errors
    async def key_observation(self, person):
        """Mapping-only read for pending ownership and creation classification."""

        async def read():
            try:
                value = await self.registry.resolve_key_fresh(person)
            except DIDKeyNotFoundError as exc:
                tree = exc.id_tree
                return KeyObservation(
                    person,
                    None,
                    None if tree is None else tree.enrolled,
                    int(time.time()),
                )
            tree = value.id_tree
            return KeyObservation(
                person,
                value.current_did_key,
                None if tree is None else tree.enrolled,
                int(time.time()),
            )

        return await self._cached(("key-mapping", person), read)

    @public_errors
    async def issuer(self, intent):
        i = intent["intent"]
        certificate = i["pending_certificate"]["certificate"]
        parent = certificate["parent"]
        # Parse/check the signed certificate before a malformed admission can
        # become a network failure. This is shape/signature, not issuer authority.
        verify_id_certificate(
            i["pending_certificate"], issuer_key=certificate["issuer_key"]
        )

        async def read():
            if parent["kind"] == "namespace":
                evidence = await self.registry.id_chain_evidence(
                    {
                        "v": 1,
                        "type": "aweb.id-chain",
                        "certificates": [i["pending_certificate"]],
                    },
                    {"id": i["person"], "did_key": i["identity_key"]},
                    domain=i["organisation"],
                )
                observed = self._age(evidence)
                status = evidence.status
                if status.get("domain") != i["organisation"]:
                    raise Refused("issuer_unavailable")
                namespace = status.get("namespace", {})
                epochs = namespace.get("epochs", [])
                if not epochs or epochs[-1].get("retired_at", "missing") is not None:
                    raise Refused("issuer_unavailable")
                key = epochs[-1]["did_key"]
                if not namespace_authority_valid(
                    i["organisation"],
                    evidence.namespace_authority,
                    key,
                    namespace.get("delegation"),
                ):
                    raise Refused("issuer_unavailable")
                return PublicIssuer(key, observed)
            # The SDK reconstructs the issuing parent's chain from current public
            # status when it is not carried. The pending child's claim is not authority.
            subject = {"id": parent["id"], "did_key": certificate["issuer_key"]}
            evidence = await self.registry.id_chain_evidence(
                None, subject, domain=i["organisation"]
            )
            observed = self._age(evidence)
            checked = verify_id_chain(
                None, subject=subject, evidence=evidence, domain=i["organisation"]
            )
            if checked["identity_valid"] is not True:
                raise Refused("issuer_unavailable")
            return PublicIssuer(subject["did_key"], observed)

        return await self._cached(
            ("issuer", i["organisation"], canonical(parent), certificate["issuer_key"]),
            read,
        )

    @staticmethod
    def _age(evidence):
        age = evidence.age_seconds
        if (
            type(age) not in (int, float)
            or not math.isfinite(age)
            or not 0 <= age <= 60
        ):
            raise Refused("status_unavailable")
        return int(time.time()) - math.ceil(age)

    @public_errors
    async def requester(
        self,
        descriptor,
        *,
        organisation,
        admission,
        intent=None,
        purpose=None,
        origin=None,
        rp_id=None,
    ):
        # This path cannot be reached from an act packet: the handler's closed
        # act schema has no intent, and it supplies its own trusted route purpose.
        if intent is not None and descriptor.get("kind") == "identity":
            i = intent["intent"]
            if (
                i["purpose"] == "enroll_person"
                and "previous_binding_commitment" not in i
                and descriptor.get("id") == i["person"]
            ):
                observation = await self.key_observation(i["person"])
                if observation.committed is False:
                    issuer = await self.issuer(intent)
                    return admit_enrollment_target(
                        intent,
                        descriptor,
                        issuer_key=issuer.key,
                        observation=observation,
                        origin=origin,
                        rp_id=rp_id,
                        now=int(time.time()),
                        purpose=purpose,
                    )

        async def read():
            if descriptor["kind"] == "team_member":
                return await read_team_member(
                    self.registry,
                    descriptor,
                    organisation=organisation,
                    certificate_header=admission["team_certificate"],
                )
            if descriptor["kind"] == "namespace_controller":
                if intent is None or descriptor["namespace"] != organisation:
                    raise Refused("requester_namespace_mismatch")
                issuer = await self.issuer(intent)
                if (
                    intent["intent"]["pending_certificate"]["certificate"]["parent"][
                        "kind"
                    ]
                    != "namespace"
                    or descriptor["key"] != issuer.key
                ):
                    raise Refused("requester_namespace_mismatch")
                return AdmittedRequester(
                    canonical(descriptor), descriptor["key"], issuer.observed_at
                )
            subject = {"id": descriptor["id"], "did_key": descriptor["key"]}
            chain = admission["id_chain"]
            if not chain:
                raise Refused("identity_chain_required")
            bundle = {"v": 1, "type": "aweb.id-chain", "certificates": chain}
            status_request(bundle, subject, domain=organisation)
            evidence = await self.registry.id_chain_evidence(
                bundle, subject, domain=organisation
            )
            observed = self._age(evidence)
            checked = verify_id_chain(
                bundle, subject=subject, evidence=evidence, domain=organisation
            )
            if checked["identity_valid"] is not True:
                raise Refused("requester_identity_invalid")
            return AdmittedRequester(canonical(descriptor), descriptor["key"], observed)

        return await self._cached(
            (
                "requester",
                canonical(descriptor),
                organisation,
                canonical(admission),
                canonical(intent) if intent else None,
            ),
            read,
        )
