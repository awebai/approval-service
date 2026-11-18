"""Actual registry/DNS/TLS, including the system host resolver's private answer.

The owned native runner maps signer.example.com to 127.0.0.1 through its normal
resolver configuration. No resolver, HTTP client, public read or verifier is
replaced. This belongs to the placed integration selection, not unit fixtures.
"""

from uuid import uuid4

import pytest
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.external_registry import SystemHostResolver
from awid.federation_errors import FederationAuthorityError
from awid.id_certificates import status_request
from awid.registry import RegistryClient, RegistryError

from approval_service.public import PublicReader
from approval_service.verify import Refused

from .real_stack import RegistryTransport, registry_stack
from .test_signed_journey import certificate_for, commit_identity


def refusal_reasons(error: BaseException) -> list[str]:
    reasons = []
    current: BaseException | None = error
    while current is not None:
        if isinstance(current, FederationAuthorityError):
            reasons.append(current.reason)
        current = current.__cause__
    return reasons


@pytest.mark.asyncio
async def test_discovered_private_hostname_refuses_identity_post_but_operator_pin_works(
    tmp_path,
):
    host = "signer.example.com"
    assert set(await SystemHostResolver().resolve_all(host)) == {"127.0.0.1"}, (
        "native runner must configure signer.example.com as its own loopback host"
    )
    root, root_public = generate_keypair()
    seed, public = generate_keypair()
    key = did_from_public_key(public)
    person = stable_id_from_did_key(key)
    organisation = "guard-" + uuid4().hex[:10] + ".example.test"
    certificate = certificate_for(person, organisation, root)
    chain = [certificate]
    requester = {"kind": "identity", "id": person, "key": key}
    admission = {"team_certificate": None, "id_chain": chain}
    async with registry_stack(
        tmp_path,
        {organisation: (root, root_public)},
        transport=RegistryTransport.HTTPS,
        advertised_registry_host=host,
    ) as pinned:
        await pinned.register_did(key, seed)
        await commit_identity(pinned, certificate, seed)
        admitted = await PublicReader(pinned).requester(
            requester,
            organisation=organisation,
            admission=admission,
        )
        assert admitted.key == key
        discovered = RegistryClient("https://api.awid.ai")
        try:
            request = status_request(
                {"v": 1, "type": "aweb.id-chain", "certificates": chain},
                {"id": person, "did_key": key},
                domain=organisation,
            )
            assert request is not None
            with pytest.raises(RegistryError) as refusal:
                await discovered.fetch_id_certificate_status(organisation, request)
            assert "sender_registry_origin_forbidden" in refusal_reasons(refusal.value)
            with pytest.raises(Refused, match="status_unavailable"):
                await PublicReader(discovered).requester(
                    requester,
                    organisation=organisation,
                    admission=admission,
                )
        finally:
            await discovered.aclose()
