"""Real HTTPS exact-status reads, real team signatures, no registry substitutes."""

import base64
import json

import pytest
from awid.registry import RegistryClient
from test_requester import world

from approval_service.canonical import canonical
from approval_service.public import PublicReader
from approval_service.verify import Refused


def registry(transport):
    async def pinned(_domain):
        return transport[0]

    return RegistryClient(transport[0], domain_registry_resolver=pinned)


def path(descriptor):
    name, domain = descriptor["team_id"].split(":")
    return f"/v1/namespaces/{domain}/teams/{name}/certificates/{descriptor['certificate_id']}/status"


@pytest.mark.asyncio
async def test_fifty_unknown_selectors_make_one_public_read(transport):
    descriptor, header, _ = world()
    transport[1][path(descriptor)] = None
    client = registry(transport)
    reader = PublicReader(client)
    try:
        for _ in range(50):
            with pytest.raises(Refused):
                await reader.requester(
                    descriptor,
                    organisation="tenant.example",
                    admission={"team_certificate": header, "id_chain": []},
                )
        assert transport[2] == [path(descriptor)]
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_invalid_signature_under_cached_team_key_makes_no_read(transport):
    descriptor, header, observation = world()
    transport[1][path(descriptor)] = json.dumps(observation.status).encode()
    client = registry(transport)
    reader = PublicReader(client)
    try:
        await reader.requester(
            descriptor,
            organisation="tenant.example",
            admission={"team_certificate": header, "id_chain": []},
        )
        transport[2].clear()
        certificate = json.loads(base64.b64decode(header))
        certificate["alias"] = "tampered"
        header = base64.b64encode(canonical(certificate)).decode()
        with pytest.raises(Refused):
            await reader.requester(
                descriptor,
                organisation="tenant.example",
                admission={"team_certificate": header, "id_chain": []},
            )
        assert not transport[2]
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_unsigned_selectors_must_match_certificate_before_discovery(transport):
    descriptor, header, _ = world()
    descriptor["certificate_id"] = "unsigned-other-selector"
    client = registry(transport)
    try:
        with pytest.raises(Refused):
            await PublicReader(client).requester(
                descriptor,
                organisation="tenant.example",
                admission={"team_certificate": header, "id_chain": []},
            )
        assert not transport[2]
    finally:
        await client.aclose()
