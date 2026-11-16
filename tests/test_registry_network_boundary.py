"""Actual DNS/HTTPS prove the installed SDK's discovered-versus-pinned boundary."""

import asyncio
import json

import dns.asyncresolver
import dns.flags
import dns.message
import dns.rrset
import pytest
from awid.registry import RegistryClient
from test_requester import world

from approval_service.public import PublicReader
from approval_service.verify import Refused


@pytest.mark.asyncio
async def test_dns_selected_private_host_is_not_dialed_but_operator_pin_works(
    transport,
):
    descriptor, certificate, observation = world()
    origin, payloads, paths = transport
    path = "/v1/namespaces/tenant.example/teams/private/certificates/cert-1/status"
    payloads[path] = json.dumps(observation.status).encode()
    queries = []

    class Authority(asyncio.DatagramProtocol):
        def connection_made(self, channel):
            self.channel = channel

        def datagram_received(self, raw, peer):
            query = dns.message.from_wire(raw)
            queries.append(str(query.question[0].name))
            answer = dns.message.make_response(query)
            answer.flags |= dns.flags.AA
            answer.answer.append(
                dns.rrset.from_text(
                    str(query.question[0].name),
                    0,
                    "IN",
                    "TXT",
                    '"awid=v1; controller='
                    + observation.status["team_did_key"]
                    + "; registry="
                    + origin
                    + ';"',
                )
            )
            self.channel.sendto(answer.to_wire(), peer)

    channel, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        Authority, local_addr=("127.0.0.1", 0)
    )
    previous = dns.asyncresolver.default_resolver
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = channel.get_extra_info("sockname")[1]
    dns.asyncresolver.default_resolver = resolver
    admission = {"team_certificate": certificate, "id_chain": []}
    discovered = RegistryClient("https://api.awid.ai")
    pinned = RegistryClient(origin)
    try:
        with pytest.raises(Refused, match="status_unavailable"):
            await PublicReader(discovered).requester(
                descriptor, organisation="tenant.example", admission=admission
            )
        assert queries == ["_awid.tenant.example."]
        assert not paths
        result = await PublicReader(pinned).requester(
            descriptor, organisation="tenant.example", admission=admission
        )
        assert result.key == descriptor["key"]
        assert paths == [path]
        assert queries == ["_awid.tenant.example."]
    finally:
        await discovered.aclose()
        await pinned.aclose()
        dns.asyncresolver.default_resolver = previous
        channel.close()
