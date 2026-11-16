"""The normal locked environment must supply the service's public SDK port."""

from awid.registry import RegistryClient


def test_locked_sdk_has_the_public_exact_certificate_status_reader():
    client=RegistryClient('https://api.awid.ai')
    assert callable(getattr(client,'get_team_certificate_status_fresh',None))
