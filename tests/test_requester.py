"""Real signed certificates, with independent public exact-status inputs."""

import base64
import copy

import pytest
from awid.did import did_from_public_key, generate_keypair
from awid.signing import canonical_json_bytes, sign_message

from approval_service.requester import CertificateObservation, admit_team_member
from approval_service.verify import Refused


def world():
    team_private, team_public = generate_keypair()
    _, member_public = generate_keypair()
    key = did_from_public_key(member_public)
    cert = {
        "version": 1,
        "certificate_id": "cert-1",
        "team_id": "private:tenant.example",
        "member_did_key": key,
        "member_did_aw": "did:aw:external-global-member",
        "alias": "agent",
    }
    cert["signature"] = sign_message(team_private, canonical_json_bytes(cert))
    header = base64.b64encode(canonical_json_bytes(cert)).decode()
    desc = {
        "kind": "team_member",
        "team_id": cert["team_id"],
        "certificate_id": cert["certificate_id"],
        "key": key,
    }
    status = {
        "team_id": cert["team_id"],
        "team_did_key": did_from_public_key(team_public),
        "status": "active",
        "revoked_at": None,
    }
    return (
        desc,
        header,
        CertificateObservation(desc["team_id"], desc["certificate_id"], status, 1000),
    )


def test_certificate_only_and_admitted_global_member_need_no_id_chain():
    desc, header, observation = world()
    result = admit_team_member(
        desc,
        organisation="tenant.example",
        certificate_header=header,
        observation=observation,
        now=1060,
    )
    assert result.descriptor_bytes == canonical_json_bytes(desc)
    assert result.key == desc["key"]
    assert result.observed_at == 1000


@pytest.mark.parametrize(
    "fault",
    [
        "sibling",
        "parent",
        "revoked",
        "missing",
        "other-path",
        "other-team",
        "other-key",
        "wrong-team-key",
        "signature",
        "stale",
        "future",
    ],
)
def test_exact_namespace_member_and_status_refusals(fault):
    desc, header, observation = world()
    status = copy.deepcopy(observation.status)
    org = "tenant.example"
    now = 1000
    if fault == "sibling":
        org = "other.example"
    elif fault == "parent":
        org = "example"
    elif fault == "revoked":
        status.update(status="revoked", revoked_at="2026-11-15T00:00:00Z")
    elif fault == "missing":
        status = None
    elif fault == "other-path":
        observation = CertificateObservation(
            desc["team_id"], "other-cert", status, 1000
        )
    elif fault == "other-team":
        status["team_id"] = "other:tenant.example"
    elif fault in ("other-key", "wrong-team-key"):
        _, pub = generate_keypair()
        key = did_from_public_key(pub)
        if fault == "other-key":
            desc["key"] = key
        else:
            status["team_did_key"] = key
    elif fault == "signature":
        cert = __import__("json").loads(base64.b64decode(header))
        cert["alias"] = "changed"
        header = base64.b64encode(canonical_json_bytes(cert)).decode()
    elif fault == "stale":
        now = 1061
    elif fault == "future":
        now = 999
    if fault != "other-path":
        observation = CertificateObservation(
            observation.team_id,
            observation.certificate_id,
            status,
            observation.acquired_at,
        )
    with pytest.raises(Refused):
        admit_team_member(
            desc,
            organisation=org,
            certificate_header=header,
            observation=observation,
            now=now,
        )
