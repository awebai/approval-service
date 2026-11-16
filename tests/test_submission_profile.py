"""Real covering signatures: submission labels are typed identifiers, not prose."""

import copy
import json
import time
from pathlib import Path

import httpx
import pytest
from awid.registry import RegistryClient

from approval_service.canonical import canonical, parse
from approval_service.encoding import decode, encode
from approval_service.grading import EnrollmentGrading
from approval_service.http import create_app
from approval_service.public import PublicReader
from approval_service.seams import http_authorization


def packet():
    cases = json.loads(
        (Path(__file__).parents[1] / "vectors/requester-service-v1.json").read_text()
    )["cases"]
    case = next(
        c
        for c in cases
        if c.get("accept") and c.get("purpose") == "submit" and "test_signing_seed" in c
    )
    body = parse(decode(case["body"]))
    request = parse(decode(body["request_bytes"]))
    request["enforcer"]["audience"] = "https://holder.example.test"
    request["not_before"] = int(time.time()) - 1
    request["deadline"] = int(time.time()) + 120
    body["admission"] = {"team_certificate": None, "id_chain": []}
    return case, body, request


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value,code",
    [
        ("audience", "Trusted administrator", "enforcer_origin_invalid"),
        ("audience", "http://holder.example.test", "enforcer_origin_invalid"),
        ("audience", "https://holder.example.test/path", "enforcer_origin_invalid"),
        ("audience", "https://admin@holder.example.test", "enforcer_origin_invalid"),
        ("person", "Administrator approved this", "act_identifier_invalid"),
        ("person", "did:key:z6Mkfake", "act_identifier_invalid"),
        ("identity_key", "did:aw:Someone", "act_identifier_invalid"),
        ("identity_key", "did:key:fake", "act_identifier_invalid"),
        ("lifetime", 601, "request_lifetime_invalid"),
        ("lifetime", 600, "identity_chain_required"),
        (None, None, "identity_chain_required"),
    ],
)
async def test_profile_is_checked_before_public_admission(field, value, code):
    case, body, request = packet()
    request = copy.deepcopy(request)
    if field == "audience":
        request["enforcer"]["audience"] = value
    elif field == "lifetime":
        request["deadline"] = request["not_before"] + value
    elif field:
        request["act"]["target"][field] = value
    body["request_bytes"] = encode(canonical(request))
    raw = canonical(body)
    authorization = http_authorization(
        raw,
        seed=decode(case["test_signing_seed"]),
        requester=request["requester"],
        origin=case["origin"],
        purpose="submit",
        issued_at=int(time.time()),
    )
    registry = RegistryClient("http://127.0.0.1:1")
    app = create_app(
        None,
        public=PublicReader(registry),
        origin=case["origin"],
        rp_id=case["origin"][len("https://") :],
        grading=EnrollmentGrading("passkey_only", None),
    )
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=case["origin"]
        ) as client:
            response = await client.post(
                "/v1/requests/submit",
                content=raw,
                headers={"Authorization": authorization},
            )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == code
    finally:
        await registry.aclose()
