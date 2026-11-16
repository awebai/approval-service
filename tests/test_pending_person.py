"""A pending person's possession is scoped to their exact enrollment only."""

import copy
import json
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from approval_service.canonical import canonical
from approval_service.encoding import encode
from approval_service.requester import KeyObservation, admit_enrollment_target
from approval_service.verify import Refused
from approval_service.wire import domain


def world():
    c = json.loads(
        (Path(__file__).parents[1] / "vectors/later-enrollment-v1.json").read_text()
    )["cases"][0]
    i = copy.deepcopy(c["activation"]["intent"])
    i["intent"]["purpose"] = "enroll_person"
    i["signature"] = encode(
        SigningKey(bytes([1]) * 32)
        .sign(domain("enrollment_intent") + canonical(i["intent"]))
        .signature
    )
    observation = KeyObservation(
        c["trust"]["person"], c["trust"]["identity_key"], False, 1100
    )
    return c, i, observation


@pytest.mark.parametrize(
    "purpose",
    [
        "enrollment_start",
        "enrollment_material",
        "enrollment_confirm",
        "enrollment_activate",
        "holder_binding",
        "holder_finish",
        "holder_activate",
    ],
)
def test_exact_pending_person_may_only_carry_enrollment(purpose):
    c, i, observation = world()
    result = admit_enrollment_target(
        i,
        c["requester"],
        issuer_key=c["issuer_key"],
        observation=observation,
        origin=c["origin"],
        rp_id=c["rp_id"],
        now=1100,
        purpose=purpose,
    )
    assert result.key == c["requester"]["key"]


@pytest.mark.parametrize(
    "fault", ["other_intent", "act_route", "noncurrent_key", "admin_carrier"]
)
def test_pending_person_refusal_neighbors(fault):
    c, i, observation = world()
    descriptor = copy.deepcopy(c["requester"])
    purpose = "enrollment_start"
    if fault == "other_intent":
        i["intent"]["person"] = "did:aw:another-person"
        i["signature"] = encode(
            SigningKey(bytes([1]) * 32)
            .sign(domain("enrollment_intent") + canonical(i["intent"]))
            .signature
        )
    elif fault == "act_route":
        purpose = "submit"
    elif fault == "noncurrent_key":
        observation = KeyObservation(
            observation.person, "another-current-key", False, 1100
        )
    else:
        descriptor = {
            "kind": "namespace_controller",
            "namespace": "customer.example",
            "key": c["issuer_key"],
        }
    with pytest.raises(Refused):
        admit_enrollment_target(
            i,
            descriptor,
            issuer_key=c["issuer_key"],
            observation=observation,
            origin=c["origin"],
            rp_id=c["rp_id"],
            now=1100,
            purpose=purpose,
        )
