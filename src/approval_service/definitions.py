"""Bundled exact act/display definitions; no network or requester-authored copy."""

import copy
import hashlib

from awid.did import public_key_from_did, validate_stable_id
from awid.team_ids import build_team_id, parse_team_id
from jsonschema import ValidationError

from .canonical import canonical
from .verify import Refused
from .wire import SCHEMA, WireValidator, validate


def definition(identifier):
    value = SCHEMA["x-act-definitions"].get(identifier)
    if value is None:
        raise Refused("definition_unavailable")
    return copy.deepcopy(value)


def definition_ref(identifier):
    value = definition(identifier)
    return {
        "id": identifier,
        "version": value["version"],
        "sha256": hashlib.sha256(canonical(value)).hexdigest(),
    }


def check_definition(request):
    try:
        validate("request", request)
        value = definition(request["definition"]["id"])
        if canonical(request["definition"]) != canonical(definition_ref(value["id"])):
            raise Refused("definition_mismatch")
        if request["purpose"] != value["purpose"]:
            raise Refused("purpose_invalid")
        WireValidator(value["act_schema"]).validate(request["act"])
        if value["id"] == "agent.root.authorize":
            target = request["act"]["target"]
            for identifier in (target["person"], target["root_id"]):
                if validate_stable_id(identifier) != identifier:
                    raise ValueError("noncanonical ID")
            public_key_from_did(target["root_key"])
            if target["teams"] != sorted(target["teams"]):
                raise ValueError("teams must be sorted")
            for team in target["teams"]:
                domain, name = parse_team_id(team)
                if build_team_id(domain, name) != team:
                    raise ValueError("noncanonical team ID")
                if domain != request["organisation"]:
                    raise Refused("root_team_organisation_mismatch")
        return value
    except Refused:
        raise
    except (ValueError, TypeError, KeyError, ValidationError) as exc:
        raise Refused("definition_invalid") from exc
