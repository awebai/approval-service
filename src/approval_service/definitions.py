"""Bundled exact act/display definitions; no network or requester-authored copy."""

import copy
import hashlib

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
        return value
    except Refused:
        raise
    except (ValueError, TypeError, KeyError, ValidationError) as exc:
        raise Refused("definition_invalid") from exc
