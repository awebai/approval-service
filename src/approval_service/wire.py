"""One reviewed closed schema shared by generated Go and Python consumers."""

import re
from importlib.resources import files
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, ValidationError, validators

from .schema_projection import load_wire_schema

SCHEMA = load_wire_schema(files("approval_service").joinpath("data"))


def _whole_pattern(validator, pattern, instance, schema):
    # The wire profile matches the entire string in every language. Python's
    # ordinary `$` also matches before one terminal newline; do not inherit it.
    if isinstance(instance, str) and re.fullmatch(pattern, instance) is None:
        yield ValidationError("string does not match the complete wire pattern")


WireValidator = validators.extend(Draft202012Validator, {"pattern": _whole_pattern})
VALIDATORS = {
    name: WireValidator({"$ref": "#/$defs/" + name, "$defs": SCHEMA["$defs"]})
    for name in SCHEMA["$defs"]
}


def validate(kind, value):
    VALIDATORS[kind].validate(value)


def domain(name):
    return SCHEMA["x-domains"][name].encode("ascii")


def validate_site(origin, rp_id):
    """One exact site pin for receipts, registration and the service runtime."""
    properties = SCHEMA["$defs"]["binding_body"]["properties"]
    WireValidator(properties["rp_id"]).validate(rp_id)
    WireValidator(properties["origin"]).validate(origin)
    try:
        parsed = urlsplit(origin)
        port = parsed.port
        suffix = "" if port is None else ":" + str(port)
        if (
            parsed.scheme != "https"
            or parsed.hostname != rp_id
            or origin != "https://" + rp_id + suffix
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ValueError("origin_invalid")
    except ValueError as exc:
        raise ValidationError("origin_invalid") from exc
