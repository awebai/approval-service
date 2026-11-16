"""One reviewed closed schema shared by generated Go and Python consumers."""

import json
import re
from importlib.resources import files

from jsonschema import Draft202012Validator, ValidationError, validators

SCHEMA = json.loads(
    files("approval_service").joinpath("data/format-v1.json").read_text()
)


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
