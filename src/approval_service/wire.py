"""One reviewed closed schema shared by generated Go and Python consumers."""
import json
from importlib.resources import files
from jsonschema import Draft202012Validator, ValidationError

SCHEMA=json.loads(files("approval_service").joinpath("data/format-v1.json").read_text())
VALIDATORS={name:Draft202012Validator({"$ref":"#/$defs/"+name,"$defs":SCHEMA["$defs"]}) for name in SCHEMA["$defs"]}

def validate(kind,value):
    VALIDATORS[kind].validate(value)

def domain(name):
    return SCHEMA["x-domains"][name].encode("ascii")
