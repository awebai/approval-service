"""Compose an additive transport profile without rewriting frozen format bytes."""

from __future__ import annotations

import json
from importlib.resources.abc import Traversable
from typing import Any

from .http_purpose import HTTPPurpose


def _object(value: Any, *, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"packaged {name} must be an object")
    return value


def load_wire_schema(data_directory: Traversable) -> dict[str, Any]:
    """The frozen base plus binding-refresh-v1.json own one compiled projection.

    protocol.md:900-908 permits current issuer re-signing without changing the
    saved historical binding. The extension adds only its own transport purpose.
    """
    base = _object(
        json.loads(data_directory.joinpath("format-v1.json").read_text()), name="format"
    )
    extension = _object(
        json.loads(data_directory.joinpath("binding-refresh-v1.json").read_text()),
        name="binding refresh profile",
    )
    definitions = _object(base["$defs"], name="base definitions")
    for name, schema in _object(extension["$defs"], name="refresh definitions").items():
        if name in definitions:
            raise ValueError("extension cannot replace a frozen definition")
        definitions[name] = _object(schema, name=name)
    transport = _object(extension["http"], name="refresh HTTP configuration")
    purpose = HTTPPurpose(transport["purpose"])
    path = transport["path"]
    if not isinstance(path, str) or not path.startswith("/v1/"):
        raise ValueError("refresh path must be a versioned absolute path")
    http = _object(base["x-http"], name="HTTP configuration")
    routes = _object(http["routes"], name="HTTP routes")
    if purpose in routes:
        raise ValueError("extension cannot replace a frozen route")
    routes[purpose] = path
    proof = _object(definitions["http_proof"], name="HTTP proof")
    properties = _object(proof["properties"], name="HTTP proof properties")
    purpose_schema = _object(properties["purpose"], name="HTTP purpose schema")
    purposes = purpose_schema["enum"]
    if not isinstance(purposes, list):
        raise TypeError("HTTP purposes must be an enum")
    purposes.append(purpose)
    return base
