"""Canonical JSON extracted from the existing B2 profile (MIT source in LICENSE)."""
from __future__ import annotations
import json
from typing import Any

MAX_INTEGER = 2**53 - 1

class InvalidJSON(ValueError):
    pass

def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise InvalidJSON("duplicate_member")
        result[key] = value
    return result

def _noninteger(raw):
    raise InvalidJSON("integer_required")

def canonical(value: Any) -> bytes:
    def check(item):
        if item is None or isinstance(item, (str, bool)):
            return
        if isinstance(item, int) and abs(item) <= MAX_INTEGER:
            return
        if isinstance(item, dict) and all(isinstance(k, str) for k in item):
            for v in item.values(): check(v)
            return
        if isinstance(item, list):
            for v in item: check(v)
            return
        raise InvalidJSON("invalid_value")
    check(value)
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (UnicodeError, ValueError, TypeError) as exc:
        raise InvalidJSON("invalid_text") from exc

def parse(raw: bytes) -> dict:
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_float=_noninteger, parse_constant=_noninteger)
    except (ValueError, UnicodeError) as exc:
        raise InvalidJSON("invalid_json") from exc
    if not isinstance(value, dict):
        raise InvalidJSON("object_required")
    return value
