"""Canonical JSON extracted from the existing B2 profile (MIT source in LICENSE)."""
from __future__ import annotations
import json
from typing import Any

MAX_INTEGER = 2**53 - 1
MAX_BYTES = 1 << 20
MAX_DEPTH = 32

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

def _integer(raw):
    if raw == "-0":
        raise InvalidJSON("negative_zero")
    value = int(raw)
    if abs(value) > MAX_INTEGER:
        raise InvalidJSON("unsafe_integer")
    return value

def canonical(value: Any) -> bytes:
    def check(item, depth=0):
        if depth > MAX_DEPTH:
            raise InvalidJSON("too_deep")
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeError as exc:
                raise InvalidJSON("invalid_text") from exc
            return
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, int) and abs(item) <= MAX_INTEGER:
            return
        if isinstance(item, dict) and all(isinstance(k, str) for k in item):
            for k, v in item.items():
                check(k, depth + 1)
                check(v, depth + 1)
            return
        if isinstance(item, list):
            for v in item: check(v, depth + 1)
            return
        raise InvalidJSON("invalid_value")
    check(value)
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (UnicodeError, ValueError, TypeError) as exc:
        raise InvalidJSON("invalid_text") from exc

def parse(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise InvalidJSON("body_too_large")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_int=_integer, parse_float=_noninteger,
                           parse_constant=_noninteger)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidJSON("invalid_json") from exc
    if not isinstance(value, dict):
        raise InvalidJSON("object_required")
    canonical(value)  # Validate text/depth before callers can lose raw input.
    return value
