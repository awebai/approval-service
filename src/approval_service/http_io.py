"""One bounded, original-byte JSON reader for requester and browser routes."""

from collections.abc import Collection

from fastapi import Request

from .canonical import parse
from .verify import Refused


async def read_json_body(request: Request, *, fields: Collection[str] | None = None):
    size = 0
    chunks = []
    async for chunk in request.stream():
        size += len(chunk)
        if size > 1048576:
            raise Refused("body_too_large")
        chunks.append(chunk)
    raw = b"".join(chunks)
    try:
        value = parse(raw)
        if type(value) is not dict or (
            fields is not None and set(value) != set(fields)
        ):
            raise Refused("body_invalid")
        if fields is not None:
            for field in ("locator", "csrf", "id", "user_handle"):
                if field in value and (
                    type(value[field]) is not str or not 1 <= len(value[field]) <= 4096
                ):
                    raise Refused("body_invalid")
        return raw, value
    except (ValueError, TypeError, KeyError) as exc:
        raise Refused("body_invalid") from exc
