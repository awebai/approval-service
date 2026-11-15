"""The format's single strict binary encoding."""
import base64
import re

class EncodingError(ValueError):
    pass

def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

def decode(value: str) -> bytes:
    if not isinstance(value,str) or not re.fullmatch(r"[A-Za-z0-9_-]+",value):
        raise EncodingError("invalid_base64url")
    try:
        raw=base64.b64decode(value+"="*(-len(value)%4),altchars=b"-_",validate=True)
    except ValueError as exc:
        raise EncodingError("invalid_base64url") from exc
    if encode(raw)!=value:
        raise EncodingError("noncanonical_base64url")
    return raw
