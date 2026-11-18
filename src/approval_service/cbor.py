"""Compatibility names for the single shared bounded CBOR reader."""

from aweb_naapp.webauthn_cbor import (
    LIMITS,
    CBORProfileError,
)
from aweb_naapp.webauthn_cbor import (
    cbor_item_end as item_end,
)
from aweb_naapp.webauthn_cbor import (
    decode_cbor_map as decode_map,
)
from aweb_naapp.webauthn_cbor import (
    read_cbor_item as read,
)

__all__ = ["LIMITS", "CBORProfileError", "decode_map", "item_end", "read"]
