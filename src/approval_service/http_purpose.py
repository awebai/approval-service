"""Named purposes of the covering HTTP authorization profile."""

from enum import StrEnum


class HTTPPurpose(StrEnum):
    SUBMIT = "submit"
    POLL = "poll"
    CANCEL = "cancel"
    ENROLLMENT_START = "enrollment_start"
    ENROLLMENT_MATERIAL = "enrollment_material"
    ENROLLMENT_CONFIRM = "enrollment_confirm"
    ENROLLMENT_ACTIVATE = "enrollment_activate"
    BINDING_REFRESH = "binding_refresh"
