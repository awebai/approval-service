"""One closed status/body projection for deliberate service refusals."""

from enum import StrEnum
from http import HTTPStatus

from fastapi.responses import JSONResponse

from .store import StoreRefused
from .verify import Refused


class ForbiddenFailure(StrEnum):
    ORIGIN = "origin_invalid"
    CSRF = "csrf_invalid"
    SESSION_INVALID = "session_invalid"
    SESSION_EXPIRED = "session_expired"


class RateFailure(StrEnum):
    LIMITED = "rate_limited"


class AdvisedRefused(Refused):
    """A refusal with controlled next-step text, never an echoed request body."""

    def __init__(self, *, reason: StrEnum, advice: str):
        self.reason = reason
        self.message = advice
        super().__init__(reason.value)


def refusal_response(error: Refused | StoreRefused) -> JSONResponse:
    """Keep requester, unavailable and absence outcomes distinct and closed."""
    code = error.code
    status = (
        HTTPStatus.TOO_MANY_REQUESTS
        if code == RateFailure.LIMITED
        else HTTPStatus.SERVICE_UNAVAILABLE
        if code.endswith("_unavailable")
        else HTTPStatus.FORBIDDEN
        if code in frozenset(ForbiddenFailure) or code.startswith("requester_")
        else HTTPStatus.NOT_FOUND
        if code.endswith("_not_found")
        else HTTPStatus.BAD_REQUEST
    )
    details = {"code": code}
    if isinstance(error, AdvisedRefused):
        details["message"] = error.message
    return JSONResponse({"version": 1, "error": details}, status_code=status)
