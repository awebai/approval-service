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
    return JSONResponse({"version": 1, "error": {"code": code}}, status_code=status)
