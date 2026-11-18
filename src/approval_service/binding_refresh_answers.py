"""Read the additive refresh result without interpreting historical evidence."""

from jsonschema import ValidationError

from .answers import ServiceError
from .seams import commitment
from .verify import Refused
from .wire import validate


class BindingRefreshServiceError(ServiceError):
    def __init__(self, *, code: str, status: int, advice: str | None):
        super().__init__(code, status)
        self.advice = advice


def read_binding_refresh_answer(body: dict, *, status: int, binding: dict) -> dict:
    """binding-refresh-v1.json: the result commits to the submitted signed B."""
    try:
        if status >= 400:
            validate("binding_refresh_error", body)
            raise BindingRefreshServiceError(
                code=body["error"]["code"],
                status=status,
                advice=body["error"].get("message"),
            )
        if status != 200:
            raise Refused("service_response_invalid")
        validate("binding_refresh_answer", body)
        validate("binding", binding)
        if body["person"] != binding["binding"]["person"]:
            raise Refused("person_mismatch")
        if body["binding_commitment"] != commitment("binding_commitment", binding):
            raise Refused("binding_mismatch")
        return body
    except Refused:
        raise
    except (ValidationError, ValueError, TypeError, KeyError) as error:
        raise Refused("service_response_invalid") from error
