"""Mount the compiled, purpose-bound requester routes in one place."""

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request

from .http_purpose import HTTPPurpose
from .wire import SCHEMA

Endpoint = Callable[[Request], Awaitable[dict]]


def mount_requester_routes(
    app: FastAPI, *, route_factory: Callable[[HTTPPurpose], Endpoint]
) -> None:
    """Each covering proof binds its compiled method/path: protocol.md section6."""
    for purpose, path in SCHEMA["x-http"]["routes"].items():
        app.add_api_route(path, route_factory(HTTPPurpose(purpose)), methods=["POST"])
