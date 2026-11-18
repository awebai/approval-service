"""Authenticated current-person transport for the active binding refresh owner."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Protocol

from fastapi import Request
from jsonschema import ValidationError

from .binding_refresh import (
    BindingRefresher,
    RefreshFailure,
    RefreshRefused,
    RequesterKind,
)
from .canonical import canonical
from .http_io import read_json_body
from .http_purpose import HTTPPurpose
from .public import PublicReader
from .requester import AdmittedRequester
from .seams import check_http
from .store import Store
from .verify import Refused
from .wire import validate

logger = logging.getLogger(__name__)


class RequesterBudget(Protocol):
    def take(self, key: tuple[str, str], limit: int) -> None: ...


@dataclass(frozen=True, kw_only=True)
class BindingRefreshEndpoint:
    store: Store
    public: PublicReader
    origin: str
    rp_id: str
    rates: RequesterBudget

    async def handle(self, request: Request) -> dict:
        try:
            return await self._refresh(request)
        except RefreshRefused as error:
            logger.info("binding refresh refused (%s)", error.code)
            raise
        except ValidationError as error:
            raise RefreshRefused(RefreshFailure.REQUEST_INVALID) from error
        except Refused as error:
            logger.info("binding refresh refused (%s)", error.code)
            if error.code.endswith("_unavailable"):
                raise RefreshRefused(RefreshFailure.UNAVAILABLE) from error
            if error.code.startswith("body_"):
                raise RefreshRefused(RefreshFailure.REQUEST_INVALID) from error
            raise RefreshRefused(RefreshFailure.AUTHORIZATION) from error

    async def _refresh(self, request: Request) -> dict:
        """Covering signature and both budgets precede the shared public read.

        binding-refresh-v1.json permits only the committed current person as
        carrier; issuer signature alone cannot admit an administrator here.
        """
        raw, packet = await read_json_body(request)
        validate("binding_refresh_request", packet)
        descriptor = packet["requester"]
        headers = request.headers.getlist("authorization")
        if len(headers) != 1:
            raise RefreshRefused(RefreshFailure.AUTHORIZATION)
        check_http(
            headers[0],
            raw,
            requester=descriptor,
            origin=self.origin,
            method=request.method,
            path=request.url.path,
            purpose=HTTPPurpose.BINDING_REFRESH,
            now=int(time.time()),
        )
        self.rates.take(("requester", descriptor["key"]), 32)
        binding = packet["binding"]["binding"]
        if descriptor != {
            "kind": RequesterKind.IDENTITY,
            "id": binding["person"],
            "key": binding["identity_key"],
        }:
            raise RefreshRefused(RefreshFailure.REQUESTER)
        if binding["origin"] != self.origin or binding["rp_id"] != self.rp_id:
            raise RefreshRefused(RefreshFailure.SITE_CHANGED)
        trust = await self.public.person(
            packet["id_chain"],
            person=binding["person"],
            identity_key=binding["identity_key"],
            organisation=binding["organisation"],
        )
        carrier = AdmittedRequester(
            canonical(descriptor), trust.identity_key, trust.observed_at
        )
        return await BindingRefresher(self.store).refresh(
            packet, trust=trust, carrier=carrier
        )
