"""awsign's requester transport and same-origin browser ceremonies.

The application is composed with a configured registry and a process-owned
pool. Enforcers never contact it. No supplied URL selects a public trust read.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import OrderedDict
from importlib.resources import files

from asyncpg import UniqueViolationError
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from jsonschema import ValidationError

from .canonical import canonical, parse
from .ceremonies import Ceremonies
from .ceremonies import commitment as token_commitment
from .definitions import check_definition
from .encoding import decode
from .enrollment import Enrollments
from .seams import check_http, commitment
from .store import StoreRefused
from .verify import Refused
from .wire import SCHEMA, domain, validate, validate_site

logger = logging.getLogger(__name__)
SESSION_COOKIE = "__Host-awsign"


class RateWindow:
    """Bound work before public reads; this is not an authority cache."""

    def __init__(self, capacity=4096):
        self.rows = OrderedDict()
        self.capacity = capacity

    def take(self, key, limit):
        minute = int(time.monotonic()) // 60
        old, count = self.rows.get(key, (minute, 0))
        count = count + 1 if old == minute else 1
        if count > limit:
            raise Refused("rate_limited")
        self.rows[key] = (minute, count)
        self.rows.move_to_end(key)
        while len(self.rows) > self.capacity:
            self.rows.popitem(last=False)


def create_app(store, *, public, origin, rp_id, grading):
    validate_site(origin, rp_id)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    ceremonies = Ceremonies(store, origin=origin, rp_id=rp_id)
    enrollments = Enrollments(store, origin=origin, rp_id=rp_id, grading=grading)
    rates = RateWindow()
    app.state.store = store
    app.state.enrollments = enrollments

    @app.middleware("http")
    async def boundary(request, call_next):
        try:
            response = await call_next(request)
        except (Refused, StoreRefused) as exc:
            code = exc.code
            status = (
                429
                if code == "rate_limited"
                else 503
                if code.endswith("_unavailable")
                else 403
                if code
                in (
                    "origin_invalid",
                    "csrf_invalid",
                    "session_invalid",
                    "session_expired",
                )
                or code.startswith("requester_")
                else 404
                if code.endswith("_not_found")
                else 400
            )
            response = JSONResponse(
                {"version": 1, "error": {"code": code}}, status_code=status
            )
        except UniqueViolationError:
            response = JSONResponse(
                {"version": 1, "error": {"code": "credential_conflict"}},
                status_code=400,
            )
        except Exception as exc:  # noqa: BLE001 — final HTTP boundary must retain the closed body and headers.
            # Query exceptions may carry private act parameters. Record type and
            # SQLSTATE, never serialize exception objects, bodies or credentials.
            cause = getattr(exc, "original_error", None) or exc.__cause__ or exc
            logger.error(
                "awsign request failed: type=%s cause=%s sqlstate=%s constraint=%s",
                type(exc).__name__,
                type(cause).__name__,
                getattr(cause, "sqlstate", None),
                getattr(cause, "constraint_name", None),
            )
            response = JSONResponse(
                {"version": 1, "error": {"code": "internal_error"}}, status_code=500
            )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    async def body(request, fields=None):
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
                        type(value[field]) is not str
                        or not 1 <= len(value[field]) <= 4096
                    ):
                        raise Refused("body_invalid")
            return raw, value
        except (ValueError, TypeError, KeyError) as exc:
            raise Refused("body_invalid") from exc

    def browser_origin(request):
        if request.headers.getlist("origin") != [origin]:
            raise Refused("origin_invalid")
        rates.take(("browser", request.client.host), 60)

    def request_value(value):
        raw = decode(value["request_bytes"])
        r = parse(raw)
        check_definition(r)
        if raw != canonical(r):
            raise Refused("request_mismatch")
        return raw, r

    async def current_session(request, csrf=None):
        token = request.cookies.get(SESSION_COOKIE, "")
        row = await store.db.fetch_one(
            """SELECT s.*,e.organisation,e.state,e.certificate,v.id_chain
            FROM {{tables.approval_sessions}} s JOIN {{tables.approval_enrollments}} e ON e.person_id=s.person_id AND e.organisation=s.organisation
            JOIN {{tables.approval_binding_versions}} v ON v.digest=e.binding_ref AND v.organisation=e.organisation AND v.person_id=e.person_id
            WHERE s.token_hash=$1""",
            token_commitment(token),
        )
        if row is None or row["state"] != "active":
            raise Refused("session_invalid")
        trust = await public.person(
            json.loads(row["id_chain"]),
            person=row["person_id"],
            identity_key=row["identity_key"],
            organisation=row["organisation"],
        )
        row = await store.db.fetch_one(
            """SELECT s.*,e.state FROM {{tables.approval_sessions}} s
            JOIN {{tables.approval_enrollments}} e ON e.person_id=s.person_id AND e.organisation=s.organisation
            JOIN {{tables.approval_credentials}} c ON c.person_id=s.person_id AND c.organisation=s.organisation AND c.credential_id=s.credential_id
            WHERE s.token_hash=$1 AND e.state='active' AND e.identity_key=s.identity_key AND NOT c.retired""",
            token_commitment(token),
        )
        if row is None:
            raise Refused("session_invalid")
        Ceremonies._bounds(int(time.time()), trust=trust, session=row)
        if csrf is not None and token_commitment(csrf) != row["csrf_hash"]:
            raise Refused("csrf_invalid")
        return token, row, trust

    async def pending_context(request, value):
        token, session, trust = await current_session(request, value["csrf"])
        row = await store.db.fetch_one(
            "SELECT * FROM {{tables.approval_requests}} WHERE operation_id=$1 AND person_id=$2 AND organisation=$3",
            value["locator"],
            trust.person,
            trust.organisation,
        )
        if row is None or row["request_bytes"] is None or row["admission"] is None:
            raise Refused("request_not_found")
        r = parse(bytes(row["request_bytes"]))
        caller = await public.requester(
            r["requester"],
            organisation=r["organisation"],
            admission=json.loads(row["admission"]),
        )
        Ceremonies._bounds(
            int(time.time()),
            trust=trust,
            requester=caller,
            session=session,
            request=row,
            covered=r,
        )
        return token, trust, caller

    async def requester_route(request, purpose):
        raw, value = await body(request)
        try:
            schema = {
                "submit": "submission",
                "poll": "selection",
                "cancel": "selection",
                "enrollment_start": "enrollment_start",
                "enrollment_material": "enrollment_material_request",
                "enrollment_confirm": "enrollment_confirm_request",
                "enrollment_activate": "enrollment_activation",
            }[purpose]
            validate(schema, value)
            intent = value.get("intent")
            if intent is None:
                original, r = request_value(value)
                descriptor = r["requester"]
                organisation = r["organisation"]
                admission = value["admission"]
            else:
                i = intent["intent"]
                descriptor = i["requester"]
                organisation = i["organisation"]
                admission = value.get("admission")
            headers = request.headers.getlist("authorization")
            if len(headers) != 1:
                raise Refused("http_invalid")
            check_http(
                headers[0],
                raw,
                requester=descriptor,
                origin=origin,
                method=request.method,
                path=request.url.path,
                purpose=purpose,
                now=int(time.time()),
            )
        except (ValueError, TypeError, KeyError, ValidationError) as exc:
            if isinstance(exc, Refused):
                raise
            raise Refused("body_invalid") from exc
        rates.take(
            ("requester", hashlib.sha256(canonical(descriptor)).hexdigest()),
            120
            if purpose in ("poll", "enrollment_material", "enrollment_confirm")
            else 32,
        )
        if admission is None:
            locator = commitment("enrollment_locator", intent)
            row = await store.db.fetch_one(
                "SELECT admission FROM {{tables.approval_enrollments}} WHERE enrollment_locator=$1",
                locator,
            )
            if row is None or row["admission"] is None:
                raise Refused("enrollment_not_found")
            admission = json.loads(row["admission"])
        caller = await public.requester(
            descriptor, organisation=organisation, admission=admission, intent=intent
        )
        if intent is not None:
            if purpose == "enrollment_activate":
                b = value["binding"]["binding"]
                trust = await public.person(
                    value["id_chain"],
                    person=b["person"],
                    identity_key=b["identity_key"],
                    organisation=b["organisation"],
                )
                return await enrollments.activate(value, trust=trust, requester=caller)
            issuer = await public.issuer(intent)
            if purpose == "enrollment_start":
                return await enrollments.start(
                    intent, issuer=issuer, requester=caller, admission=admission
                )
            if purpose == "enrollment_material":
                return await enrollments.material(
                    intent, issuer=issuer, requester=caller
                )
            return await enrollments.confirm(value, issuer=issuer, requester=caller)
        digest = hashlib.sha256(domain("request") + original).hexdigest()
        if purpose == "submit":
            if r["purpose"] != "act_approval":
                raise Refused("purpose_invalid")
            Ceremonies._bounds(int(time.time()), requester=caller, covered=r)
            row = await store.prepare(
                "req-" + secrets_token(),
                digest,
                caller.commitment,
                r["approver"],
                original,
                int(time.time()),
                r["deadline"],
                admission=admission,
                organisation=r["organisation"],
            )
        else:
            if value["digest"] != digest:
                raise Refused("request_digest_mismatch")
            if purpose == "cancel":
                row = await store.cancel(
                    value["locator"],
                    digest,
                    caller.commitment,
                    int(time.time()),
                    organisation=r["organisation"],
                    person_id=r["approver"],
                )
            else:
                row = await store.poll(
                    value["locator"],
                    digest,
                    caller.commitment,
                    int(time.time()),
                    organisation=r["organisation"],
                    person_id=r["approver"],
                )
        Ceremonies._bounds(int(time.time()), requester=caller)
        if purpose == "poll":
            answer = await store.decision_answer(row, row["operation_id"])
            Ceremonies._bounds(int(time.time()), requester=caller)
            return answer
        return {
            "version": 1,
            "locator": row["operation_id"],
            "digest": row["digest"],
            "deadline": row["deadline"],
            "state": row["outcome"],
        }

    def route(purpose):
        async def handle(request: Request):
            return await requester_route(request, purpose)

        return handle

    for purpose, path in SCHEMA["x-http"]["routes"].items():
        app.add_api_route(path, route(purpose), methods=["POST"])

    @app.post("/browser/login/options")
    async def login_options(request: Request):
        browser_origin(request)
        await body(request, ())
        return await ceremonies.login_options()

    @app.post("/browser/login/finish")
    async def login_finish(request: Request):
        browser_origin(request)
        _, v = await body(request, ("id", "assertion", "user_handle"))
        subject = await ceremonies.login_subject(v["assertion"], v["user_handle"])
        trust = await public.person(
            subject["id_chain"],
            person=subject["person"],
            identity_key=subject["identity_key"],
            organisation=subject["organisation"],
        )
        session = await ceremonies.finish_login(
            v["id"], v["assertion"], v["user_handle"], trust
        )
        response = JSONResponse(
            {
                "csrf": session["csrf"],
                "person": trust.person,
                "deadline": session["deadline"],
            }
        )
        response.set_cookie(
            SESSION_COOKIE,
            session["session"],
            secure=True,
            httponly=True,
            samesite="strict",
            path="/",
            max_age=max(0, session["deadline"] - int(time.time())),
        )
        return response

    @app.get("/browser/pending")
    async def pending(request: Request):
        _token, session, trust = await current_session(request)
        rows = await store.pending(
            trust.person, organisation=trust.organisation, now=int(time.time())
        )
        result = []
        for row in rows:
            r = parse(bytes(row["request_bytes"]))
            d = check_definition(r)
            result.append(
                {
                    "locator": row["operation_id"],
                    "digest": row["digest"],
                    "request": r,
                    "display": d["display"],
                }
            )
        await current_session(request)
        Ceremonies._bounds(int(time.time()), trust=trust, session=session)
        return {"person": trust.person, "requests": result}

    @app.post("/browser/approval/options")
    async def approval_options(request: Request):
        browser_origin(request)
        _, v = await body(request, ("locator", "csrf"))
        token, trust, caller = await pending_context(request, v)
        return await ceremonies.approval_options(
            trust.person, v["locator"], token, v["csrf"], trust, caller
        )

    @app.post("/browser/approval/finish")
    async def approval_finish(request: Request):
        browser_origin(request)
        _, v = await body(request, ("locator", "csrf", "id", "assertion"))
        token, trust, caller = await pending_context(request, v)
        return await ceremonies.finish_approval(
            trust.person,
            v["locator"],
            v["id"],
            v["assertion"],
            token,
            v["csrf"],
            trust,
            caller,
        )

    @app.post("/browser/approval/deny")
    async def approval_deny(request: Request):
        browser_origin(request)
        _, v = await body(request, ("locator", "csrf"))
        token, trust, caller = await pending_context(request, v)
        return await ceremonies.deny(
            trust.person, v["locator"], token, v["csrf"], trust, caller
        )

    @app.post("/browser/enrollment/options")
    async def enrollment_options(request: Request):
        browser_origin(request)
        _, v = await body(request, ("locator",))
        return await enrollments.browser_options(v["locator"])

    @app.post("/browser/enrollment/register")
    async def registration_finish(request: Request):
        browser_origin(request)
        _, v = await body(
            request, ("locator", "csrf", "registration", "client_extension_results")
        )
        return await enrollments.register(
            v["locator"], v["csrf"], v["registration"], v["client_extension_results"]
        )

    @app.post("/browser/enrollment/confirmation/options")
    async def confirmation_options(request: Request):
        browser_origin(request)
        _, v = await body(request, ("locator", "csrf"))
        return await enrollments.confirmation_options(v["locator"], v["csrf"])

    @app.post("/browser/enrollment/confirmation/finish")
    async def confirmation_finish(request: Request):
        browser_origin(request)
        _, v = await body(request, ("locator", "csrf", "id", "assertion"))
        row = await store.db.fetch_one(
            "SELECT intent FROM {{tables.approval_enrollments}} WHERE enrollment_locator=$1",
            v["locator"],
        )
        if row is None or row["intent"] is None:
            raise Refused("enrollment_not_found")
        issuer = await public.issuer(json.loads(row["intent"]))
        return await enrollments.finish_confirmation(
            v["locator"], v["csrf"], v["id"], v["assertion"], issuer=issuer
        )

    @app.get("/health")
    async def health():
        await store.db.fetch_one("SELECT 1 AS ok")
        status = grading.status()
        return JSONResponse(status, status_code=200)

    @app.get("/assets/app.mjs")
    async def script():
        return Response(
            files("approval_service").joinpath("assets/app.mjs").read_text(),
            media_type="text/javascript",
        )

    @app.get("/")
    @app.get("/enroll")
    async def page():
        return HTMLResponse(
            files("approval_service").joinpath("assets/index.html").read_text()
        )

    return app


def secrets_token():
    import secrets

    return secrets.token_urlsafe(24)
