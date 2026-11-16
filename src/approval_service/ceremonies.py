"""Service-local LOGIN and exact-act ceremonies. No roles or external effects.

Network evidence is obtained before entering these transactions. Original
bounds and observation ages are checked after the last database write too, so
a lock wait cannot extend a session, challenge or request's authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time

from jsonschema import ValidationError
from webauthn import verify_authentication_response
from webauthn.helpers.exceptions import WebAuthnException

from .canonical import canonical, parse
from .client_data import verify_client_data
from .encoding import decode, encode
from .verify import Refused, verify_historical
from .wire import domain, validate, validate_site


def commitment(value):
    if type(value) is not str or not 1 <= len(value) <= 128 or (not value.isascii()):
        raise Refused("session_token_invalid")
    return hashlib.sha256(value.encode("ascii")).hexdigest()


class Ceremonies:
    def __init__(
        self, store, *, origin, rp_id, session_seconds=900, challenge_seconds=120
    ):
        validate_site(origin, rp_id)
        self.store = store
        self.origin = origin
        self.rp_id = rp_id
        if not 1 <= session_seconds <= 900 or not 1 <= challenge_seconds <= 120:
            raise ValueError("ceremony bounds")
        self.session_seconds = session_seconds
        self.challenge_seconds = challenge_seconds

    async def _enrollment(self, conn, person):
        row = await conn.fetch_one(
            "SELECT * FROM {{tables.approval_enrollments}} WHERE person_id=$1 FOR UPDATE",
            person,
        )
        if row is None or row["state"] != "active":
            raise Refused("enrollment_not_active")
        version = await conn.fetch_one(
            "SELECT * FROM {{tables.approval_binding_versions}} WHERE digest=$1 AND person_id=$2",
            row["binding_ref"],
            person,
        )
        if version is None:
            raise Refused("binding_unavailable")
        version = {
            **version,
            "binding": json.loads(version["binding"]),
            "id_chain": json.loads(version["id_chain"]),
        }
        body = version["binding"]["binding"]
        if body["origin"] != self.origin or body["rp_id"] != self.rp_id:
            raise Refused("origin_invalid")
        return {**row, "_binding_version": version}

    @staticmethod
    async def _credential(conn, person, credential_id):
        row = await conn.fetch_one(
            "SELECT * FROM {{tables.approval_credentials}} WHERE person_id=$1 AND credential_id=$2 AND NOT retired FOR UPDATE",
            person,
            credential_id,
        )
        if row is None:
            raise Refused("credential_not_enrolled")
        return row

    @staticmethod
    def _bounds(
        now,
        *,
        trust=None,
        session=None,
        challenge=None,
        request=None,
        requester=None,
        covered=None,
    ):
        if covered is not None and (
            not covered["not_before"] <= now < covered["deadline"]
        ):
            raise Refused("request_expired")
        if trust is not None and (not 0 <= now - trust.observed_at <= 60):
            raise Refused("status_unavailable")
        if requester is not None and (not 0 <= now - requester.observed_at <= 60):
            raise Refused("requester_status_unavailable")
        if session is not None and (session["retired"] or now >= session["deadline"]):
            raise Refused("session_expired")
        if challenge is not None and (
            challenge["consumed"]
            or not challenge["issued_at"] <= now < challenge["deadline"]
        ):
            raise Refused("challenge_expired")
        if request is not None and (
            request["outcome"] != "pending" or now >= request["deadline"]
        ):
            raise Refused("request_expired")

    @staticmethod
    def _bind_enrollment(enrollment, trust):
        if (
            enrollment["person_id"],
            enrollment["organisation"],
            enrollment["identity_key"],
            enrollment["certificate"],
        ) != (trust.person, trust.organisation, trust.identity_key, trust.certificate):
            raise Refused("enrollment_identity_changed")

    async def _session(self, conn, token, csrf, person, enrollment):
        session = await conn.fetch_one(
            "SELECT * FROM {{tables.approval_sessions}} WHERE token_hash=$1 AND person_id=$2 FOR UPDATE",
            commitment(token),
            person,
        )
        if session is None or session["identity_key"] != enrollment["identity_key"]:
            raise Refused("session_invalid")
        if not hmac.compare_digest(commitment(csrf), session["csrf_hash"]):
            raise Refused("csrf_invalid")
        return session

    async def _issue(
        self,
        conn,
        person,
        purpose,
        challenge,
        now,
        deadline,
        *,
        session_hash=None,
        operation_id=None,
    ):
        identifier = secrets.token_urlsafe(32)
        await conn.execute(
            "INSERT INTO {{tables.approval_challenges}}(challenge_id,person_id,purpose,operation_id,session_hash,challenge,issued_at,deadline) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            identifier,
            person,
            purpose,
            operation_id,
            session_hash,
            challenge,
            now,
            deadline,
        )
        return {
            "id": identifier,
            "challenge": encode(challenge),
            "rpId": self.rp_id,
            "userVerification": "required",
            "deadline": deadline,
        }

    async def login_options(self, person, trust):
        async with self.store.transaction() as conn:
            enrollment = await self._enrollment(conn, person)
            self._bind_enrollment(enrollment, trust)
            now = int(time.time())
            self._bounds(now, trust=trust)
            challenge = hashlib.sha256(
                b"aweb.human-approval-login/1\n" + secrets.token_bytes(32)
            ).digest()
            result = await self._issue(
                conn, person, "login", challenge, now, now + self.challenge_seconds
            )
            credentials = await conn.fetch_all(
                "SELECT credential_id FROM {{tables.approval_credentials}} WHERE person_id=$1 AND NOT retired ORDER BY credential_id LIMIT 8",
                person,
            )
            if not credentials:
                raise Refused("credential_not_enrolled")
            result["allowCredentials"] = [
                {"type": "public-key", "id": r["credential_id"]} for r in credentials
            ]
            self._bounds(int(time.time()), trust=trust)
            return result

    @staticmethod
    async def _challenge(conn, identifier, person, purpose):
        row = await conn.fetch_one(
            "SELECT * FROM {{tables.approval_challenges}} WHERE challenge_id=$1 AND person_id=$2 AND purpose=$3 FOR UPDATE",
            identifier,
            person,
            purpose,
        )
        if row is None:
            raise Refused("challenge_not_found")
        return row

    def _assertion(self, assertion, credential, challenge):
        validate("assertion", assertion)
        verify_client_data(
            decode(assertion["client_data_json"]),
            expected_type="webauthn.get",
            expected_challenge=bytes(challenge),
            expected_origin=self.origin,
        )
        result = verify_authentication_response(
            credential={
                "id": assertion["id"],
                "rawId": assertion["id"],
                "type": "public-key",
                "response": {
                    "clientDataJSON": assertion["client_data_json"],
                    "authenticatorData": assertion["authenticator_data"],
                    "signature": assertion["signature"],
                },
            },
            expected_challenge=bytes(challenge),
            expected_rp_id=self.rp_id,
            expected_origin=self.origin,
            credential_public_key=bytes(credential["public_key"]),
            credential_current_sign_count=credential["sign_count"],
            require_user_verification=True,
        )
        if result.credential_id != decode(credential["credential_id"]):
            raise Refused("credential_not_enrolled")
        return result.new_sign_count

    async def finish_login(self, person, identifier, assertion, trust):
        try:
            async with self.store.transaction() as conn:
                enrollment = await self._enrollment(conn, person)
                self._bind_enrollment(enrollment, trust)
                challenge = await self._challenge(conn, identifier, person, "login")
                credential = await self._credential(conn, person, assertion["id"])
                self._bounds(int(time.time()), trust=trust, challenge=challenge)
                counter = self._assertion(assertion, credential, challenge["challenge"])
                token = secrets.token_urlsafe(32)
                csrf = secrets.token_urlsafe(32)
                now = int(time.time())
                deadline = now + self.session_seconds
                await conn.execute(
                    "UPDATE {{tables.approval_credentials}} SET sign_count=$1 WHERE person_id=$2 AND credential_id=$3",
                    counter,
                    person,
                    credential["credential_id"],
                )
                await conn.execute(
                    "UPDATE {{tables.approval_challenges}} SET consumed=true WHERE challenge_id=$1",
                    identifier,
                )
                await conn.execute(
                    "INSERT INTO {{tables.approval_sessions}}(token_hash,person_id,identity_key,credential_id,csrf_hash,deadline) VALUES($1,$2,$3,$4,$5,$6)",
                    commitment(token),
                    person,
                    enrollment["identity_key"],
                    credential["credential_id"],
                    commitment(csrf),
                    deadline,
                )
                self._bounds(int(time.time()), trust=trust, challenge=challenge)
                return {"session": token, "csrf": csrf, "deadline": deadline}
        except (
            ValueError,
            TypeError,
            KeyError,
            WebAuthnException,
            ValidationError,
        ) as exc:
            if isinstance(exc, Refused):
                raise
            raise Refused("login_assertion_invalid") from exc

    async def approval_options(
        self, person, operation_id, session_token, csrf, trust, requester
    ):
        async with self.store.transaction() as conn:
            enrollment = await self._enrollment(conn, person)
            self._bind_enrollment(enrollment, trust)
            session = await self._session(conn, session_token, csrf, person, enrollment)
            await self._credential(conn, person, session["credential_id"])
            request = await conn.fetch_one(
                "SELECT * FROM {{tables.approval_requests}} WHERE operation_id=$1 AND person_id=$2 FOR UPDATE",
                operation_id,
                person,
            )
            if request is None or request["requester_hash"] != requester.commitment:
                raise Refused("request_not_found")
            now = int(time.time())
            self._bounds(
                now, trust=trust, session=session, request=request, requester=requester
            )
            raw = bytes(request["request_bytes"])
            r = parse(raw)
            if r["purpose"] != "act_approval" or raw != canonical(r):
                raise Refused("purpose_invalid")
            self._bounds(
                int(time.time()),
                trust=trust,
                session=session,
                request=request,
                requester=requester,
                covered=r,
            )
            challenge = hashlib.sha256(domain("request") + raw).digest()
            if challenge.hex() != request["digest"]:
                raise Refused("request_digest_mismatch")
            result = await self._issue(
                conn,
                person,
                "approval",
                challenge,
                now,
                min(
                    request["deadline"],
                    session["deadline"],
                    now + self.challenge_seconds,
                ),
                session_hash=commitment(session_token),
                operation_id=operation_id,
            )
            self._bounds(
                int(time.time()),
                trust=trust,
                session=session,
                request=request,
                requester=requester,
                covered=r,
            )
            return result

    async def finish_approval(
        self,
        person,
        operation_id,
        identifier,
        assertion,
        session_token,
        csrf,
        trust,
        requester,
    ):
        try:
            async with self.store.transaction() as conn:
                enrollment = await self._enrollment(conn, person)
                self._bind_enrollment(enrollment, trust)
                session = await self._session(
                    conn, session_token, csrf, person, enrollment
                )
                request = await conn.fetch_one(
                    "SELECT * FROM {{tables.approval_requests}} WHERE operation_id=$1 AND person_id=$2 FOR UPDATE",
                    operation_id,
                    person,
                )
                if request is None or request["requester_hash"] != requester.commitment:
                    raise Refused("request_not_found")
                challenge = await self._challenge(conn, identifier, person, "approval")
                if challenge["operation_id"] != operation_id or challenge[
                    "session_hash"
                ] != commitment(session_token):
                    raise Refused("challenge_binding_mismatch")
                credential = await self._credential(conn, person, assertion["id"])
                await self._credential(conn, person, session["credential_id"])
                self._bounds(
                    int(time.time()),
                    trust=trust,
                    session=session,
                    challenge=challenge,
                    request=request,
                    requester=requester,
                )
                version = enrollment["_binding_version"]
                raw = bytes(request["request_bytes"])
                r = parse(raw)
                if r["purpose"] != "act_approval":
                    raise Refused("purpose_invalid")
                binding = version["binding"]
                body = binding["binding"]
                if body["origin"] != self.origin or body["rp_id"] != self.rp_id:
                    raise Refused("origin_invalid")
                receipt = {
                    "version": 1,
                    "request_bytes": encode(raw),
                    "binding": binding,
                    "id_chain": version["id_chain"],
                    "assertion": assertion,
                }
                checked = verify_historical(receipt, expected_request=r, trust=trust)
                if checked.digest != request["digest"]:
                    raise Refused("request_digest_mismatch")
                selected = next(
                    c for c in body["credentials"] if c["id"] == assertion["id"]
                )
                if (
                    decode(selected["key"]),
                    selected["grade"],
                    selected["snapshot"],
                ) != (
                    bytes(credential["public_key"]),
                    credential["grade"],
                    credential["snapshot"],
                ):
                    raise Refused("binding_credential_mismatch")
                counter = self._assertion(assertion, credential, challenge["challenge"])
                self._bounds(
                    int(time.time()),
                    trust=trust,
                    session=session,
                    challenge=challenge,
                    request=request,
                    requester=requester,
                    covered=r,
                )
                await conn.execute(
                    "UPDATE {{tables.approval_credentials}} SET sign_count=$1 WHERE person_id=$2 AND credential_id=$3",
                    counter,
                    person,
                    credential["credential_id"],
                )
                await conn.execute(
                    "UPDATE {{tables.approval_challenges}} SET consumed=true WHERE challenge_id=$1",
                    identifier,
                )
                # The receipt verifier and the real UV assertion ran above.
                await self.store._terminal(
                    conn,
                    request,
                    "approved",
                    int(time.time()),
                    assertion,
                    version["digest"],
                )
                self._bounds(
                    int(time.time()),
                    trust=trust,
                    session=session,
                    challenge=challenge,
                    request=request,
                    requester=requester,
                    covered=r,
                )
                # No awaited read/write remains after this check: a SQL lock wait
                # cannot renew the original request, session or evidence lifetime.
                return {"digest": checked.digest, "outcome": "approved"}
        except (
            ValueError,
            TypeError,
            KeyError,
            WebAuthnException,
            ValidationError,
        ) as exc:
            if isinstance(exc, Refused):
                raise
            raise Refused("approval_assertion_invalid") from exc
