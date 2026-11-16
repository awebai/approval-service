"""Pending WebAuthn enrollment, limited confirmation, then public activation.

No pending flag is identity authority. The issuer checks the same raw create
response and its own confirmation nonce; only committed public Trust activates.
"""

from __future__ import annotations

import hmac
import json
import secrets
import time
from dataclasses import dataclass

from awid.did import public_key_from_did

from .answers import read_enrollment_request
from .canonical import canonical, parse
from .ceremonies import Ceremonies
from .ceremonies import commitment as token_commitment
from .encoding import decode, encode
from .seams import (
    _creation_assertion,
    check_activation,
    check_enrollment_intent,
    commitment,
)
from .store import request_row
from .verify import Refused, Trust
from .wire import SCHEMA, validate


@dataclass(frozen=True)
class PublicIssuer:
    """An independently checked public issuer observation, never HTTP input."""

    key: str
    observed_at: int


class Enrollments:
    def __init__(self, store, *, origin, rp_id, grading):
        self.store = store
        self.ceremonies = Ceremonies(store, origin=origin, rp_id=rp_id)
        self.origin, self.rp_id, self.grading = origin, rp_id, grading

    @staticmethod
    def _bounds(row, *, issuer=None, requester=None, browser=False):
        now = int(time.time())
        Ceremonies._bounds(now, trust=issuer, requester=requester)
        if now >= row["deadline"]:
            raise Refused("enrollment_expired")
        if browser and now >= row["browser_deadline"]:
            raise Refused("enrollment_browser_expired")

    def _check(self, intent, issuer, requester):
        Ceremonies._bounds(int(time.time()), trust=issuer, requester=requester)
        return check_enrollment_intent(
            intent,
            issuer_key=issuer.key,
            requester=parse(requester.descriptor_bytes),
            origin=self.origin,
            rp_id=self.rp_id,
            now=int(time.time()),
        )

    async def _row(self, tx, locator, *, pending=True):
        row = await tx.fetch_one(
            "SELECT * FROM {{tables.approval_enrollments}} WHERE enrollment_locator=$1 FOR UPDATE",
            locator,
        )
        if row is None:
            raise Refused("enrollment_not_found")
        if pending and row["state"] != "pending":
            raise Refused("enrollment_not_pending")
        self._bounds(row)
        return row

    def _browser(self, row, csrf):
        if row["browser_hash"] is None or not hmac.compare_digest(
            row["browser_hash"], token_commitment(csrf)
        ):
            raise Refused("csrf_invalid")
        self._bounds(row, browser=True)

    @staticmethod
    def _options(row):
        i = json.loads(row["intent"])["intent"]
        return {
            "challenge": i["challenge"],
            "rp": {"id": i["rp_id"], "name": "awsign"},
            "user": {
                "id": encode(bytes(row["user_handle"])),
                "name": i["person"],
                "displayName": i["person"],
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": a}
                for a in SCHEMA["$defs"]["credential"]["properties"]["algorithm"][
                    "enum"
                ]
            ],
            "timeout": 120000,
            "authenticatorSelection": {
                "residentKey": "required",
                "requireResidentKey": True,
                "userVerification": "required",
            },
            "attestation": "direct",
            "extensions": {"credProps": True},
        }

    async def start(self, intent, *, issuer, requester):
        checked = self._check(intent, issuer, requester)
        i = intent["intent"]
        async with self.store.transaction() as tx:
            await tx.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", i["person"]
            )
            old = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_enrollments}} WHERE person_id=$1 FOR UPDATE",
                i["person"],
            )
            if old is None:
                count = await tx.fetch_one(
                    "SELECT count(*) AS n FROM {{tables.approval_enrollments}} WHERE requester_hash=$1 AND state='pending' AND deadline>$2",
                    requester.commitment,
                    int(time.time()),
                )
                if count["n"] >= 32:
                    raise Refused("pending_limit")
                old = await tx.fetch_one(
                    """INSERT INTO {{tables.approval_enrollments}}
                    (person_id,organisation,identity_key,certificate,issuer,user_handle,deadline,state,enrollment_locator,intent,requester_hash)
                    VALUES($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9::jsonb,$10) RETURNING *""",
                    i["person"],
                    i["organisation"],
                    checked["identity_key"],
                    checked["certificate"],
                    issuer.key,
                    secrets.token_bytes(32),
                    i["deadline"],
                    checked["locator"],
                    json.dumps(intent),
                    requester.commitment,
                )
            elif (
                old["state"] != "pending"
                or old["enrollment_locator"] != checked["locator"]
                or old["requester_hash"] != requester.commitment
            ):
                raise Refused("enrollment_conflict")
            self._bounds(old, issuer=issuer, requester=requester)
            return {
                "version": 1,
                "locator": checked["locator"],
                "deadline": old["deadline"],
                "state": "pending",
                "public_key": self._options(old),
            }

    async def browser_options(self, locator):
        async with self.store.transaction() as tx:
            row = await self._row(tx, locator)
            csrf = secrets.token_urlsafe(32)
            deadline = min(row["deadline"], int(time.time()) + 120)
            await tx.execute(
                "UPDATE {{tables.approval_enrollments}} SET browser_hash=$1,browser_deadline=$2 WHERE person_id=$3",
                token_commitment(csrf),
                deadline,
                row["person_id"],
            )
            self._bounds(row)
            return {
                "public_key": self._options(row),
                "csrf": csrf,
                "deadline": deadline,
            }

    async def register(self, locator, csrf, registration, extensions):
        validate("registration", registration)
        if extensions != {"credProps": {"rk": True}}:
            raise Refused("discoverable_credential_required")
        async with self.store.transaction() as tx:
            row = await self._row(tx, locator)
            self._browser(row, csrf)
            if row["binding_ref"] is not None:
                raise Refused("enrollment_already_confirming")
            i = json.loads(row["intent"])["intent"]
            checked = self.grading.check(
                registration,
                expected_challenge=decode(i["challenge"]),
                origin=self.origin,
                rp_id=self.rp_id,
            )
            existing = await tx.fetch_one(
                "SELECT registration FROM {{tables.approval_credentials}} WHERE credential_id=$1 AND person_id=$2",
                checked.credential_id,
                row["person_id"],
            )
            if existing is not None:
                if canonical(json.loads(existing["registration"])) != canonical(
                    registration
                ):
                    raise Refused("credential_conflict")
            else:
                count = await tx.fetch_one(
                    "SELECT count(*) AS n FROM {{tables.approval_credentials}} WHERE person_id=$1 AND NOT retired",
                    row["person_id"],
                )
                if count["n"] >= 8:
                    raise Refused("credential_limit")
                await tx.execute(
                    """INSERT INTO {{tables.approval_credentials}}
                    (person_id,credential_id,public_key,sign_count,grade,snapshot,attestation,registration,client_extension_results,binding_entry)
                    VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10::jsonb)""",
                    row["person_id"],
                    checked.credential_id,
                    checked.public_key,
                    checked.sign_count,
                    checked.grade,
                    checked.snapshot,
                    checked.attestation,
                    json.dumps(registration),
                    json.dumps(extensions),
                    json.dumps(checked.binding_entry()),
                )
            self._bounds(row, browser=True)
            return {
                "state": "pending",
                "credential": checked.credential_id,
                "grade": checked.grade,
            }

    async def material(self, intent, *, issuer, requester):
        checked = self._check(intent, issuer, requester)
        async with self.store.transaction() as tx:
            row = await self._row(tx, checked["locator"])
            if row["requester_hash"] != requester.commitment:
                raise Refused("requester_mismatch")
            credentials = await tx.fetch_all(
                "SELECT registration,client_extension_results FROM {{tables.approval_credentials}} WHERE person_id=$1 AND NOT retired ORDER BY credential_id",
                row["person_id"],
            )
            self._bounds(row, issuer=issuer, requester=requester)
            return {
                "version": 1,
                "locator": checked["locator"],
                "deadline": row["deadline"],
                "state": "pending",
                "registrations": [
                    {
                        "registration": json.loads(c["registration"]),
                        "client_extension_results": json.loads(
                            c["client_extension_results"]
                        ),
                    }
                    for c in credentials
                ],
            }

    async def _private_binding(self, tx, row, binding):
        credentials = await tx.fetch_all(
            "SELECT * FROM {{tables.approval_credentials}} WHERE person_id=$1 AND NOT retired ORDER BY credential_id FOR UPDATE",
            row["person_id"],
        )
        entries = sorted(binding["binding"]["credentials"], key=lambda c: c["id"])
        if (
            not credentials
            or [json.loads(c["binding_entry"]) for c in credentials] != entries
        ):
            raise Refused("binding_credential_mismatch")
        return credentials

    async def _answer(self, tx, row, locator):
        answer = {
            "version": 1,
            "locator": locator,
            "digest": row["digest"],
            "deadline": row["deadline"],
            "state": row["outcome"],
            "approval": None,
        }
        row = request_row(row)
        if row["assertion"] is not None:
            version = await tx.fetch_one(
                "SELECT binding,id_chain FROM {{tables.approval_binding_versions}} WHERE digest=$1",
                row["binding_ref"],
            )
            if version is None:
                raise Refused("binding_unavailable")
            answer["approval"] = {
                "assertion": row["assertion"],
                "binding": json.loads(version["binding"]),
                "id_chain": json.loads(version["id_chain"]),
            }
        return answer

    async def confirm(self, body, *, issuer, requester):
        checked = read_enrollment_request(
            "enrollment_confirm",
            body,
            intent=body["intent"],
            issuer_key=issuer.key,
            requester=parse(requester.descriptor_bytes),
            origin=self.origin,
            rp_id=self.rp_id,
            now=int(time.time()),
        )
        self._check(body["intent"], issuer, requester)
        locator = checked["locator"]
        raw = decode(body["request_bytes"])
        r = parse(raw)
        async with self.store.transaction() as tx:
            row = await self._row(tx, locator)
            if row["requester_hash"] != requester.commitment:
                raise Refused("requester_mismatch")
            await self._private_binding(tx, row, body["binding"])
            ref = commitment("binding_commitment", body["binding"])
            if row["binding_ref"] is not None and row["binding_ref"] != ref:
                raise Refused("binding_mismatch")
            chain = [body["intent"]["intent"]["pending_certificate"]]
            await tx.execute(
                "INSERT INTO {{tables.approval_binding_versions}}(digest,person_id,binding,id_chain) VALUES($1,$2,$3::jsonb,$4::jsonb) ON CONFLICT DO NOTHING",
                ref,
                row["person_id"],
                json.dumps(body["binding"]),
                json.dumps(chain),
            )
            await tx.execute(
                """INSERT INTO {{tables.approval_requests}}(operation_id,digest,requester_hash,person_id,request_bytes,created_at,deadline)
                VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING""",
                locator,
                checked["digest"],
                requester.commitment,
                row["person_id"],
                raw,
                r["not_before"],
                r["deadline"],
            )
            request = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_requests}} WHERE operation_id=$1 FOR UPDATE",
                locator,
            )
            if (request["digest"], request["requester_hash"]) != (
                checked["digest"],
                requester.commitment,
            ):
                raise Refused("selection_conflict")
            await tx.execute(
                "UPDATE {{tables.approval_enrollments}} SET binding_ref=$1,confirmation_id=$2 WHERE person_id=$3",
                ref,
                locator,
                row["person_id"],
            )
            answer = await self._answer(tx, request, locator)
            self._bounds(row, issuer=issuer, requester=requester)
            return answer

    async def confirmation_options(self, locator, csrf):
        async with self.store.transaction() as tx:
            row = await self._row(tx, locator)
            self._browser(row, csrf)
            request = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_requests}} WHERE operation_id=$1 AND outcome='pending' FOR UPDATE",
                row["confirmation_id"],
            )
            if request is None:
                raise Refused("request_not_found")
            result = await self.ceremonies._issue(
                tx,
                row["person_id"],
                "approval",
                bytes.fromhex(request["digest"]),
                int(time.time()),
                min(request["deadline"], row["browser_deadline"]),
                session_hash=token_commitment(csrf),
                operation_id=row["confirmation_id"],
            )
            result["request"] = parse(bytes(request["request_bytes"]))
            self._bounds(row, browser=True)
            return result

    async def finish_confirmation(
        self, locator, csrf, identifier, assertion, *, issuer
    ):
        async with self.store.transaction() as tx:
            row = await self._row(tx, locator)
            self._browser(row, csrf)
            intent = json.loads(row["intent"])
            i = intent["intent"]
            if issuer.key != row["issuer"]:
                raise Refused("issuer_mismatch")
            request = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_requests}} WHERE operation_id=$1 FOR UPDATE",
                row["confirmation_id"],
            )
            challenge = await self.ceremonies._challenge(
                tx, identifier, row["person_id"], "approval"
            )
            if (
                challenge["session_hash"] != token_commitment(csrf)
                or challenge["operation_id"] != row["confirmation_id"]
            ):
                raise Refused("challenge_binding_mismatch")
            credential = await self.ceremonies._credential(
                tx, row["person_id"], assertion["id"]
            )
            version = await tx.fetch_one(
                "SELECT binding,id_chain FROM {{tables.approval_binding_versions}} WHERE digest=$1",
                row["binding_ref"],
            )
            Ceremonies._bounds(
                int(time.time()), trust=issuer, challenge=challenge, request=request
            )
            self._bounds(row, issuer=issuer, browser=True)
            trust = Trust(
                row["person_id"],
                row["organisation"],
                row["identity_key"],
                row["certificate"],
                issuer.key,
                public_key_from_did(issuer.key),
                issuer.observed_at,
            )
            c = {
                "version": 1,
                "request_bytes": encode(bytes(request["request_bytes"])),
                "assertion": assertion,
                "binding": json.loads(version["binding"]),
                "id_chain": json.loads(version["id_chain"]),
            }
            checked, _bh, _r = _creation_assertion(
                c,
                requester=i["requester"],
                origin=self.origin,
                now=int(time.time()),
                trust=trust,
            )
            await self._private_binding(tx, row, c["binding"])
            counter = self.ceremonies._assertion(
                assertion, credential, challenge["challenge"]
            )
            await tx.execute(
                "UPDATE {{tables.approval_credentials}} SET sign_count=$1 WHERE person_id=$2 AND credential_id=$3",
                counter,
                row["person_id"],
                assertion["id"],
            )
            await tx.execute(
                "UPDATE {{tables.approval_challenges}} SET consumed=true WHERE challenge_id=$1",
                identifier,
            )
            await self.store._terminal(
                tx, request, "approved", int(time.time()), assertion, row["binding_ref"]
            )
            Ceremonies._bounds(
                int(time.time()), trust=issuer, challenge=challenge, request=request
            )
            self._bounds(row, issuer=issuer, browser=True)
            return {"digest": checked.digest, "state": "approved"}

    async def activate(self, value, *, trust, requester):
        checked = check_activation(
            value,
            issuer_key=trust.issuer,
            requester=parse(requester.descriptor_bytes),
            origin=self.origin,
            rp_id=self.rp_id,
            now=int(time.time()),
            trust=trust,
        )
        locator = commitment("enrollment_locator", value["intent"])
        async with self.store.transaction() as tx:
            row = await self._row(tx, locator, pending=False)
            if (
                row["state"] not in ("pending", "active")
                or row["requester_hash"] != requester.commitment
            ):
                raise Refused("enrollment_conflict")
            await self._private_binding(tx, row, value["binding"])
            if row["binding_ref"] != checked["binding_commitment"]:
                raise Refused("binding_mismatch")
            await tx.execute(
                "UPDATE {{tables.approval_enrollments}} SET state='active',intent=NULL,browser_hash=NULL,browser_deadline=NULL WHERE person_id=$1",
                trust.person,
            )
            await tx.execute(
                "UPDATE {{tables.approval_credentials}} SET registration=NULL,client_extension_results=NULL WHERE person_id=$1",
                trust.person,
            )
            self._bounds(row, issuer=trust, requester=requester)
            return {
                "version": 1,
                "locator": locator,
                "person": trust.person,
                "state": "active",
            }
