"""Pending WebAuthn enrollment, limited confirmation, then public activation.

No pending flag is identity authority. The issuer checks the same raw create
response and its own confirmation nonce; only committed public Trust activates.
"""

from __future__ import annotations

import hashlib
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
from .definitions import check_definition
from .encoding import decode, encode
from .registration import require_supported_entry
from .seams import (
    _creation_assertion,
    check_activation,
    check_activation_carrier,
    check_enrollment_intent,
    commitment,
)
from .verify import Refused, Trust
from .wire import SCHEMA, domain, validate

CONFIRMED_ACTIVATION_RETENTION_SECONDS = 30 * 86400


@dataclass(frozen=True)
class PublicIssuer:
    """An independently checked public issuer observation, never HTTP input."""

    key: str
    observed_at: int


class Enrollments:
    def __init__(self, store, *, origin, rp_id, grading):
        self.store = store
        self.ceremonies = Ceremonies(store, origin=origin, rp_id=rp_id)
        self.origin, self.rp_id, self.grading = (origin, rp_id, grading)

    @staticmethod
    def _bounds(
        row,
        *,
        issuer=None,
        requester=None,
        browser=False,
        activation=False,
        current=None,
    ):
        now = int(time.time())
        Ceremonies._bounds(now, trust=issuer, requester=requester)
        if current is not None:
            Ceremonies._bounds(now, trust=current)
        if now >= row["deadline"] and not (
            activation and row.get("confirmation_approved", False)
        ):
            raise Refused("enrollment_expired")
        if browser and now >= row["browser_deadline"]:
            raise Refused("enrollment_browser_expired")

    def _check(self, intent, issuer, requester, current=None):
        Ceremonies._bounds(int(time.time()), trust=issuer, requester=requester)
        return check_enrollment_intent(
            intent,
            issuer_key=issuer.key,
            requester=parse(requester.descriptor_bytes),
            origin=self.origin,
            rp_id=self.rp_id,
            now=int(time.time()),
            trust=current,
        )

    async def _row(self, tx, locator, *, pending=True, activation=False):
        query = "SELECT * FROM {{tables.approval_enrollments}} WHERE enrollment_locator=$1 FOR UPDATE"
        if activation:
            query = """SELECT e.*,EXISTS (
                SELECT 1 FROM {{tables.approval_requests}} r
                WHERE r.organisation=e.organisation AND r.person_id=e.person_id
                AND r.operation_id=e.confirmation_id AND r.binding_ref=e.binding_ref
                AND r.outcome='approved'
            ) AS confirmation_approved
            FROM {{tables.approval_enrollments}} e WHERE e.enrollment_locator=$1
            FOR UPDATE OF e"""
        row = await tx.fetch_one(
            query,
            locator,
        )
        if row is None:
            raise Refused("enrollment_not_found")
        if pending and row["state"] != "pending":
            raise Refused("enrollment_not_pending")
        self._bounds(row, activation=activation)
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

    async def start(
        self,
        intent,
        *,
        issuer,
        requester,
        admission=None,
        current=None,
        observation=None,
    ):
        checked = self._check(intent, issuer, requester, current)
        i = intent["intent"]
        if i["deadline"] - i["not_before"] > 86400:
            raise Refused("enrollment_lifetime_invalid")
        async with self.store.transaction() as tx:
            await tx.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                requester.key,
            )
            await tx.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                hashlib.sha256(canonical([i["organisation"], i["person"]])).hexdigest(),
            )
            old = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_enrollments}} WHERE person_id=$1 AND organisation=$2 AND state='pending' FOR UPDATE",
                i["person"],
                i["organisation"],
            )
            if old is not None and int(time.time()) >= old["deadline"]:
                await self._delete_pending(tx, old, int(time.time()))
                old = None
            active = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_enrollments}} WHERE person_id=$1 AND organisation=$2 AND state='active' FOR UPDATE",
                i["person"],
                i["organisation"],
            )
            previous = i.get("previous_binding_commitment")
            if active is not None:
                if previous != active["binding_ref"]:
                    raise Refused("enrollment_previous_mismatch")
                if i["identity_key"] == active["identity_key"]:
                    raise Refused("enrollment_identity_unchanged")
                if current is None:
                    raise Refused("identity_unavailable")
                Ceremonies._bounds(int(time.time()), trust=current)
                # Recovery follows an ordinary previous-key-signed ID rotation;
                # an organisation signature cannot move an existing stable ID.
                expected = (
                    (
                        i["person"],
                        i["organisation"],
                        i["identity_key"],
                        checked["certificate"],
                    )
                    if i["purpose"] == "enroll_person"
                    else (
                        active["person_id"],
                        active["organisation"],
                        active["identity_key"],
                        active["certificate"],
                    )
                )
                if (
                    current.person,
                    current.organisation,
                    current.identity_key,
                    current.certificate,
                ) != expected:
                    raise Refused("enrollment_identity_mismatch")
            elif previous is not None or i["purpose"] not in (
                "enroll_person",
                "enroll_existing_person",
            ):
                raise Refused("enrollment_previous_unavailable")
            if old is None and active is None and i["purpose"] == "enroll_person":
                if (
                    observation is None
                    or observation.person != i["person"]
                    or not 0 <= int(time.time()) - observation.observed_at <= 60
                    or observation.committed is None
                ):
                    raise Refused("identity_unavailable")
                if observation.committed:
                    raise Refused("enrollment_creation_committed")
                if (
                    observation.current_key is not None
                    and observation.current_key != i["identity_key"]
                ):
                    raise Refused("enrollment_identity_mismatch")
            if old is None:
                count = await tx.fetch_one(
                    "SELECT count(*) AS n FROM {{tables.approval_enrollments}} WHERE requester_key=$1 AND state='pending' AND deadline>$2",
                    requester.key,
                    int(time.time()),
                )
                if count["n"] >= 32:
                    raise Refused("pending_limit")
                old = await tx.fetch_one(
                    """INSERT INTO {{tables.approval_enrollments}}
                    (person_id,organisation,identity_key,certificate,issuer,user_handle,deadline,state,enrollment_locator,intent,requester_hash,previous_locator,requester_key)
                    VALUES($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9::jsonb,$10,$11,$12) RETURNING *""",
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
                    None if active is None else active["enrollment_locator"],
                    requester.key,
                )
            elif (
                old["enrollment_locator"] != checked["locator"]
                or old["requester_hash"] != requester.commitment
            ):
                raise Refused("enrollment_conflict")
            if admission is not None and old["admission"] is None:
                await tx.execute(
                    "UPDATE {{tables.approval_enrollments}} SET admission=$1::jsonb WHERE enrollment_locator=$2",
                    json.dumps(admission),
                    old["enrollment_locator"],
                )
            self._bounds(old, issuer=issuer, requester=requester, current=current)
            if observation is not None:
                Ceremonies._bounds(int(time.time()), trust=observation)
            if current is not None:
                Ceremonies._bounds(int(time.time()), trust=current)
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
                "UPDATE {{tables.approval_enrollments}} SET browser_hash=$1,browser_deadline=$2 WHERE enrollment_locator=$3",
                token_commitment(csrf),
                deadline,
                row["enrollment_locator"],
            )
            self._bounds({**row, "browser_deadline": deadline}, browser=True)
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
                "SELECT registration FROM {{tables.approval_credentials}} WHERE credential_id=$1 AND person_id=$2 AND organisation=$3 AND enrollment_locator=$4",
                checked.credential_id,
                row["person_id"],
                row["organisation"],
                row["enrollment_locator"],
            )
            if existing is not None:
                if canonical(json.loads(existing["registration"])) != canonical(
                    registration
                ):
                    raise Refused("credential_conflict")
            else:
                count = await tx.fetch_one(
                    "SELECT count(*) AS n FROM {{tables.approval_credentials}} WHERE person_id=$1 AND NOT retired AND organisation=$2 AND enrollment_locator=$3",
                    row["person_id"],
                    row["organisation"],
                    row["enrollment_locator"],
                )
                if count["n"] >= 8:
                    raise Refused("credential_limit")
                await tx.execute(
                    """INSERT INTO {{tables.approval_credentials}}
                    (person_id,credential_id,public_key,sign_count,grade,snapshot,registration,client_extension_results,binding_entry,organisation,enrollment_locator)
                    VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb,$10,$11)""",
                    row["person_id"],
                    checked.credential_id,
                    checked.public_key,
                    checked.sign_count,
                    checked.grade,
                    checked.snapshot,
                    json.dumps(registration),
                    json.dumps(extensions),
                    json.dumps(checked.binding_entry()),
                    row["organisation"],
                    row["enrollment_locator"],
                )
            self._bounds(row, browser=True)
            return {
                "state": "pending",
                "credential": checked.credential_id,
                "grade": checked.grade,
            }

    async def material(self, intent, *, issuer, requester, current=None):
        checked = self._check(intent, issuer, requester, current)
        async with self.store.transaction() as tx:
            row = await self._row(tx, checked["locator"])
            if row["requester_hash"] != requester.commitment:
                raise Refused("requester_mismatch")
            credentials = await tx.fetch_all(
                "SELECT registration,client_extension_results FROM {{tables.approval_credentials}} WHERE person_id=$1 AND NOT retired AND organisation=$2 AND enrollment_locator=$3 ORDER BY credential_id",
                row["person_id"],
                row["organisation"],
                row["enrollment_locator"],
            )
            self._bounds(row, issuer=issuer, requester=requester, current=current)
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
            "SELECT * FROM {{tables.approval_credentials}} WHERE person_id=$1 AND NOT retired AND organisation=$2 AND enrollment_locator=$3 ORDER BY credential_id FOR UPDATE",
            row["person_id"],
            row["organisation"],
            row["enrollment_locator"],
        )
        entries = sorted(binding["binding"]["credentials"], key=lambda c: c["id"])
        credentials = sorted(credentials, key=lambda c: c["credential_id"])
        if not credentials or len(credentials) != len(entries):
            raise Refused("binding_credential_mismatch")
        for credential, entry in zip(credentials, entries, strict=True):
            require_supported_entry(json.loads(credential["binding_entry"]), entry)
        return credentials

    async def confirm(self, body, *, issuer, requester, current=None):
        validate("enrollment_confirm_request", body)
        # Terminal receipt recovery remains a deadline-bound confirmation step;
        # only activation may use a retained, approved pending enrollment.
        self._check(body["intent"], issuer, requester, current)
        locator = commitment("enrollment_locator", body["intent"])
        old = await self.store.db.fetch_one(
            "SELECT * FROM {{tables.approval_requests}} WHERE operation_id=$1 AND organisation=$2 AND person_id=$3",
            locator,
            body["intent"]["intent"]["organisation"],
            body["intent"]["intent"]["person"],
        )
        if old is not None and (
            old["outcome"] != "pending" or int(time.time()) >= old["deadline"]
        ):
            raw = decode(body["request_bytes"])
            r = parse(raw)
            if (
                raw != canonical(r)
                or hashlib.sha256(domain("request") + raw).hexdigest() != old["digest"]
            ):
                raise Refused("request_mismatch")
            row = await self.store.db.fetch_one(
                "SELECT binding_ref,requester_hash FROM {{tables.approval_enrollments}} WHERE enrollment_locator=$1",
                locator,
            )
            if (
                row is None
                or row["requester_hash"] != requester.commitment
                or row["binding_ref"]
                != commitment("binding_commitment", body["binding"])
            ):
                raise Refused("requester_mismatch")
            Ceremonies._bounds(int(time.time()), requester=requester)
            recovered = await self.store.poll(
                locator,
                old["digest"],
                requester.commitment,
                int(time.time()),
                organisation=old["organisation"],
                person_id=old["person_id"],
            )
            answer = await self.store.decision_answer(recovered, locator)
            Ceremonies._bounds(int(time.time()), requester=requester, trust=issuer)
            if current is not None:
                Ceremonies._bounds(int(time.time()), trust=current)
            return answer
        checked = read_enrollment_request(
            "enrollment_confirm",
            body,
            intent=body["intent"],
            issuer_key=issuer.key,
            requester=parse(requester.descriptor_bytes),
            origin=self.origin,
            rp_id=self.rp_id,
            now=int(time.time()),
            trust=current,
        )
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
            chain = (
                json.loads(row["admission"])["id_chain"]
                if body["intent"]["intent"]["purpose"] == "enroll_existing_person"
                and row["admission"] is not None
                else [body["intent"]["intent"]["pending_certificate"]]
            )
            await tx.execute(
                "INSERT INTO {{tables.approval_binding_versions}}(digest,person_id,binding,id_chain,organisation,enrollment_locator) VALUES($1,$2,$3::jsonb,$4::jsonb,$5,$6) ON CONFLICT DO NOTHING",
                ref,
                row["person_id"],
                json.dumps(body["binding"]),
                json.dumps(chain),
                row["organisation"],
                row["enrollment_locator"],
            )
            await tx.execute(
                """INSERT INTO {{tables.approval_requests}}(operation_id,digest,requester_hash,person_id,request_bytes,created_at,deadline,organisation,requester_key)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING""",
                locator,
                checked["digest"],
                requester.commitment,
                row["person_id"],
                raw,
                r["not_before"],
                r["deadline"],
                row["organisation"],
                requester.key,
            )
            request = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_requests}} WHERE operation_id=$1 AND organisation=$2 AND person_id=$3 FOR UPDATE",
                locator,
                row["organisation"],
                row["person_id"],
            )
            if (request["digest"], request["requester_hash"]) != (
                checked["digest"],
                requester.commitment,
            ):
                raise Refused("selection_conflict")
            await tx.execute(
                "UPDATE {{tables.approval_enrollments}} SET binding_ref=$1,confirmation_id=$2 WHERE enrollment_locator=$3",
                ref,
                locator,
                row["enrollment_locator"],
            )
            answer = await self.store.decision_answer(request, locator, db=tx)
            self._bounds(row, issuer=issuer, requester=requester, current=current)
            return answer

    async def confirmation_options(self, locator, csrf):
        async with self.store.transaction() as tx:
            row = await self._row(tx, locator)
            self._browser(row, csrf)
            request = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_requests}} WHERE operation_id=$1 AND outcome='pending' AND organisation=$2 AND person_id=$3 FOR UPDATE",
                row["confirmation_id"],
                row["organisation"],
                row["person_id"],
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
                organisation=row["organisation"],
                enrollment_locator=row["enrollment_locator"],
            )
            result["request"] = parse(bytes(request["request_bytes"]))
            result["display"] = check_definition(result["request"])["display"]
            result["digest"] = request["digest"]
            Ceremonies._bounds(int(time.time()), request=request)
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
                "SELECT * FROM {{tables.approval_requests}} WHERE operation_id=$1 AND organisation=$2 AND person_id=$3 FOR UPDATE",
                row["confirmation_id"],
                row["organisation"],
                row["person_id"],
            )
            challenge = await self.ceremonies._challenge(
                tx,
                identifier,
                row["person_id"],
                "approval",
                organisation=row["organisation"],
            )
            if (
                challenge["session_hash"] != token_commitment(csrf)
                or challenge["operation_id"] != row["confirmation_id"]
            ):
                raise Refused("challenge_binding_mismatch")
            credential = await self.ceremonies._credential(
                tx,
                row["person_id"],
                assertion["id"],
                organisation=row["organisation"],
                enrollment_locator=row["enrollment_locator"],
            )
            version = await tx.fetch_one(
                "SELECT binding,id_chain FROM {{tables.approval_binding_versions}} WHERE digest=$1 AND organisation=$2 AND person_id=$3",
                row["binding_ref"],
                row["organisation"],
                row["person_id"],
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
                "UPDATE {{tables.approval_credentials}} SET sign_count=$1 WHERE person_id=$2 AND credential_id=$3 AND organisation=$4 AND enrollment_locator=$5",
                counter,
                row["person_id"],
                assertion["id"],
                row["organisation"],
                row["enrollment_locator"],
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

    @staticmethod
    def _historical_state(version, enrollment):
        binding = json.loads(version["binding"])
        b = binding["binding"]
        if enrollment["state"] not in (
            "active",
            "retired",
        ):
            raise Refused("enrollment_previous_unavailable")
        return {
            "binding": binding,
            "evidence": None
            if enrollment["evidence"] is None
            else json.loads(enrollment["evidence"]),
            "trust": Trust(
                b["person"],
                b["organisation"],
                b["identity_key"],
                b["certificate"],
                b["issuer"],
                public_key_from_did(b["issuer"]),
                0,
                b["issuer"]
                if enrollment.get("evidence") is not None
                and json.loads(enrollment["evidence"])["evidence"].get("kind")
                == "human_enrolled_later"
                else None,
            ),
        }

    async def activate(self, value, *, trust, requester):
        check_activation_carrier(
            value, requester=parse(requester.descriptor_bytes), trust=trust
        )
        locator = commitment("enrollment_locator", value["intent"])
        async with self.store.transaction() as tx:
            await tx.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                hashlib.sha256(
                    canonical([trust.organisation, trust.person])
                ).hexdigest(),
            )
            row = await self._row(tx, locator, pending=False, activation=True)
            if (
                row["state"] not in ("pending", "active")
                or row["requester_hash"]
                != hashlib.sha256(
                    canonical(value["intent"]["intent"]["requester"])
                ).hexdigest()
            ):
                raise Refused("enrollment_conflict")
            if (
                row["state"] == "active"
                and row["evidence"] is not None
                and canonical(json.loads(row["evidence"]))
                != canonical(value["evidence"])
            ):
                # The retired BEFORE exception permits the original retry,
                # never rewriting an assisted/recreated history as unbroken.
                raise Refused("enrollment_conflict")
            current = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_enrollments}} WHERE organisation=$1 AND person_id=$2 AND state='active' FOR UPDATE",
                trust.organisation,
                trust.person,
            )
            previous = None
            transition_trust = None
            if row["previous_locator"] is not None:
                before = await tx.fetch_one(
                    "SELECT * FROM {{tables.approval_enrollments}} WHERE enrollment_locator=$1 FOR UPDATE",
                    row["previous_locator"],
                )
                if (
                    before is None
                    or current is None
                    or current["enrollment_locator"]
                    not in (before["enrollment_locator"], row["enrollment_locator"])
                ):
                    raise Refused("enrollment_previous_mismatch")
                version = await tx.fetch_one(
                    "SELECT * FROM {{tables.approval_binding_versions}} WHERE digest=$1 AND enrollment_locator=$2",
                    before["binding_ref"],
                    before["enrollment_locator"],
                )
                if version is None:
                    raise Refused("enrollment_previous_unavailable")
                previous = self._historical_state(version, before)
                receipt = value.get("transition_receipt")
                if receipt is not None:
                    # A helper must still be active. Only the target's exact
                    # BEFORE generation may be retired, for an idempotent
                    # retry of its own unbroken replacement.
                    proof_version = await tx.fetch_one(
                        """SELECT v.*,e.state,e.evidence FROM {{tables.approval_binding_versions}} v
                        JOIN {{tables.approval_enrollments}} e ON e.enrollment_locator=v.enrollment_locator
                        WHERE v.digest=$1 AND v.organisation=$2 AND v.digest=e.binding_ref
                        AND (e.state='active' OR (e.state='retired' AND e.enrollment_locator=$3 AND e.person_id=$4))""",
                        commitment("binding_commitment", receipt["binding"]),
                        trust.organisation,
                        before["enrollment_locator"],
                        trust.person,
                    )
                    if proof_version is None:
                        raise Refused("transition_receipt_unavailable")
                    transition_trust = self._historical_state(
                        proof_version, proof_version
                    )["trust"]
            elif (
                current is not None
                and current["enrollment_locator"] != row["enrollment_locator"]
            ):
                raise Refused("enrollment_conflict")
            checked = check_activation(
                value,
                issuer_key=trust.namespace_issuer
                if value["version"] == 2
                else trust.issuer,
                requester=parse(requester.descriptor_bytes),
                origin=self.origin,
                rp_id=self.rp_id,
                now=int(time.time()),
                trust=trust,
                previous=previous,
                transition_trust=transition_trust,
            )
            await self._private_binding(tx, row, value["binding"])
            if row["binding_ref"] != checked["binding_commitment"]:
                raise Refused("binding_mismatch")
            if (
                current is not None
                and current["enrollment_locator"] != row["enrollment_locator"]
            ):
                old_locator = current["enrollment_locator"]
                await tx.execute(
                    "UPDATE {{tables.approval_enrollments}} SET state='retired' WHERE enrollment_locator=$1",
                    old_locator,
                )
                await tx.execute(
                    "UPDATE {{tables.approval_sessions}} SET retired=true WHERE enrollment_locator=$1",
                    old_locator,
                )
                await tx.execute(
                    "UPDATE {{tables.approval_credentials}} SET retired=true WHERE enrollment_locator=$1",
                    old_locator,
                )
                await tx.execute(
                    "UPDATE {{tables.approval_challenges}} SET consumed=true WHERE enrollment_locator=$1",
                    old_locator,
                )
            await tx.execute(
                "UPDATE {{tables.approval_enrollments}} SET state='active',intent=NULL,browser_hash=NULL,browser_deadline=NULL,evidence=$1::jsonb WHERE enrollment_locator=$2",
                json.dumps(value["evidence"]),
                locator,
            )
            await tx.execute(
                "UPDATE {{tables.approval_credentials}} SET registration=NULL,client_extension_results=NULL WHERE enrollment_locator=$1",
                locator,
            )
            self._bounds(row, issuer=trust, requester=requester, activation=True)
            return {
                "version": 1,
                "locator": locator,
                "person": trust.person,
                "state": "active",
            }

    async def cleanup(self, now):
        async with self.store.transaction() as tx:
            rows = await tx.fetch_all(
                """SELECT e.organisation,e.person_id,e.confirmation_id,e.enrollment_locator
                FROM {{tables.approval_enrollments}} e
                WHERE e.state='pending' AND e.deadline<=$1
                AND (e.deadline<=$1-$2 OR NOT EXISTS (
                    SELECT 1 FROM {{tables.approval_requests}} r
                    WHERE r.organisation=e.organisation AND r.person_id=e.person_id
                    AND r.operation_id=e.confirmation_id AND r.binding_ref=e.binding_ref
                    AND r.outcome='approved'
                )) ORDER BY e.deadline LIMIT 128 FOR UPDATE OF e SKIP LOCKED""",
                now,
                CONFIRMED_ACTIVATION_RETENTION_SECONDS,
            )
            for row in rows:
                await self._delete_pending(tx, row, now)
            await tx.execute(
                "DELETE FROM {{tables.approval_challenges}} WHERE challenge_id IN (SELECT challenge_id FROM {{tables.approval_challenges}} WHERE deadline<=$1 LIMIT 128 FOR UPDATE SKIP LOCKED)",
                now,
            )
            await tx.execute(
                "DELETE FROM {{tables.approval_sessions}} WHERE token_hash IN (SELECT token_hash FROM {{tables.approval_sessions}} WHERE deadline<=$1 LIMIT 128 FOR UPDATE SKIP LOCKED)",
                now,
            )
            return len(rows)

    async def _delete_pending(self, tx, row, now):
        if row["confirmation_id"] is not None:
            request = await tx.fetch_one(
                "SELECT * FROM {{tables.approval_requests}} WHERE organisation=$1 AND person_id=$2 AND operation_id=$3 FOR UPDATE",
                row["organisation"],
                row["person_id"],
                row["confirmation_id"],
            )
            if request is not None:
                await self.store._expire(tx, request, now)
        # One expired pending enrollment: fixed five deletes, no active/public
        # identity is changed. Expiry need not wait for the background sweep.
        for table in (
            "approval_challenges",
            "approval_sessions",
            "approval_credentials",
            "approval_binding_versions",
            "approval_enrollments",
        ):
            await tx.execute(
                "DELETE FROM {{tables." + table + "}} WHERE enrollment_locator=$1",
                row["enrollment_locator"],
            )
