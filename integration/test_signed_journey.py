"""One signed HTTP path across real DNS, AWID, PostgreSQL and WebAuthn crypto.

The software authenticator is the existing signing fixture. This is not the
physical-key/browser or holder-effect journey, which consumes the same seams.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import time
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from awid.did import (
    did_from_public_key,
    generate_keypair,
    public_key_from_did,
    stable_id_from_did_key,
)
from awid.id_certificates import id_certificate_id, id_certificate_signing_bytes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.signing import SigningKey
from receipts import assertion, fixture
from vendor import Vendor

from approval_service.answers import assemble_receipt, read_answer
from approval_service.canonical import canonical
from approval_service.definitions import definition_ref
from approval_service.encoding import decode, encode
from approval_service.grading import EnrollmentGrading
from approval_service.http import create_app
from approval_service.public import PublicReader
from approval_service.registration import check_registration
from approval_service.seams import check_creation_proof, commitment, http_authorization
from approval_service.trust import read_trust
from approval_service.verify import Trust, verify_for_effect
from approval_service.wire import SCHEMA, domain

from .real_stack import registry_stack, tls_config
from .test_ceremonies import login_assertion
from .test_enrollment import ORIGIN, RP, confirmation_request, sign_binding
from .test_requester_registry import listener


def certificate_for(identity, organisation, issuer_seed, *, kind="human"):
    c = {
        "v": 1,
        "type": "aweb.id-certificate",
        "id": identity,
        "domain": organisation,
        "parent": {"kind": "namespace", "id": organisation},
        "kind": kind,
        "issuer_key": did_from_public_key(bytes(SigningKey(issuer_seed).verify_key)),
        "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return {
        "certificate": c,
        "signature": encode(
            SigningKey(issuer_seed).sign(id_certificate_signing_bytes(c)).signature
        ),
    }


def signed_intent(certificate, identity_key, issuer_seed, *, deadline=None):
    org = certificate["certificate"]["domain"]
    key = certificate["certificate"]["issuer_key"]
    i = {
        "version": 1,
        "purpose": "enroll_person",
        "organisation": org,
        "person": certificate["certificate"]["id"],
        "pending_certificate": certificate,
        "identity_key": identity_key,
        "requester": {"kind": "namespace_controller", "namespace": org, "key": key},
        "origin": ORIGIN,
        "rp_id": RP,
        "challenge": encode(__import__("secrets").token_bytes(32)),
        "not_before": int(time.time()) - 1,
        "deadline": deadline or int(time.time()) + 600,
    }
    return {
        "intent": i,
        "signature": encode(
            SigningKey(issuer_seed)
            .sign(domain("enrollment_intent") + canonical(i))
            .signature
        ),
    }


async def exchange(client, purpose, body, seed, descriptor):
    raw = canonical(body)
    auth = http_authorization(
        raw,
        seed=seed,
        requester=descriptor,
        origin=ORIGIN,
        purpose=purpose,
        issued_at=int(time.time()),
    )
    return await client.post(
        SCHEMA["x-http"]["routes"][purpose],
        content=raw,
        headers={"Authorization": auth, "Content-Type": "application/json"},
    )


async def browser(client, path, body):
    response = await client.post(
        "/browser/" + path, json=body, headers={"Origin": ORIGIN}
    )
    assert response.status_code == 200, (path, response.status_code, response.text)
    return response.json()


async def commit_identity(registry, certificate, seed):
    key = did_from_public_key(bytes(SigningKey(seed).verify_key))
    await registry.register_did(key, seed)
    bundle = {"v": 1, "type": "aweb.id-chain", "certificates": [certificate]}
    await registry.register_id_certificate(
        bundle,
        signer=lambda raw: (key, SigningKey(seed).sign(raw).signature),
        expected_head=None,
        invitation_id=None,
    )


@pytest.mark.asyncio
async def test_signed_http_enrollment_approval_and_foreign_organisation_fences(
    store, tmp_path
):
    root_a, pub_a = generate_keypair()
    root_b, pub_b = generate_keypair()
    org_a = "alpha-" + uuid4().hex[:10] + ".example.test"
    org_b = "beta-" + uuid4().hex[:10] + ".example.test"
    person_seed, person_public = generate_keypair()
    person_key = did_from_public_key(person_public)
    person = stable_id_from_did_key(person_key)
    cert_a = certificate_for(person, org_a, root_a)
    intent_a = signed_intent(cert_a, person_key, root_a)
    poison = signed_intent(certificate_for(person, org_b, root_b), person_key, root_b)
    async with registry_stack(
        tmp_path, {org_a: (root_a, pub_a), org_b: (root_b, pub_b)}
    ) as registry:
        app = create_app(
            store,
            public=PublicReader(registry),
            origin=ORIGIN,
            rp_id=RP,
            grading=EnrollmentGrading("passkey_only", None),
        )
        config, tls = tls_config(app, tmp_path)
        async with (
            listener(app, config=config) as (origin, _server),
            httpx.AsyncClient(base_url=origin, verify=tls, trust_env=False) as client,
        ):
            empty = {"team_certificate": None, "id_chain": []}
            # R2: a valid foreign controller reserves the same bare person ID.
            for intent, seed in ((poison, root_b), (intent_a, root_a)):
                response = await exchange(
                    client,
                    "enrollment_start",
                    {"version": 1, "intent": intent, "admission": empty},
                    seed,
                    intent["intent"]["requester"],
                )
                assert response.status_code == 200, response.text
            started = response.json()
            read_answer("enrollment_start", started, status=200, intent=intent_a)
            locator = started["locator"]
            rows = await store.db.fetch_all(
                "SELECT organisation FROM {{tables.approval_enrollments}} WHERE person_id=$1 ORDER BY organisation",
                person,
            )
            assert [r["organisation"] for r in rows] == sorted([org_a, org_b])
            too_long = copy.deepcopy(intent_a)
            too_long["intent"]["deadline"] = too_long["intent"]["not_before"] + 86401
            too_long["signature"] = encode(
                SigningKey(root_a)
                .sign(domain("enrollment_intent") + canonical(too_long["intent"]))
                .signature
            )
            response = await exchange(
                client,
                "enrollment_start",
                {"version": 1, "intent": too_long, "admission": empty},
                root_a,
                intent_a["intent"]["requester"],
            )
            assert (
                response.status_code == 400
                and response.json()["error"]["code"] == "enrollment_lifetime_invalid"
            )
            opened = await browser(client, "enrollment/options", {"locator": locator})
            w = fixture()
            registered, _ = Vendor().registration(
                challenge=decode(intent_a["intent"]["challenge"]),
                credential=w["receipt"]["binding"]["binding"]["credentials"][0],
            )
            await browser(
                client,
                "enrollment/register",
                {
                    "locator": locator,
                    "csrf": opened["csrf"],
                    "registration": registered,
                    "client_extension_results": {"credProps": {"rk": True}},
                },
            )
            response = await exchange(
                client,
                "enrollment_material",
                {"version": 1, "intent": intent_a, "admission": empty},
                root_a,
                intent_a["intent"]["requester"],
            )
            assert response.status_code == 200, response.text
            material = read_answer(
                "enrollment_material", response.json(), status=200, intent=intent_a
            )
            assert (
                len(material["registrations"]) == 1
            )  # The person's reported count is one.
            same = material["registrations"][0]["registration"]
            assert same == registered
            entry = check_registration(
                same,
                expected_challenge=decode(intent_a["intent"]["challenge"]),
                origin=ORIGIN,
                rp_id=RP,
                snapshot=None,
                now=datetime.now(UTC),
            ).binding_entry()
            binding = sign_binding(
                intent_a, Ed25519PrivateKey.from_private_bytes(root_a), [entry]
            )
            # The issuer signs B only after its SAME raw registration check.
            confirmation = confirmation_request(intent_a, binding)
            confirm = {
                "version": 1,
                "intent": intent_a,
                "binding": binding,
                "request_bytes": encode(canonical(confirmation)),
                "admission": empty,
            }
            response = await exchange(
                client,
                "enrollment_confirm",
                confirm,
                root_a,
                intent_a["intent"]["requester"],
            )
            assert (
                response.status_code == 200 and response.json()["state"] == "pending"
            ), response.text
            # R3: a fresh page/token after the administrator prepared B.
            reopened = await browser(client, "enrollment/options", {"locator": locator})
            assert reopened["csrf"] != opened["csrf"]
            options = await browser(
                client,
                "enrollment/confirmation/options",
                {"locator": locator, "csrf": reopened["csrf"]},
            )
            creation_assertion = assertion(w["private"], -7, confirmation, entry["id"])
            await browser(
                client,
                "enrollment/confirmation/finish",
                {
                    "locator": locator,
                    "csrf": reopened["csrf"],
                    "id": options["id"],
                    "assertion": creation_assertion,
                },
            )
            response = await exchange(
                client,
                "enrollment_confirm",
                confirm,
                root_a,
                intent_a["intent"]["requester"],
            )
            assert (
                response.status_code == 200 and response.json()["state"] == "approved"
            ), response.text
            creation = assemble_receipt(
                canonical(confirmation),
                response.json(),
                locator=locator,
                intent=intent_a,
            )
            # Issuer checks its own nonce before committing any certificate.
            observed_issuer = await PublicReader(registry).issuer(intent_a)
            pending_trust = Trust(
                person,
                org_a,
                person_key,
                id_certificate_id(cert_a["certificate"]),
                observed_issuer.key,
                public_key_from_did(observed_issuer.key),
                observed_issuer.observed_at,
            )
            checked = check_creation_proof(
                creation,
                intent=intent_a,
                issuer_key=binding["binding"]["issuer"],
                requester=intent_a["intent"]["requester"],
                origin=ORIGIN,
                rp_id=RP,
                now=int(time.time()),
                nonce_keys={"k1": b"holder-owned-nonce-secret-for-test"},
                pending_trust=pending_trust,
            )
            assert checked["state"] == "pending"
            await commit_identity(registry, cert_a, person_seed)
            evidence = {
                "version": 1,
                "kind": "human",
                "organisation": org_a,
                "subject": {
                    "id": person,
                    "certificate": id_certificate_id(cert_a["certificate"]),
                    "key": person_key,
                },
                "issuer": binding["binding"]["issuer"],
                "binding_commitment": commitment("binding_commitment", binding),
                "creation": {
                    "credential": entry["id"],
                    "grade": entry["grade"],
                    "receipt_commitment": commitment("receipt_commitment", creation),
                },
            }
            signed_e = {
                "evidence": evidence,
                "signature": encode(
                    SigningKey(root_a)
                    .sign(domain("identity_evidence") + canonical(evidence))
                    .signature
                ),
            }
            activate = {
                "version": 1,
                "intent": intent_a,
                "binding": binding,
                "creation_receipt": creation,
                "evidence": signed_e,
                "id_chain": [cert_a],
            }
            response = await exchange(
                client,
                "enrollment_activate",
                activate,
                root_a,
                intent_a["intent"]["requester"],
            )
            assert (
                response.status_code == 200 and response.json()["state"] == "active"
            ), response.text
            # A real second-org agent, admitted by its own public ID chain.
            agent_seed, agent_public = generate_keypair()
            agent_key = did_from_public_key(agent_public)
            agent = stable_id_from_did_key(agent_key)
            agent_cert = certificate_for(agent, org_b, root_b, kind="agent")
            await commit_identity(registry, agent_cert, agent_seed)
            caller = {"kind": "identity", "id": person, "key": person_key}
            admission = {"team_certificate": None, "id_chain": [cert_a]}
            _target_seed, target_public = generate_keypair()
            target_key = did_from_public_key(target_public)
            target = stable_id_from_did_key(target_key)
            target_cert = certificate_for(target, org_a, root_a)
            r = {
                "version": 1,
                "purpose": "act_approval",
                "organisation": org_a,
                "approver": person,
                "requester": caller,
                "enforcer": {"audience": "https://holder.example.test"},
                "definition": definition_ref("human.add"),
                "act": {
                    "operation": "human.add",
                    "target": {
                        "person": target,
                        "certificate": id_certificate_id(target_cert["certificate"]),
                        "identity_key": target_key,
                    },
                    "expected_revision": 0,
                },
                "not_before": int(time.time()) - 1,
                "deadline": int(time.time()) + 120,
                "nonce": {"kid": "holder", "value": ""},
            }
            secret = b"private-holder-mac-key-for-native-test"
            r["nonce"]["value"] = encode(
                hmac.digest(secret, domain("nonce") + canonical(r), "sha256")
            )
            # R1: valid B requester, B-labelled R, A's enrolled person. Same
            # submit result, but it must never enter A's page or UV options.
            foreign = copy.deepcopy(r)
            foreign["organisation"] = org_b
            foreign["requester"] = {"kind": "identity", "id": agent, "key": agent_key}
            foreign_body = {
                "version": 1,
                "request_bytes": encode(canonical(foreign)),
                "admission": {"team_certificate": None, "id_chain": [agent_cert]},
            }
            response = await exchange(
                client, "submit", foreign_body, agent_seed, foreign["requester"]
            )
            assert (
                response.status_code == 200 and response.json()["state"] == "pending"
            ), response.text
            hidden = response.json()
            login = await browser(client, "login/options", {})
            session = await browser(
                client,
                "login/finish",
                {
                    "id": login["id"],
                    "assertion": login_assertion(w, login),
                    "user_handle": started["public_key"]["user"]["id"],
                },
            )
            response = await client.get("/browser/pending")
            assert response.status_code == 200, response.text
            assert response.json()["requests"] == []
            denied = await client.post(
                "/browser/approval/options",
                json={"locator": hidden["locator"], "csrf": session["csrf"]},
                headers={"Origin": ORIGIN},
            )
            assert denied.status_code == 404
            for path, extra in [
                ("approval/deny", {}),
                (
                    "approval/finish",
                    {"id": options["id"], "assertion": creation_assertion},
                ),
            ]:
                refused = await client.post(
                    "/browser/" + path,
                    json={
                        "locator": hidden["locator"],
                        "csrf": session["csrf"],
                        **extra,
                    },
                    headers={"Origin": ORIGIN},
                )
                assert refused.status_code == 404
            submit = {
                "version": 1,
                "request_bytes": encode(canonical(r)),
                "admission": admission,
            }
            response = await exchange(client, "submit", submit, person_seed, caller)
            assert response.status_code == 200, response.text
            original = response.json()
            # The other signed requester operation, cancellation, uses exact R.
            cancelled = copy.deepcopy(r)
            cancelled["act"]["expected_revision"] = 1
            cancelled["nonce"]["value"] = ""
            cancelled["nonce"]["value"] = encode(
                hmac.digest(secret, domain("nonce") + canonical(cancelled), "sha256")
            )
            body = {
                "version": 1,
                "request_bytes": encode(canonical(cancelled)),
                "admission": admission,
            }
            response = await exchange(client, "submit", body, person_seed, caller)
            assert response.status_code == 200, response.text
            selection = {
                "version": 1,
                "request_bytes": body["request_bytes"],
                "admission": admission,
                "locator": response.json()["locator"],
                "digest": response.json()["digest"],
            }
            response = await exchange(client, "cancel", selection, person_seed, caller)
            assert (
                response.status_code == 200 and response.json()["state"] == "cancelled"
            ), response.text
            response = await client.get("/browser/pending")
            assert response.status_code == 200, response.text
            assert [v["digest"] for v in response.json()["requests"]] == [
                original["digest"]
            ]
            options = await browser(
                client,
                "approval/options",
                {"locator": original["locator"], "csrf": session["csrf"]},
            )
            proof = assertion(w["private"], -7, r, entry["id"])
            await browser(
                client,
                "approval/finish",
                {
                    "locator": original["locator"],
                    "csrf": session["csrf"],
                    "id": options["id"],
                    "assertion": proof,
                },
            )
            selection = {
                "version": 1,
                "request_bytes": submit["request_bytes"],
                "admission": admission,
                "locator": original["locator"],
                "digest": original["digest"],
            }
            response = await exchange(client, "poll", selection, person_seed, caller)
            assert response.status_code == 200, response.text
            receipt = assemble_receipt(
                canonical(r), response.json(), locator=original["locator"]
            )
            trust = await read_trust(
                registry,
                [cert_a],
                person=person,
                identity_key=person_key,
                organisation=org_a,
            )
            checked = verify_for_effect(
                receipt,
                expected_request=r,
                presenter=caller,
                now=int(time.time()),
                trust=trust,
                required_grade="passkey_uv",
                nonce_keys={"holder": secret},
            )
            assert checked.person == person and checked.digest == original["digest"]
            assert (
                await store.poll(
                    original["locator"],
                    original["digest"],
                    hashlib.sha256(canonical(caller)).hexdigest(),
                    int(time.time()),
                    organisation=org_a,
                    person_id=person,
                )
            )["request_bytes"] is None
            # Sole-human recovery keeps the stable ID. Organisation authority
            # cannot rotate it: the real registry requires the previous ID key.
            from awid.registry import RegistryError

            new_seed, new_public = generate_keypair()
            new_key = did_from_public_key(new_public)
            with pytest.raises(RegistryError) as foreign_rotation:
                await registry.rotate_key(person, new_key, root_a, new_seed)
            assert foreign_rotation.value.status_code == 403
            assert (await registry.resolve_key(person)).current_did_key == person_key
            rotated = await registry.rotate_key(person, new_key, person_seed, new_seed)
            assert rotated.did_aw == person and rotated.current_did_key == new_key
            recovery_intent = signed_intent(cert_a, new_key, root_a)
            recovery_intent["intent"]["previous_binding_commitment"] = commitment(
                "binding_commitment", binding
            )
            recovery_intent["signature"] = encode(
                SigningKey(root_a)
                .sign(
                    domain("enrollment_intent") + canonical(recovery_intent["intent"])
                )
                .signature
            )
            response = await exchange(
                client,
                "enrollment_start",
                {"version": 1, "intent": recovery_intent, "admission": empty},
                root_a,
                recovery_intent["intent"]["requester"],
            )
            assert response.status_code == 200, response.text
            recovery_started = response.json()
            read_answer(
                "enrollment_start", recovery_started, status=200, intent=recovery_intent
            )
            recovery_locator = recovery_started["locator"]
            opened = await browser(
                client, "enrollment/options", {"locator": recovery_locator}
            )
            recovery_w = fixture()
            raw, _ = Vendor().registration(
                challenge=decode(recovery_intent["intent"]["challenge"]),
                credential=recovery_w["receipt"]["binding"]["binding"]["credentials"][
                    0
                ],
            )
            await browser(
                client,
                "enrollment/register",
                {
                    "locator": recovery_locator,
                    "csrf": opened["csrf"],
                    "registration": raw,
                    "client_extension_results": {"credProps": {"rk": True}},
                },
            )
            response = await exchange(
                client,
                "enrollment_material",
                {"version": 1, "intent": recovery_intent, "admission": empty},
                root_a,
                recovery_intent["intent"]["requester"],
            )
            assert response.status_code == 200, response.text
            material = read_answer(
                "enrollment_material",
                response.json(),
                status=200,
                intent=recovery_intent,
            )
            assert len(material["registrations"]) == 1
            new_entry = check_registration(
                material["registrations"][0]["registration"],
                expected_challenge=decode(recovery_intent["intent"]["challenge"]),
                origin=ORIGIN,
                rp_id=RP,
                snapshot=None,
                now=datetime.now(UTC),
            ).binding_entry()
            new_binding = sign_binding(
                recovery_intent,
                Ed25519PrivateKey.from_private_bytes(root_a),
                [new_entry],
            )
            new_r = confirmation_request(recovery_intent, new_binding)
            recovery_body = {
                "version": 1,
                "intent": recovery_intent,
                "binding": new_binding,
                "request_bytes": encode(canonical(new_r)),
                "admission": empty,
            }
            response = await exchange(
                client,
                "enrollment_confirm",
                recovery_body,
                root_a,
                recovery_intent["intent"]["requester"],
            )
            assert (
                response.status_code == 200 and response.json()["state"] == "pending"
            ), response.text
            options = await browser(
                client,
                "enrollment/confirmation/options",
                {"locator": recovery_locator, "csrf": opened["csrf"]},
            )
            await browser(
                client,
                "enrollment/confirmation/finish",
                {
                    "locator": recovery_locator,
                    "csrf": opened["csrf"],
                    "id": options["id"],
                    "assertion": assertion(
                        recovery_w["private"], -7, new_r, new_entry["id"]
                    ),
                },
            )
            response = await exchange(
                client,
                "enrollment_confirm",
                recovery_body,
                root_a,
                recovery_intent["intent"]["requester"],
            )
            assert (
                response.status_code == 200 and response.json()["state"] == "approved"
            ), response.text
            new_c = assemble_receipt(
                canonical(new_r),
                response.json(),
                locator=recovery_locator,
                intent=recovery_intent,
            )
            new_trust = await read_trust(
                registry,
                [cert_a],
                person=person,
                identity_key=new_key,
                organisation=org_a,
            )
            assert new_trust.person == person and new_trust.identity_key == new_key
            assert (
                check_creation_proof(
                    new_c,
                    intent=recovery_intent,
                    issuer_key=new_trust.issuer,
                    requester=recovery_intent["intent"]["requester"],
                    origin=ORIGIN,
                    rp_id=RP,
                    now=int(time.time()),
                    nonce_keys={"k1": b"holder-owned-nonce-secret-for-test"},
                    pending_trust=new_trust,
                )["state"]
                == "pending"
            )
            new_e = copy.deepcopy(evidence)
            new_e.update(
                subject={
                    "id": person,
                    "certificate": new_trust.certificate,
                    "key": new_key,
                },
                binding_commitment=commitment("binding_commitment", new_binding),
                creation={
                    "credential": new_entry["id"],
                    "grade": new_entry["grade"],
                    "receipt_commitment": commitment("receipt_commitment", new_c),
                },
                transition={
                    "mode": "recreated",
                    "before": {
                        "subject": evidence["subject"],
                        "binding_commitment": commitment("binding_commitment", binding),
                    },
                    "previous_evidence_commitment": commitment(
                        "identity_evidence_commitment", signed_e
                    ),
                    "confirmation_receipt_commitment": commitment(
                        "receipt_commitment", new_c
                    ),
                    "approval_receipt_commitment": None,
                },
            )
            recovery_activation = {
                "version": 1,
                "intent": recovery_intent,
                "binding": new_binding,
                "creation_receipt": new_c,
                "id_chain": [cert_a],
                "evidence": {
                    "evidence": new_e,
                    "signature": encode(
                        SigningKey(root_a)
                        .sign(domain("identity_evidence") + canonical(new_e))
                        .signature
                    ),
                },
            }
            carrier = {"kind": "identity", "id": person, "key": new_key}
            recovery_activation["carrier"] = carrier
            response = await exchange(
                client,
                "enrollment_activate",
                recovery_activation,
                new_seed,
                carrier,
            )
            assert (
                response.status_code == 200 and response.json()["state"] == "active"
            ), response.text
            old_session = await client.get("/browser/pending")
            assert (
                old_session.status_code == 403
                and old_session.json()["error"]["code"] == "session_invalid"
            )
            login = await browser(client, "login/options", {})
            await browser(
                client,
                "login/finish",
                {
                    "id": login["id"],
                    "assertion": login_assertion(recovery_w, login),
                    "user_handle": recovery_started["public_key"]["user"]["id"],
                },
            )
            assert (
                new_e["transition"]["mode"] == "recreated"
                and new_e["creation"] != evidence["creation"]
            )
