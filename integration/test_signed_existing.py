"""Actual HTTP and registry: enrollment after creation has no creation claim."""

import time
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.signing import SigningKey
from receipts import assertion, fixture
from vendor import Vendor

from approval_service.answers import assemble_receipt
from approval_service.canonical import canonical
from approval_service.encoding import decode, encode
from approval_service.grading import EnrollmentGrading
from approval_service.http import create_app
from approval_service.public import PublicReader
from approval_service.registration import check_registration
from approval_service.seams import commitment
from approval_service.statements import verify_enrollment_evidence
from approval_service.trust import read_trust
from approval_service.wire import domain

from .real_stack import registry_stack
from .test_enrollment import ORIGIN, RP, confirmation_request, sign_binding
from .test_signed_journey import (
    browser,
    certificate_for,
    commit_identity,
    exchange,
    signed_intent,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "existing", [True, False], ids=["committed-later", "pending-own-key"]
)
async def test_signed_person_carries_only_their_enrollment(store, tmp_path, existing):
    root, pub = generate_keypair()
    seed, public = generate_keypair()
    key = did_from_public_key(public)
    person = stable_id_from_did_key(key)
    org = "later-" + uuid4().hex[:10] + ".example.test"
    cert = certificate_for(person, org, root)
    intent = signed_intent(cert, key, root)
    i = intent["intent"]
    i["requester"] = {"kind": "identity", "id": person, "key": key}
    if existing:
        i["purpose"] = "enroll_existing_person"
    intent["signature"] = encode(
        SigningKey(root).sign(domain("enrollment_intent") + canonical(i)).signature
    )
    chain = [cert] if existing else []
    admission = {"team_certificate": None, "id_chain": chain}
    async with registry_stack(tmp_path, {org: (root, pub)}) as registry:
        await registry.register_did(key, seed)
        if existing:
            await commit_identity(registry, cert, seed)
        app = create_app(
            store,
            public=PublicReader(registry),
            origin=ORIGIN,
            rp_id=RP,
            grading=EnrollmentGrading("passkey_only", None),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=ORIGIN
        ) as client:
            packet = {"version": 1, "intent": intent, "admission": admission}
            response = await exchange(
                client, "enrollment_start", packet, seed, i["requester"]
            )
            assert response.status_code == 200, response.text
            locator = response.json()["locator"]
            opened = await browser(client, "enrollment/options", {"locator": locator})
            w = fixture()
            raw, _ = Vendor().registration(
                challenge=decode(i["challenge"]),
                credential=w["receipt"]["binding"]["binding"]["credentials"][0],
            )
            await browser(
                client,
                "enrollment/register",
                {
                    "locator": locator,
                    "csrf": opened["csrf"],
                    "registration": raw,
                    "client_extension_results": {"credProps": {"rk": True}},
                },
            )
            response = await exchange(
                client, "enrollment_material", packet, seed, i["requester"]
            )
            assert response.status_code == 200, response.text
            entry = check_registration(
                response.json()["registrations"][0]["registration"],
                expected_challenge=decode(i["challenge"]),
                origin=ORIGIN,
                rp_id=RP,
                snapshot=None,
                now=datetime.now(UTC),
            ).binding_entry()
            binding = sign_binding(
                intent, Ed25519PrivateKey.from_private_bytes(root), [entry]
            )
            r = confirmation_request(intent, binding)
            confirm = {
                **packet,
                "binding": binding,
                "request_bytes": encode(canonical(r)),
            }
            response = await exchange(
                client, "enrollment_confirm", confirm, seed, i["requester"]
            )
            assert response.status_code == 200, response.text
            options = await browser(
                client,
                "enrollment/confirmation/options",
                {"locator": locator, "csrf": opened["csrf"]},
            )
            await browser(
                client,
                "enrollment/confirmation/finish",
                {
                    "locator": locator,
                    "csrf": opened["csrf"],
                    "id": options["id"],
                    "assertion": assertion(w["private"], -7, r, entry["id"]),
                },
            )
            response = await exchange(
                client, "enrollment_confirm", confirm, seed, i["requester"]
            )
            assert response.status_code == 200, response.text
            c = assemble_receipt(
                canonical(r), response.json(), locator=locator, intent=intent
            )
            if not existing:
                await commit_identity(registry, cert, seed)
            trust = await read_trust(
                registry, [cert], person=person, identity_key=key, organisation=org
            )
            e = {
                "version": 1,
                "kind": "human_enrolled_later" if existing else "human",
                "organisation": org,
                "subject": {"id": person, "certificate": trust.certificate, "key": key},
                "issuer": trust.namespace_issuer,
                "binding_commitment": commitment("binding_commitment", binding),
            }
            if existing:
                e["enrollment"] = {
                    "credential": entry["id"],
                    "grade": entry["grade"],
                    "since": int(time.time()),
                    "confirmation_receipt_commitment": commitment(
                        "receipt_commitment", c
                    ),
                }
            else:
                e["creation"] = {
                    "credential": entry["id"],
                    "grade": entry["grade"],
                    "receipt_commitment": commitment("receipt_commitment", c),
                }
            signed = {
                "evidence": e,
                "signature": encode(
                    SigningKey(root)
                    .sign(
                        domain(
                            "later_enrollment_evidence"
                            if existing
                            else "identity_evidence"
                        )
                        + canonical(e)
                    )
                    .signature
                ),
            }
            activation = {
                "version": 2 if existing else 1,
                "intent": intent,
                "binding": binding,
                "evidence": signed,
                "id_chain": [cert],
                ("confirmation_receipt" if existing else "creation_receipt"): c,
            }
            response = await exchange(
                client, "enrollment_activate", activation, seed, i["requester"]
            )
            assert response.status_code == 200, response.text
            if existing:
                assert "creation" not in e
                assert (
                    verify_enrollment_evidence(signed, trust=trust, receipt=c)[
                        "proof_status"
                    ]
                    == "checked"
                )
