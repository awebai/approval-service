"""Current-issuer refresh over actual DNS, registry continuity and signed HTTP."""

import copy
import time

import httpx
import pytest
from awid.controller_signing import ControllerDescriptor, parse_controller_request
from awid.did import did_from_public_key, generate_keypair
from nacl.signing import SigningKey
from receipts import assertion

from approval_service.binding_refresh import BindingRefresher
from approval_service.binding_refresh_answers import read_binding_refresh_answer
from approval_service.canonical import canonical
from approval_service.encoding import encode
from approval_service.grading import EnrollmentGrading
from approval_service.http import create_app
from approval_service.public import PublicReader
from approval_service.seams import commitment
from approval_service.trust import read_trust
from approval_service.verify import Refused, verify_historical
from approval_service.wire import domain

from .real_stack import dns_zone
from .test_enrollment import ORIGIN, RP
from .test_signed_existing import EnrollmentMoment, signed_enrollment_world
from .test_signed_journey import exchange


@pytest.mark.asyncio
async def test_controller_rotation_refreshes_the_binding_without_another_ceremony(
    store, tmp_path
):
    async with signed_enrollment_world(
        store=store, tmp_path=tmp_path, moment=EnrollmentMoment.LATER
    ) as enrolled:
        seed, public = generate_keypair()
        key = did_from_public_key(public)
        old = ControllerDescriptor(
            "namespace", enrolled.organisation, enrolled.trust.issuer, "old", 0
        )
        new = ControllerDescriptor("namespace", enrolled.organisation, key, "new", 1)
        keys = {"old": enrolled.root, "new": seed}

        def sign_rotation(context):
            signer = SigningKey(keys[context.controller.key_reference])
            return context.controller.did_key, signer.sign(
                context.signing_bytes()
            ).signature

        # A real newly published TXT authorizes the normal continuity write.
        async with dns_zone(
            tmp_path / "rotation-dns", {enrolled.organisation: (seed, public)}
        ):
            await enrolled.registry.controller_request(
                parse_controller_request(
                    {
                        "operation": "namespace_rotate",
                        "domain": enrolled.organisation,
                        "from_seq": 1,
                        "previous_did_key": old.did_key,
                        "new_did_key": key,
                    }
                ),
                controllers={"controller": old, "new_controller": new},
                signer=sign_rotation,
            )
            trust = await read_trust(
                enrolled.registry,
                [enrolled.certificate],
                person=enrolled.person,
                identity_key=enrolled.key,
                organisation=enrolled.organisation,
            )
            assert trust.issuer == key and trust.namespace_issuer == key
            request = copy.deepcopy(enrolled.world["request"])
            request.update(
                organisation=enrolled.organisation,
                approver=enrolled.person,
                requester=enrolled.requester,
                not_before=int(time.time()) - 1,
                deadline=int(time.time()) + 120,
            )
            proof = assertion(
                enrolled.world["private"],
                -7,
                request,
                enrolled.binding["binding"]["credentials"][0]["id"],
            )
            receipt = {
                "version": 1,
                "request_bytes": encode(canonical(request)),
                "binding": enrolled.binding,
                "id_chain": [enrolled.certificate],
                "assertion": proof,
            }
            with pytest.raises(Refused) as refused:
                verify_historical(receipt, expected_request=request, trust=trust)
            assert refused.value.code == "binding_mismatch"
            body = {**enrolled.binding["binding"], "issuer": key}
            binding = {
                "binding": body,
                "signature": encode(
                    SigningKey(seed).sign(domain("binding") + canonical(body)).signature
                ),
            }
            packet = {
                "version": 1,
                "requester": enrolled.requester,
                "previous_binding_commitment": commitment(
                    "binding_commitment", enrolled.binding
                ),
                "binding": binding,
                "id_chain": [enrolled.certificate],
            }
            # A normal restart uses fresh checked public status; no cache or age is reset in storage.
            app = create_app(
                store,
                public=PublicReader(enrolled.registry),
                origin=ORIGIN,
                rp_id=RP,
                grading=EnrollmentGrading("passkey_only", None),
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url=ORIGIN
            ) as client:
                controller = {
                    "kind": "namespace_controller",
                    "namespace": enrolled.organisation,
                    "key": key,
                }
                refused = await exchange(
                    client,
                    "binding_refresh",
                    {**packet, "requester": controller},
                    seed,
                    controller,
                )
                assert refused.status_code == 403, refused.text
                assert refused.json()["error"]["code"] == "requester_mismatch"
                assert refused.json()["error"]["message"]
                response = await exchange(
                    client, "binding_refresh", packet, enrolled.seed, enrolled.requester
                )
                assert response.status_code == 200, response.text
                read_binding_refresh_answer(
                    response.json(), status=200, binding=binding
                )
                assert (
                    verify_historical(
                        {**receipt, "binding": binding},
                        expected_request=request,
                        trust=trust,
                    ).person
                    == enrolled.person
                )
                audit = await BindingRefresher(store).audit()
                assert len(audit) == 1
                assert (audit[0]["previous_issuer"], audit[0]["current_issuer"]) == (
                    old.did_key,
                    key,
                )
                # The original evidence still commits to its original ceremony and B.
                assert enrolled.statement["evidence"][
                    "binding_commitment"
                ] == commitment("binding_commitment", enrolled.binding)
