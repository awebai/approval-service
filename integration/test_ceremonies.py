"""Real SQL/registration/UV controls; public Trust is an explicit checked port.

People are created through registration, confirmation and committed activation;
no credential or active enrollment is inserted by the tests with SQL.
"""

import hashlib
import sys
import time
from pathlib import Path

import pytest

from approval_service.canonical import canonical
from approval_service.ceremonies import Ceremonies
from approval_service.requester import AdmittedRequester
from approval_service.store import StoreRefused
from approval_service.verify import Refused

sys.path.insert(0, str(Path(__file__).parents[1] / "tests"))
from receipts import PREFIX, b64, signed_client


async def active_port(store):
    from dataclasses import replace

    from .test_enrollment import enroll_person

    w, trust, _bootstrap, binding, creation, started = await enroll_person(store)
    now = int(time.time())
    trust = replace(trust, observed_at=now)
    r = w["request"]
    r.update(
        organisation=trust.organisation,
        approver=trust.person,
        not_before=now - 1,
        deadline=now + 120,
        requester={"kind": "identity", "id": trust.person, "key": trust.identity_key},
    )
    w["receipt"].update(
        binding=binding, id_chain=creation["id_chain"], request_bytes=b64(canonical(r))
    )
    w["user_handle"] = started["public_key"]["user"]["id"]
    requester = AdmittedRequester(canonical(r["requester"]), r["requester"]["key"], now)
    await store.prepare(
        "operation",
        hashlib.sha256(PREFIX + canonical(r)).hexdigest(),
        requester.commitment,
        trust.person,
        canonical(r),
        now,
        r["deadline"],
        organisation=trust.organisation,
        requester_key=requester.key,
    )
    return (w, trust, requester)


def login_assertion(w, options, *, uv=True):
    import copy

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    a = copy.deepcopy(w["receipt"]["assertion"])
    client = canonical(
        {
            "type": "webauthn.get",
            "challenge": options["challenge"],
            "origin": "https://approval.example.test",
            "crossOrigin": False,
        }
    )
    auth = (
        hashlib.sha256(b"approval.example.test").digest()
        + bytes([5 if uv else 1])
        + b"\x00" * 4
    )
    a.update(
        client_data_json=b64(client),
        authenticator_data=b64(auth),
        signature=b64(
            w["private"].sign(
                auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())
            )
        ),
    )
    return a


@pytest.mark.asyncio
async def test_login_never_approves_and_act_uv_is_single_consumed_and_recoverable(
    store,
):
    w, trust, requester = await active_port(store)
    person = trust.person
    ceremonies = Ceremonies(
        store, origin="https://approval.example.test", rp_id="approval.example.test"
    )
    login = await ceremonies.login_options()
    assert login["allowCredentials"] == []
    subject = await ceremonies.login_subject(
        w["receipt"]["assertion"], w["user_handle"]
    )
    assert subject["person"] == person
    proof = login_assertion(w, login)
    session = await ceremonies.finish_login(login["id"], proof, w["user_handle"], trust)
    assert (
        await store.poll(
            "operation",
            hashlib.sha256(PREFIX + canonical(w["request"])).hexdigest(),
            requester.commitment,
            int(time.time()),
            organisation=trust.organisation,
            person_id=trust.person,
        )
    )["outcome"] == "pending"
    with pytest.raises(Refused):
        await ceremonies.finish_login(login["id"], proof, w["user_handle"], trust)
    options = await ceremonies.approval_options(
        person, "operation", session["session"], session["csrf"], trust, requester
    )
    with pytest.raises(Refused):
        await ceremonies.finish_approval(
            person,
            "operation",
            options["id"],
            proof,
            session["session"],
            session["csrf"],
            trust,
            requester,
        )
    signed_client(w, canonical)
    result = await ceremonies.finish_approval(
        person,
        "operation",
        options["id"],
        w["receipt"]["assertion"],
        session["session"],
        session["csrf"],
        trust,
        requester,
    )
    assert result == {
        "digest": hashlib.sha256(PREFIX + canonical(w["request"])).hexdigest(),
        "outcome": "approved",
    }
    with pytest.raises(Refused):
        await ceremonies.finish_approval(
            person,
            "operation",
            options["id"],
            w["receipt"]["assertion"],
            session["session"],
            session["csrf"],
            trust,
            requester,
        )
    saved = await store.poll(
        "operation",
        result["digest"],
        requester.commitment,
        int(time.time()),
        organisation=trust.organisation,
        person_id=trust.person,
    )
    assert saved["request_bytes"] is None
    assert saved["assertion"] == w["receipt"]["assertion"]
    assert (
        await store.poll(
            "operation",
            result["digest"],
            requester.commitment,
            int(time.time()),
            organisation=trust.organisation,
            person_id=trust.person,
        )
    )["assertion"] == saved["assertion"]
    assert (
        await store.audit(
            "operation", organisation=trust.organisation, person_id=trust.person
        )
    )[0]["outcome"] == "approved"
    assert await store.pending(person, organisation=trust.organisation) == []
    with pytest.raises(StoreRefused):
        await store.poll(
            "operation",
            result["digest"],
            "not-the-original-requester",
            int(time.time()),
            organisation=trust.organisation,
            person_id=trust.person,
        )
    expired = await store.poll(
        "operation",
        result["digest"],
        requester.commitment,
        w["request"]["deadline"],
        organisation=trust.organisation,
        person_id=trust.person,
    )
    assert expired["outcome"] == "approved"
    assert expired["assertion"] is None
    assert expired["request_bytes"] is None
    assert expired["receipt_available"] is False


@pytest.mark.asyncio
async def test_no_uv_login_and_wrong_csrf_do_not_create_or_consume_authority(store):
    w, trust, requester = await active_port(store)
    person = trust.person
    ceremonies = Ceremonies(
        store, origin="https://approval.example.test", rp_id="approval.example.test"
    )
    login = await ceremonies.login_options()
    assert login["allowCredentials"] == []
    subject = await ceremonies.login_subject(
        w["receipt"]["assertion"], w["user_handle"]
    )
    assert subject["person"] == person
    with pytest.raises(Refused):
        await ceremonies.finish_login(
            login["id"], login_assertion(w, login, uv=False), w["user_handle"], trust
        )
    async with store.transaction() as conn:
        assert (
            await conn.fetch_one(
                "SELECT count(*) AS n FROM {{tables.approval_sessions}}"
            )
        )["n"] == 0
        assert (
            await conn.fetch_one(
                "SELECT consumed FROM {{tables.approval_challenges}} WHERE challenge_id=$1",
                login["id"],
            )
        )["consumed"] is False
    session = await ceremonies.finish_login(
        login["id"], login_assertion(w, login), w["user_handle"], trust
    )
    with pytest.raises(Refused):
        await ceremonies.approval_options(
            person, "operation", session["session"], "wrong-csrf", trust, requester
        )
    assert len(await store.pending(person, organisation=trust.organisation)) == 1


@pytest.mark.asyncio
async def test_anonymous_login_does_not_enumerate_people_or_accept_another_handle(
    store,
):
    w, trust, _requester = await active_port(store)
    ceremonies = Ceremonies(
        store, origin="https://approval.example.test", rp_id="approval.example.test"
    )
    options = await ceremonies.login_options()
    assert options["allowCredentials"] == []
    assert not {"person", "user", "credentials"}.intersection(options)
    assertion = login_assertion(w, options)
    with pytest.raises(Refused, match="credential_not_enrolled"):
        await ceremonies.finish_login(
            options["id"], assertion, b64(b"another-handle"), trust
        )
    assert await store.db.fetch_one(
        "SELECT count(*) AS n FROM {{tables.approval_sessions}}"
    ) == {"n": 0}
    session = await ceremonies.finish_login(
        options["id"], assertion, w["user_handle"], trust
    )
    assert session["deadline"] > int(time.time())
