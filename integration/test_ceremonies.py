"""Real SQL and software-key UV controls, not enrollment/registry qualification.

SQL prepares the already-active private credential/binding port. No verifier,
challenge, clock, session, counter, transaction or transport is substituted.
"""

import hashlib
import json
import sys
import time
from pathlib import Path

import pytest

from approval_service.canonical import canonical
from approval_service.ceremonies import Ceremonies
from approval_service.encoding import decode
from approval_service.requester import AdmittedRequester
from approval_service.store import StoreRefused
from approval_service.verify import Refused, Trust

sys.path.insert(0, str(Path(__file__).parents[1] / "tests"))
from receipts import PREFIX, b64, fixture, resign, signed_client


async def active_port(store):
    w = fixture()
    now = int(time.time())
    w["status"]["observed_at"] = now
    r = w["request"]
    r.update(not_before=now - 1, deadline=now + 120)
    w["receipt"]["request_bytes"] = b64(canonical(r))
    b = w["receipt"]["binding"]["binding"]
    w["receipt"]["binding"] = resign(w, b)
    ref = "sha256:" + hashlib.sha256(canonical(w["receipt"]["binding"])).hexdigest()
    credential = b["credentials"][0]
    async with store.transaction() as conn:
        await conn.execute(
            "INSERT INTO {{tables.approval_enrollments}}(person_id,organisation,identity_key,certificate,issuer,user_handle,deadline,state,binding_ref) VALUES($1,$2,$3,$4,$5,$6,$7,'active',$8)",
            b["person"],
            b["organisation"],
            b["identity_key"],
            b["certificate"],
            b["issuer"],
            b"disposable-user-handle",
            now + 120,
            ref,
        )
        await conn.execute(
            "INSERT INTO {{tables.approval_binding_versions}}(digest,person_id,binding,id_chain) VALUES($1,$2,$3::jsonb,'[]'::jsonb)",
            ref,
            b["person"],
            json.dumps(w["receipt"]["binding"]),
        )
        await conn.execute(
            "INSERT INTO {{tables.approval_credentials}}(person_id,credential_id,public_key,sign_count,grade,snapshot,attestation) VALUES($1,$2,$3,0,'passkey_uv',NULL,$4)",
            b["person"],
            credential["id"],
            decode(credential["key"]),
            b"software-key-fixture-no-hardware-claim",
        )
    requester = AdmittedRequester(canonical(r["requester"]), r["requester"]["key"], now)
    await store.prepare(
        "operation",
        hashlib.sha256(PREFIX + canonical(r)).hexdigest(),
        requester.commitment,
        b["person"],
        canonical(r),
        now,
        r["deadline"],
    )
    return (w, Trust(**w["status"]), requester)


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
        w["receipt"]["assertion"], b64(b"disposable-user-handle")
    )
    assert subject["person"] == person
    proof = login_assertion(w, login)
    session = await ceremonies.finish_login(
        login["id"], proof, b64(b"disposable-user-handle"), trust
    )
    assert (
        await store.poll(
            "operation",
            hashlib.sha256(PREFIX + canonical(w["request"])).hexdigest(),
            requester.commitment,
            int(time.time()),
        )
    )["outcome"] == "pending"
    with pytest.raises(Refused):
        await ceremonies.finish_login(
            login["id"], proof, b64(b"disposable-user-handle"), trust
        )
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
        "operation", result["digest"], requester.commitment, int(time.time())
    )
    assert saved["request_bytes"] is None
    assert saved["assertion"] == w["receipt"]["assertion"]
    assert (
        await store.poll(
            "operation", result["digest"], requester.commitment, int(time.time())
        )
    )["assertion"] == saved["assertion"]
    assert (await store.audit("operation"))[0]["outcome"] == "approved"
    assert await store.pending(person) == []
    with pytest.raises(StoreRefused):
        await store.poll(
            "operation",
            result["digest"],
            "not-the-original-requester",
            int(time.time()),
        )
    expired = await store.poll(
        "operation", result["digest"], requester.commitment, w["request"]["deadline"]
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
        w["receipt"]["assertion"], b64(b"disposable-user-handle")
    )
    assert subject["person"] == person
    with pytest.raises(Refused):
        await ceremonies.finish_login(
            login["id"],
            login_assertion(w, login, uv=False),
            b64(b"disposable-user-handle"),
            trust,
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
        login["id"], login_assertion(w, login), b64(b"disposable-user-handle"), trust
    )
    with pytest.raises(Refused):
        await ceremonies.approval_options(
            person, "operation", session["session"], "wrong-csrf", trust, requester
        )
    assert len(await store.pending(person)) == 1


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
        options["id"], assertion, b64(b"disposable-user-handle"), trust
    )
    assert session["deadline"] > int(time.time())
