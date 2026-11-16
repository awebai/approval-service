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
from approval_service.verify import Refused, Trust

sys.path.insert(0, str(Path(__file__).parents[1] / "tests"))
from receipts import PREFIX, b64, fixture, resign, signed_client


def active_port(store):
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
    with store.connection() as conn, conn.transaction():
        conn.execute(
            "INSERT INTO approval_enrollments(person_id,organisation,identity_key,certificate,issuer,user_handle,deadline,state,binding_ref) VALUES(%s,%s,%s,%s,%s,%s,%s,'active',%s)",
            (
                b["person"],
                b["organisation"],
                b["identity_key"],
                b["certificate"],
                b["issuer"],
                b"disposable-user-handle",
                now + 120,
                ref,
            ),
        )
        conn.execute(
            "INSERT INTO approval_binding_versions(digest,person_id,binding,id_chain) VALUES(%s,%s,%s::jsonb,'[]'::jsonb)",
            (ref, b["person"], json.dumps(w["receipt"]["binding"])),
        )
        conn.execute(
            "INSERT INTO approval_credentials(person_id,credential_id,public_key,sign_count,grade,snapshot,attestation) VALUES(%s,%s,%s,0,'passkey_uv',NULL,%s)",
            (
                b["person"],
                credential["id"],
                decode(credential["key"]),
                b"software-key-fixture-no-hardware-claim",
            ),
        )
    requester = AdmittedRequester(canonical(r["requester"]), r["requester"]["key"], now)
    store.prepare(
        "operation",
        hashlib.sha256(PREFIX + canonical(r)).hexdigest(),
        requester.commitment,
        b["person"],
        canonical(r),
        now,
        r["deadline"],
    )
    return w, Trust(**w["status"]), requester


def login_assertion(w, options, *, uv=True):
    # This proof signs the actual issued LOGIN challenge, never an act digest.
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
        + b"\0" * 4
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


def test_login_never_approves_and_act_uv_is_single_consumed_and_recoverable(store):
    w, trust, requester = active_port(store)
    person = trust.person
    ceremonies = Ceremonies(
        store, origin="https://approval.example.test", rp_id="approval.example.test"
    )
    login = ceremonies.login_options(person, trust)
    proof = login_assertion(w, login)
    session = ceremonies.finish_login(person, login["id"], proof, trust)
    assert (
        store.poll(
            "operation",
            hashlib.sha256(PREFIX + canonical(w["request"])).hexdigest(),
            requester.commitment,
            int(time.time()),
        )["outcome"]
        == "pending"
    )
    with pytest.raises(Refused):
        ceremonies.finish_login(person, login["id"], proof, trust)
    options = ceremonies.approval_options(
        person, "operation", session["session"], session["csrf"], trust, requester
    )
    with pytest.raises(Refused):
        ceremonies.finish_approval(
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
    result = ceremonies.finish_approval(
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
        ceremonies.finish_approval(
            person,
            "operation",
            options["id"],
            w["receipt"]["assertion"],
            session["session"],
            session["csrf"],
            trust,
            requester,
        )
    saved = store.poll(
        "operation", result["digest"], requester.commitment, int(time.time())
    )
    assert saved["request_bytes"] is None
    assert saved["assertion"] == w["receipt"]["assertion"]
    assert (
        store.poll(
            "operation", result["digest"], requester.commitment, int(time.time())
        )["assertion"]
        == saved["assertion"]
    )
    assert store.audit("operation")[0]["outcome"] == "approved"


def test_no_uv_login_and_wrong_csrf_do_not_create_or_consume_authority(store):
    w, trust, requester = active_port(store)
    person = trust.person
    ceremonies = Ceremonies(
        store, origin="https://approval.example.test", rp_id="approval.example.test"
    )
    login = ceremonies.login_options(person, trust)
    with pytest.raises(Refused):
        ceremonies.finish_login(
            person, login["id"], login_assertion(w, login, uv=False), trust
        )
    with store.connection() as conn:
        assert (
            conn.execute("SELECT count(*) AS n FROM approval_sessions").fetchone()["n"]
            == 0
        )
        assert (
            conn.execute(
                "SELECT consumed FROM approval_challenges WHERE challenge_id=%s",
                (login["id"],),
            ).fetchone()["consumed"]
            is False
        )
    session = ceremonies.finish_login(
        person, login["id"], login_assertion(w, login), trust
    )
    with pytest.raises(Refused):
        ceremonies.approval_options(
            person, "operation", session["session"], "wrong-csrf", trust, requester
        )
    assert len(store.pending(person)) == 1
