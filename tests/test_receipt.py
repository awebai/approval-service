import copy

import pytest
from receipts import assertion, fixture, resign

from approval_service.verify import Refused, Trust, verify_for_effect, verify_historical


def check(w, *, now=1100, grade="passkey_uv", presenter=None):
    return verify_for_effect(
        w["receipt"],
        expected_request=w["request"],
        trust=Trust(**w["status"]),
        now=now,
        required_grade=grade,
        presenter=presenter or w["request"]["requester"],
        nonce_keys={"k1": w["secret"]},
    )


@pytest.mark.parametrize("algorithm", [-7, -8, -257])
def test_actual_assertion_algorithms_and_zero_counter(algorithm):
    w = fixture(algorithm)
    result = check(w)
    assert result.grade == "passkey_uv"
    assert result.person == w["request"]["approver"]


@pytest.mark.parametrize("packaging", ["carried", "dropped", "superseded"])
@pytest.mark.parametrize("expired", [False, True])
def test_current_binding_rotation_rule_from_antares(packaging, expired):
    w = fixture()
    later = copy.deepcopy(w["receipt"]["binding"]["binding"])
    later["identity_key"] = "identity-key-after"
    later["certificate"] = "sha256:" + "c" * 64
    w["status"].update(
        identity_key=later["identity_key"],
        certificate=later["certificate"],
        observed_at=1301 if expired else 1100,
    )
    if packaging == "dropped":
        later["credentials"][0]["id"] = "bm90LXRoZS1vbGQta2V5"
    if packaging != "superseded":
        w["receipt"]["binding"] = resign(w, later)
    if packaging == "carried" and not expired:
        assert check(w).grade == "passkey_uv"
    else:
        with pytest.raises(Refused):
            check(w, now=1301 if expired else 1100)


@pytest.mark.parametrize(
    "fault",
    [
        "no_uv",
        "origin",
        "credential",
        "signature",
        "request",
        "presenter",
        "nonce",
        "stale_status",
        "issuer_signature",
    ],
)
def test_real_proof_and_enforcer_binding_refusals(fault):
    w = fixture()
    presenter = None
    if fault == "no_uv":
        w["receipt"]["assertion"] = assertion(
            w["private"],
            w["algorithm"],
            w["request"],
            w["receipt"]["assertion"]["id"],
            uv=False,
        )
    elif fault == "origin":
        w["receipt"]["assertion"] = assertion(
            w["private"],
            w["algorithm"],
            w["request"],
            w["receipt"]["assertion"]["id"],
            origin="https://other.example.test",
        )
    elif fault == "credential":
        w["receipt"]["assertion"]["id"] = "b3RoZXI"
    elif fault == "signature":
        w["receipt"]["assertion"]["signature"] = "YmFk"
    elif fault == "request":
        w["request"]["act"]["rights"] = ["admin"]
    elif fault == "presenter":
        presenter = {"kind": "identity", "id": "did:aw:another", "key": "other"}
    elif fault == "nonce":
        w["secret"] = b"wrong-secret"
    elif fault == "stale_status":
        w["status"]["observed_at"] = 1039
    else:
        w["receipt"]["binding"]["signature"] = "YmFk"
    with pytest.raises(Refused):
        check(w, presenter=presenter)


def test_other_enrolled_hardware_claim_cannot_upgrade_passkey_assertion():
    w = fixture()
    b = w["receipt"]["binding"]["binding"]
    other = copy.deepcopy(b["credentials"][0])
    other.update(
        id="b3RoZXI", grade="certified_hardware", snapshot="sha256:" + "d" * 64
    )
    b["credentials"].append(other)
    w["receipt"]["binding"] = resign(w, b)
    with pytest.raises(Refused):
        check(w, grade="certified_hardware")


def test_historical_saved_proof_does_not_apply_current_clock_deadline():
    w = fixture()
    result = verify_historical(
        w["receipt"], expected_request=w["request"], trust=Trust(**w["status"])
    )
    assert result.grade == "passkey_uv"


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", True),
        ("id_chain", {}),
        ("assertion", None),
        ("binding", []),
        ("request_bytes", 17),
    ],
)
def test_malformed_outer_input_is_a_named_refusal(field, value):
    w = fixture()
    w["receipt"][field] = value
    with pytest.raises(Refused):
        check(w)


def test_cose_private_key_duplicate_or_trailing_object_is_refused():
    from receipts import b64

    for suffix in (b"\xa0",):
        w = fixture()
        b = w["receipt"]["binding"]["binding"]
        raw = __import__("base64").urlsafe_b64decode(b["credentials"][0]["key"] + "==")
        b["credentials"][0]["key"] = b64(raw + suffix)
        w["receipt"]["binding"] = resign(w, b)
        with pytest.raises(Refused):
            check(w)


def test_binding_downgrade_of_the_actual_key_applies_to_old_assertion():
    w = fixture()
    b = w["receipt"]["binding"]["binding"]
    # Only an authenticated issuer grade claim is under test, not hardware evidence.
    b["credentials"][0].update(
        grade="certified_hardware", snapshot="sha256:" + "d" * 64
    )
    w["receipt"]["binding"] = resign(w, b)
    assert check(w, grade="certified_hardware").grade == "certified_hardware"
    b["credentials"][0].update(grade="passkey_uv", snapshot=None)
    w["receipt"]["binding"] = resign(w, b)
    with pytest.raises(Refused):
        check(w, grade="certified_hardware")


import json
from pathlib import Path

from approval_service.encoding import decode

_CASES = json.loads((Path(__file__).parents[1] / "vectors/receipts.json").read_text())[
    "cases"
]


@pytest.mark.parametrize("case", _CASES, ids=lambda c: c["id"])
def test_the_shared_frozen_receipt_corpus(case):
    status = {
        **case["trust"],
        "issuer_public_key": decode(case["trust"]["issuer_public_key"]),
    }
    kwargs = {
        "expected_request": case["request"],
        "trust": Trust(**status),
        "now": case["now"],
        "required_grade": case["required_grade"],
        "presenter": case["presenter"],
        "nonce_keys": {"k1": decode(case["nonce_key"])},
    }
    if case["accept"]:
        assert (
            verify_for_effect(case["receipt"], **kwargs).person
            == case["request"]["approver"]
        )
    else:
        with pytest.raises(Refused):
            verify_for_effect(case["receipt"], **kwargs)


def test_shared_corpus_keeps_all_review_neighbors():
    assert len(_CASES) == 22
    assert len({c["id"] for c in _CASES}) == 22


@pytest.mark.parametrize(
    "variant", ["cross-origin-absent", "leading-whitespace", "explicit-port"]
)
def test_legitimate_raw_client_data_variants_keep_their_signed_bytes(variant):
    from receipts import canon, signed_client

    w = fixture()
    if variant == "explicit-port":
        b = w["receipt"]["binding"]["binding"]
        b["origin"] = "https://approval.example.test:8443"
        w["receipt"]["binding"] = resign(w, b)

    def body(c):
        if variant == "cross-origin-absent":
            return canon({k: v for k, v in c.items() if k != "crossOrigin"})
        if variant == "leading-whitespace":
            return b" " + canon(c)
        return canon(c)

    signed_client(w, body)
    assert check(w).grade == "passkey_uv"


def test_malformed_bracketed_origin_is_a_named_refusal():
    w = fixture()
    b = w["receipt"]["binding"]["binding"]
    b["origin"] = "https://[invalid"
    w["receipt"]["binding"] = resign(w, b)
    with pytest.raises(Refused):
        check(w)
