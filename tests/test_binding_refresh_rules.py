"""A current issuer may re-sign, but cannot use refresh to replace credentials."""

import copy
from dataclasses import replace

import pytest
from awid.did import did_from_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from receipts import b64, canon, fixture

from approval_service.binding_refresh import (
    RefreshFailure,
    RefreshRefused,
    check_refresh_replacement,
)
from approval_service.verify import BINDING_PREFIX, Trust


def refresh_world():
    original = fixture()
    issuer = Ed25519PrivateKey.generate()
    trust = replace(
        Trust(**original["status"]),
        issuer=did_from_public_key(issuer.public_key().public_bytes_raw()),
        issuer_public_key=issuer.public_key().public_bytes_raw(),
        certificate="sha256:" + "c" * 64,
    )
    return original["receipt"]["binding"], issuer, trust


def signed_candidate(previous, *, issuer, trust, credential_changes=None):
    body = copy.deepcopy(previous["binding"])
    body.update(issuer=trust.issuer, certificate=trust.certificate)
    if credential_changes:
        body["credentials"][0].update(credential_changes)
    return {
        "binding": body,
        "signature": b64(issuer.sign(BINDING_PREFIX + canon(body))),
    }


def test_current_issuer_can_resign_the_same_enrollment_for_a_current_certificate():
    previous, issuer, trust = refresh_world()
    candidate = signed_candidate(previous, issuer=issuer, trust=trust)
    check_refresh_replacement(previous, candidate, trust=trust)


@pytest.mark.parametrize(
    "changes",
    [
        {"id": b64(b"another credential")},
        {"key": b64(b"another key")},
        {"algorithm": -8},
        {"grade": "certified_hardware", "snapshot": "sha256:" + "a" * 64},
    ],
)
def test_even_a_valid_current_issuer_signature_cannot_replace_credentials(changes):
    previous, issuer, trust = refresh_world()
    candidate = signed_candidate(
        previous, issuer=issuer, trust=trust, credential_changes=changes
    )
    with pytest.raises(RefreshRefused) as refusal:
        check_refresh_replacement(previous, candidate, trust=trust)
    assert refusal.value.reason is RefreshFailure.CREDENTIAL_CHANGED
    assert refusal.value.message


def test_an_unrelated_signer_is_not_current_issuer_authority():
    previous, issuer, trust = refresh_world()
    candidate = signed_candidate(previous, issuer=issuer, trust=trust)
    candidate["signature"] = b64(
        Ed25519PrivateKey.generate().sign(BINDING_PREFIX + canon(candidate["binding"]))
    )
    with pytest.raises(RefreshRefused) as refusal:
        check_refresh_replacement(previous, candidate, trust=trust)
    assert refusal.value.reason is RefreshFailure.PROOF_INVALID


def test_python_cbor_profile_implements_the_frozen_cross_language_limits():
    from aweb_naapp.webauthn_cbor import LIMITS

    from approval_service.wire import SCHEMA

    # format-v1's x-cbor-limits is the contract read by the Go verifier too.
    assert LIMITS == SCHEMA["x-cbor-limits"]
