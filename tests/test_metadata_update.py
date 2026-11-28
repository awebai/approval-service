"""The pin publisher verifies actual signatures before proposing any hashes."""

import copy
import json
import sys
from datetime import timedelta

import pytest
from test_metadata_cache import manifest
from vendor import NOW, Vendor, signed_metadata

from approval_service.metadata import MetadataRefused
from approval_service.metadata_cache import fetch_and_pin
from approval_service.metadata_update import main, propose_pin


def test_unchanged_upstream_does_not_create_a_daily_pin_diff(transport, tmp_path):
    current = manifest(transport)
    current.update(
        retrieved_at=NOW.isoformat(),
        next_update="2026-11-16",
        valid_until="2026-11-16T00:00:00Z",
    )
    cache = tmp_path / "cache"
    proposed = propose_pin(current, cache_dir=cache, now=NOW)
    assert proposed == current
    assert fetch_and_pin(cache, manifest=proposed, now=NOW).sequence == 1
    assert transport[2] == ["/1/root", "/1/blob", "/1/crl"]


@pytest.mark.parametrize("headers", [{}, {"Retry-After": "120"}])
def test_rate_limit_stops_the_pin_cli_without_retry(
    transport, tmp_path, monkeypatch, capsys, headers
):
    current = manifest(transport)
    pin = tmp_path / "pin.json"
    pin.write_text(json.dumps(current))
    cache = tmp_path / "cache"
    transport[1]["/1/blob"] = (429, headers)
    monkeypatch.setattr(
        sys, "argv", ["metadata_update", "--manifest", str(pin), "--cache-dir", str(cache)]
    )

    with pytest.raises(SystemExit) as failure:
        main()

    assert failure.value.code == 1
    output = capsys.readouterr()
    hint = "; Retry-After header present" if headers else ""
    assert output.err == f"FIDO metadata upstream unavailable (HTTP 429{hint}).\n"
    assert output.out == ""
    assert pin.read_text() == json.dumps(current)
    assert transport[2] == ["/1/root", "/1/blob"]


def test_new_signed_blob_is_verified_and_proposed_without_changing_root(
    transport, tmp_path
):
    current = manifest(transport)
    before = copy.deepcopy(current)
    new = signed_metadata(
        [Vendor().entry()], sequence=2, next_update=NOW + timedelta(days=10)
    )
    transport[1]["/1/blob"] = new["blob"]
    proposed = propose_pin(current, cache_dir=tmp_path / "cache", now=NOW)
    assert current == before
    assert proposed["minimum_sequence"] == 2
    assert proposed["artifacts"]["blob"]["sha256"] == new["blob_sha256"]
    assert proposed["artifacts"]["root"] == current["artifacts"]["root"]
    assert proposed["next_update"] == "2026-11-25"
    assert proposed["valid_until"] == "2026-11-22T21:00:00Z"
    assert proposed["retrieved_at"] == NOW.isoformat()


@pytest.mark.parametrize(
    "fault", ["changed_signature", "rollback", "untrusted_root", "missing_crl"]
)
def test_upstream_replacement_cannot_create_a_pin_without_trust(
    transport, tmp_path, fault
):
    current = manifest(transport)
    if fault == "changed_signature":
        raw = bytearray(transport[1]["/1/blob"])
        raw[-20] = ord("A") if raw[-20] != ord("A") else ord("B")
        transport[1]["/1/blob"] = bytes(raw)
    elif fault == "rollback":
        current["minimum_sequence"] = 2
    elif fault == "untrusted_root":
        current["artifacts"]["root"]["sha256"] = "0" * 64
    else:
        transport[1]["/1/crl"] = b"not a CRL"
    before = copy.deepcopy(current)
    with pytest.raises((ValueError, MetadataRefused)):
        propose_pin(current, cache_dir=tmp_path / "cache", now=NOW)
    assert current == before
    assert not (tmp_path / "cache" / "installed-sequence.json").exists()
