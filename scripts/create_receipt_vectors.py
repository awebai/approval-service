"""Freeze real software-authenticator signatures; NEVER auto-refreeze in tests."""

import copy
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tests"))
from receipts import b64, canon, fixture, resign, signed_client

out = root / "vectors/receipts.json"
append_review = "--append-review" in sys.argv
append_hostnames = "--append-hostnames" in sys.argv
append_patterns = "--append-patterns" in sys.argv
append_cose = "--append-cose" in sys.argv
append_extra = "--append-cose-extra" in sys.argv
if out.exists() and not (
    append_review or append_hostnames or append_patterns or append_cose or append_extra
):
    raise SystemExit("refuse to overwrite frozen vectors")
cases = (
    json.loads(out.read_text())["cases"]
    if (
        append_review
        or append_hostnames
        or append_patterns
        or append_cose
        or append_extra
    )
    else []
)


def add(name, w, accept, now=1100, required_grade="passkey_uv"):
    if any(case["id"] == name for case in cases):
        raise SystemExit("refuse to replace existing vector: " + name)
    status = {**w["status"], "issuer_public_key": b64(w["status"]["issuer_public_key"])}
    cases.append(
        {
            "id": name,
            "receipt": w["receipt"],
            "request": w["request"],
            "trust": status,
            "nonce_key": b64(w["secret"]),
            "now": now,
            "required_grade": required_grade,
            "presenter": w["request"]["requester"],
            "accept": accept,
        }
    )


if not (
    append_review or append_hostnames or append_patterns or append_cose or append_extra
):
    for algorithm in (-7, -8, -257):
        add("algorithm-" + str(algorithm), fixture(algorithm), True)
    for packaging in ("carried", "dropped", "superseded"):
        for expired in (False, True):
            w = fixture()
            later = copy.deepcopy(w["receipt"]["binding"]["binding"])
            later.update(
                identity_key="identity-key-after", certificate="sha256:" + "c" * 64
            )
            w["status"].update(
                identity_key=later["identity_key"],
                certificate=later["certificate"],
                observed_at=1301 if expired else 1100,
            )
            if packaging == "dropped":
                later["credentials"][0]["id"] = b64(b"another-key")
            if packaging != "superseded":
                w["receipt"]["binding"] = resign(w, later)
            add(
                packaging + ("-expired" if expired else "-current"),
                w,
                packaging == "carried" and not expired,
                now=1301 if expired else 1100,
            )
    w = fixture()
    w["receipt"]["assertion"]["signature"] = b64(b"bad")
    add("changed-signature", w, False)
    w = fixture()
    b = w["receipt"]["binding"]["binding"]
    other = copy.deepcopy(b["credentials"][0])
    other.update(
        id=b64(b"other"), grade="certified_hardware", snapshot="sha256:" + "d" * 64
    )
    b["credentials"].append(other)
    w["receipt"]["binding"] = resign(w, b)
    add(
        "different-key-hardware-cannot-upgrade",
        w,
        False,
        required_grade="certified_hardware",
    )
if not (append_hostnames or append_patterns or append_cose or append_extra):
    # Six review regressions: each has a genuine issuer and assertion signature.
    import cbor2

    for name, mutate in [
        ("cross-origin-true", lambda c: canon({**c, "crossOrigin": True})),
        (
            "client-duplicate-same",
            lambda c: canon(c)[:-1] + b',"origin":"https://approval.example.test"}',
        ),
        (
            "client-duplicate-first-foreign",
            lambda c: b'{"origin":"https://foreign.example.test",' + canon(c)[1:],
        ),
        (
            "client-padded-challenge",
            lambda c: canon({**c, "challenge": c["challenge"] + "="}),
        ),
    ]:
        w = fixture()
        signed_client(w, mutate)
        add(name, w, False)
    w = fixture()
    b = w["receipt"]["binding"]["binding"]
    b["origin"] = "https://APPROVAL.example.test"
    w["receipt"]["binding"] = resign(w, b)
    signed_client(w, canon)
    add("origin-uppercase-host", w, False)
    w = fixture()
    b = w["receipt"]["binding"]["binding"]
    other = copy.deepcopy(b["credentials"][0])
    other["id"] = b64(b"other-off-curve")
    other["key"] = b64(
        cbor2.dumps({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})
    )
    b["credentials"].append(other)
    w["receipt"]["binding"] = resign(w, b)
    add("unselected-off-curve-key", w, False)
if append_hostnames:
    import hashlib

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    for name, rp in [
        ("rp-uppercase", "APPROVAL.example.test"),
        ("rp-space", "a b.example"),
        ("rp-percent", "a%41.example"),
        ("rp-trailing-dot", "approval.example.test."),
        ("rp-raw-unicode", "approvál.example.test"),
    ]:
        w = fixture()
        b = w["receipt"]["binding"]["binding"]
        b["rp_id"] = rp
        b["origin"] = "https://" + rp
        w["receipt"]["binding"] = resign(w, b)
        signed_client(w, canon)
        a = w["receipt"]["assertion"]
        from approval_service.encoding import decode

        auth = (
            hashlib.sha256(rp.encode()).digest() + decode(a["authenticator_data"])[32:]
        )
        a["authenticator_data"] = b64(auth)
        a["signature"] = b64(
            w["private"].sign(
                auth + hashlib.sha256(decode(a["client_data_json"])).digest(),
                ec.ECDSA(hashes.SHA256()),
            )
        )
        add(name, w, False)
if append_patterns:
    import hmac

    from receipts import NONCE_PREFIX

    w = fixture()
    b = w["receipt"]["binding"]["binding"]
    b["credentials"][0]["snapshot"] = "sha256:" + "c" * 64 + "\n"
    w["receipt"]["binding"] = resign(w, b)
    add("snapshot-trailing-newline", w, False)
    w = fixture()
    r = w["request"]
    r["definition"]["sha256"] += "\n"
    r["nonce"]["value"] = ""
    r["nonce"]["value"] = b64(
        hmac.digest(w["secret"], NONCE_PREFIX + canon(r), "sha256")
    )
    w["receipt"]["request_bytes"] = b64(canon(r))
    signed_client(w, canon)
    add("definition-digest-trailing-newline", w, False)
if append_cose:
    import hashlib

    import cbor2
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    from approval_service.encoding import decode

    for name, algorithm, label, value in [
        ("cose-float-key-type", -7, 1, 2.0),
        ("cose-bool-curve", -7, -1, True),
        ("cose-bool-key-type", -8, 1, True),
        ("cose-rsa-float-key-type", -257, 1, 3.0),
        ("cose-tagged-key-type", -7, 1, cbor2.CBORTag(2, b"\x02")),
    ]:
        w = fixture(algorithm)
        b = w["receipt"]["binding"]["binding"]
        key = cbor2.loads(decode(b["credentials"][0]["key"]))
        key[label] = value
        b["credentials"][0]["key"] = b64(cbor2.dumps(key))
        w["receipt"]["binding"] = resign(w, b)
        add(name, w, False)
    for name, tagged in [("cose-tagged-map", True), ("cose-map-over-limit", False)]:
        w = fixture()
        b = w["receipt"]["binding"]["binding"]
        key = cbor2.loads(decode(b["credentials"][0]["key"]))
        if tagged:
            key = cbor2.CBORTag(55799, key)
        else:
            key.update({100 + i: i for i in range(12)})
        b["credentials"][0]["key"] = b64(cbor2.dumps(key))
        w["receipt"]["binding"] = resign(w, b)
        add(name, w, False)
    for name, extension, accept in [
        ("assertion-tagged-extension", cbor2.CBORTag(55799, {"x": 1}), False),
        ("assertion-nonstring-extension", {1: 1}, False),
        ("assertion-extension-over-limit", {"x" + str(i): i for i in range(17)}, False),
        ("assertion-valid-extension", {"uvm": [[1, 2, 3]]}, True),
    ]:
        w = fixture()
        a = w["receipt"]["assertion"]
        auth = bytearray(decode(a["authenticator_data"]))
        auth[32] |= 128
        raw = bytes(auth) + cbor2.dumps(extension)
        a["authenticator_data"] = b64(raw)
        a["signature"] = b64(
            w["private"].sign(
                raw + hashlib.sha256(decode(a["client_data_json"])).digest(),
                ec.ECDSA(hashes.SHA256()),
            )
        )
        add(name, w, accept)
if append_extra:
    import hashlib

    import cbor2
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    from approval_service.encoding import decode

    for name, extension, accept in [
        ("assertion-null-extension", None, False),
        ("assertion-empty-extension", {}, True),
    ]:
        w = fixture()
        a = w["receipt"]["assertion"]
        auth = bytearray(decode(a["authenticator_data"]))
        auth[32] |= 128
        raw = bytes(auth) + cbor2.dumps(extension)
        a["authenticator_data"] = b64(raw)
        a["signature"] = b64(
            w["private"].sign(
                raw + hashlib.sha256(decode(a["client_data_json"])).digest(),
                ec.ECDSA(hashes.SHA256()),
            )
        )
        add(name, w, accept)
out.write_text(
    json.dumps(
        {
            "version": 1,
            "note": "Real software-authenticator assertions. No private identity/passkey keys retained. Non-production fixed nonce secret is a vector input. These cases do not qualify hardware or registry.",
            "cases": cases,
        },
        indent=2,
    )
    + "\n"
)
