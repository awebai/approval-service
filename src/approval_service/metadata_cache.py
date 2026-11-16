"""Fetch, pin and verify metadata into private storage OUTSIDE the repository.

The hosted process uses this same loader before installing its Snapshot. Its
manifest is trusted operator configuration, never an HTTP request parameter.
No FIDO blob is distributed with the code. Expired inputs fail, never downgrade.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .metadata import load_snapshot


class CacheRefused(ValueError):
    pass


def default_manifest():
    return json.loads(
        files("approval_service").joinpath("data/mds-pin-v1.json").read_text()
    )


def _cache(path):
    path = Path(path)
    if path.is_symlink():
        raise CacheRefused("cache_symlink")
    resolved = path.resolve()
    source = Path(__file__).resolve().parents[2]
    if resolved.is_relative_to(source):
        raise CacheRefused("cache_must_be_outside_repository")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise CacheRefused("cache_permissions")
    return resolved


@contextmanager
def _lock(cache):
    fd = os.open(cache / "metadata.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _atomic(path, raw):
    fd, name = tempfile.mkstemp(prefix=".metadata-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def _read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as inp:
        if not stat.S_ISREG(os.fstat(inp.fileno()).st_mode):
            raise CacheRefused("cache_file_type")
        raw = inp.read(limit + 1)
    if len(raw) > limit:
        raise CacheRefused("artifact_too_large")
    return raw


def _artifact(client, cache, spec):
    digest = spec["sha256"]
    limit = spec["max_bytes"]
    if (
        not isinstance(digest, str)
        or not re.fullmatch("[0-9a-f]{64}", digest)
        or type(limit) is not int
        or not 1 <= limit <= 33554432
    ):
        raise CacheRefused("artifact_pin_invalid")
    uri = urlsplit(spec["url"])
    if (
        uri.scheme != "https"
        or not uri.hostname
        or uri.username
        or uri.password
        or uri.fragment
    ):
        raise CacheRefused("artifact_url_invalid")
    target = cache / (digest + ".artifact")
    if target.exists():
        raw = _read(target, limit)
    else:
        chunks = []
        size = 0
        with client.stream("GET", spec["url"]) as response:
            response.raise_for_status()
            for chunk in response.iter_bytes(65536):
                size += len(chunk)
                if size > limit:
                    raise CacheRefused("artifact_too_large")
                chunks.append(chunk)
        raw = b"".join(chunks)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise CacheRefused("artifact_pin_mismatch")
        _atomic(target, raw)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise CacheRefused("artifact_pin_mismatch")
    return raw


def fetch_and_pin(cache_dir, *, manifest=None, now=None):
    """Return a fully verified Snapshot, preserving a monotonic installed sequence.

    Runtime uses the host clock. Explicit as-of input is for historical checks;
    callers must never take it from an enrollment request. Disk hits still pass
    hash, chain, CRL, signature and deadline verification before installation.
    """
    manifest = default_manifest() if manifest is None else manifest
    now = datetime.now(UTC) if now is None else now
    cache = _cache(cache_dir)
    if (
        type(manifest.get("version")) is not int
        or manifest["version"] != 1
        or type(manifest.get("minimum_sequence")) is not int
        or manifest["minimum_sequence"] < 0
    ):
        raise CacheRefused("manifest_invalid")
    with _lock(cache):
        sequence_path = cache / "installed-sequence.json"
        installed = (
            json.loads(_read(sequence_path, 1024))
            if sequence_path.exists()
            else {"sequence": 0}
        )
        if (
            set(installed) != {"sequence"}
            or type(installed["sequence"]) is not int
            or installed["sequence"] < 0
        ):
            raise CacheRefused("installed_sequence_invalid")
        artifacts = manifest["artifacts"]
        if (
            set(artifacts) != {"blob", "root", "crls"}
            or not isinstance(artifacts["crls"], list)
            or not 1 <= len(artifacts["crls"]) <= 4
        ):
            raise CacheRefused("manifest_invalid")
        with httpx.Client(timeout=15, follow_redirects=False) as client:
            blob = _artifact(client, cache, artifacts["blob"])
            root = _artifact(client, cache, artifacts["root"])
            crls = [_artifact(client, cache, spec) for spec in artifacts["crls"]]
        snapshot = load_snapshot(
            blob=blob,
            root_der=root,
            crls=crls,
            blob_sha256=artifacts["blob"]["sha256"],
            root_sha256=artifacts["root"]["sha256"],
            minimum_sequence=max(manifest["minimum_sequence"], installed["sequence"]),
            now=now,
        )
        _atomic(sequence_path, json.dumps({"sequence": snapshot.sequence}).encode())
        return snapshot


def main():
    parser = argparse.ArgumentParser(
        description="Fetch and verify pinned FIDO metadata outside the repository"
    )
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text()) if args.manifest else None
    snapshot = fetch_and_pin(args.cache_dir, manifest=manifest)
    print(
        json.dumps(
            {
                "digest": snapshot.digest,
                "sequence": snapshot.sequence,
                "next_update": snapshot.next_update.isoformat(),
            }
        )
    )


if __name__ == "__main__":
    main()
