"""Maintainer-side pin proposals. No automatic root change or deployment."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx

from .metadata import load_snapshot
from .metadata_cache import _artifact, _atomic, _cache, _download, _lock


def propose_pin(current, *, cache_dir, now=None):
    """Verify live data under the EXISTING pinned root before proposing hashes.

    URLs, bounds and root pin are trusted maintainer inputs. New blob/CRL bytes
    are never trusted because they came over HTTPS or had a computable hash.
    Only the chain/JWT/CRL verifier admits them. Unknown roots/CRL routes require
    a manual reviewed change; this function discovers neither from the blob.
    """
    now = datetime.now(UTC) if now is None else now
    proposed = copy.deepcopy(current)
    cache = _cache(cache_dir)
    with _lock(cache), httpx.Client(timeout=15, follow_redirects=False) as client:
        artifacts = current["artifacts"]
        root = _artifact(client, cache, artifacts["root"])
        blob = _download(client, artifacts["blob"])
        if (
            not isinstance(artifacts["crls"], list)
            or not 1 <= len(artifacts["crls"]) <= 4
        ):
            raise ValueError("manifest_invalid")
        crls = [_download(client, spec) for spec in artifacts["crls"]]
        blob_hash = hashlib.sha256(blob).hexdigest()
        snapshot = load_snapshot(
            blob=blob,
            root_der=root,
            crls=crls,
            blob_sha256=blob_hash,
            root_sha256=artifacts["root"]["sha256"],
            minimum_sequence=current["minimum_sequence"],
            now=now,
        )
        proposed["artifacts"]["blob"]["sha256"] = blob_hash
        for spec, raw in zip(proposed["artifacts"]["crls"], crls, strict=True):
            spec["sha256"] = hashlib.sha256(raw).hexdigest()
        proposed["minimum_sequence"] = snapshot.sequence
        proposed["next_update"] = snapshot.next_update.strftime("%Y-%m-%d")
        unchanged = (
            proposed["artifacts"] == current["artifacts"]
            and proposed["minimum_sequence"] == current["minimum_sequence"]
            and proposed["next_update"] == current.get("next_update")
        )
        if unchanged:
            return copy.deepcopy(current)
        proposed["retrieved_at"] = now.isoformat()
        # Cache only the fully verified bytes, outside Git, for local validation.
        for raw in [blob, *crls]:
            _atomic(cache / (hashlib.sha256(raw).hexdigest() + ".artifact"), raw)
        return proposed


def main():
    parser = argparse.ArgumentParser(
        description="Verify and propose a metadata pin update; never deploy"
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    args = parser.parse_args()
    current = json.loads(args.manifest.read_text())
    proposed = propose_pin(current, cache_dir=args.cache_dir)
    if proposed != current:
        args.manifest.write_text(json.dumps(proposed, indent=2) + "\n")
        print("Verified metadata pin update ready for review")
    else:
        print("Verified metadata pins unchanged")


if __name__ == "__main__":
    main()
