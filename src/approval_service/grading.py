"""Operator-selected grading; an input failure never selects a weaker policy."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

from .metadata import Snapshot, metadata_health
from .metadata_cache import CacheRefused, fetch_and_pin
from .registration import check_registration


@dataclass
class EnrollmentGrading:
    mode: str
    _snapshot: Snapshot | None
    _cache_dir: Path | None = None
    _manifest_path: Path | None = None
    _manifest_digest: bytes | None = None
    _reload_error: str | None = None

    def __post_init__(self):
        if self.mode not in ("hardware", "passkey_only"):
            raise ValueError("grading_mode_invalid")
        if self.mode == "passkey_only" and self._snapshot is not None:
            raise ValueError("passkey_only_has_snapshot")

    @classmethod
    def load(cls, *, mode, cache_dir=None, manifest=None, manifest_path=None, now=None):
        """Verify the operator's installed pin before starting hardware enrollment.

        Mode and manifest are trusted operator configuration, never HTTP input.
        Runtime uses the host clock. Unavailable metadata leaves attested
        enrollment paused; ordinary passkeys remain available. The watcher can
        install a verified replacement without changing that grading policy.
        """
        if mode not in ("hardware", "passkey_only"):
            raise ValueError("grading_mode_invalid")
        if mode == "passkey_only":
            return cls(mode, None)
        if cache_dir is None:
            raise ValueError("hardware_cache_required")
        if manifest is not None and manifest_path is not None:
            raise ValueError("manifest_selection_invalid")
        path = (
            None
            if manifest is not None
            else (
                Path(manifest_path)
                if manifest_path is not None
                else Path(
                    str(files("approval_service").joinpath("data/mds-pin-v1.json"))
                )
            )
        )
        grading = cls(mode, None, Path(cache_dir), path)
        try:
            if manifest is not None:
                grading._snapshot = fetch_and_pin(cache_dir, manifest=manifest, now=now)
            else:
                grading.refresh(now=now)
        except Exception as error:  # noqa: BLE001 — unavailable metadata pauses attested enrollment, not ordinary passkeys.
            grading._reload_error = "metadata_reload_failed"
            logging.getLogger(__name__).warning(
                "metadata load failed (%s)", type(error).__name__
            )
        return grading

    @staticmethod
    def _manifest_bytes(path):
        with path.open("rb") as source:
            raw = source.read(65537)
        if len(raw) > 65536:
            raise ValueError("manifest_too_large")
        return raw

    def refresh(self, *, now=None):
        """Install a changed, fully verified pin; leave a failed replacement out.

        A still-valid old snapshot can serve during a failed update. Its original
        expiry remains binding, and hardware mode never becomes passkey_only.
        """
        if self.mode != "hardware" or self._manifest_path is None:
            return False
        try:
            raw = self._manifest_bytes(self._manifest_path)
            digest = hashlib.sha256(raw).digest()
            if digest == self._manifest_digest:
                self._reload_error = None
                return False
            manifest = json.loads(raw)
            if not isinstance(manifest, dict):
                raise CacheRefused("manifest_invalid")
            replacement = fetch_and_pin(self._cache_dir, manifest=manifest, now=now)
        except Exception:
            self._reload_error = "metadata_reload_failed"
            raise
        self._snapshot = replacement
        self._manifest_digest = digest
        self._reload_error = None
        return True

    def check(self, response, *, expected_challenge, origin, rp_id, now=None):
        now = datetime.now(UTC) if now is None else now
        # Hardware metadata controls attested grading; an ordinary passkey is
        # independent of that list. The shared verifier distinguishes the two.
        snapshot = self._snapshot
        return check_registration(
            response,
            expected_challenge=expected_challenge,
            origin=origin,
            rp_id=rp_id,
            snapshot=snapshot,
            hardware_grading=self.mode == "hardware",
            now=now,
        )

    def status(self, *, now=None):
        now = datetime.now(UTC) if now is None else now
        if self.mode == "passkey_only":
            return {"mode": self.mode, "enrollment_ready": True, "metadata": None}
        snapshot = self._snapshot
        if snapshot is None:
            return {
                "mode": self.mode,
                "enrollment_ready": False,
                "metadata": {
                    "warning": "snapshot_unavailable",
                    "reload_error": self._reload_error,
                },
            }
        health = metadata_health(snapshot, now=now)
        if self._reload_error is not None:
            health["reload_error"] = self._reload_error
        return {
            "mode": self.mode,
            "enrollment_ready": health["seconds_remaining"] > 0,
            "metadata": health,
        }


@asynccontextmanager
async def watch_metadata(grading, *, interval=60):
    """Shared service/holder lifecycle: verify new operator pins off the hot path."""
    if grading is None or grading.mode != "hardware" or grading._manifest_path is None:
        yield
        return

    async def refresh():
        last_warning = None
        logger = logging.getLogger(__name__)
        while True:
            await asyncio.sleep(interval)
            try:
                await asyncio.to_thread(grading.refresh)
            except Exception as error:  # noqa: BLE001 — a bad operator replacement must not stop future reloads.
                logger.warning("metadata reload failed (%s)", type(error).__name__)
            health = grading.status()["metadata"]
            warning = (health["warning"], health.get("valid_until"))
            if health["warning"] is not None and warning != last_warning:
                logger.warning("metadata validity warning=%s valid_until=%s", *warning)
            last_warning = warning

    worker = asyncio.create_task(refresh())
    try:
        yield
    finally:
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)
