"""Operator-selected grading; an input failure never selects a weaker policy."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from .metadata import Snapshot, metadata_health
from .metadata_cache import fetch_and_pin
from .registration import check_registration
from .verify import Refused


@dataclass(frozen=True)
class EnrollmentGrading:
    mode: str
    _snapshot: Snapshot | None

    def __post_init__(self):
        if self.mode not in ("hardware", "passkey_only"):
            raise ValueError("grading_mode_invalid")
        if self.mode == "hardware" and self._snapshot is None:
            raise Refused("snapshot_unavailable")
        if self.mode == "passkey_only" and self._snapshot is not None:
            raise ValueError("passkey_only_has_snapshot")

    @classmethod
    def load(cls, *, mode, cache_dir=None, manifest=None, now=None):
        """Installation/startup only. Metadata errors propagate; no fallback.

        Mode and manifest are trusted operator configuration, never HTTP input.
        Runtime omits now and uses the host clock. A replacement is installed
        only by constructing a successfully verified new policy instance.
        """
        if mode not in ("hardware", "passkey_only"):
            raise ValueError("grading_mode_invalid")
        if mode == "passkey_only":
            return cls(mode, None)
        if cache_dir is None:
            raise ValueError("hardware_cache_required")
        return cls(mode, fetch_and_pin(cache_dir, manifest=manifest, now=now))

    def check(self, response, *, expected_challenge, origin, rp_id, now=None):
        now = datetime.now(UTC) if now is None else now
        # Check the invariant again at the enrollment boundary; no caller may
        # turn unavailable hardware metadata into a software-only ceremony.
        if self.mode == "hardware" and self._snapshot is None:
            raise Refused("snapshot_unavailable")
        return check_registration(
            response,
            expected_challenge=expected_challenge,
            origin=origin,
            rp_id=rp_id,
            snapshot=self._snapshot,
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
                "metadata": {"warning": "snapshot_unavailable"},
            }
        health = metadata_health(snapshot, now=now)
        return {
            "mode": self.mode,
            "enrollment_ready": health["seconds_remaining"] > 0,
            "metadata": health,
        }
