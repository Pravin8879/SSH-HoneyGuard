"""
Brute-force authentication tracking for SSH-HoneyGuard (Phase 6).

Referenced by name in app/authentication.py's docstring since Phase 4 —
this is that module, finally implemented.

Tracks FAILED authentication attempts per source IP in a sliding time
window (config: detection.brute_force.attempt_threshold /
window_minutes). State is in-memory only (a plain dict), scoped to the
lifetime of the running process — restarting the container resets all
counters. This is a real limitation, not hidden: Phase 9's database will
persist this across restarts and across the eventual multi-instance case.

IMPORTANT — current real-world coverage: as of Phase 6, password
authentication is still Phase 3/4's temporary accept-all placeholder (see
app/authentication.py), so a password attempt can never fail. In practice
this tracker can currently only be triggered by repeated rejected
public-key attempts from the same source IP, not by real password
brute-forcing. That will change once real credential validation exists.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone


class BruteForceTracker:
    """Thread-safe sliding-window counter of failed auth attempts per source IP."""

    def __init__(self, attempt_threshold: int, window_minutes: int) -> None:
        self._attempt_threshold = attempt_threshold
        self._window = timedelta(minutes=window_minutes)
        self._failures_by_ip: dict[str, list[datetime]] = defaultdict(list)
        self._lock = threading.Lock()

    def record_failure(self, source_ip: str) -> tuple[bool, int]:
        """
        Record a failed authentication attempt from `source_ip`.

        Returns (threshold_reached, attempt_count_in_window). Old entries
        outside the sliding window are pruned on every call, so the count
        always reflects "failures in the last `window_minutes` minutes,
        as of now" — not a lifetime total.
        """
        now = datetime.now(timezone.utc)
        cutoff = now - self._window

        with self._lock:
            timestamps = self._failures_by_ip[source_ip]
            timestamps[:] = [t for t in timestamps if t >= cutoff]
            timestamps.append(now)
            count = len(timestamps)
            threshold_reached = count >= self._attempt_threshold

        return threshold_reached, count

    def record_success(self, source_ip: str) -> None:
        """
        A successful auth doesn't need to reset the window — real
        brute-force tooling often succeeds eventually without that
        invalidating the fact that many failures preceded it. Kept as an
        explicit no-op method (rather than omitted) so the design choice
        is visible and callable sites don't need a conditional.
        """
        return None
