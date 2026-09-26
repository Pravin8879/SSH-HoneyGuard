"""
Detection engine for SSH-HoneyGuard (Phase 6).

There is no event bus or database yet (confirmed by inspection before this
phase was implemented) — SSHSession.log_event() logs directly and
synchronously at the point each event happens. This engine follows the
same pattern: app.authentication and app.fake_shell call its methods
directly, in-process, at the moment an auth attempt or command occurs.
There is nothing to "subscribe" to after the fact.

Explainability (Phase 0 Section 6 NFR): every alert this engine emits
traces back to a single rule in app.detection.rules or a simple, stated
threshold comparison here — no learned weights, no ML, no hidden logic.

Scope boundary: this module decides "is this worth alerting on" and emits
the alert as a structured log event. It does NOT persist alerts to a
database, deduplicate/suppress across restarts, or deliver notifications
(email/webhook/etc) — that is app/alerts/alert_manager.py's job in a later
phase, once a database exists to back it.
"""

from __future__ import annotations

import logging
import threading
import uuid

from app.database import Database
from app.detection.brute_force import BruteForceTracker
from app.detection.rules import (
    BRUTE_FORCE_SEVERITY,
    CATEGORY_ALERT_REASONS,
    CATEGORY_SEVERITY,
    MULTI_STAGE_SEVERITY,
    SUSPICIOUS_CATEGORIES,
)
from app.ssh_session import SSHSession

logger = logging.getLogger("honeyguard.detection")

# Minimum number of distinct suspicious categories in one session before a
# multi-stage alert fires. Kept as a module constant (not hardcoded inline)
# so it's visible as an explicit, explainable rule.
DEFAULT_MULTI_STAGE_CATEGORY_THRESHOLD = 2


def _emit_alert(
    *,
    database: Database,
    alert_type: str,
    severity: str,
    reason: str,
    evidence: dict[str, object],
    session_id: str | None,
    source_ip: str | None,
) -> None:
    """
    Log a structured `security_alert` event. Uses the standard `logging`
    module directly (not SSHSession.log_event()) because brute-force alerts
    are cross-session, keyed by source IP rather than a single session —
    there may be no single SSHSession to attach the event to.
    """
    database.record_alert(
        alert_id=str(uuid.uuid4()),
        session_id=session_id or "",
        source_ip=source_ip or "",
        severity=severity,
        alert_type=alert_type,
        reason=reason,
        evidence=evidence,
    )

    logger.warning(
        "security_alert",
        extra={
            "context": {
                "alert_id": str(uuid.uuid4()),
                "session_id": session_id,
                "source_ip": source_ip,
                "severity": severity,
                "alert_type": alert_type,
                "reason": reason,
                "evidence": evidence,
            }
        },
    )


class DetectionEngine:
    """
    One instance shared across all connections handled by a single
    SSHServer. Thread-safe: multiple connection-handler threads call
    record_auth_attempt()/record_command() concurrently.
    """

    def __init__(
        self,
        database: Database,
        brute_force_attempt_threshold: int,
        brute_force_window_minutes: int,
        multi_stage_category_threshold: int = DEFAULT_MULTI_STAGE_CATEGORY_THRESHOLD,
    ) -> None:
        self._database = database
        self._brute_force = BruteForceTracker(
            attempt_threshold=brute_force_attempt_threshold,
            window_minutes=brute_force_window_minutes,
        )
        self._multi_stage_threshold = multi_stage_category_threshold

        # Per-session tracking of which suspicious categories have been
        # seen, and whether the multi-stage alert has already fired for
        # that session (fire-once, not once-per-command — avoids spam).
        self._session_categories: dict[str, set[str]] = {}
        self._multi_stage_alerted: set[str] = set()
        self._lock = threading.Lock()

    # --- authentication events -------------------------------------------

    def record_auth_attempt(
        self,
        session: SSHSession,
        *,
        username: str,
        method: str,
        result: str,
    ) -> None:
        """
        Feed one authentication_attempt into the brute-force tracker.

        Requirement B scope note: only `result == "failure"` attempts count
        toward the threshold. As of Phase 6, password auth is still
        accept-all (see app/authentication.py) and can never fail, so in
        practice this currently only triggers on repeated publickey
        rejections from the same source IP — documented in
        app/detection/brute_force.py.
        """
        if result != "failure":
            self._brute_force.record_success(session.source_ip)
            return

        threshold_reached, attempt_count = self._brute_force.record_failure(session.source_ip)
        if threshold_reached:
            _emit_alert(
                database=self._database,
                alert_type="brute_force_authentication",
                severity=BRUTE_FORCE_SEVERITY,
                reason=(
                    f"{attempt_count} failed authentication attempts from {session.source_ip} "
                    f"within the configured window (threshold reached)."
                ),
                evidence={
                    "username": username,
                    "method": method,
                    "failed_attempt_count_in_window": attempt_count,
                },
                session_id=session.session_id,
                source_ip=session.source_ip,
            )

    # --- command events ---------------------------------------------------

    def record_command(self, session: SSHSession, *, command_text: str, category: str) -> None:
        """
        Feed one command_entered event into the detection engine.

        Requirement A: categories in SUSPICIOUS_CATEGORIES generate an
        immediate per-command alert.
        Requirement C: a session that accumulates
        `multi_stage_category_threshold` or more *distinct* suspicious
        categories generates one multi-stage alert.
        """
        if category in SUSPICIOUS_CATEGORIES:
            _emit_alert(
                database=self._database,
                alert_type=f"suspicious_command_{category}",
                severity=CATEGORY_SEVERITY[category],
                reason=CATEGORY_ALERT_REASONS.get(
                    category, f"Command classified as '{category}' was entered."
                ),
                evidence={"command_text": command_text, "category": category},
                session_id=session.session_id,
                source_ip=session.source_ip,
            )
            self._check_multi_stage(session, category)

    def _check_multi_stage(self, session: SSHSession, category: str) -> None:
        with self._lock:
            categories_seen = self._session_categories.setdefault(session.session_id, set())
            categories_seen.add(category)
            already_alerted = session.session_id in self._multi_stage_alerted
            reached_threshold = len(categories_seen) >= self._multi_stage_threshold
            should_alert = reached_threshold and not already_alerted
            if should_alert:
                self._multi_stage_alerted.add(session.session_id)
                categories_snapshot = sorted(categories_seen)

        if should_alert:
            _emit_alert(
                database=self._database,
                alert_type="multi_stage_activity",
                severity=MULTI_STAGE_SEVERITY,
                reason=(
                    f"Session touched {len(categories_snapshot)} distinct suspicious "
                    f"categories ({', '.join(categories_snapshot)}), suggesting "
                    f"multi-stage attacker behavior rather than a single isolated command."
                ),
                evidence={"categories": categories_snapshot},
                session_id=session.session_id,
                source_ip=session.source_ip,
            )
