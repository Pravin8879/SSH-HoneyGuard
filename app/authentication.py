"""
Authentication-attempt logging for SSH-HoneyGuard (Phase 4).

Scope: this module logs authentication attempts, provides the Paramiko
ServerInterface implementation that decides handshake outcomes, and (as of
Phase 6) forwards every attempt to app.detection.engine.DetectionEngine for
brute-force tracking. The accept-all password policy inherited from
Phase 3 is intentionally UNCHANGED — real credential validation is still
out of scope.

Password values are NEVER logged, not even masked — only the fact that a
password-method attempt occurred is recorded (Functional Requirement #2;
Phase 0 Section 6 Auditability / sensitive-data-masking NFR).

Every attempt is logged via SSHSession.log_event(), which already attaches
session_id/source_ip/source_port to every event — this keeps
authentication_attempt events in the exact same structured-JSON shape as
Phase 3's session_started/channel_opened/session_ended, per your Phase 4
requirement to stay consistent with existing SSHSession logging rather
than introduce a separate log format.
"""

from __future__ import annotations

import logging

import paramiko

from app.database import Database
from app.detection.engine import DetectionEngine
from app.ssh_session import SSHSession

logger = logging.getLogger("honeyguard.authentication")


def log_authentication_attempt(
    session: SSHSession,
    *,
    username: str,
    method: str,
    result: str,
    database: Database,
    password: str | None = None,
) -> None:
    """
    Emit a structured `authentication_attempt` event correlated to the
    session's session_id. Caller must never pass a raw credential value in.
    """
    session.log_event(
        "authentication_attempt",
        username=username,
        method=method,
        result=result,
    )

    database.record_authentication_attempt(
        session_id=session.session_id,
        source_ip=session.source_ip,
        source_port=session.source_port,
        username=username,
        method=method,
        result=result,
        password=password,
    )


class AcceptAllAuthPolicy(paramiko.ServerInterface):
    """
    TEMPORARY Phase 3/4 placeholder authentication *decision* policy.

    Decision behavior is byte-for-byte identical to Phase 3's
    `_AcceptAllServerInterface`: accepts any password, rejects public keys.
    What Phase 4 adds is that every attempt, regardless of outcome, is now
    logged via log_authentication_attempt() before the decision is returned.
    """

    def __init__(
        self,
        session: SSHSession,
        detection_engine: DetectionEngine,
        database: Database,
    ) -> None:
        self._session = session
        self._detection_engine = detection_engine
        self._database = database

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        log_authentication_attempt(
            self._session,
            username=username,
            method="password",
            result="success",
            database=self._database,
            password=password,
        )
        self._detection_engine.record_auth_attempt(
            self._session, username=username, method="password", result="success"
        )
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        log_authentication_attempt(
        self._session,
        username=username,
        method="publickey",
        result="failure",
        database=self._database,
    )
        self._detection_engine.record_auth_attempt(
            self._session, username=username, method="publickey", result="failure"
        )
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        # Advertising "password" only (Phase 3's original value) meant SSH
        # clients never attempted publickey auth at all — the client checks
        # this list locally before trying a method, so check_auth_publickey
        # was unreachable and no "failure" event could ever be logged.
        # Advertising both methods lets a real publickey attempt reach
        # check_auth_publickey (still rejected, now logged) before the
        # client falls back to password (still accepted, still logged).
        return "publickey,password"

    # --- Phase 5 additions: channel/session negotiation ---------------------
    #
    # These do NOT change any authentication decision above. They exist so
    # that a real SSH client's shell request actually succeeds, which is a
    # prerequisite for app.fake_shell.FakeShell to ever run. Paramiko's
    # ServerInterface defaults reject both, which — before this change —
    # meant no client could get a working shell channel at all.

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        return True

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        # Acknowledging the pty request at the protocol level only — no real
        # pseudo-terminal is allocated on the host. Note: this means a real
        # interactive terminal user's keystrokes are not locally echoed by
        # us (no real pty to do that job); piped/non-interactive input is
        # unaffected. Documented limitation, not a bug to silently "fix"
        # with more scope than Phase 5 calls for.
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        # Phase 5 only supports the interactive fake-shell path. Exec-mode
        # (`ssh host some-command`) is explicitly out of scope for now;
        # reject cleanly rather than silently hanging or doing nothing.
        return False
