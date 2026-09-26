"""
Paramiko-based fake SSH server for SSH-HoneyGuard (Phase 6).

Scope, deliberately narrow per the Phase 0 phase boundaries:
  - Accepts TCP connections and completes the SSH handshake.
  - Delegates authentication decisions AND logging to
    app.authentication.AcceptAllAuthPolicy — decision behavior is still the
    TEMPORARY Phase 3 accept-all placeholder; real credential/brute-force
    *decision* logic is still out of scope (brute-force *detection*, as
    opposed to prevention, is Phase 6 — see app.detection.engine).
  - Hands the connection to an SSHSession for lifecycle logging.
  - If a channel is opened, hands it to app.fake_shell.FakeShell, which
    reads attacker input, logs every command, and responds with static
    canned text — never executing anything.
  - Owns one app.detection.engine.DetectionEngine, shared across every
    connection, so brute-force tracking works across connections from the
    same source IP (not reset per-session).

Never executes attacker-supplied data. Never touches a real shell.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
from pathlib import Path

import paramiko

from app.authentication import AcceptAllAuthPolicy
from app.config import Settings
from app.database import Database
from app.detection.engine import DetectionEngine
from app.fake_shell import FakeShell
from app.ssh_session import SSHSession

logger = logging.getLogger("honeyguard.ssh_server")

# How long to wait for a client to open a channel after auth succeeds
# before giving up on the connection.
CHANNEL_ACCEPT_TIMEOUT_SECONDS = 20

# How often the accept loop wakes up to check for a shutdown request.
ACCEPT_POLL_INTERVAL_SECONDS = 1.0


class SSHServer:
    """Owns the listening socket and the per-connection handler threads."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings.honeypot
        self._shutdown = threading.Event()
        self._server_socket: socket.socket | None = None
        self._host_key: paramiko.RSAKey | None = None
        self._database = Database(settings.database.path)
        # One DetectionEngine shared across every connection this server
        # handles, so brute-force tracking works across connections from
        # the same source IP, not just within a single session.
        self._detection_engine = DetectionEngine(
            database=self._database,
            brute_force_attempt_threshold=settings.detection.brute_force.attempt_threshold,
            brute_force_window_minutes=settings.detection.brute_force.window_minutes,
            multi_stage_category_threshold=settings.detection.multi_stage_category_threshold,
        )

    # --- host key -----------------------------------------------------

    def _load_or_create_host_key(self) -> paramiko.RSAKey:
        key_path = Path(self._settings.host_key_path)
        key_path.parent.mkdir(parents=True, exist_ok=True)

        if key_path.is_file():
            logger.info("host_key_loaded", extra={"context": {"path": str(key_path)}})
            return paramiko.RSAKey(filename=str(key_path))

        logger.info("host_key_generating", extra={"context": {"path": str(key_path)}})
        key = paramiko.RSAKey.generate(bits=2048)
        key.write_private_key_file(str(key_path))
        os.chmod(key_path, 0o600)
        logger.info("host_key_generated", extra={"context": {"path": str(key_path)}})
        return key

    # --- lifecycle ------------------------------------------------------

    def start(self) -> None:
        """Blocking call: listens and handles connections until stop() is called."""
        self._host_key = self._load_or_create_host_key()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self._settings.host, self._settings.port))
        sock.listen(100)
        sock.settimeout(ACCEPT_POLL_INTERVAL_SECONDS)
        self._server_socket = sock

        logger.info(
            "ssh_server_listening",
            extra={"context": {"host": self._settings.host, "port": self._settings.port}},
        )

        while not self._shutdown.is_set():
            try:
                client_sock, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                # Socket was closed by stop() during shutdown.
                break

            thread = threading.Thread(
                target=self._handle_connection,
                args=(client_sock, addr),
                daemon=True,
                name=f"honeyguard-conn-{addr[0]}:{addr[1]}",
            )
            thread.start()

        try:
            sock.close()
        except OSError:
            pass
        logger.info("ssh_server_stopped")

    def stop(self) -> None:
        self._shutdown.set()
        if self._server_socket is not None:
            try:
                self._server_socket.close()
            except OSError:
                pass

    # --- per-connection handling -----------------------------------------

    def _handle_connection(self, client_sock: socket.socket, addr: tuple[str, int]) -> None:
        source_ip, source_port = addr[0], addr[1]
        session = SSHSession((source_ip, source_port), self._database)
        session.start()

        transport: paramiko.Transport | None = None
        try:
            transport = paramiko.Transport(client_sock)
            transport.add_server_key(self._host_key)

            server_interface = AcceptAllAuthPolicy(
                session,
                self._detection_engine,
                self._database,
            )
            transport.start_server(server=server_interface)

            channel = transport.accept(timeout=CHANNEL_ACCEPT_TIMEOUT_SECONDS)
            if channel is None:
                session.end(outcome="no_channel_opened")
                return

            session.log_event("channel_opened", channel_type="session")

            shell = FakeShell(
                channel=channel,
                session=session,
                idle_timeout_seconds=self._settings.session_timeout_seconds,
                detection_engine=self._detection_engine,
                database=self._database,
            )

            outcome = shell.run()
            channel.close()
            session.end(outcome=outcome)

        except paramiko.SSHException:
            session.end(outcome="ssh_negotiation_failed")

        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "unexpected_error_handling_connection",
                extra={
                    "context": {
                        "source_ip": source_ip,
                        "source_port": source_port,
                    }
                },
            )
            session.end(outcome="unexpected_error")

        finally:
            if transport is not None:
                try:
                    transport.close()
                except Exception:  # noqa: BLE001
                    pass

            try:
                client_sock.close()
            except OSError:
                pass

