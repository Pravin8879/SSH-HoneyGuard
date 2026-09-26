"""
SSH-HoneyGuard — honeypot container entrypoint.

Phase 6 status:
Runs the real Paramiko SSH server (app.ssh_server.SSHServer), which now
also owns a shared app.detection.engine.DetectionEngine for rule-based
brute-force and suspicious-command alerting. Authentication decisions are
still a temporary accept-all placeholder (unchanged since Phase 3) — Phase
6 only adds detection/alerting on top of what's already logged.
"""

from __future__ import annotations

import logging
import signal
from types import FrameType

from app.config import load_settings
from app.logging_config import configure_logging
from app.ssh_server import SSHServer

logger = logging.getLogger("honeyguard.main")


def main() -> int:
    settings = load_settings()
    configure_logging(level=settings.logging.level, log_dir=settings.logging.directory)

    logger.info(
        "SSH-HoneyGuard container starting",
        extra={
            "context": {
                "environment": settings.environment,
                "honeypot_host": settings.honeypot.host,
                "honeypot_port": settings.honeypot.port,
                "phase": "6 (detection engine) — auth decision is still a temporary "
                "accept-all stub (unchanged from Phase 3); rule-based brute-force "
                "and suspicious-command alerting now active, see app/detection/",
            }
        },
    )

    server = SSHServer(settings)

    def _handle_shutdown_signal(signum: int, frame: FrameType | None) -> None:
        logger.info(
            "Shutdown signal received, stopping SSH server",
            extra={"context": {"signal": signal.Signals(signum).name}},
        )
        server.stop()

    signal.signal(signal.SIGTERM, _handle_shutdown_signal)
    signal.signal(signal.SIGINT, _handle_shutdown_signal)

    try:
        server.start()  # blocks until server.stop() is called from the signal handler
    except Exception:
        logger.exception("Unhandled error running SSH server")
        return 1

    logger.info("SSH-HoneyGuard container stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
