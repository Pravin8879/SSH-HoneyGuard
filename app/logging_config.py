"""Structured JSON logging for SSH-HoneyGuard."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path


class JSONFormatter(logging.Formatter):
    """Render ordinary log records and `context` alerts as JSON lines."""

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()

        try:
            payload = json.loads(message)
        except (json.JSONDecodeError, TypeError):
            payload = {"event": message}

        if not isinstance(payload, dict):
            payload = {"event": message}

        context = getattr(record, "context", None)
        if isinstance(context, dict):
            payload.update(context)

        payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        payload.setdefault("level", record.levelname)
        payload.setdefault("logger", record.name)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def configure_logging(level: str, log_dir: str) -> None:
    """Send structured logs to the terminal and logs/honeyguard.log."""

    directory = Path(log_dir)
    directory.mkdir(parents=True, exist_ok=True)

    formatter = JSONFormatter()
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(level.upper())

    for handler in (
        logging.StreamHandler(),
        logging.FileHandler(directory / "honeyguard.log", encoding="utf-8"),
    ):
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)
