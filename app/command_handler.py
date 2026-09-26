"""
Command-event logging and database persistence for SSH-HoneyGuard.

This module records every command entered during an SSH session.

Attacker-supplied command text is treated strictly as data. It is never
executed or passed to an operating-system shell.
"""

from __future__ import annotations

import logging

from app.database import Database
from app.ssh_session import SSHSession

logger = logging.getLogger("honeyguard.command_handler")


def log_command_event(
    session: SSHSession,
    *,
    command_text: str,
    category: str,
    response_text: str | None = None,
    database: Database,
) -> None:
    """
    Emit the structured command event and persist it in SQLite.

    The command text is stored as data only.
    """

    session.log_event(
        "command_entered",
        command_text=command_text,
        category=category,
        response_text=response_text,
    )

    database.record_command(
        session_id=session.session_id,
        source_ip=session.source_ip,
        source_port=session.source_port,
        command_text=command_text,
        category=category,
        response_text=response_text,
    )
