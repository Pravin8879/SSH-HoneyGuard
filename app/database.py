from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.models import (
    AlertRecord,
    AuthAttemptRecord,
    Base,
    CommandRecord,
    SessionRecord,
)

logger = logging.getLogger("ssh_honeyguard")


class Database:
    """
    SQLite persistence layer for SSH-HoneyGuard Phase 9.

    Database failures are fail-soft: a database error must never
    terminate the honeypot or interfere with SSH handling.
    """

    def __init__(self, path: str) -> None:
        self.path = path

        # Ensure the parent directory exists.
        Path(path).parent.mkdir(parents=True, exist_ok=True)

        self.engine = create_engine(
            f"sqlite:///{path}",
            connect_args={"check_same_thread": False},
            future=True,
        )

        # Enable SQLite foreign-key enforcement and WAL mode.
        @event.listens_for(self.engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection: Any, connection_record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

        self.SessionLocal = sessionmaker(
            bind=self.engine,
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )

        Base.metadata.create_all(self.engine)

        # Add the password column to existing SQLite databases.
        # SQLAlchemy create_all() does not alter existing tables.
        with self.engine.begin() as connection:
            columns = connection.exec_driver_sql(
                "PRAGMA table_info(authentication_attempts)"
            ).fetchall()

            column_names = {row[1] for row in columns}

            if "password" not in column_names:
                connection.exec_driver_sql(
                    "ALTER TABLE authentication_attempts "
                    "ADD COLUMN password TEXT"
                )
                logger.info(
                    "Added password column to authentication_attempts"
                )

        logger.info("Database initialized: %s", os.path.abspath(path))

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    def record_session_start(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        started_at: datetime,
    ) -> None:
        try:
            with self.SessionLocal() as db:
                record = SessionRecord(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    started_at=started_at,
                )
                db.add(record)
                db.commit()
        except Exception:
            logger.warning(
                "Database write failed for session start",
                exc_info=True,
            )

    def record_session_end(
        self,
        *,
        session_id: str,
        ended_at: datetime,
        outcome: str,
    ) -> None:
        try:
            with self.SessionLocal() as db:
                record = (
                    db.query(SessionRecord)
                    .filter(SessionRecord.session_id == session_id)
                    .one_or_none()
                )

                if record is not None:
                    record.ended_at = ended_at
                    record.outcome = outcome
                    db.commit()
        except Exception:
            logger.warning(
                "Database write failed for session end",
                exc_info=True,
            )

    def record_authentication_attempt(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        username: str,
        method: str,
        result: str,
        password: str | None = None,
        timestamp: datetime | None = None,
    ) -> None:
        try:
            with self.SessionLocal() as db:
                record = AuthAttemptRecord(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    username=username,
                    method=method,
                    result=result,
                    password=password,
                    timestamp=timestamp or self._now(),
                )
                db.add(record)
                db.commit()
        except Exception:
            logger.warning(
                "Database write failed for authentication attempt",
                exc_info=True,
            )

    def record_command(
        self,
        *,
        session_id: str,
        source_ip: str,
        source_port: int,
        command_text: str,
        category: str,
        response_text: str | None = None,
        timestamp: datetime | None = None,
    ) -> None:
        try:
            with self.SessionLocal() as db:
                record = CommandRecord(
                    session_id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    command_text=command_text,
                    category=category,
                    response_text=response_text,
                    timestamp=timestamp or self._now(),
                )
                db.add(record)
                db.commit()
        except Exception:
            logger.warning(
                "Database write failed for command",
                exc_info=True,
            )

    def record_alert(
        self,
        *,
        alert_id: str,
        session_id: str,
        source_ip: str,
        severity: str,
        alert_type: str,
        reason: str,
        evidence: dict[str, Any] | str,
        timestamp: datetime | None = None,
    ) -> None:
        try:
            if isinstance(evidence, dict):
                evidence_value = json.dumps(evidence, sort_keys=True)
            else:
                evidence_value = str(evidence)

            with self.SessionLocal() as db:
                record = AlertRecord(
                    alert_id=alert_id,
                    session_id=session_id,
                    source_ip=source_ip,
                    severity=severity,
                    alert_type=alert_type,
                    reason=reason,
                    evidence=evidence_value,
                    timestamp=timestamp or self._now(),
                )
                db.add(record)
                db.commit()
        except Exception:
            logger.warning(
                "Database write failed for alert",
                exc_info=True,
            )
