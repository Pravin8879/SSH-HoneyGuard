import json
import logging
import uuid
from datetime import datetime, timezone

from app.database import Database

logger = logging.getLogger("ssh_honeyguard")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SSHSession:
    def __init__(self, client_address, database: Database):
        self.session_id = str(uuid.uuid4())
        self.source_ip = client_address[0]
        self.source_port = client_address[1]
        self.started_at = utc_now()
        self.ended_at = None
        self._database = database

    def start(self):
        self.log_event(
            "session_started",
            started_at=self.started_at,
        )

        self._database.record_session_start(
            session_id=self.session_id,
            source_ip=self.source_ip,
            source_port=self.source_port,
            started_at=datetime.fromisoformat(self.started_at),
        )

    def channel_opened(self):
        self.log_event(
            "channel_opened",
        )

    def log_event(self, event: str, **fields):
        """
        Log a structured event associated with this SSH session.

        Every event automatically receives:
        - event
        - session_id
        - source_ip
        - source_port
        """

        payload = {
            "event": event,
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            **fields,
        }

        logger.info(json.dumps(payload))

    def end(self, outcome: str):
        self.ended_at = utc_now()

        self.log_event(
            "session_ended",
            ended_at=self.ended_at,
            outcome=outcome,
        )

        self._database.record_session_end(
            session_id=self.session_id,
            ended_at=datetime.fromisoformat(self.ended_at),
            outcome=outcome,
        )
