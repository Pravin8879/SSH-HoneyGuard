from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class SessionRecord(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    source_ip: Mapped[str] = mapped_column(String(64))
    source_port: Mapped[int] = mapped_column(Integer)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    outcome: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AuthAttemptRecord(Base):
    __tablename__ = "authentication_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(64), index=True)
    source_ip: Mapped[str] = mapped_column(String(64))
    source_port: Mapped[int] = mapped_column(Integer)
    username: Mapped[str] = mapped_column(String(128))
    method: Mapped[str] = mapped_column(String(32))
    result: Mapped[str] = mapped_column(String(32))
    password: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CommandRecord(Base):
    __tablename__ = "commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(64), index=True)
    source_ip: Mapped[str] = mapped_column(String(64))
    source_port: Mapped[int] = mapped_column(Integer)
    command_text: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(64))
    response_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AlertRecord(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    session_id: Mapped[str] = mapped_column(String(64), index=True)
    source_ip: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    alert_type: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
