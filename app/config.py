"""
Configuration loading for SSH-HoneyGuard.

Merges two sources, in this order of precedence (highest last):
  1. config/config.yaml   — committed defaults, safe to version-control
  2. environment variables (loaded from .env in development) — overrides

This module has no dependency on any detection/analysis/API/dashboard code
(those don't exist yet — Phases 6-11) so it is safe to introduce now as
shared infrastructure that later phases will import from.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "config.yaml"


class HoneypotSettings(BaseModel):
    host: str = "0.0.0.0"
    port: int = 2222
    max_connections: int = 50
    session_timeout_seconds: int = 300
    # Persisted so the host key (and therefore the server's identity as seen
    # by SSH clients) doesn't change on every container restart. Lives on
    # the same Docker-managed volume as the rest of data/ (Phase 2).
    host_key_path: str = "data/ssh_host_key"


class DatabaseSettings(BaseModel):
    path: str = "data/honeyguard.db"


class LoggingSettings(BaseModel):
    directory: str = "logs"
    format: str = "json"
    level: str = "INFO"


class BruteForceSettings(BaseModel):
    attempt_threshold: int = 5
    window_minutes: int = 5


class DetectionSettings(BaseModel):
    brute_force: BruteForceSettings = Field(default_factory=BruteForceSettings)
    multi_stage_category_threshold: int = 2


class Settings(BaseModel):
    """Top-level, validated application settings."""

    environment: str = "development"
    honeypot: HoneypotSettings = Field(default_factory=HoneypotSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)


def _load_yaml(config_path: Path) -> dict[str, Any]:
    if not config_path.is_file():
        # Missing config.yaml is a real problem, not something to silently
        # paper over with defaults — fail loudly so check_environment.py-style
        # issues surface at startup, not three layers deep at runtime.
        raise FileNotFoundError(
            f"Expected config file not found: {config_path}. "
            "Copy or restore config/config.yaml before starting the container."
        )
    with config_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_settings(config_path: Path | None = None, load_dotenv_file: bool = True) -> Settings:
    """
    Build a validated Settings object.

    `load_dotenv_file=True` reads a local .env if present (development
    convenience). Inside Docker, real env vars are injected by Compose and
    load_dotenv() is a harmless no-op if no .env file exists in the image.
    """
    if load_dotenv_file:
        load_dotenv(PROJECT_ROOT / ".env")

    raw = _load_yaml(config_path or DEFAULT_CONFIG_PATH)
    app_section = raw.get("app", {})
    honeypot_section = raw.get("honeypot", {})
    database_section = raw.get("database", {})
    logging_section = raw.get("logging", {})
    detection_section = raw.get("detection", {})

    # Environment variables override YAML values, matching the precedence
    # documented in .env.example.
    environment = os.getenv("ENVIRONMENT", app_section.get("environment", "development"))
    log_level = os.getenv("LOG_LEVEL", logging_section.get("level") or app_section.get("log_level", "INFO"))

    honeypot = HoneypotSettings(
        host=os.getenv("HONEYPOT_HOST", honeypot_section.get("host", "0.0.0.0")),
        port=int(os.getenv("HONEYPOT_PORT", honeypot_section.get("port", 2222))),
        max_connections=int(honeypot_section.get("max_connections", 50)),
        session_timeout_seconds=int(honeypot_section.get("session_timeout_seconds", 300)),
        host_key_path=os.getenv(
            "HONEYPOT_HOST_KEY_PATH", honeypot_section.get("host_key_path", "data/ssh_host_key")
        ),
    )

    database = DatabaseSettings(
        path=os.getenv("DATABASE_PATH", database_section.get("path", "data/honeyguard.db")),
    )

    logging_settings = LoggingSettings(
        directory=logging_section.get("directory", "logs"),
        format=logging_section.get("format", "json"),
        level=log_level,
    )

    brute_force_section = detection_section.get("brute_force", {})
    detection = DetectionSettings(
        brute_force=BruteForceSettings(
            attempt_threshold=int(brute_force_section.get("attempt_threshold", 5)),
            window_minutes=int(brute_force_section.get("window_minutes", 5)),
        ),
        multi_stage_category_threshold=int(detection_section.get("multi_stage_category_threshold", 2)),
    )

    return Settings(
        environment=environment,
        honeypot=honeypot,
        database=database,
        logging=logging_settings,
        detection=detection,
    )
