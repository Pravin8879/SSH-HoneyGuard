#!/usr/bin/env python3
"""
SSH-HoneyGuard — Environment Verification Script (Phase 1)

Checks that the local development environment is ready before work begins
on later phases. Never touches the network beyond local subprocess calls
(git --version, docker --version, etc.) and never contacts the honeypot
itself — this script is a pre-flight check, not part of the honeypot.

Exit code is 0 if every check passes, 1 otherwise, so it can be used in
CI or a pre-commit hook later if desired.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MIN_PYTHON = (3, 11)

# Packages required at this stage of the project (installed via requirements.txt).
# Kept in sync manually with requirements.txt / requirements-dev.txt; a mismatch
# here just means an incomplete check, not a broken project.
REQUIRED_PACKAGES = [
    "paramiko",
    "fastapi",
    "uvicorn",
    "sqlalchemy",
    "pydantic",
    "dotenv",  # python-dotenv's import name is "dotenv"
    "yaml",  # pyyaml's import name is "yaml"
]

REQUIRED_DIRS = [
    "app",
    "app/detection",
    "app/analysis",
    "app/threat_intelligence",
    "app/alerts",
    "app/api",
    "dashboard",
    "tests",
    "data",
    "logs",
    "reports",
    "scripts",
    "config",
]

REQUIRED_CONFIG_FILES = [
    "config/config.yaml",
    ".env.example",
    "requirements.txt",
    "requirements-dev.txt",
    ".gitignore",
]

RESULTS: list[tuple[str, bool, str]] = []  # (label, passed, fix_hint)


def record(label: str, passed: bool, fix_hint: str = "") -> None:
    RESULTS.append((label, passed, fix_hint))


def check_python_version() -> None:
    ok = sys.version_info[:2] >= MIN_PYTHON
    record(
        "Python",
        ok,
        f"Install Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ "
        f"(e.g. `sudo apt install python3.11 python3.11-venv python3-pip`)",
    )


def check_virtual_env() -> None:
    in_venv = sys.prefix != sys.base_prefix
    record(
        "Virtual Environment",
        in_venv,
        "Create and activate a venv: `python3.11 -m venv .venv && source .venv/bin/activate`",
    )


def check_required_packages() -> None:
    missing = [pkg for pkg in REQUIRED_PACKAGES if importlib.util.find_spec(pkg) is None]
    ok = not missing
    hint = (
        "Install dependencies: `pip install -r requirements.txt`"
        if not ok
        else ""
    )
    if missing:
        hint += f" (missing: {', '.join(missing)})"
    record("Required Packages", ok, hint)


def check_git() -> None:
    ok = shutil.which("git") is not None
    record("Git", ok, "Install Git: `sudo apt install git`")


def _command_ok(cmd: list[str]) -> bool:
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def check_docker() -> None:
    installed = shutil.which("docker") is not None
    daemon_ok = installed and _command_ok(["docker", "info"])
    ok = installed and daemon_ok
    if not installed:
        hint = "Install Docker Desktop from docker.com and enable the WSL2 backend if on Windows"
    elif not daemon_ok:
        hint = "Docker is installed but the daemon isn't reachable — start Docker Desktop"
    else:
        hint = ""
    record("Docker", ok, hint)


def check_docker_compose() -> None:
    ok = _command_ok(["docker", "compose", "version"])
    record("Docker Compose", ok, "Ensure Docker Desktop (bundles the v2 compose plugin) is installed and running")


def check_ssh_client() -> None:
    ok = shutil.which("ssh") is not None
    record("SSH Client", ok, "Install OpenSSH client: `sudo apt install openssh-client`")


def check_project_structure() -> None:
    missing = [d for d in REQUIRED_DIRS if not (PROJECT_ROOT / d).is_dir()]
    ok = not missing
    hint = f"Missing directories: {', '.join(missing)}" if missing else ""
    record("Project Structure", ok, hint)


def check_config_files() -> None:
    missing = [f for f in REQUIRED_CONFIG_FILES if not (PROJECT_ROOT / f).is_file()]
    ok = not missing
    hint = f"Missing files: {', '.join(missing)}" if missing else ""
    record("Configuration Files", ok, hint)


def check_database() -> None:
    """
    Phase 1 only checks that the data/ directory is writable — the actual
    schema/models don't exist until Phase 9, so we don't try to initialize
    a database yet. This check is a placeholder that will be extended in
    Phase 9 to verify the schema initializes cleanly.
    """
    data_dir = PROJECT_ROOT / "data"
    ok = data_dir.is_dir() and _is_writable(data_dir)
    hint = "" if ok else "Ensure the data/ directory exists and is writable"
    record("Database Directory Writable", ok, hint)


def _is_writable(path: Path) -> bool:
    probe = path / ".write_test"
    try:
        probe.write_text("ok")
        probe.unlink()
        return True
    except OSError:
        return False


def main() -> int:
    check_python_version()
    check_virtual_env()
    check_required_packages()
    check_git()
    check_docker()
    check_docker_compose()
    check_ssh_client()
    check_project_structure()
    check_config_files()
    check_database()

    all_passed = True
    for label, passed, hint in RESULTS:
        status = "[OK]" if passed else "[FAIL]"
        line = f"{status} {label}"
        print(line)
        if not passed:
            all_passed = False
            if hint:
                print(f"       fix: {hint}")

    print()
    print("All checks passed." if all_passed else "One or more checks failed — see fix hints above.")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
