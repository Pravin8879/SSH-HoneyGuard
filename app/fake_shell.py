"""
Fake interactive SSH shell for SSH-HoneyGuard (Phase 6).

SAFETY-CRITICAL MODULE. This is the only place in the codebase that reads
attacker-supplied text and decides how to respond to it. The following
invariants MUST hold and must not be relaxed by future edits:

- Attacker input is NEVER passed to subprocess, os.system, eval, exec,
  or any other execution primitive. It is only ever (a) logged verbatim
  as data, and (b) compared against a fixed dict of literal strings to
  pick a canned response.
- There is no access to the real filesystem on the attacker's behalf —
  ls, pwd, cat, etc. return fixed fake text, never real host paths
  or real file contents.
- Unrecognized input always falls back to a generic, harmless
  "command not found"-style message. Nothing is ever silently ignored
  in a way that could be mistaken for success.

Scope boundary: this module classifies commands into coarse categories
(Functional Requirement #5) using simple keyword matching only. Deciding
whether a category/command is alert-worthy is app.detection.engine's job
(Phase 6) — this module just classifies and forwards.
"""

from __future__ import annotations

import logging
import socket

import paramiko

from app.command_handler import log_command_event
from app.database import Database
from app.detection.engine import DetectionEngine
from app.ssh_session import SSHSession


logger = logging.getLogger("honeyguard.fake_shell")


PROMPT = b"honeypot:~$ "


# Bound how much unbroken input we'll buffer per connection.
# This prevents a client from streaming an endless line without
# pressing Enter.
MAX_BUFFERED_BYTES = 4096


# How many bytes to read from the SSH channel at once.
RECV_CHUNK_SIZE = 1024


# Exact-match commands with fixed, static, non-sensitive responses.
#
# Every value here is a literal string chosen ahead of time.
# Nothing is obtained from the real filesystem or operating system.
STATIC_RESPONSES: dict[str, bytes] = {
    "whoami": b"honeypot\r\n",

    "id": (
        b"uid=1000(honeypot) gid=1000(honeypot) "
        b"groups=1000(honeypot)\r\n"
    ),

    "pwd": b"/home/honeypot\r\n",

    "ls": b"Documents  Downloads  readme.txt\r\n",

    "uname -a": (
        b"Linux honeypot 5.15.0-generic #1 SMP x86_64 GNU/Linux\r\n"
    ),

    "ps": (
        b"  PID TTY          TIME CMD\r\n"
        b"    1 ?        00:00:00 init\r\n"
        b"   42 pts/0    00:00:00 bash\r\n"
        b"   57 pts/0    00:00:00 ps\r\n"
    ),

    "hostname": b"honeypot\r\n",

    "date": b"Sat Sep  5 11:00:00 UTC 2026\r\n",

    "ip addr": (
        b"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\r\n"
        b"    inet 127.0.0.1/8 scope host lo\r\n"
        b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\r\n"
        b"    inet 172.20.0.10/16 scope global eth0\r\n"
    ),

    "ifconfig": (
        b"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>\r\n"
        b"        inet 172.20.0.10  netmask 255.255.0.0\r\n"
        b"        RX packets 128  TX packets 96\r\n"
        b"lo: flags=73<UP,LOOPBACK,RUNNING>\r\n"
        b"        inet 127.0.0.1  netmask 255.0.0.0\r\n"
    ),

    "ipconfig": (
        b"Windows IP Configuration\r\n"
        b"\r\n"
        b"Ethernet adapter Ethernet:\r\n"
        b"   IPv4 Address. . . . . . . . . . : 172.20.0.10\r\n"
        b"   Subnet Mask . . . . . . . . . . : 255.255.0.0\r\n"
    ),

    "ss": (
        b"Netid State  Local Address:Port  Peer Address:Port\r\n"
        b"tcp   LISTEN 0.0.0.0:22       0.0.0.0:*\r\n"
        b"tcp   ESTAB  172.20.0.10:22   172.20.0.1:49152\r\n"
    ),

    "netstat": (
        b"Active Internet connections\r\n"
        b"Proto Recv-Q Send-Q Local Address   Foreign Address State\r\n"
        b"tcp        0      0 0.0.0.0:22      0.0.0.0:*       LISTEN\r\n"
    ),

    "route": (
        b"Kernel IP routing table\r\n"
        b"Destination     Gateway         Genmask         Flags Iface\r\n"
        b"0.0.0.0         172.20.0.1      0.0.0.0         UG    eth0\r\n"
        b"172.20.0.0      0.0.0.0         255.255.0.0     U     eth0\r\n"
    ),

}

# Commands that end the session from the attacker's side.
EXIT_COMMANDS = {
    "exit",
    "logout",
    "quit",
}


# Ordered category rules.
#
# First matching rule wins.
#
# More specific/dangerous categories are checked before broad categories.
# For example:
#
#     cat /etc/shadow
#
# is classified as "credential" rather than "file_activity".
_CATEGORY_RULES: list[tuple[str, tuple[str, ...]]] = [
    (
        "destructive",
        (
            "rm -rf",
            "mkfs",
            "dd if=",
            ":(){:|:&};:",
            "shutdown",
            "reboot",
        ),
    ),

    (
        "credential",
        (
            "passwd",
            "/etc/shadow",
            "/etc/passwd",
            "chpasswd",
        ),
    ),

    (
        "persistence",
        (
            "crontab",
            "systemctl",
            "ssh-keygen",
            "/etc/init.d",
            "rc.local",
            "at ",
        ),
    ),

    (
        "privesc",
        (
            "sudo",
            "su -",
            "su ",
            "chmod +s",
            "chmod 4",
            "chown root",
            "visudo",
        ),
    ),

    (
        "download",
        (
            "curl",
            "wget",
            "scp ",
            "ftp ",
            "tftp",
        ),
    ),

    (
        "network",
        (
            "nc ",
            "netcat",
            "ncat",
            "nmap",
            "telnet",
            "ping",
        ),
    ),

    (
        "recon",
        (
            "whoami",
            "id",
            "uname",
            "pwd",
            "ls",
            "ps",
            "netstat",
            "ifconfig",
            "ip addr",
            "hostname",
            "who",
            "uptime",
        ),
    ),

    (
        "file_activity",
        (
            "cat ",
            "touch",
            "mkdir",
            "cp ",
            "mv ",
            "nano",
            "vi ",
            "vim",
            "rm ",
            "find ",
        ),
    ),
]


def classify_command(command_text: str) -> str:
    """
    Classify a command into one of the project's command categories.

    Classification uses simple keyword matching only.
    No machine learning or command execution is involved.
    """
    normalized = command_text.strip().lower()

    if not normalized:
        return "empty"

    for category, keywords in _CATEGORY_RULES:
        if any(keyword in normalized for keyword in keywords):
            return category

    return "unclassified"


class FakeShell:
    """
    Owns the read/respond loop over a single already-open Paramiko channel.

    One instance is used for exactly one SSH session.

    IMPORTANT:
    This class NEVER creates or invokes a real operating-system shell.
    All command responses are predefined static responses.
    """

    def __init__(
        self,
        channel: paramiko.Channel,
        session: SSHSession,
        idle_timeout_seconds: int,
        detection_engine: DetectionEngine,
        database: Database,
    ) -> None:
        self._channel = channel
        self._session = session
        self._idle_timeout_seconds = idle_timeout_seconds
        self._detection_engine = detection_engine
        self._database = database

    def run(self) -> str:
        """
        Blocking fake-shell loop with basic terminal line editing.

        Supports:
        - Enter
        - Backspace
        - Ctrl+C
        - Ctrl+U
        - Up arrow for command history
        - Down arrow for command history

        Attacker input is always treated as data and is never executed.
        """

        self._channel.settimeout(self._idle_timeout_seconds)

        if not self._safe_send(PROMPT):
            return "channel_send_failed"

        buffer = bytearray()
        saw_carriage_return = False

        # Command history exists only for this SSH session.
        command_history = []
        history_index = 0

        # Terminal escape sequence buffer.
        # Up    = ESC [ A
        # Down  = ESC [ B
        escape_buffer = bytearray()

        def redraw_line(new_text: str) -> bool:
            """Replace the currently displayed command line."""
            nonlocal buffer

            # Erase the currently displayed input.
            erase = bytes([8, 32, 8]) * len(buffer)

            new_bytes = new_text.encode(
                "utf-8",
                errors="replace",
            )

            buffer.clear()
            buffer.extend(new_bytes)

            return self._safe_send(
                erase + new_bytes
            )

        while True:
            try:
                data = self._channel.recv(RECV_CHUNK_SIZE)

            except socket.timeout:
                self._safe_send(
                    b"\r\nIdle timeout reached. Closing connection.\r\n"
                )
                return "session_timeout"

            except OSError as exc:
                logger.info(
                    "fake_shell_channel_error",
                    extra={
                        "context": {
                            "session_id": self._session.session_id,
                            "error": str(exc),
                        }
                    },
                )
                return "channel_error"

            if not data:
                return "client_disconnected"

            for byte in data:

                # -------------------------------------------------
                # TERMINAL ESCAPE SEQUENCES
                # -------------------------------------------------

                if escape_buffer:
                    escape_buffer.append(byte)

                    # UP ARROW: ESC [ A
                    if escape_buffer == bytes([27, 91, 65]):
                        escape_buffer.clear()
                        saw_carriage_return = False

                        if command_history:
                            if history_index > 0:
                                history_index -= 1

                            if not redraw_line(
                                command_history[history_index]
                            ):
                                return "channel_send_failed"

                        continue

                    # DOWN ARROW: ESC [ B
                    if escape_buffer == bytes([27, 91, 66]):
                        escape_buffer.clear()
                        saw_carriage_return = False

                        if command_history:
                            if history_index < len(command_history) - 1:
                                history_index += 1
                                new_text = command_history[history_index]
                            else:
                                history_index = len(command_history)
                                new_text = ""

                            if not redraw_line(new_text):
                                return "channel_send_failed"

                        continue

                    # Unknown escape sequence.
                    # Do not pass it to a real shell.
                    if len(escape_buffer) >= 3:
                        escape_buffer.clear()

                    continue

                # ESC starts an escape sequence.
                if byte == 27:
                    saw_carriage_return = False
                    escape_buffer.clear()
                    escape_buffer.append(byte)
                    continue

                # -------------------------------------------------
                # ENTER
                # -------------------------------------------------

                if byte == 13:
                    command_text = bytes(buffer).decode(
                        "utf-8",
                        errors="replace",
                    ).strip()

                    buffer.clear()
                    saw_carriage_return = True

                    if command_text:
                        command_history.append(command_text)
                        history_index = len(command_history)

                    outcome = self._handle_command(command_text)

                    if outcome is not None:
                        return outcome

                # -------------------------------------------------
                # LINE FEED
                # -------------------------------------------------

                elif byte == 10:

                    if saw_carriage_return:
                        saw_carriage_return = False
                        continue

                    command_text = bytes(buffer).decode(
                        "utf-8",
                        errors="replace",
                    ).strip()

                    buffer.clear()

                    if command_text:
                        command_history.append(command_text)
                        history_index = len(command_history)

                    outcome = self._handle_command(command_text)

                    if outcome is not None:
                        return outcome

                # -------------------------------------------------
                # BACKSPACE
                # -------------------------------------------------

                elif byte in (8, 127):
                    saw_carriage_return = False

                    if buffer:
                        buffer.pop()

                        if not self._safe_send(
                            bytes([8, 32, 8])
                        ):
                            return "channel_send_failed"

                # -------------------------------------------------
                # CTRL+C
                # -------------------------------------------------

                elif byte == 3:
                    saw_carriage_return = False
                    buffer.clear()
                    history_index = len(command_history)

                    if not self._safe_send(
                        b"^C\r\n" + PROMPT
                    ):
                        return "channel_send_failed"

                # -------------------------------------------------
                # CTRL+U
                # -------------------------------------------------

                elif byte == 21:
                    saw_carriage_return = False
                    history_index = len(command_history)

                    if buffer:
                        erase = bytes([8, 32, 8]) * len(buffer)
                        buffer.clear()

                        if not self._safe_send(
                            erase + PROMPT
                        ):
                            return "channel_send_failed"

                # -------------------------------------------------
                # NORMAL CHARACTER
                # -------------------------------------------------

                else:
                    saw_carriage_return = False

                    history_index = len(command_history)

                    if len(buffer) >= MAX_BUFFERED_BYTES:
                        self._safe_send(
                            b"\r\nInput too long. Closing connection.\r\n"
                        )
                        return "input_too_long"

                    buffer.append(byte)

                    # Echo only. Never execute.
                    if not self._safe_send(bytes([byte])):
                        return "channel_send_failed"

        return "client_disconnected"

    def _handle_command(self, command_text: str) -> str | None:
        """
        Process exactly ONE complete command.

        This function is called only after Enter has terminated a line.

        Returns an outcome string when the SSH session should close.
        Otherwise returns None and the fake shell continues.

        Attacker commands are treated strictly as data. No command is
        executed on the operating system.
        """

        # Empty line.
        if not command_text:
            if not self._safe_send(b"\r\n" + PROMPT):
                return "channel_send_failed"

            return None

        # Classify the command before responding.
        category = classify_command(command_text)

        # -------------------------------------------------------------
        # EXIT / LOGOUT / QUIT
        # -------------------------------------------------------------
        #
        # Preserve the existing logout behavior.
        if command_text.lower() in EXIT_COMMANDS:
            if not self._safe_send(b"\r\nlogout\r\n"):
                return "channel_send_failed"

            # Store the command and the exact response shown to the
            # attacker. The response is still only data.
            log_command_event(
                self._session,
                command_text=command_text,
                category=category,
                response_text="logout\r\n",
                database=self._database,
            )

            # Send the command to the detection engine.
            self._detection_engine.record_command(
                self._session,
                command_text=command_text,
                category=category,
            )

            return "client_exit"

        # -------------------------------------------------------------
        # NORMAL COMMAND
        # -------------------------------------------------------------

        # Generate the exact fake response without executing anything.
        response_text = self._get_command_response(command_text)

        # Store the exact response generated by the fake shell.
        log_command_event(
            self._session,
            command_text=command_text,
            category=category,
            response_text=response_text,
            database=self._database,
        )

        # Send the command to the Phase 6 detection engine.
        #
        # The detection engine decides whether the command represents
        # suspicious activity and whether a security alert should be raised.
        self._detection_engine.record_command(
            self._session,
            command_text=command_text,
            category=category,
        )

        # Move to a new line before showing the fake response.
        if not self._safe_send(b"\r\n"):
            return "channel_send_failed"

        # Send the exact response that was stored above.
        if not self._safe_send(response_text.encode("utf-8", errors="replace")):
            return "channel_send_failed"

        # Show a new fake prompt.
        if not self._safe_send(PROMPT):
            return "channel_send_failed"

        return None

    def _get_command_response(self, command_text: str) -> str:
        """
        Generate the fake shell response for a command.

        NEVER executes command_text.

        The command is only used as a dictionary lookup and for creating
        a harmless command-not-found message.
        """

        # Exact-match lookup against the predefined static responses.
        response = STATIC_RESPONSES.get(command_text.strip())

        if response is not None:
            return response.decode("utf-8", errors="replace")

        # Unknown commands receive a harmless fake shell error.
        #
        # Only the first word is displayed.
        # The value is never executed.
        words = command_text.split()
        first_word = words[0] if words else command_text

        return f"-bash: {first_word}: command not found\r\n"

    def _safe_send(self, data: bytes) -> bool:
        """
        Safely send bytes through the Paramiko channel.

        Returns False if the channel is no longer usable.
        """

        try:
            self._channel.send(data)
            return True

        except OSError as exc:
            logger.info(
                "fake_shell_send_failed",
                extra={
                    "context": {
                        "session_id": self._session.session_id,
                        "error": str(exc),
                    }
                },
            )
            return False
