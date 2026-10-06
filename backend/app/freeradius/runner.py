"""Controlled subprocess execution.

Rules enforced here (see SECURITY.md):

* every command is an **argument array**, never a shell string;
* ``shell=False`` always;
* commands must be in the explicit allow-list below, so no caller can turn
  user input into an arbitrary command;
* timeouts are always set;
* output is captured and truncated, never streamed to the client verbatim.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shlex
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30


class CommandNotAllowed(PermissionError):
    """Raised when a command is not present in the allow-list."""


class CommandFailed(RuntimeError):
    """A command ran but returned a non-zero exit status."""

    def __init__(self, argv: list[str], returncode: int, stdout: str, stderr: str):
        self.argv = argv
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(f"{argv[0]} exited {returncode}")


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


#: argv[0] -> whether extra arguments are permitted.
ALLOWED_COMMANDS: dict[str, bool] = {
    # read-only validation
    "/usr/sbin/freeradius": True,
    # service control (normally reached through the sudoers wrappers)
    "/usr/bin/systemctl": True,
    # authentication test
    "/usr/bin/radtest": True,
    # service introspection
    "/usr/bin/journalctl": True,
    "/usr/bin/ss": True,
    "/bin/ps": True,
    "/usr/bin/openssl": True,
    "/usr/bin/ldapwhoami": True,
    "/usr/bin/wbinfo": True,
    "/usr/bin/net": True,
    "/usr/bin/readlink": True,
    "/usr/bin/stat": True,
    # privilege discovery
    "/usr/sbin/radsecret": True,
}

#: systemctl subcommands the panel may ever invoke.
ALLOWED_SYSTEMCTL_ACTIONS = {
    "status",
    "show",
    "is-active",
    "is-enabled",
    "restart",
    "reload",
    "cat",
    "list-units",
}

#: systemctl subcommands that change system state. These are additionally
#: restricted to the allow-listed units below.
MUTATING_SYSTEMCTL_ACTIONS = {"restart", "reload", "stop", "start"}

#: Only this unit may be started/stopped/reloaded by the panel.
ALLOWED_SYSTEMCTL_UNITS = {"freeradius"}

MAX_OUTPUT = 64 * 1024


def validate_argv(argv: list[str]) -> None:
    if not argv:
        raise CommandNotAllowed("empty command")
    program = argv[0]
    if program not in ALLOWED_COMMANDS:
        raise CommandNotAllowed(f"{program} is not in the allow-list")
    if not ALLOWED_COMMANDS[program]:
        raise CommandNotAllowed(f"{program} does not accept arguments")

    if program.endswith("systemctl"):
        action: str | None = None
        positional: list[str] = []
        for arg in argv[1:]:
            if arg.startswith("-"):
                continue
            if action is None:
                if arg not in ALLOWED_SYSTEMCTL_ACTIONS:
                    raise CommandNotAllowed(f"systemctl action {arg!r} not allowed")
                action = arg
            else:
                positional.append(arg)

        # `systemctl restart nginx` would otherwise be a privilege-escalation
        # path for a process that can call systemctl at all, so only the
        # freeradius unit may be addressed.
        if action in MUTATING_SYSTEMCTL_ACTIONS:
            for unit in positional:
                if unit not in ALLOWED_SYSTEMCTL_UNITS:
                    raise CommandNotAllowed(
                        f"systemctl {action} on unit {unit!r} not allowed"
                    )


def needs_sudo(argv: list[str]) -> bool:
    """Whether this command must be elevated through sudo.

    The panel normally runs as the unprivileged ``freeradius-web`` user, which
    cannot restart FreeRADIUS. Those calls go through a sudoers rule that
    allows exactly these commands and no others, so elevation stays narrow.
    """
    if not argv:
        return False
    program = Path(argv[0]).name
    if program != "systemctl":
        return False
    return any(arg in MUTATING_SYSTEMCTL_ACTIONS for arg in argv[1:])


def elevate(argv: list[str]) -> list[str]:
    """Prefix a command with sudo when the process is not already root."""
    if os.geteuid() == 0 or not needs_sudo(argv):
        return argv
    return ["sudo", "--non-interactive", "--", *argv]


async def run_command(argv: list[str], timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
    """Run an allow-listed command with an argument array."""
    validate_argv(argv)
    argv = elevate(argv)
    logger.info("exec: %s", " ".join(shlex.quote(a) for a in argv))

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise CommandFailed(argv, 127, "", str(exc)) from exc

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise CommandFailed(argv, 124, "", f"timed out after {timeout}s") from None

    return CommandResult(
        argv=argv,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout.decode("utf-8", "replace")[:MAX_OUTPUT],
        stderr=stderr.decode("utf-8", "replace")[:MAX_OUTPUT],
    )


def run_command_sync(argv: list[str], timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
    """Synchronous convenience wrapper (used by CLI tooling and tests)."""
    validate_argv(argv)
    logger.info("exec(sync): %s", " ".join(shlex.quote(a) for a in argv))
    try:
        proc = asyncio.run(run_command(argv, timeout=timeout))
    except CommandNotAllowed:
        raise
    return proc
