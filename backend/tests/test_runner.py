"""Tests for the command allow-list and privilege elevation.

``runner`` is the boundary between web input and the operating system, so the
allow-list is tested adversarially: unit injection, unknown programs and
unexpected elevation must all be refused.
"""
from __future__ import annotations

import os

import pytest

from app.freeradius.runner import (
    CommandNotAllowed,
    elevate,
    needs_sudo,
    validate_argv,
)

SYSTEMCTL = "/usr/bin/systemctl"


# -- the allow-list ------------------------------------------------------
def test_unknown_program_refused():
    with pytest.raises(CommandNotAllowed):
        validate_argv(["/bin/bash", "-c", "id"])


def test_empty_argv_refused():
    with pytest.raises(CommandNotAllowed):
        validate_argv([])


def test_shell_metacharacters_are_not_a_shell():
    """Arguments are never interpreted by a shell, so these are inert."""
    validate_argv([SYSTEMCTL, "status", "freeradius; rm -rf /"])
    # The whole string is just a bogus unit name, not two commands.


def test_program_without_argument_support_refuses_args():
    with pytest.raises(CommandNotAllowed):
        validate_argv(["/usr/bin/ps", "--output", "/etc/passwd"])


# -- systemctl -----------------------------------------------------------
@pytest.mark.parametrize(
    "action", ["status", "show", "is-active", "is-enabled", "cat", "list-units"]
)
def test_read_only_systemctl_actions_allowed(action):
    validate_argv([SYSTEMCTL, action])


def test_restart_freeradius_allowed():
    validate_argv([SYSTEMCTL, "restart", "freeradius"])


def test_reload_freeradius_allowed():
    validate_argv([SYSTEMCTL, "reload", "freeradius"])


def test_unknown_action_refused():
    with pytest.raises(CommandNotAllowed):
        validate_argv([SYSTEMCTL, "disable", "freeradius"])


def test_stop_and_start_are_not_reachable():
    """stop/start are deliberately absent from the reachable action set."""
    for action in ("stop", "start"):
        with pytest.raises(CommandNotAllowed):
            validate_argv([SYSTEMCTL, action, "freeradius"])


@pytest.mark.parametrize(
    "unit",
    ["nginx", "ssh", "postgresql", "freeradius.service.d", "freeradius-other"],
)
def test_other_units_cannot_be_restarted(unit):
    with pytest.raises(CommandNotAllowed):
        validate_argv([SYSTEMCTL, "restart", unit])


def test_extra_positional_units_refused():
    """Hiding a second unit after the allowed one must not work."""
    with pytest.raises(CommandNotAllowed):
        validate_argv([SYSTEMCTL, "restart", "freeradius", "nginx"])


def test_flags_are_ignored_for_unit_check():
    validate_argv([SYSTEMCTL, "restart", "--no-block", "freeradius"])


# -- privilege elevation -------------------------------------------------
def test_restart_needs_sudo():
    assert needs_sudo([SYSTEMCTL, "restart", "freeradius"]) is True


def test_reload_needs_sudo():
    assert needs_sudo([SYSTEMCTL, "reload", "freeradius"]) is True


@pytest.mark.parametrize(
    "argv",
    [
        [SYSTEMCTL, "status", "freeradius"],
        [SYSTEMCTL, "is-active", "freeradius"],
        ["/usr/sbin/freeradius", "-XC"],
        ["/usr/bin/journalctl", "-u", "freeradius", "-n", "50"],
    ],
)
def test_read_only_commands_do_not_need_sudo(argv):
    assert needs_sudo(argv) is False


def test_elevation_is_added_when_unprivileged(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    out = elevate([SYSTEMCTL, "restart", "freeradius"])
    assert out[:3] == ["sudo", "--non-interactive", "--"]
    assert out[3:] == [SYSTEMCTL, "restart", "freeradius"]


def test_no_elevation_when_already_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    argv = [SYSTEMCTL, "restart", "freeradius"]
    assert elevate(argv) == argv


def test_read_only_command_never_gets_sudo(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    argv = [SYSTEMCTL, "status", "freeradius"]
    assert elevate(argv) == argv


def test_elevation_does_not_bypass_validation():
    """Elevate() must not be a way to smuggle a command past the allow-list."""
    monkeypatch_euid = os.geteuid
    try:
        os.geteuid = lambda: 1000  # type: ignore[assignment]
        with pytest.raises(CommandNotAllowed):
            validate_argv([SYSTEMCTL, "restart", "nginx"])
    finally:
        os.geteuid = monkeypatch_euid  # type: ignore[assignment]