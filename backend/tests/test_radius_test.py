"""Unit coverage for the radius-test request builder and validators.

The API tests stub run_test(), so the validation and argv assembly below were
never executed by the suite. That gap is how validate_port() came to reject
port 0 - the value every UI request carries - while the code right below it
still had a branch for port 0.
"""
from __future__ import annotations

import pytest

from app.services import radius_test as rt_mod
from app.services.radius_test import (
    RadiusTestError,
    run_test,
    validate_port,
    validate_secret,
    validate_username,
)


@pytest.fixture
def captured(monkeypatch):
    """Capture the argv run_test would hand to radtest."""
    seen: dict = {}

    async def fake_run_command(argv, timeout=15):
        seen["argv"] = argv
        seen["timeout"] = timeout
        return type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "Sent Access-Request Id 1\nReceived Access-Accept Id 1\n",
                "stderr": "",
            },
        )()

    monkeypatch.setattr(rt_mod, "run_command", fake_run_command)
    return seen


# -- validate_port ------------------------------------------------------
def test_port_zero_is_allowed():
    """0 means "unspecified", not "invalid"."""
    assert validate_port(0) == 0


@pytest.mark.parametrize("port", [1, 1812, 18120, 65535])
def test_valid_ports_pass_through(port):
    assert validate_port(port) == port


@pytest.mark.parametrize("port", [-1, 65536, 99999])
def test_out_of_range_ports_are_rejected(port):
    with pytest.raises(RadiusTestError, match="between 1 and 65535"):
        validate_port(port)


def test_non_integer_port_is_rejected():
    with pytest.raises(RadiusTestError, match="between 1 and 65535"):
        validate_port("1812")  # type: ignore[arg-type]


def test_bool_is_not_accepted_as_a_port():
    with pytest.raises(RadiusTestError):
        validate_port(True)  # type: ignore[arg-type]


# -- other validators ---------------------------------------------------
@pytest.mark.parametrize("name", ["serhat", "user.name", "a@b", "A_B-c"])
def test_valid_usernames(name):
    assert validate_username(name) == name


@pytest.mark.parametrize("name", ["", " leading", "has space", "x" * 64, "no/slash"])
def test_invalid_usernames(name):
    with pytest.raises(RadiusTestError):
        validate_username(name)


def test_short_secret_is_rejected():
    with pytest.raises(RadiusTestError, match="minimum 8"):
        validate_secret("short")


def test_secret_with_newline_is_rejected():
    with pytest.raises(RadiusTestError, match="invalid characters"):
        validate_secret("LongEnough123\n")


# -- argv assembly ------------------------------------------------------
@pytest.mark.asyncio
async def test_default_port_omits_the_suffix(captured):
    """No port in the request means radtest applies its own default."""
    out = await run_test(
        username="serhat",
        password="Whatever12345!",
        server="127.0.0.1",
        secret="SharedSecret123",
        port=0,
    )
    target = captured["argv"][3]
    assert target == "127.0.0.1", f"port suffix must be omitted, got {target}"
    assert out["result"] == "Access-Accept"
    assert out["port"] == 0


@pytest.mark.asyncio
async def test_explicit_port_is_appended(captured):
    out = await run_test(
        username="serhat",
        password="Whatever12345!",
        server="127.0.0.1",
        secret="SharedSecret123",
        port=18120,
    )
    assert captured["argv"][3] == "127.0.0.1:18120"
    assert out["port"] == 18120


@pytest.mark.asyncio
async def test_rejects_a_bad_port_before_running_anything(captured):
    with pytest.raises(RadiusTestError, match="between 1 and 65535"):
        await run_test(
            username="serhat",
            password="Whatever12345!",
            server="127.0.0.1",
            secret="SharedSecret123",
            port=70000,
        )
    assert "argv" not in captured, "must not shell out after validation fails"


@pytest.mark.asyncio
async def test_secret_never_appears_in_the_result(captured):
    out = await run_test(
        username="serhat",
        password="Whatever12345!",
        server="127.0.0.1",
        secret="SharedSecret123",
    )
    assert "SharedSecret123" not in str(out)
    assert "Whatever12345!" not in str(out)