"""RADIUS authentication testing.

Wraps ``radtest`` with an argument array. Passwords and shared secrets are
never written to the audit log or returned in error messages.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import secrets
import time

from ..core.config import get_settings
from ..freeradius.runner import run_command
from .audit import RADIUS_TEST, record

logger = logging.getLogger(__name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,62}$")

# radtest exit codes: 0 accept, 1 reject, 2 error/unreachable.
RESULT_ACCEPT = "Access-Accept"
RESULT_REJECT = "Access-Reject"
RESULT_ERROR = "ERROR"


class RadiusTestError(ValueError):
    pass


def validate_username(username: str) -> str:
    if not username or not USERNAME_RE.match(username):
        raise RadiusTestError("Username contains characters that are not permitted")
    return username


def validate_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        # Allow a resolvable hostname too, but keep it tight.
        if not re.match(r"^[A-Za-z0-9.-]{1,253}$", host or ""):
            raise RadiusTestError("Invalid RADIUS server address")
    return host


def validate_port(port: int) -> int:
    if not isinstance(port, int) or not (0 < port < 65536):
        raise RadiusTestError("Port must be between 1 and 65535")
    return port


def validate_secret(secret: str) -> str:
    if not secret or len(secret) < 8:
        raise RadiusTestError("Shared secret is required (minimum 8 characters)")
    if any(ch in secret for ch in "\r\n\x00"):
        raise RadiusTestError("Shared secret contains invalid characters")
    return secret


_ATTR_RE = re.compile(r'^\s*(?P<key>[A-Za-z0-9_.\-]+)\s*=\s*(?P<value>.*?)\s*$')


def parse_radtest_output(stdout: str) -> dict:
    """Split radtest output into request, response and returned attributes."""
    request: list[dict] = []
    response: dict[str, str] = {}
    reply_attrs: list[dict] = []
    section = None

    for line in stdout.splitlines():
        if line.startswith("Sent "):
            section = "request"
            continue
        if line.startswith("Received "):
            section = "response"
            continue

        m = _ATTR_RE.match(line)
        if not m:
            continue
        key, value = m.group("key"), m.group("value")
        if section == "request":
            request.append({"attribute": key, "value": value})
        elif section == "response":
            if key == "Message-Authenticator":
                response[key] = value
            else:
                reply_attrs.append({"attribute": key, "value": value})

    return {"request_attributes": request, "reply_attributes": reply_attrs, "response": response}


def detect_result(stdout: str, returncode: int) -> str:
    if RESULT_ACCEPT in stdout:
        return RESULT_ACCEPT
    if RESULT_REJECT in stdout:
        return RESULT_REJECT
    if "no response" in stdout.lower() or "timeout" in stdout.lower():
        return RESULT_ERROR
    return RESULT_ERROR


async def run_test(
    *,
    username: str,
    password: str,
    server: str,
    secret: str,
    port: int = 0,
    timeout: int = 15,
    administrator: str | None = None,
    source_ip: str | None = None,
    db=None,
) -> dict:
    """Perform one Access-Request and return a normalised result."""
    settings = get_settings()

    username = validate_username(username)
    server = validate_host(server)
    port = validate_port(port)
    secret = validate_secret(secret)

    if not password:
        raise RadiusTestError("Password is required")

    # argv form: radtest USER PASSWORD SERVER[:port] NAS_PORT SECRET
    target = f"{server}:{port}" if port else server
    argv = [
        str(settings.radtest_binary),
        username,
        password,
        target,
        "0",
        secret,
    ]

    started = time.perf_counter()
    try:
        result = await run_command(argv, timeout=timeout)
    finally:
        # The password lives only in the argv of a short-lived process; make
        # sure nothing persistent captured it.
        password = ""
        secret = ""

    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    verdict = detect_result(result.stdout, result.returncode)
    parsed = parse_radtest_output(result.stdout)

    if administrator:
        record(
            db, RADIUS_TEST, administrator, object_type="radius_test",
            object_id=username, source_ip=source_ip, success=verdict == RESULT_ACCEPT,
            detail={
                "server": server,
                "port": port,
                "result": verdict,
                "response_time_ms": elapsed_ms,
            },
        )

    error_info = None
    if verdict == RESULT_ERROR:
        error_info = (
            result.stderr.strip()
            or _extract_error(result.stdout)
            or "No response from the RADIUS server"
        )

    return {
        "result": verdict,
        "response_time_ms": elapsed_ms,
        "username": username,
        "server": server,
        "port": port,
        "returned_attributes": parsed["reply_attributes"],
        "request_attributes": [
            # Never echo the password back to the browser.
            a
            for a in parsed["request_attributes"]
            if a["attribute"] not in {"User-Password", "Cleartext-Password", "CHAP-Password"}
        ],
        "message_authenticator": parsed["response"].get("Message-Authenticator"),
        "error": error_info,
        "raw_accepted": verdict == RESULT_ACCEPT,
    }


def _extract_error(stdout: str) -> str | None:
    for line in stdout.splitlines():
        lowered = line.lower()
        if "expected access-accept" in lowered:
            return "Server returned Access-Reject (credentials or policy rejected)"
        if "no response" in lowered:
            return "No response - check the server address, port and firewall"
        if "timed out" in lowered:
            return "Request timed out"
    return None


def generate_test_secret(length: int = 24) -> str:
    """Convenience for operators who want a throwaway lab secret."""
    return secrets.token_urlsafe(length)[:32]