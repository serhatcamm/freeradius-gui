"""Security primitives: password hashing, policy and generated secrets."""
from __future__ import annotations

import threading

import pytest

from app.freeradius.clients_parser import parse_clients
from app.security.passwords import (
    PasswordPolicyError,
    check_password_policy,
    generate_secret,
    hash_password,
    needs_rehash,
    verify_password,
)


# -- session signing key ------------------------------------------------
def test_concurrent_first_run_agrees_on_one_key(tmp_path, monkeypatch):
    """First-run key generation must be race-free.

    ``load_secret_key`` is called while serving every request. With a plain
    check-then-generate, two threads that both find no key each generate a
    different one: the response that signs a session cookie returns key A
    while the file holds key B, and the next request reports the session as
    not found. This is what broke ``/api/users`` on CI, where the timing
    reliably lost the race.
    """
    from app.core import config as config_mod

    key_file = tmp_path / "secret_key"
    monkeypatch.setenv("FRW_SECRET_KEY_FILE", str(key_file))
    config_mod.get_settings.cache_clear()

    results: list[bytes] = []
    barrier = threading.Barrier(8)
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            barrier.wait(timeout=10)
            results.append(config_mod.load_secret_key())
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert not errors, f"worker raised: {errors!r}"
    assert len(results) == 8
    assert len(set(results)) == 1, "concurrent callers disagreed on the key"
    assert key_file.exists()
    assert key_file.read_bytes().strip() == results[0]


def test_existing_key_is_reused(tmp_path, monkeypatch):
    from app.core import config as config_mod

    key_file = tmp_path / "secret_key"
    key_file.write_bytes(b"a" * 48)
    monkeypatch.setenv("FRW_SECRET_KEY_FILE", str(key_file))
    config_mod.get_settings.cache_clear()

    assert config_mod.load_secret_key() == b"a" * 48
    assert config_mod.load_secret_key() == b"a" * 48


def test_empty_key_file_is_replaced(tmp_path, monkeypatch):
    """An interrupted first run leaves a zero-length file; it must recover."""
    from app.core import config as config_mod

    key_file = tmp_path / "secret_key"
    key_file.write_bytes(b"")
    monkeypatch.setenv("FRW_SECRET_KEY_FILE", str(key_file))
    config_mod.get_settings.cache_clear()

    key = config_mod.load_secret_key()
    assert len(key) == 48
    assert key_file.read_bytes().strip() == key


# -- hashing ------------------------------------------------------------
def test_hash_and_verify_roundtrip():
    h = hash_password("CorrectHorseBattery12!")
    assert verify_password(h, "CorrectHorseBattery12!") is True


def test_verify_rejects_wrong_password():
    h = hash_password("CorrectHorseBattery12!")
    assert verify_password(h, "WrongHorseBattery12!") is False


def test_hash_is_salted():
    assert hash_password("same12CharPass!") != hash_password("same12CharPass!")


def test_verify_handles_argon2_phc_prefix():
    """Argon2 hashes begin with '$argon2id$'; that must not be rejected."""
    h = hash_password("CorrectHorseBattery12!")
    assert h.startswith("$argon2")
    assert verify_password(h, "CorrectHorseBattery12!") is True


def test_verify_rejects_garbage_hash():
    assert verify_password("not-a-hash", "whatever") is False
    assert verify_password("", "whatever") is False
    assert verify_password("", "whatever") is False


def test_verify_never_raises_on_malformed_hash():
    for bad in ("$argon2id$broken", "argon2id$", "$$$", "\x00\x01"):
        assert verify_password(bad, "x") is False


def test_needs_rehash_detects_argon2():
    h = hash_password("CorrectHorseBattery12!")
    assert needs_rehash(h) is False
    assert needs_rehash("legacy-md5-hash") is True


# -- policy -------------------------------------------------------------
def test_policy_rejects_short_password():
    with pytest.raises(PasswordPolicyError):
        check_password_policy("short")


def test_policy_rejects_surrounding_whitespace():
    with pytest.raises(PasswordPolicyError):
        check_password_policy(" leadingSpace12")
    with pytest.raises(PasswordPolicyError):
        check_password_policy("trailingSpace12 ")


def test_policy_accepts_reasonable_password():
    check_password_policy("CorrectHorseBattery12!")


def test_hash_enforces_policy():
    with pytest.raises(PasswordPolicyError):
        hash_password("tooshort")


# -- generated secrets --------------------------------------------------
def test_generated_secret_length():
    assert len(generate_secret()) == 32
    assert len(generate_secret(48)) == 48


def test_generated_secrets_are_unique():
    assert len({generate_secret() for _ in range(200)}) == 200


def test_generated_secret_contains_no_comment_character():
    """'#' would truncate the value when FreeRADIUS re-reads the file."""
    for _ in range(500):
        secret = generate_secret()
        assert "#" not in secret
        assert '"' not in secret
        assert "\\" not in secret
        assert not any(ch.isspace() for ch in secret)


@pytest.mark.parametrize("iteration", range(50))
def test_generated_secret_survives_a_clients_conf_roundtrip(iteration):
    """Whatever we generate must be the value FreeRADIUS reads back.

    This is the invariant that the '#' bug violated: the secret was written
    but silently truncated on reload, breaking NAS authentication.
    """
    secret = generate_secret()
    text = (
        "client roundtrip-nas {\n"
        f"\tipaddr = 10.99.0.0/16\n"
        f"\tsecret = {secret}\n"
        "}\n"
    )
    doc = parse_clients(text)
    entry = doc.unique_find("roundtrip-nas")
    assert entry is not None
    assert entry.has_secret, "the secret was lost during parsing"
    assert doc.render() == text, "round-trip must be lossless"


# -- static file serving -------------------------------------------------
# The SPA fallback route is registered at import time only when
# FRW_STATIC_DIR already exists, and it lives in the same process as every
# other test, so the probe runs in a clean subprocess (see probe_static.py).
@pytest.fixture(scope="module")
def static_probe():
    import json
    import os
    import subprocess
    import sys
    from pathlib import Path

    probe = Path(__file__).parent / "probe_static.py"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    # The app logs to stdout, so the JSON result is the last line rather than
    # the whole stream.
    env["FRW_LOG_LEVEL"] = "ERROR"
    proc = subprocess.run(
        [sys.executable, str(probe)],
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
    )
    assert proc.returncode == 0, f"probe failed:\n{proc.stdout}\n{proc.stderr}"

    payload = proc.stdout.strip().splitlines()[-1]
    return json.loads(payload)


def test_index_is_served(static_probe):
    assert static_probe["index"]["status"] == 200
    assert static_probe["index"]["is_index"] is True


def test_spa_routes_fall_back_to_index(static_probe):
    assert static_probe["spa_route"]["status"] == 200
    assert static_probe["spa_route"]["is_index"] is True


def test_assets_are_served(static_probe):
    assert static_probe["asset"]["status"] == 200
    assert static_probe["asset"]["body"] == "export const x = 1"


def test_unknown_api_path_is_json_404_not_the_spa(static_probe):
    """The catch-all must never shadow the API surface."""
    assert static_probe["api_404"]["status"] == 404
    assert static_probe["api_404"]["is_json"] is True


@pytest.mark.parametrize(
    "path",
    [
        "/../frw-outside-secret.txt",
        "/../../frw-outside-secret.txt",
        "/assets/../../frw-outside-secret.txt",
        "/%2e%2e/frw-outside-secret.txt",
        "/%2e%2e%2f%2e%2e%2ffrw-outside-secret.txt",
        "/..%2ffrw-outside-secret.txt",
    ],
)
def test_static_fallback_rejects_traversal(static_probe, path):
    """The SPA fallback must not read files outside the bundle directory.

    The encoded forms are the ones that matter: an HTTP client normalises a
    literal `..` before the request leaves, so the plain cases pass even with a
    vulnerable handler. Only the percent-encoded ones reach the route intact.
    """
    entry = next(item for item in static_probe["traversal"] if item["path"] == path)
    assert entry["leaked"] is False, f"{path} escaped the static directory"