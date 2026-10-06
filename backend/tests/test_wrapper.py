"""Tests for the privileged helper's allow-list.

The helper is the only place the panel touches root, so it is tested
adversarially: traversal, symlink escape, wrong path families, bad modes and
oversized payloads must all be refused.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

WRAPPER_SRC = Path(__file__).resolve().parent.parent / "wrappers" / "frw-write"
RADDB = Path("/etc/freeradius/3.0")

pytestmark = pytest.mark.skipif(
    not WRAPPER_SRC.exists(), reason="wrapper source not present"
)


@pytest.fixture
def wrapper(tmp_path: Path) -> Path:
    """Placeholder kept for symmetry with make_wrapper()."""
    return WRAPPER_SRC


def make_wrapper(tmp_path: Path, allowed: list[str]) -> Path:
    """Copy the wrapper with ``allowed`` swapped for the supplied paths.

    The real ALLOWED tuple is replaced by regex rather than an exact string
    match: adding an entry to the production allow-list must not silently stop
    these tests from replacing it, which is exactly what happened when the
    groups path was added and the literal match went stale.
    """
    src = WRAPPER_SRC.read_text(encoding="utf-8")
    listing = "\n".join(f'    "{p}",' for p in allowed)

    replaced, count = re.subn(
        r"ALLOWED = \([^)]*\)",
        f"ALLOWED = (\n{listing}\n)",
        src,
        count=1,
    )
    if count != 1:
        raise AssertionError(
            "could not find the ALLOWED tuple in the wrapper; the source "
            "structure changed and this helper must be updated"
        )

    target = tmp_path / "frw-write"
    target.write_text(replaced, encoding="utf-8")
    target.chmod(0o755)
    return target


def call(wrapper: Path, *args: str, payload: bytes = b""):
    return subprocess.run(
        [sys.executable, str(wrapper), *args],
        input=payload,
        capture_output=True,
        timeout=30,
    )


# -- basic behaviour ----------------------------------------------------
def test_allowed_path_is_written(tmp_path: Path):
    target = tmp_path / "authorize"
    target.write_text("old\n")
    w = make_wrapper(tmp_path, [str(target)])

    r = call(w, str(target), payload=b"new content\n")
    assert r.returncode == 0, r.stderr
    assert target.read_text() == "new content\n"


def test_mode_and_ownership_preserved(tmp_path: Path):
    target = tmp_path / "authorize"
    target.write_text("old\n")
    os.chmod(target, 0o640)
    w = make_wrapper(tmp_path, [str(target)])

    assert call(w, str(target), payload=b"new\n").returncode == 0
    assert target.stat().st_mode & 0o7777 == 0o640


def test_explicit_mode_is_applied(tmp_path: Path):
    target = tmp_path / "authorize"
    target.write_text("old\n")
    w = make_wrapper(tmp_path, [str(target)])

    assert call(w, str(target), "600", payload=b"new\n").returncode == 0
    assert target.stat().st_mode & 0o7777 == 0o600


def test_missing_mode_dash_is_accepted(tmp_path: Path):
    target = tmp_path / "authorize"
    target.write_text("old\n")
    w = make_wrapper(tmp_path, [str(target)])

    assert call(w, str(target), "-", payload=b"new\n").returncode == 0


# -- the allow-list is the security boundary ----------------------------
def test_path_outside_allowlist_refused(tmp_path: Path):
    victim = tmp_path / "shadow"
    victim.write_text("untouched\n")
    w = make_wrapper(tmp_path, [str(tmp_path / "allowed")])

    r = call(w, str(victim), payload=b"pwned\n")
    assert r.returncode == 1
    assert b"allow-list" in r.stderr
    assert victim.read_text() == "untouched\n"


def test_etc_passwd_refused_even_if_listed_by_mistake(tmp_path: Path):
    """Sanity: the shipped allow-list must not contain system files."""
    src = WRAPPER_SRC.read_text(encoding="utf-8")
    assert "/etc/passwd" not in src
    assert "/etc/shadow" not in src
    assert "/etc/sudoers" not in src


def test_relative_path_refused(tmp_path: Path):
    w = make_wrapper(tmp_path, [str(tmp_path)])
    r = call(w, "etc/passwd", payload=b"x")
    assert r.returncode == 1
    assert b"absolute" in r.stderr


def test_path_traversal_refused(tmp_path: Path):
    allowed = tmp_path / "allowed"
    allowed.write_text("ok\n")
    w = make_wrapper(tmp_path, [str(allowed)])

    r = call(w, f"{allowed}/../../etc/passwd", payload=b"x")
    assert r.returncode == 1
    assert b".." in r.stderr


def test_symlink_escape_refused(tmp_path: Path):
    """A symlink pointing outside the allow-list must not be followed."""
    allowed = tmp_path / "authorize"
    allowed.write_text("ok\n")
    victim = tmp_path / "victim"
    victim.write_text("safe\n")

    link = tmp_path / "link"
    link.symlink_to(victim)

    w = make_wrapper(tmp_path, [str(allowed)])
    r = call(w, str(link), payload=b"pwned\n")
    assert r.returncode == 1
    assert victim.read_text() == "safe\n"


def test_symlink_to_allowed_target_is_allowed(tmp_path: Path):
    """The real users symlink must work: the *resolved* path is allow-listed."""
    mods = tmp_path / "mods-config" / "files"
    mods.mkdir(parents=True)
    real = mods / "authorize"
    real.write_text("old\n")

    link = tmp_path / "users"
    link.symlink_to(real)

    w = make_wrapper(tmp_path, [str(real)])
    assert call(w, str(link), payload=b"new\n").returncode == 0
    assert real.read_text() == "new\n"
    assert link.is_symlink(), "the symlink itself must survive"


# -- argument and payload validation ------------------------------------
def test_help_lists_the_allowlist(tmp_path: Path):
    """`--help` is the first thing an operator runs when diagnosing."""
    w = make_wrapper(tmp_path, ["/etc/freeradius/3.0/clients.conf"])
    r = call(w, "--help")
    assert r.returncode == 0
    assert "usage: frw-write" in r.stdout.decode()
    assert "/etc/freeradius/3.0/clients.conf" in r.stdout.decode()


def test_too_many_arguments_refused(tmp_path: Path):
    target = tmp_path / "authorize"
    target.write_text("old\n")
    w = make_wrapper(tmp_path, [str(target)])

    r = call(w, str(target), "644", "extra", payload=b"x")
    assert r.returncode == 1


def test_non_octal_mode_refused(tmp_path: Path):
    target = tmp_path / "authorize"
    target.write_text("old\n")
    w = make_wrapper(tmp_path, [str(target)])

    r = call(w, str(target), "not-a-mode", payload=b"x")
    assert r.returncode == 1
    assert b"octal" in r.stderr


def test_mode_with_setuid_bits_refused(tmp_path: Path):
    target = tmp_path / "authorize"
    target.write_text("old\n")
    w = make_wrapper(tmp_path, [str(target)])

    r = call(w, str(target), "4777", payload=b"x")
    assert r.returncode == 1


def test_oversized_payload_refused(tmp_path: Path):
    target = tmp_path / "authorize"
    target.write_text("old\n")
    w = make_wrapper(tmp_path, [str(target)])

    r = call(w, str(target), payload=b"A" * (8 * 1024 * 1024 + 10))
    assert r.returncode == 1
    assert b"too large" in r.stderr
    assert target.read_text() == "old\n", "the file must be untouched"


def test_empty_payload_writes_empty_file(tmp_path: Path):
    target = tmp_path / "authorize"
    target.write_text("old\n")
    w = make_wrapper(tmp_path, [str(target)])

    assert call(w, str(target), payload=b"").returncode == 0
    assert target.read_bytes() == b""


def test_no_temp_files_left_behind(tmp_path: Path):
    target = tmp_path / "authorize"
    target.write_text("old\n")
    w = make_wrapper(tmp_path, [str(target)])

    call(w, str(target), payload=b"new\n")
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".frw-write.")]
    assert leftovers == []


def test_binary_content_survives(tmp_path: Path):
    """FreeRADIUS files are text, but the helper must not corrupt bytes."""
    target = tmp_path / "authorize"
    target.write_bytes(b"old\n")
    w = make_wrapper(tmp_path, [str(target)])

    blob = bytes(range(256))
    assert call(w, str(target), payload=blob).returncode == 0
    assert target.read_bytes() == blob


# -- the shipped allow-list matches reality ------------------------------
@pytest.mark.skipif(not RADDB.exists(), reason="no live FreeRADIUS")
def test_shipped_allowlist_covers_the_managed_files():
    src = WRAPPER_SRC.read_text(encoding="utf-8")
    assert "/etc/freeradius/3.0/clients.conf" in src
    assert "/etc/freeradius/3.0/mods-config/files/authorize" in src
    assert "/etc/freeradius/3.0/sites-available/default" in src
    assert "/etc/freeradius/3.0/mods-available/linelog" in src

    # And those paths must actually exist on this host.
    assert (RADDB / "clients.conf").exists()
    assert (RADDB / "users").exists()
    assert (RADDB / "sites-available" / "default").exists()
    assert (RADDB / "mods-available" / "linelog").exists()