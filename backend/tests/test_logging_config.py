"""Request-logging configuration must produce config FreeRADIUS accepts.

These tests run the real ``freeradius -XC`` against a *copy* of the live raddb
tree, so a syntactically invalid managed block fails here rather than breaking
the running server.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.services import logs as logs_mod

RADDB = Path("/etc/freeradius/3.0")
BIN = "/usr/sbin/freeradius"

pytestmark = pytest.mark.skipif(
    not Path(BIN).exists() or not RADDB.exists(),
    reason="requires a real FreeRADIUS installation",
)


@pytest.fixture
def raddb_copy() -> Iterator[Path]:
    """A faithful copy of the live raddb that freerad can actually read.

    Two details matter and both were found the hard way:

    * ``cp -a`` is used rather than ``shutil.copytree`` because ownership
      matters - FreeRADIUS drops privileges to ``freerad`` before opening
      these files, and a ``root:root 0640`` copy makes rlm_preprocess fail.
    * The tree lives under ``/tmp`` with a traversable path, because
      pytest's own ``tmp_path`` is 0700 and freerad cannot descend into it.
    """
    base = Path(tempfile.mkdtemp(prefix="frw-val-", dir="/tmp"))
    base.chmod(0o755)
    dest = base / "3.0"
    subprocess.run(["cp", "-a", str(RADDB), str(dest)], check=True)

    # The live tree may already carry managed blocks, because the panel has
    # installed them on this host at some point. A round-trip test needs a
    # pristine file: install_* is idempotent (a no-op when the block is
    # present), so remove_* would then strip a block it did not add and the
    # round trip could never restore the original. Strip the markers from the
    # copy only - the live files are never touched.
    _strip_managed_blocks(dest)

    try:
        yield dest
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _strip_managed_blocks(raddb: Path) -> None:
    """Remove the panel's managed logging blocks from a copied config tree."""
    import app.services.logs as logs_mod

    for path, begin, end in (
        (raddb / "sites-available" / "default", logs_mod._BEGIN, logs_mod._END),
        (raddb / "mods-available" / "linelog", logs_mod._BEGIN_DETAIL, logs_mod._END_DETAIL),
    ):
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        if begin not in text:
            continue
        # Mirror the removal the service performs, including the newline that
        # install inserted, so the stripped file matches a never-touched one.
        pattern = re.compile(rf"\n{re.escape(begin)}.*?{re.escape(end)}", re.DOTALL)
        cleaned = pattern.sub("", text)
        path.write_text(cleaned, encoding="utf-8")
        _sync_ownership(path)


def _sync_ownership(tree: Path) -> None:
    """Re-apply the production owner to anything a test rewrote.

    This is exactly what ``LocalAtomicWriter`` does on a real write, so the
    validated tree matches what the running server would see.
    """
    ref = RADDB.stat()
    subprocess.run(
        ["chown", "-R", f"{ref.st_uid}:{ref.st_gid}", str(tree)], check=True
    )


def write_managed(tree: Path, relative: str, content: str) -> None:
    target = tree / relative
    target.write_text(content, encoding="utf-8")
    _sync_ownership(tree)


def validate(tree: Path) -> subprocess.CompletedProcess:
    _sync_ownership(tree)
    return subprocess.run(
        [BIN, "-XC", "-d", str(tree), "-l", "stdout"],
        capture_output=True,
        text=True,
        timeout=120,
    )


def assert_config_ok(tree: Path) -> None:
    proc = validate(tree)
    output = proc.stdout + proc.stderr
    assert "Configuration appears to be OK" in output, output[-3000:]


# -- the baseline must be good, or the test proves nothing --------------
def test_untouched_raddb_copy_validates(raddb_copy: Path):
    assert_config_ok(raddb_copy)


def test_site_block_validates(raddb_copy: Path, monkeypatch):
    site = raddb_copy / "sites-available" / "default"
    monkeypatch.setattr(logs_mod.paths, "SITES_AVAILABLE", raddb_copy / "sites-available")

    write_managed(
        raddb_copy, "sites-available/default", logs_mod.install_request_logging_block()
    )
    assert_config_ok(raddb_copy)


def test_detail_block_validates(raddb_copy: Path, monkeypatch):
    mod = raddb_copy / "mods-available" / "linelog"
    monkeypatch.setattr(logs_mod.paths, "MODS_AVAILABLE", raddb_copy / "mods-available")

    mod.write_text(logs_mod.install_linelog_detail_block(), encoding="utf-8")
    assert_config_ok(raddb_copy)


def test_both_blocks_together_validate(raddb_copy: Path, monkeypatch):
    """The combination the API actually installs."""
    site = raddb_copy / "sites-available" / "default"
    mod = raddb_copy / "mods-available" / "linelog"
    monkeypatch.setattr(logs_mod.paths, "SITES_AVAILABLE", raddb_copy / "sites-available")
    monkeypatch.setattr(logs_mod.paths, "MODS_AVAILABLE", raddb_copy / "mods-available")

    write_managed(
        raddb_copy, "sites-available/default", logs_mod.install_request_logging_block()
    )
    write_managed(
        raddb_copy, "mods-available/linelog", logs_mod.install_linelog_detail_block()
    )
    assert_config_ok(raddb_copy)


def test_old_nested_syntax_would_have_been_invalid(raddb_copy: Path):
    """Guard the regression: the previous block really was a parse error."""
    site = raddb_copy / "sites-available" / "default"
    text = site.read_text("utf-8")
    bad = "\tlinelog {\n\t\tfilename = /tmp/x\n\t}\n"
    m = re.search(r"^authenticate\s*\{", text, re.MULTILINE)
    write_managed(
        raddb_copy, "sites-available/default", text[: m.end()] + "\n" + bad + text[m.end():]
    )

    proc = validate(raddb_copy)
    output = proc.stdout + proc.stderr
    assert "Configuration appears to be OK" not in output
    assert "linelog" in output.lower()


# -- shape of the generated text ----------------------------------------
def test_installed_site_block_is_idempotent(raddb_copy: Path, monkeypatch):
    monkeypatch.setattr(logs_mod.paths, "SITES_AVAILABLE", raddb_copy / "sites-available")
    once = logs_mod.install_request_logging_block()
    monkeypatch.setattr(
        logs_mod.paths, "SITES_AVAILABLE", raddb_copy / "sites-available"
    )
    assert logs_mod.install_request_logging_block() == once


def test_enable_disable_roundtrip_restores_the_file(raddb_copy: Path, monkeypatch):
    site_dir = raddb_copy / "sites-available"
    monkeypatch.setattr(logs_mod.paths, "SITES_AVAILABLE", site_dir)
    original = (site_dir / "default").read_text("utf-8")

    installed = logs_mod.install_request_logging_block()
    assert installed != original
    assert logs_mod.remove_request_logging_block() == original


def test_detail_block_roundtrip_restores_the_file(raddb_copy: Path, monkeypatch):
    mods = raddb_copy / "mods-available"
    monkeypatch.setattr(logs_mod.paths, "MODS_AVAILABLE", mods)
    original = (mods / "linelog").read_text("utf-8")

    installed = logs_mod.install_linelog_detail_block()
    assert "auth_goodpass" in installed
    assert logs_mod.remove_linelog_detail_block() == original


def test_accounting_instance_is_not_patched(raddb_copy: Path, monkeypatch):
    """Only the first `linelog { }` instance may gain the options."""
    mods = raddb_copy / "mods-available"
    monkeypatch.setattr(logs_mod.paths, "MODS_AVAILABLE", mods)
    installed = logs_mod.install_linelog_detail_block()

    head, _, tail = installed.partition("linelog log_accounting {")
    assert "auth_goodpass" in head
    assert "auth_goodpass" not in tail, "accounting instance must be untouched"