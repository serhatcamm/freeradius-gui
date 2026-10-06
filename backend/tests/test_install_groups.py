"""The installer's groupfile wiring, exercised without touching /etc.

FreeRADIUS only reads mods-config/files/groups when the ``files`` module has an
active ``groupfile`` directive. If the installer gets that wrong the Groups page
still saves happily and nothing changes for authentication, so the shell logic
is tested here against a copy of a real module file.

These run only when the real file is present (the test host has FreeRADIUS
installed); otherwise they skip rather than fail.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

SRC = Path("/etc/freeradius/3.0/mods-available/files")

pytestmark = pytest.mark.skipif(
    not SRC.is_file(), reason="needs a real FreeRADIUS module file"
)


def _apply(work: Path) -> None:
    """The exact sed sequence from scripts/install.sh."""
    subprocess.run(
        ["sed", "-i", r"/^[[:space:]]*#\?[[:space:]]*groupfile[[:space:]]*=/d", str(work)],
        check=True,
    )
    subprocess.run(
        ["sed", "-i", r"/^[[:space:]]*moddir[[:space:]]*=/a\\tgroupfile = ${moddir}/groups", str(work)],
        check=True,
    )


def _active_lines(work: Path) -> int:
    pattern = re.compile(r"^\s*groupfile\s*=", re.MULTILINE)
    return len(pattern.findall(work.read_text()))


@pytest.fixture
def work(tmp_path: Path) -> Path:
    target = tmp_path / "files"
    shutil.copy(SRC, target)
    return target


def test_installs_exactly_one_directive(work: Path):
    _apply(work)
    assert _active_lines(work) == 1


def test_is_idempotent(work: Path):
    """Re-running the installer must not duplicate the directive."""
    for _ in range(3):
        _apply(work)
    assert _active_lines(work) == 1


def test_lands_after_moddir_so_the_variable_expands(work: Path):
    """${moddir} is expanded while the section is parsed.

    Inserting before moddir is defined can expand to nothing and silently
    point groupfile at /groups.
    """
    _apply(work)
    lines = [i for i, l in enumerate(work.read_text().splitlines()) if "moddir" in l]
    groupfile = [i for i, l in enumerate(work.read_text().splitlines()) if "groupfile" in l]
    assert lines and groupfile
    assert min(groupfile) > min(lines), "groupfile must come after moddir"


def test_replaces_a_commented_directive(work: Path):
    text = work.read_text()
    text = text.replace(
        "\tfilename", "\t#groupfile = ${moddir}/groups\n\tfilename", 1
    )
    work.write_text(text)
    _apply(work)
    assert _active_lines(work) == 1


def test_collapses_duplicate_directives(work: Path):
    """Even a hand-edited file with two entries is normalised to one."""
    _apply(work)
    text = work.read_text()
    work.write_text(
        text.replace(
            "groupfile = ${moddir}/groups",
            "groupfile = ${moddir}/groups\n\tgroupfile = ${moddir}/groups",
            1,
        )
    )
    assert _active_lines(work) == 2
    _apply(work)
    assert _active_lines(work) == 1