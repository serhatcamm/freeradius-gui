"""The privileged writer's allow-list and the managed-path list must agree.

``frw-write`` is the only route to root, so its ALLOWED tuple is the real
security boundary. ``paths.WRITABLE_KINDS`` is what the services layer thinks
it may write. If those drift apart the failure is silent in the worst way:
the panel happily builds a transaction, the writer refuses it at the last
moment, and nobody notices until a user tries to save.

These tests compare the two lists directly instead of trusting a comment.
"""
from __future__ import annotations

import os
import runpy
from pathlib import Path

import pytest

from app.freeradius import paths as paths_mod

WRAPPER = Path(__file__).resolve().parents[1] / "wrappers" / "frw-write"


def _wrapper_allowed() -> tuple[str, ...]:
    """Load ALLOWED out of the wrapper without executing its main()."""
    namespace = runpy.run_path(str(WRAPPER), run_name="frw_write_under_test")
    return tuple(namespace["ALLOWED"])


def test_wrapper_file_exists_and_is_not_world_writable():
    assert WRAPPER.is_file(), f"missing privileged writer: {WRAPPER}"


def test_every_writable_kind_is_allowed_by_the_wrapper():
    allowed = _wrapper_allowed()
    missing = []
    for kind in paths_mod.WRITABLE_KINDS:
        path = str(paths_mod.managed_path(kind))
        # The wrapper compares after realpath, so accept either spelling.
        if path not in allowed and os.path.realpath(path) not in allowed:
            missing.append(f"{kind} -> {path}")
    assert not missing, "privileged writer would refuse these: " + ", ".join(missing)


def test_groups_is_writable():
    """Groups is a first-class writable file for this feature."""
    assert "groups" in paths_mod.WRITABLE_KINDS
    assert paths_mod.MANAGED_FILES["groups"] == paths_mod.GROUPS_FILE


def test_wrapper_does_not_allow_anything_outside_the_raddb():
    """Nothing outside the FreeRADIUS tree may ever be writable."""
    raddir = str(paths_mod.RADDB_DIR)
    for path in _wrapper_allowed():
        assert path.startswith(raddir + "/"), f"allow-list escapes the raddb: {path}"


def test_wrapper_allow_list_has_no_duplicates():
    allowed = _wrapper_allowed()
    assert len(allowed) == len(set(allowed))


def test_read_only_kinds_are_absent_from_the_wrapper():
    """'accounting' is reported in the UI but is never edited."""
    assert "accounting" in paths_mod.MANAGED_FILES
    assert "accounting" not in paths_mod.WRITABLE_KINDS
    allowed = _wrapper_allowed()
    accounting = str(paths_mod.ACCOUNTING_FILE)
    assert accounting not in allowed