"""The CLI takes `username` positionally, but `--username` is accepted too.

This exists because the installer once printed a `--username` form that argparse
rejected outright, which was unhelpful. Both spellings now work and a
contradictory pair is refused.
"""
from __future__ import annotations

import pytest

from app.cli import main


def test_create_admin_accepts_positional_username(capsys):
    rc = main(["create-admin", "someone", "--password", "Correct-Horse-1!"])
    assert rc == 0
    assert "created administrator 'someone'" in capsys.readouterr().out


def test_create_admin_accepts_username_flag(capsys):
    rc = main(["create-admin", "--username", "flagged",
               "--password", "Correct-Horse-1!"])
    assert rc == 0
    assert "created administrator 'flagged'" in capsys.readouterr().out


def test_create_admin_without_username_is_a_usage_error(capsys):
    rc = main(["create-admin", "--password", "Correct-Horse-1!"])
    assert rc == 2
    assert "username is required" in capsys.readouterr().out


def test_create_admin_rejects_conflicting_usernames():
    with pytest.raises(SystemExit) as exc:
        main(["create-admin", "one", "--username", "two",
              "--password", "Correct-Horse-1!"])
    assert "given twice" in str(exc.value)


def test_set_password_accepts_both_spellings(capsys):
    assert main(["create-admin", "target", "--password", "Correct-Horse-1!"]) == 0

    assert main(["set-password", "target", "--password", "Another-Strong-2!"]) == 0
    assert "password updated for 'target'" in capsys.readouterr().out

    assert main(["set-password", "--username", "target",
                 "--password", "Third-Strong-Pass-3!"]) == 0
    assert "password updated for 'target'" in capsys.readouterr().out


def test_set_password_unknown_user(capsys):
    rc = main(["set-password", "ghost", "--password", "Whatever-Strong-9!"])
    assert rc == 1
    assert "no such administrator" in capsys.readouterr().out