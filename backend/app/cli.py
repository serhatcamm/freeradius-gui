"""Management CLI.

    frw-admin create-admin <username>
    frw-admin list-admins
    frw-admin set-password <username>
    frw-admin validate
    frw-admin show-users
    frw-admin show-clients

``username`` is positional, but ``--username NAME`` is accepted as well so a
mistyped flag is not an instant failure.
"""
from __future__ import annotations

import argparse
import getpass
import secrets
import string
import sys

from sqlalchemy import select

from .core.db import init_db, session_scope
from .models.db import Administrator, utcnow
from .security.passwords import (
    MIN_PASSWORD_LENGTH,
    PasswordPolicyError,
    hash_password,
    verify_password,
)


def _prompt_password(confirm: bool = True) -> str:
    while True:
        pw = getpass.getpass("Password: ")
        try:
            if len(pw) < MIN_PASSWORD_LENGTH:
                print(f"  too short (minimum {MIN_PASSWORD_LENGTH})")
                continue
            if confirm and pw != getpass.getpass("Confirm password: "):
                print("  passwords do not match")
                continue
            return pw
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(130)


def _resolve_username(args: argparse.Namespace) -> str | None:
    """Accept the username positionally or via --username, and reject both/none.

    Both spellings are supported because the flag form is what people reach for
    by habit, and a hard argparse error is a poor way to learn that.
    """
    positional = getattr(args, "username_pos", None)
    flag = getattr(args, "username_opt", None)
    if positional and flag and positional != flag:
        raise SystemExit(
            f"error: username given twice and they differ "
            f"({positional!r} vs {flag!r})"
        )
    return positional or flag


def create_admin(args: argparse.Namespace) -> int:
    init_db()
    username = _resolve_username(args)
    if not username:
        print("error: a username is required "
              "(positional, or --username NAME)")
        return 2
    password = args.password or _prompt_password()
    try:
        password_hash = hash_password(password)
    except PasswordPolicyError as exc:
        print(f"error: {exc}")
        return 1

    with session_scope() as db:
        existing = db.execute(
            select(Administrator).where(Administrator.username == username)
        ).scalar_one_or_none()
        if existing and not args.force:
            print(f"error: administrator {username!r} already exists (use --force)")
            return 1
        if existing:
            existing.password_hash = password_hash
            existing.is_active = True
            existing.failed_attempts = 0
            existing.locked_until = None
            print(f"password reset for {username!r}")
            return 0

        db.add(
            Administrator(
                username=username,
                password_hash=password_hash,
                full_name=args.full_name,
                role="admin",
                is_active=True,
                created_at=utcnow(),
            )
        )
        print(f"created administrator {username!r}")
        return 0


def list_admins(_args: argparse.Namespace) -> int:
    init_db()
    with session_scope() as db:
        rows = db.execute(select(Administrator).order_by(Administrator.username)).scalars()
        for a in rows:
            state = "active" if a.is_active else "disabled"
            last = a.last_login_at.isoformat() if a.last_login_at else "never"
            print(f"{a.username:20} {a.role:8} {state:8} last_login={last}")
    return 0


def set_password(args: argparse.Namespace) -> int:
    init_db()
    username = _resolve_username(args)
    if not username:
        print("error: a username is required (positional, or --username NAME)")
        return 2
    password = args.password or _prompt_password()
    try:
        password_hash = hash_password(password)
    except PasswordPolicyError as exc:
        print(f"error: {exc}")
        return 1

    with session_scope() as db:
        admin = db.execute(
            select(Administrator).where(Administrator.username == username)
        ).scalar_one_or_none()
        if admin is None:
            print(f"error: no such administrator {username!r}")
            return 1
        admin.password_hash = password_hash
        admin.failed_attempts = 0
        admin.locked_until = None
        print(f"password updated for {username!r}")
    return 0


def validate(_args: argparse.Namespace) -> int:
    import asyncio

    from .freeradius.validate import validate_config

    result = asyncio.run(validate_config())
    print(f"valid={result.ok} exit={result.returncode}")
    print(result.summary)
    for issue in result.issues[:20]:
        print(f"  {issue.severity} line {issue.line}: {issue.message}")
    return 0 if result.ok else 1


def show_users(_args: argparse.Namespace) -> int:
    from .services.users import UserService

    for u in UserService().list_users():
        print(
            f"{u['username']:20} {u['auth_method']:20} {u['status']:8} "
            f"priv={u['cisco_privilege']} dupes={u.get('duplicate_entries', 1)}"
        )
    return 0


def show_clients(_args: argparse.Namespace) -> int:
    from .services.clients import ClientService

    for c in ClientService().list_clients():
        print(
            f"{c['name']:20} {str(c['address']):20} {c['address_kind']:8} "
            f"secret={c['has_secret']} {c['status']}"
        )
    return 0


def generate_secret(args: argparse.Namespace) -> int:
    from .security.passwords import generate_secret

    print(generate_secret(args.length))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="freeradius-web", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create-admin", help="create or reset a web administrator")
    p.add_argument("username_pos", metavar="username", nargs="?")
    p.add_argument("--username", dest="username_opt", default=None,
                   help="alternative to the positional username")
    p.add_argument("--password", help="skip the prompt (discouraged on a shared host)")
    p.add_argument("--full-name", default=None)
    p.add_argument("--force", action="store_true", help="reset if it already exists")
    p.set_defaults(func=create_admin)

    p = sub.add_parser("list-admins")
    p.set_defaults(func=list_admins)

    p = sub.add_parser("set-password")
    p.add_argument("username_pos", metavar="username", nargs="?")
    p.add_argument("--username", dest="username_opt", default=None)
    p.add_argument("--password")
    p.set_defaults(func=set_password)

    p = sub.add_parser("validate", help="run freeradius -XC")
    p.set_defaults(func=validate)

    p = sub.add_parser("show-users")
    p.set_defaults(func=show_users)

    p = sub.add_parser("show-clients")
    p.set_defaults(func=show_clients)

    p = sub.add_parser("generate-secret")
    p.add_argument("--length", type=int, default=32)
    p.set_defaults(func=generate_secret)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())