# freeradius-gui

A web management panel for FreeRADIUS 3.x: users, RADIUS clients, backups,
request logging and service control, with every change to `raddb` gated behind a
config validation and a restorable backup.

```
backend/     FastAPI service, privileged writer, pytest suite
frontend/    React + TypeScript + Vite single-page app
```

## Design notes

- **The web app never writes `raddb` itself.** It talks to a small root-owned
  wrapper (`backend/wrappers/frw-write`) through a single sudoers entry that is
  bound to an explicit allow-list of paths. The web process itself runs
  unprivileged.
- **Every mutation validates first.** `freeradius -XC` must pass and a backup
  must exist before a change is committed; a failure rolls the transaction back.
- **Comments and formatting survive edits.** Files are parsed and re-rendered
  rather than rewritten, so hand-written directives are not lost.
- **Passwords and client secrets are write-only.** They are never returned by the
  API; listings expose `has_password` / `has_secret` instead.

## Requirements

- Debian/Ubuntu with FreeRADIUS 3.x installed
- Python 3.11+
- Node 20+ (to build the frontend)

## Install

```bash
sudo FRW_ADMIN_USER=admin ./backend/scripts/install.sh
```

The installer creates the service account, virtualenv, privileged writer, sudoers
rule, systemd unit, nginx site and the first administrator. It prompts for the
admin password; pass `FRW_SKIP_ADMIN=1` to create the account separately:

```bash
sudo -u freeradius-web /opt/freeradius-web/venv/bin/python -m app.cli \
    create-admin admin
```

Then open `https://<host>/`.

## Tests

```bash
cd backend && sudo -E env "PATH=$PATH" python -m pytest
cd frontend && npm ci && npm run typecheck && npm run build
```

The backend suite must run as **root**: `tests/test_wrapper.py` exercises the
root-only writer wrapper. That is safe because `tests/conftest.py` redirects every
config path into a tmp sandbox and fails the run if any path still resolves inside
the live `raddb`.

## CI

`.github/workflows/ci.yml` runs the pytest suite, the frontend typecheck and
build, and a scan that fails on live credentials, RFC1918 addresses or private key
material.

> The test fixtures under `backend/tests/fixtures/` are **synthetic**. They were
> originally copied from a live host and leaked a real user password and two real
> client shared secrets; those values now use the RFC 5737 documentation ranges
> and obviously fake credentials. Keep them that way.

## Documentation

See [`backend/README.md`](backend/README.md) for the API reference, settings,
the privileged-write protocol and the backup/rollback design.