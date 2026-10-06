# freeradius-gui

A web management panel for FreeRADIUS 3.x: users, RADIUS clients, attribute
groups, request logging, backups and service control, with every change to
`raddb` gated behind a config validation and a restorable backup.

```
backend/     FastAPI service, privileged writer, pytest suite
frontend/    React + TypeScript + Vite single-page app
```

## Features

| Area | What it does |
|------|--------------|
| Users | Create, edit, disable, delete; set passwords and Cisco privilege; assign a group. Duplicate entries are treated as one logical user. |
| Clients | NAS/client CRUD, secret reset, enable/disable. Secrets are write-only. |
| Groups | `mods-config/files/groups` CRUD with per-group attributes. Membership is a `Group = name` line on the user. |
| Radius test | Send a real Access-Request via `radtest` and see the reply. The shared secret is resolved server-side from the chosen client. |
| Logging | `radius.log` plus a managed, reversible `linelog` configuration. Filter by result, user, NAS or time window; live tail over SSE. |
| Backups | Every mutation is snapshotted; one-click rollback re-validates before writing. History is append-only. |
| Audit | Who did what, from where, which backup, when. |
| Service | Status, `freeradius -XC` result, journal, restart/reload. |

## Design notes

- **The web app never writes `raddb` itself.** It talks to a small root-owned
  wrapper (`backend/wrappers/frw-write`) through a single sudoers entry that is
  bound to an explicit allow-list of paths. The web process itself runs
  unprivileged, under a systemd unit with `ProtectSystem=strict`.
- **Every mutation validates first.** `freeradius -XC` must pass and a backup
  must exist before a change is committed; a failure rolls the transaction back.
- **Comments and formatting survive edits.** Files are parsed and re-rendered
  rather than rewritten, so hand-written directives are not lost.
- **Passwords and client secrets are write-only.** They are never returned by the
  API; listings expose `has_password` / `has_secret` instead.
- **Groups are reported as unavailable when inert.** If the `files` module has no
  active `groupfile`, the UI says so rather than showing a count that has no
  effect on authentication.

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

It also enables group support: it inserts `groupfile = ${moddir}/groups` into
`mods-available/files` if absent and seeds an empty `mods-config/files/groups`
owned `root:freerad` mode 0640. Both steps are idempotent, so re-running is safe.

Then open `https://<host>/`.

## Roles

| Role | Read | Users / clients / groups | RADIUS test | Restart, reload, rollback |
|------|------|--------------------------|-------------|--------------------------|
| `viewer` | yes | no | no | no |
| `operator` | yes | yes | yes | no |
| `admin` | yes | yes | yes | yes |

Enforced server-side in `app/api/deps.py`; hiding a button in the UI is not the
control.

## Tests

```bash
cd backend && sudo -E env "PATH=$PATH" python -m pytest
cd frontend && npm ci && npm run typecheck && npm run build
```

407 tests. The backend suite must run as **root**: `tests/test_wrapper.py`
exercises the root-only writer wrapper. That is safe because
`tests/conftest.py` redirects every config path into a tmp sandbox and fails the
run if any path still resolves inside the live `raddb`.

The suite runs against captured copies of a real configuration rather than
idealised input, and covers the parsers' round-tripping, atomic writes, symlink
survival, rollback, the privileged helper's allow-list under adversarial input,
the linelog configuration checked by the real `freeradius` binary, and auth,
CSRF, RBAC and redaction.

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

## Troubleshooting

**The panel loads but a page is blank.** A page that throws during render takes
the whole React tree with it. Check the browser console first; the panel does not
have a per-page error boundary yet.

**`Port must be between 1 and 65535` from the radius test.** Should not happen: the
form sends no port, and `0` is the "let radtest choose" sentinel. If you see it,
you are running a backend older than the fix in `app/services/radius_test.py`.

**A saved change had no effect on authentication.** Check the groupfile state on
the Groups page. If the `files` module has no active `groupfile`, groups are
written but never read.

**`permission denied` when saving a change.** The privileged helper is missing or
the sudoers rule is wrong:

```bash
sudo -u freeradius-web sudo -n /usr/local/libexec/freeradius-web/frw-write --help
visudo -c
```

**A user vanished after an edit.** It was probably not deleted. Check the
disabled-entry marker and restore with `POST /api/backups/{id}/rollback`.