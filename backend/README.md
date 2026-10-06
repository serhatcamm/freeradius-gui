# FreeRADIUS Web Management Panel

A web front end for FreeRADIUS 3 that edits the real configuration files
safely: every change is backed up, validated with `freeradius -XC`, applied
atomically, and recorded in an audit log with a one-click rollback.

The design goal is that the panel can never leave FreeRADIUS in a state the
operator did not intend, and can never lose configuration it did not
understand.

---

## Contents

- [How a change is applied](#how-a-change-is-applied)
- [Installation](#installation)
- [Unprivileged operation](#unprivileged-operation)
- [Roles](#roles)
- [Configuration](#configuration)
- [API reference](#api-reference)
- [Command line](#command-line)
- [Backups and rollback](#backups-and-rollback)
- [Request logging](#request-logging)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

---

## How a change is applied

Every mutation - a user password, a client secret, a request-logging toggle -
goes through the same sequence, defined once in `app/services/config_tx.py`:

1. **Read** the current file bytes.
2. **Parse and edit** it. The parsers round-trip: comments, ordering,
   indentation and anything the panel does not model are preserved verbatim.
3. **Back up** the original into an immutable, content-addressed snapshot.
4. **Validate** the *candidate* content by running the real binary against a
   temporary copy of the configuration tree:
   `freeradius -XC`.
5. **Write** the new content atomically (temp file in the same directory,
   `fsync`, `rename`, `fsync` of the directory).
6. **Audit** who did what, from where, with which backup id.

If validation fails the file is never touched. If the write fails the backup
is still available and the previous content is restored.

Two details worth knowing:

- `/etc/freeradius/3.0/users` is a **symlink** into
  `mods-config/files/authorize`. The writer resolves the link and writes
  through it, so the symlink survives and the real file is what changes.
- Duplicate entries (the same username more than once) are treated as one
  logical user. Password and delete operations affect every copy, so an
  operator cannot be surprised by a shadowed earlier entry.
- Some changes span more than one file. Enabling request logging edits both
  `mods-available/linelog` and `sites-available/default`, so those steps run
  through `ConfigTransaction.apply_group`, which treats them as one logical
  change: if either file fails, both are restored, and the response reports
  `rolled_back`. Without that, a failure on the second file would leave the
  feature half installed.

## Installation

On the FreeRADIUS host, as root:

```bash
cd /opt/freeradius-web/app
sudo ./scripts/install.sh
```

The script is idempotent. It will:

- create the `freeradius-web` system account,
- build the virtualenv in `/opt/freeradius-web/venv`,
- install the privileged writer to
  `/usr/local/libexec/freeradius-web/frw-write`,
- install `/etc/sudoers.d/freeradius-web` (validated with `visudo -c`),
- install and enable `freeradius-web.service`,
- install the built frontend into `/opt/freeradius-web/static`,
- install and enable the nginx site (skipped with a warning if the TLS
  certificate is absent),
- bootstrap the first administrator (prompted for a password),
- generate `/var/lib/freeradius-web/secret_key` if absent.

### Frontend

The single-page app is a static bundle that FastAPI serves from
`/opt/freeradius-web/static`. The installer resolves it in this order:

1. `$STATIC_SRC`, if it points at a directory,
2. `$APP_DIR/frontend/dist`, building it with npm when Node.js is present,
3. an existing non-empty `/opt/freeradius-web/static`, which is left alone.

So a bundle built on a workstation can be shipped with the release and
installed on a host without Node.js:

```bash
STATIC_SRC=/tmp/bundle ./scripts/install.sh
```

Assets are copied into a staging directory and swapped into place, so a failed
copy never leaves a half-served bundle and stale hashed assets do not pile up.

### TLS

`deploy/nginx.conf` references
`/etc/ssl/certs/freeradius-web.crt` and
`/etc/ssl/private/freeradius-web.key`. If either is missing the installer skips
the nginx site and leaves the panel reachable on `http://127.0.0.1:8080/`
rather than installing a vhost that would fail `nginx -t`. Put the real
certificate there (for example from certbot) and re-run the installer to enable
the site.

The app binds to `127.0.0.1:8080` only, so it is unreachable from anywhere else
without the reverse proxy.

To pin the accounts yourself:

```bash
FRW_ADMIN_USER=netops FRW_ADMIN_PASSWORD='...' ./scripts/install.sh
```

### TLS

`deploy/nginx.conf` references
`/etc/ssl/certs/freeradius-web.crt` and
`/etc/ssl/private/freeradius-web.key`. Put your real certificate there (for
example from certbot) before enabling the site. If it is absent the installer
skips nginx and leaves the panel on `http://127.0.0.1:8080/`; re-run it after
provisioning the certificate.

The app binds to `127.0.0.1:8080` only, so it is unreachable without the
reverse proxy.

## Unprivileged operation

The service runs as `freeradius-web`, not root. It cannot write
`/etc/freeradius`. Two narrowly scoped sudo rules are used instead:

```
Cmnd_Alias FRW_WRITE  = /usr/local/libexec/freeradius-web/frw-write *
Cmnd_Alias FRW_RADIUS = /usr/bin/systemctl restart freeradius, \
                       /usr/bin/systemctl reload freeradius, \
                       /usr/bin/systemctl status freeradius, \
                       /usr/bin/systemctl is-active freeradius, \
                       /usr/bin/systemctl is-enabled freeradius, \
                       /usr/bin/systemctl show freeradius
freeradius-web ALL=(root) NOPASSWD: FRW_WRITE, FRW_RADIUS
```

`frw-write` accepts exactly two arguments - an absolute path and an optional
octal mode - and reads the new content from stdin. It resolves the path
(through symlinks) and refuses anything outside a hard-coded allow-list:

```
/etc/freeradius/3.0/mods-config/files/authorize
/etc/freeradius/3.0/clients.conf
/etc/freeradius/3.0/sites-available/default
/etc/freeradius/3.0/mods-available/linelog
```

Relative paths, `..` traversal, symlinks that resolve outside the list, and
modes with any bit outside `rwx` are all rejected. See
`tests/test_wrapper.py` for the adversarial coverage.

The systemd unit sets `ProtectSystem=strict`, `PrivateTmp`, `PrivateDevices`,
`ProtectHome`, `ProtectKernelTunables`, `ProtectKernelModules`,
`ProtectControlGroups`, `RestrictSUIDSGID`, `RestrictRealtime` and
`LockPersonality`.

`ReadWritePaths` covers the panel's data directory plus the four directories
holding the allow-listed targets, because the atomic replace needs to create a
temp file and rename it *within* the directory:

```
ReadWritePaths=/var/lib/freeradius-web
ReadWritePaths=/etc/freeradius/3.0
ReadWritePaths=/etc/freeradius/3.0/mods-available
ReadWritePaths=/etc/freeradius/3.0/mods-config/files
ReadWritePaths=/etc/freeradius/3.0/sites-available
```

`NoNewPrivileges` is deliberately **not** set. Elevation relies on sudo being
setuid root, and that flag makes sudo refuse outright
(`sudo: The "no new privileges" flag is set, which prevents sudo from running
as root`). Widening `ReadWritePaths` does not give the service account write
access to the configuration: `/etc/freeradius/3.0` is `freerad:freerad` mode
`0755` with `0640` files, so an unprivileged write there still fails on ordinary
permission checks.

## Roles

| Role | Read | Users / clients | RADIUS test | Restart, reload, rollback |
|------|------|-----------------|-------------|--------------------------|
| `viewer` | yes | no | no | no |
| `operator` | yes | yes | yes | no |
| `admin` | yes | yes | yes | yes |

Enforced server-side in `app/api/deps.py`; hiding a button in the UI is not
the control.

## Configuration

All settings are environment variables, so nothing sensitive lives in the
code. Defaults are shown.

| Variable | Default | Purpose |
|----------|---------|---------|
| `FRW_DATABASE_URL` | `sqlite:////var/lib/freeradius-web/panel.db` | Panel database. Set only the panel, never FreeRADIUS. |
| `FRW_SECRET_KEY_FILE` | `/var/lib/freeradius-web/secret_key` | Cookie signing key; generated on first run, mode 0600. |
| `FRW_RADDB_DIR` | `/etc/freeradius/3.0` | Configuration root. |
| `FRW_USERS_FILE` | `$RADDB/users` | User file (usually a symlink). |
| `FRW_CLIENTS_FILE` | `$RADDB/clients.conf` | NAS/client definitions. |
| `FRW_BACKUP_DIR` | `/var/lib/freeradius-web/backups` | Backup store. |
| `FRW_LOG_DIR` | `/var/log/freeradius` | Where `radius.log` and `linelog` live. |
| `FRW_ENABLE_DOCS` | `false` | Serve `/docs`. Leave off in production. |
| `FRW_COOKIE_SECURE` | `true` | Set `false` only for plain-HTTP trials. |
| `FRW_LOGIN_MAX_ATTEMPTS` | `5` | Failures before lockout. |
| `FRW_LOGIN_ATTEMPT_WINDOW_SECONDS` | `300` | Window those failures are counted in. |
| `FRW_SESSION_TTL_SECONDS` | `3600` | Absolute session lifetime. |
| `FRW_SESSION_IDLE_TIMEOUT_SECONDS` | `900` | Idle timeout. |
| `FRW_COOKIE_SAMESITE` | `lax` | `lax`, `strict` or `none`. |

## API reference

Authentication is a session cookie; unsafe methods additionally require the
`X-CSRF-Token` header to match the `frw_csrf` cookie.

| Method | Path | Role | Purpose |
|--------|------|------|---------|
| `GET` | `/api/health` | public | Liveness. |
| `POST` | `/api/auth/login` | public | Start a session. |
| `POST` | `/api/auth/logout` | any | End the session. |
| `GET` | `/api/auth/me` | any | Current account. |
| `POST` | `/api/auth/change-password` | any | Change own password. |
| `GET` | `/api/dashboard` | any | Counts and service state. |
| `GET` | `/api/users`, `/api/users/{name}` | any | List / inspect. |
| `POST` `PATCH` `DELETE` `/api/users[/{name}]` | | operator | Create, edit, delete. |
| `POST` | `/api/users/{name}/enable`, `/disable` | operator | Toggle. |
| `POST` | `/api/users/{name}/password` | operator | Set password. |
| `GET` `POST` `PATCH` `DELETE` `/api/clients[/{name}]` | | operator | Client CRUD. |
| `POST` | `/api/clients/{name}/reset-secret` | operator | Generate a secret. |
| `POST` | `/api/clients/{name}/enable`, `/disable` | operator | Toggle. |
| `GET` | `/api/logs` | any | Filtered events (result, user, NAS, hours). |
| `GET` | `/api/logs/stream` | any | Server-sent events, live tail. |
| `GET` | `/api/logs/capability` | any | Whether request logging is available. |
| `POST` | `/api/logs/enable-request-logging`, `/disable-...` | operator | Install / remove the managed linelog configuration. |
| `POST` | `/api/radius/test` | operator | `radtest` against live credentials. |
| `GET` | `/api/service`, `/api/service/validate`, `/api/service/log` | any | State, `freeradius -XC` result, recent journal. |
| `POST` | `/api/service/restart`, `/api/service/reload` | admin | Change service state. |
| `GET` | `/api/backups`, `/api/backups/{id}` | any | History. |
| `POST` | `/api/backups/{id}/rollback` | admin | Restore a snapshot. |
| `GET` | `/api/audit` | any | Audit trail. |
| `GET` | `/api/settings` | any | Effective configuration and capabilities. |

Passwords and client secrets are never returned by the API. A user listing
returns `has_password`, never the hash; a client listing returns
`has_secret`, never the value.

## Command line

Useful when the panel is down:

```bash
python -m app.cli create-admin <username> [--password ...] [--force]
python -m app.cli set-password <username>
python -m app.cli list-admins
python -m app.cli validate              # run freeradius -XC
python -m app.cli show-users
python -m app.cli show-clients
python -m app.cli generate-secret
```

## Backups and rollback

Each mutation stores the previous bytes with a SHA-256 id, the label, the
operation, the operator, the source IP and a timestamp. Backups are
immutable; rollback creates a *new* backup rather than deleting anything, so
the history is append-only and you can roll back a rollback.

The restore path re-validates with `freeradius -XC` before writing, so a bad
snapshot is refused rather than installed.

## Request logging

`radius.log` does not reliably carry one line per authentication request, so
the panel can install a managed `linelog` configuration:

- a bare `linelog` invocation at the top of the `authenticate` section of
  `sites-available/default` (unlang invokes a module by name - a
  `linelog { ... }` sub-section here is a parse error), and
- `auth_goodpass` / `auth_badpass` in the first `linelog` instance of
  `mods-available/linelog`.

The change is reversible from Backup History and the enable/disable round
trip is byte-exact: nothing outside the managed block is touched. Reload
FreeRADIUS for it to take effect.

Both files are then read by the log viewer, along with `radius.log`.
Timestamps in `radius.log` have no timezone, so they are interpreted in the
server's local zone.

## Testing

```bash
cd /opt/freeradius-web/app
/opt/freeradius-web/venv/bin/python -m pytest
```

The suite runs against **captured copies of the real configuration** from the
target host (`tests/fixtures/`), not idealised input, and includes:

- `test_parsers.py` - round-tripping the real users and clients files,
  including disabled-entry markers.
- `test_transactions.py` - atomic writes, symlink survival, backups,
  validation failure leaving files untouched, rollback.
- `test_wrapper.py` - adversarial tests of the privileged helper's allow-list.
- `test_runner.py` - the command allow-list and privilege elevation.
- `test_logging_config.py` - the linelog configuration validated by the real
  `freeradius` binary on a copied tree.
- `test_api.py`, `test_api_logging.py` - auth, CSRF, RBAC, redaction.
- `test_security.py` - password hashing and secret alphabet invariants.

## Troubleshooting

**`permission denied` when saving a change**
The privileged helper is missing or the sudoers rule is wrong. Check:

```bash
sudo -u freeradius-web sudo -n /usr/local/libexec/freeradius-web/frw-write --help
visudo -c
```

**Validation fails but the config looks fine**
`freeradius -XC` is strict. Run it by hand against the reported content and
read the full output - the panel shows the last lines of the real error.

**`no ^authenticate\s*\{ section found`**
The site file was customised. The managed block must be inserted into the
`authenticate` section; the panel refuses to guess rather than write
somewhere wrong.

**The log view shows no Access-Accept/Reject**
Request logging is off, or FreeRADIUS has not been reloaded. Check
`GET /api/logs/capability` and the `linelog` file's mtime.

**A user vanished after an edit**
It was not deleted - check the disabled-entry marker, and restore with
`POST /api/backups/{id}/rollback`.