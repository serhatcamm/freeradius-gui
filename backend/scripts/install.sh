#!/usr/bin/env bash
#
# Install the FreeRADIUS web panel.
#
# Run as root on the FreeRADIUS host:
#     sudo ./scripts/install.sh
#
# The script is idempotent: re-running it upgrades the application code and
# reloads the service without touching the FreeRADIUS configuration.
#
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/freeradius-web/app}"
VENV_DIR="${VENV_DIR:-/opt/freeradius-web/venv}"
DATA_DIR="${DATA_DIR:-/var/lib/freeradius-web}"
STATIC_DIR="${STATIC_DIR:-/opt/freeradius-web/static}"
LOG_DIR="${LOG_DIR:-/var/log/freeradius}"
SERVICE_USER="${SERVICE_USER:-freeradius-web}"
WRAPPER_DIR=/usr/local/libexec/freeradius-web
RADDB=/etc/freeradius/3.0
ENV_DIR=/etc/freeradius-web
ENV_FILE="$ENV_DIR/app.env"

# Where the built single-page app is copied from. Overridable so the same script
# works when the frontend is built on a workstation and shipped with the bundle.
STATIC_SRC="${STATIC_SRC:-}"

# AD support is intentionally opt-in: installing Samba/winbind changes the
# host's authentication surface, even though it does not join a domain. The
# panel's Active Directory page still reports these packages as prerequisites
# when this is left disabled.
INSTALL_AD_DEPENDENCIES="${INSTALL_AD_DEPENDENCIES:-0}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root"

command -v python3 >/dev/null || die "python3 not found"
[[ -d $RADDB ]] || die "FreeRADIUS configuration not found at $RADDB"

# --------------------------------------------------------------- AD prerequisites
if [[ "$INSTALL_AD_DEPENDENCIES" == "1" ]]; then
    command -v apt-get >/dev/null || die "apt-get not found; install AD packages manually"
    log "Installing optional Active Directory prerequisites"
    apt-get update
    apt-get install -y freeradius-ldap samba-common-bin winbind
else
    log "Skipping optional AD packages (set INSTALL_AD_DEPENDENCIES=1 to install)"
fi

# ---------------------------------------------------------------- service user
log "Creating service account $SERVICE_USER"
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin \
            --comment "FreeRADIUS web panel" "$SERVICE_USER"
fi

install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$DATA_DIR" "$DATA_DIR/backups"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$DATA_DIR/ssl"
# FreeRADIUS logs are normally group-readable by the freerad group; let the
# panel read them without granting anything else.
if getent group freerad >/dev/null; then
    usermod -aG freerad "$SERVICE_USER"
fi

# The panel runs `freeradius -XC` itself, and the EAP module reads
# /etc/ssl/private/ssl-cert-snakeoil.key, which is root:ssl-cert 0640. Without
# ssl-cert group membership the parser cannot initialise rlm_eap_tls and
# validation reports the live configuration as broken, which then blocks every
# guarded write. freerad is already in ssl-cert; adding the panel is read-only
# on that one file and does not grant membership in freerad.
if getent group ssl-cert >/dev/null; then
    usermod -aG ssl-cert "$SERVICE_USER"
    log "  added $SERVICE_USER to ssl-cert so freeradius -XC can read the EAP key"
fi

# -------------------------------------------------------------------- groups
# FreeRADIUS ignores mods-config/files/groups unless the `files` module has an
# active `groupfile` directive. Debian ships that line commented out (or absent
# entirely), so without this the panel's Groups page would accept edits that
# never reach authentication - the worst kind of failure, because it looks like
# it worked. Wire it here, in the installer, rather than exposing module config
# to the web UI: the UI keeps a data-file-only blast radius.
#
# Both steps are idempotent so re-running the installer is safe.
log "Enabling RADIUS group support"
FILES_MODULE="$RADDB/mods-available/files"
GROUPS_FILE="$RADDB/mods-config/files/groups"

if [ ! -f "$FILES_MODULE" ]; then
    log "  WARNING: $FILES_MODULE not found; skipping groupfile wiring"
elif grep -Eq '^[[:space:]]*groupfile[[:space:]]*=' "$FILES_MODULE"; then
    log "  groupfile already enabled"
else
    # Remove any existing directive first (active or commented) and insert
    # exactly one. Delete-then-insert is idempotent by construction, so a
    # re-run cannot leave FreeRADIUS with two groupfile directives.
    sed -i '/^[[:space:]]*#\?[[:space:]]*groupfile[[:space:]]*=/d' "$FILES_MODULE"
    # Insert *after* the moddir assignment. FreeRADIUS expands ${moddir} while
    # parsing the section, so inserting before it could expand to empty and
    # silently point groupfile at /groups.
    sed -i '/^[[:space:]]*moddir[[:space:]]*=/a\\tgroupfile = ${moddir}/groups' "$FILES_MODULE"
    # Verify rather than assume.
    if [ "$(grep -cE '^[[:space:]]*groupfile[[:space:]]*=' "$FILES_MODULE")" = "1" ]; then
        log "  added 'groupfile = \${moddir}/groups' to the [files] module"
    else
        log "  WARNING: groupfile is not set up correctly in $FILES_MODULE"
        log "           expected exactly one 'groupfile = \${moddir}/groups' line"
    fi
fi

# The ntlm_auth module is shipped by FreeRADIUS but is not enabled by every
# distro package. Enabling its module definition is harmless before a domain
# join: it only runs when the AD block is explicitly enabled by the panel.
NTLM_AVAILABLE="$RADDB/mods-available/ntlm_auth"
NTLM_ENABLED="$RADDB/mods-enabled/ntlm_auth"
if [[ -f "$NTLM_AVAILABLE" && ! -e "$NTLM_ENABLED" ]]; then
    ln -s ../mods-available/ntlm_auth "$NTLM_ENABLED"
    log "  enabled FreeRADIUS ntlm_auth module"
fi

if [ ! -f "$GROUPS_FILE" ]; then
    cat > "$GROUPS_FILE" <<'GROUPS'
# RADIUS groups.
#
# One group per line: <name> followed by comma-separated attributes.
# "DEFAULT" applies to any request whose Group matches no entry above it.
#
# staff    Reply-Message = "welcome"
GROUPS
    # 0640 root:freerad, matching the other FreeRADIUS data files.
    chown root:freerad "$GROUPS_FILE" 2>/dev/null || chown root:root "$GROUPS_FILE"
    chmod 0640 "$GROUPS_FILE"
    log "  created $GROUPS_FILE"
else
    log "  $GROUPS_FILE already exists; left untouched"
fi

# ------------------------------------------------------------------ settings
# Single source of truth for both the service and the CLI.
#
# `sudo` resets the environment, so any FRW_* variable passed inline to a
# `sudo -u freeradius-web ... app.cli` call is silently discarded and the CLI
# falls back to its built-in defaults. That previously meant the CLI wrote
# administrators to a different database than the service read, and login then
# failed against a correct password. Settings therefore live in a file that
# pydantic reads directly, and the unit loads it via EnvironmentFile.
log "Writing $ENV_FILE"
install -d -o root -g "$SERVICE_USER" -m 0750 "$ENV_DIR"
cat > "$ENV_FILE" <<ENV
# Managed by freeradius-web/scripts/install.sh - edit there, not here.
FRW_DATABASE_URL=sqlite:///$DATA_DIR/panel.db
FRW_SECRET_KEY_FILE=$DATA_DIR/secret_key
FRW_BACKUP_DIR=$DATA_DIR/backups
FRW_DATA_DIR=$DATA_DIR
FRW_RADDB_DIR=$RADDB
FRW_LOG_DIR=$LOG_DIR
FRW_ENABLE_DOCS=false
FRW_COOKIE_SECURE=true
FRW_HOST=127.0.0.1
FRW_PORT=8080
ENV
chown root:"$SERVICE_USER" "$ENV_FILE"
chmod 0640 "$ENV_FILE"

# ------------------------------------------------------------------ venv/deps
log "Installing Python environment"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

# --------------------------------------------------------------------- wrapper
log "Installing privileged writer"
install -d -o root -g root -m 0755 "$WRAPPER_DIR"
install -o root -g root -m 0755 "$APP_DIR/wrappers/frw-write" "$WRAPPER_DIR/frw-write"

# ----------------------------------------------------------------- admin CLI
# `python -m app.cli` only works when the working directory is $APP_DIR, because
# that is how the package becomes importable. Printing a bare `-m app.cli`
# command therefore fails for anyone whose cwd is elsewhere ("No module named
# app"). Ship a wrapper that always chdir's first, so the documented command is
# correct regardless of where it is run.
log "Installing frw-admin wrapper"
cat > /usr/local/bin/frw-admin <<WRAPPER
#!/usr/bin/env bash
# Run the panel CLI as the service user, from any working directory.
set -euo pipefail
cd "$APP_DIR"
exec sudo -u "$SERVICE_USER" env PYTHONPATH="$APP_DIR" \\
    "$VENV_DIR/bin/python" -m app.cli "\$@"
WRAPPER
chmod 0755 /usr/local/bin/frw-admin

# The panel needs exactly two privileged actions: write a managed file, and
# restart/reload/inspect the FreeRADIUS service. Nothing else.
log "Installing sudoers rules"
cat > /etc/sudoers.d/freeradius-web <<'SUDOERS'
# Managed by freeradius-web/scripts/install.sh - do not edit by hand.
Defaults:freeradius-web !requiretty
Cmnd_Alias FRW_WRITE = /usr/local/libexec/freeradius-web/frw-write *
Cmnd_Alias FRW_RADIUS = /usr/bin/systemctl restart freeradius, \
                        /usr/bin/systemctl reload freeradius, \
                        /usr/bin/systemctl status freeradius, \
                        /usr/bin/systemctl is-active freeradius, \
                        /usr/bin/systemctl is-enabled freeradius, \
                        /usr/bin/systemctl show freeradius
freeradius-web ALL=(root) NOPASSWD: FRW_WRITE, FRW_RADIUS
SUDOERS
chmod 0440 /etc/sudoers.d/freeradius-web
visudo -cf /etc/sudoers.d/freeradius-web >/dev/null || die "sudoers syntax invalid"

# ---------------------------------------------------------------------- unit
log "Installing systemd unit"
install -o root -g root -m 0644 "$APP_DIR/deploy/freeradius-web.service" \
    /etc/systemd/system/freeradius-web.service
systemctl daemon-reload
systemctl enable freeradius-web.service >/dev/null 2>&1 || true

# ------------------------------------------------------------------- frontend
# The SPA is a plain static bundle; FastAPI serves it from $STATIC_DIR. Building
# it here is optional so the panel can be installed without Node.js present: a
# bundle built elsewhere can be supplied via STATIC_SRC, or one already in place
# is kept as-is.
#
# Resolution order:
#   1. STATIC_SRC, if it points at a directory
#   2. $APP_DIR/frontend/dist, building with npm when Node.js is available
#   3. an existing non-empty $STATIC_DIR, left untouched
resolve_frontend_src() {
    if [[ -n $STATIC_SRC && -d $STATIC_SRC ]]; then
        return 0
    fi

    if command -v npm >/dev/null && [[ -d $APP_DIR/frontend ]]; then
        log "Building frontend with npm"
        (cd "$APP_DIR/frontend" && npm ci >/dev/null 2>&1) ||
            (cd "$APP_DIR/frontend" && npm install >/dev/null)
        (cd "$APP_DIR/frontend" && npm run build >/dev/null)
        STATIC_SRC="$APP_DIR/frontend/dist"
    fi

    if [[ -n $STATIC_SRC && -d $STATIC_SRC ]]; then
        return 0
    fi

    # Nothing to build or copy: an already-installed bundle is acceptable.
    if [[ -d $STATIC_DIR ]] && [[ -n $(ls -A "$STATIC_DIR" 2>/dev/null) ]]; then
        log "No new bundle; keeping the existing one in $STATIC_DIR"
        return 1
    fi

    die "no frontend bundle: set STATIC_SRC to a built dist/ directory, install Node.js, or pre-populate $STATIC_DIR"
}

if resolve_frontend_src; then
    log "Installing static assets from $STATIC_SRC"
    # Stage into a sibling directory and swap, so a half-copied bundle is never
    # served and an existing deployment stays intact if the copy fails.
    stage="${STATIC_DIR}.new"
    old="${STATIC_DIR}.old"
    rm -rf "$stage" "$old"
    install -d -o root -g root -m 0755 "$stage"
    cp -a "$STATIC_SRC/." "$stage/"
    find "$stage" -type d -exec chmod 0755 {} +
    find "$stage" -type f -exec chmod 0644 {} +
    if [[ -d $STATIC_DIR ]]; then
        mv "$STATIC_DIR" "$old"
    fi
    mv "$stage" "$STATIC_DIR"
    rm -rf "$old"
fi

# --------------------------------------------------------------------- nginx
# The vhost references a certificate that has to exist before nginx will even
# start, so check first instead of leaving a broken symlink behind.
install_nginx() {
    command -v nginx >/dev/null || { log "nginx not installed; skipping reverse proxy"; return; }

    local crt=/etc/ssl/certs/freeradius-web.crt
    local key=/etc/ssl/private/freeradius-web.key
    if [[ ! -r $crt || ! -r $key ]]; then
        log "TLS certificate missing; skipping nginx setup"
        log "  expected: $crt and $key"
        log "  the panel is still reachable on http://127.0.0.1:8080/"
        log "  provision a certificate, then run: nginx -t && systemctl reload nginx"
        return
    fi

    log "Installing nginx site"
    install -o root -g root -m 0644 "$APP_DIR/deploy/nginx.conf" \
        /etc/nginx/sites-available/freeradius-web
    ln -sfn /etc/nginx/sites-available/freeradius-web \
            /etc/nginx/sites-enabled/freeradius-web

    # The panel vhost claims default_server, so Debian's stock site would make
    # nginx -t fail outright. Drop only that symlink; the file stays in
    # sites-available as a reference and can be re-enabled to undo this.
    local default_link=/etc/nginx/sites-enabled/default
    if [[ -L $default_link ]]; then
        log "Disabling nginx default site (file kept in sites-available/default)"
        rm -f "$default_link"
    fi

    nginx -t || die "nginx configuration is invalid"
    systemctl reload nginx || true
}

install_nginx

# --------------------------------------------------------------- first admin
log "Bootstrap"
if [[ ! -f $DATA_DIR/secret_key ]]; then
    "$VENV_DIR/bin/python" -c "import secrets,pathlib,os; \
p=pathlib.Path('$DATA_DIR/secret_key'); \
p.write_bytes(secrets.token_bytes(48)); os.chmod(p,0o600)"
fi
chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR/secret_key"

# FRW_SKIP_ADMIN=1 leaves the initial account for someone else to create. Used
# when the installer runs without a TTY (automation, remote exec), where the
# hidden prompt below cannot work and the password should not travel over the
# wire at all.
if [[ ${FRW_SKIP_ADMIN:-0} == 1 ]]; then
    log "Skipping admin bootstrap (FRW_SKIP_ADMIN=1)"
else
    if [[ -z ${FRW_ADMIN_PASSWORD:-} ]]; then
        if [[ ! -t 0 ]]; then
            die "no TTY for the admin password prompt. Either set FRW_ADMIN_PASSWORD, or set FRW_SKIP_ADMIN=1 and create the account yourself (see the command printed at the end)."
        fi
        read -rsp "Password for the initial 'admin' account: " FRW_ADMIN_PASSWORD; echo
    fi
    FRW_ADMIN_PASSWORD="$FRW_ADMIN_PASSWORD" "$VENV_DIR/bin/python" -m app.cli \
        create-admin "${FRW_ADMIN_USER:-admin}" --password "$FRW_ADMIN_PASSWORD" --force
fi

# ---------------------------------------------------------------------- start
log "Starting service"
systemctl restart freeradius-web.service
sleep 2
systemctl --no-pager --full status freeradius-web.service | head -20 || true

log "Done. The panel listens on 127.0.0.1:8080."
if [[ ${FRW_SKIP_ADMIN:-0} == 1 ]]; then
    log ""
    log "No admin account exists yet. Run this yourself (it prompts without echo):"
    log "  frw-admin create-admin admin"
fi
log ""
log "Manage accounts with: frw-admin <command>   (try: frw-admin --help)"
