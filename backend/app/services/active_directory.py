"""Active Directory authentication for RADIUS users.

Two distinct mechanisms are wired up here, and keeping them separate is the
whole point:

* **Password verification** - ``ntlm_auth``, backed by Samba/winbind. Windows
  does not authenticate plain passwords over LDAP: a user bind sends the
  password in the clear, and NTLM hashes it. NTLM cannot be performed by a
  stock LDAP library at all, because the machine needs a Kerberos service
  ticket and a machine account in the domain before it can use it. winbind
  already has both, so the panel delegates MSCHAPv1 and PAP to it. No user
  password is ever written to a FreeRADIUS config file or sent to an LDAP
  server by this panel.
* **Attribute and group lookup** - ``rlm_ldap``, using a dedicated service
  account that only reads directory objects. This supplies the user's AD
  groups, which the ``post-auth`` section turns into the same ``Group``
  attribute the panel's own groups file uses, so an AD user's entitlements are
  defined in one place.

Both halves are managed as FreeRADIUS configuration through
:class:`~app.services.config_tx.ConfigTransaction`, so enabling AD is backed
up, validated with ``freeradius -XC``, and rolled back as a unit if any part
fails. This is deliberately not exposed for arbitrary LDAP config editing -
the panel writes a known-good block, so its blast radius stays limited to the
AD connection it manages.

Nothing in this module connects to a domain. :func:`probe` reports the local
prerequisites (whether winbind is joined, whether the modules exist) so an
operator can see what is missing before enabling.
"""
from __future__ import annotations

import logging
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from ..freeradius import paths
from .config_tx import ConfigTransaction

logger = logging.getLogger(__name__)

_LDAP_BEGIN = "# >>> freeradius-web active directory >>>"
_LDAP_END = "# <<< freeradius-web active directory <<<"

_AUTHZ_BEGIN = "# >>> freeradius-web active directory authorize >>>"
_AUTHZ_END = "# <<< freeradius-web active directory authorize <<<"

_AUTH_BEGIN = "# >>> freeradius-web active directory authenticate >>>"
_AUTH_END = "# <<< freeradius-web active directory authenticate <<<"

_POSTAUTH_BEGIN = "# >>> freeradius-web active directory post-auth >>>"
_POSTAUTH_END = "# <<< freeradius-web active directory post-auth <<<"

#: Attribute AD uses for a user's group membership.
DEFAULT_MEMBERSHIP_ATTRIBUTE = "memberOf"

#: AD returns many ``memberOf`` values in one attribute, semicolon-separated.
DEFAULT_MEMBERSHIP_DELIMITER = ";"

_BIND_PASSWORD_MIN_LENGTH = 12

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
_ATTR_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
_DN_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]*=[^,]+$")
_GROUP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class AdConfigError(ValueError):
    """The submitted AD settings cannot be used as given."""


def is_dn(value: str) -> bool:
    """Whether ``value`` looks like an LDAP distinguished name."""
    parts = [p.strip() for p in value.split(",") if p.strip()]
    # Two components minimum: dc=corp alone is a base DN but cannot be a user,
    # group or bind DN, and accepting it produces a confusing LDAP error later.
    return len(parts) >= 2 and all(_DN_COMPONENT_RE.match(p) for p in parts)


@dataclass
class AdSettings:
    """The AD connection the panel manages.

    ``bind_password`` is never returned by the API - only a boolean saying
    whether one is stored. AD account passwords cannot be read back, and
    neither can this one.
    """

    domain: str
    base_dn: str
    bind_dn: str
    servers: list[str]
    port: int = 389
    use_ldaps: bool = False
    start_tls: bool = True
    tls_ca: str | None = None
    membership_attribute: str = DEFAULT_MEMBERSHIP_ATTRIBUTE
    membership_delimiter: str = DEFAULT_MEMBERSHIP_DELIMITER
    #: AD group DN -> RADIUS group name.
    group_map: dict[str, str] = field(default_factory=dict)
    bind_password: str | None = None

    def validate(self) -> None:
        """Raise :class:`AdConfigError` if these settings are unusable."""
        if not self.domain.strip():
            raise AdConfigError("A domain name is required, e.g. corp.example.com.")
        if not self.base_dn.strip():
            raise AdConfigError("A base DN is required, e.g. dc=corp,dc=example,dc=com.")
        if not is_dn(self.base_dn.strip()):
            raise AdConfigError(f"Base DN does not look like a DN: {self.base_dn!r}")
        if not self.bind_dn.strip():
            raise AdConfigError("A bind DN is required for group lookups.")
        if not is_dn(self.bind_dn.strip()):
            raise AdConfigError(f"Bind DN does not look like a DN: {self.bind_dn!r}")
        if not self.servers:
            raise AdConfigError("At least one domain controller is required.")

        for server in self.servers:
            host = server.strip()
            if not host:
                raise AdConfigError("A domain controller entry is empty.")
            if "://" in host or "/" in host:
                raise AdConfigError(
                    f"{host!r} must be a bare hostname or IP address; the scheme "
                    "belongs in the LDAPS/StartTLS setting."
                )
            if not _HOSTNAME_RE.match(host):
                raise AdConfigError(f"{host!r} is not a valid hostname or IP address.")

        if not 1 <= self.port <= 65535:
            raise AdConfigError(f"Port {self.port} is out of range.")

        # Either StartTLS or LDAPS protects the bind. AD also refuses a plain
        # LDAP bind on a domain controller by default, so this is not merely a
        # preference: without it the connection will not work at all.
        if not self.use_ldaps and not self.start_tls:
            raise AdConfigError(
                "Enable either LDAPS or StartTLS. A plain LDAP bind is refused "
                "by a domain controller by default, and where it is allowed it "
                "would send the bind password unencrypted."
            )
        if self.use_ldaps and self.start_tls:
            raise AdConfigError(
                "LDAPS already encrypts the connection; enabling StartTLS as well "
                "would attempt to negotiate TLS inside TLS."
            )
        if self.use_ldaps and self.port != 636:
            logger.warning("LDAPS on port %s: the usual port is 636", self.port)
        if not self.use_ldaps and self.port in (636, 3269):
            raise AdConfigError(
                f"Port {self.port} is not used for a plain LDAP bind "
                "(636 is LDAPS, 3269 is Global Catalog)."
            )

        if self.bind_password is not None and len(self.bind_password) < _BIND_PASSWORD_MIN_LENGTH:
            raise AdConfigError(
                f"The bind password must be at least {_BIND_PASSWORD_MIN_LENGTH} characters."
            )

        if not _ATTR_RE.match(self.membership_attribute):
            raise AdConfigError(
                f"{self.membership_attribute!r} is not a valid LDAP attribute name."
            )

        for ad_dn, radius_group in self.group_map.items():
            if not is_dn(ad_dn.strip()):
                raise AdConfigError(f"AD group is not a DN: {ad_dn!r}")
            if not _GROUP_NAME_RE.match(radius_group):
                raise AdConfigError(f"RADIUS group {radius_group!r} is not a valid group name.")


@dataclass
class Prerequisite:
    """One local thing that must be present for AD auth to work."""

    name: str
    ok: bool
    detail: str


@dataclass
class Status:
    """Whether AD is configured, plus everything still missing."""

    configured: bool
    ldap_module_installed: bool
    ldap_block_installed: bool
    ntlm_auth_available: bool
    winbind_installed: bool
    winbind_joined: bool
    prerequisites: list[Prerequisite]
    domain: str | None = None
    base_dn: str | None = None
    bind_dn: str | None = None
    servers: list[str] = field(default_factory=list)
    port: int = 389
    group_map: dict[str, str] = field(default_factory=dict)
    bind_password_set: bool = False
    use_ldaps: bool = False
    start_tls: bool = True
    tls_ca: str | None = None
    membership_attribute: str = DEFAULT_MEMBERSHIP_ATTRIBUTE
    membership_delimiter: str = DEFAULT_MEMBERSHIP_DELIMITER
    enabled: bool = False

    @property
    def ready(self) -> bool:
        """True when enabling AD would work without further changes."""
        return self.configured and all(p.ok for p in self.prerequisites)

    @property
    def blocked_by(self) -> list[str]:
        """Names of the prerequisites that are not satisfied."""
        return [p.name for p in self.prerequisites if not p.ok]


def _quote(value: str) -> str:
    """Single-quote a value for a FreeRADIUS string literal."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _module_path(name: str) -> Path:
    return paths.MODS_AVAILABLE / name


def ldap_module_exists() -> bool:
    """Whether rlm_ldap is installed on this host."""
    return _module_path("ldap").exists()


def ntlm_auth_available() -> bool:
    """Whether the ntlm_auth module exists and is enabled."""
    if not _module_path("ntlm_auth").exists():
        return False
    enabled = paths.MODS_ENABLED
    if not enabled.exists():
        return False
    return (enabled / "ntlm_auth").exists()


def winbind_installed() -> bool:
    """Whether the winbind binary is present."""
    return shutil.which("winbindd") is not None


def winbind_joined() -> bool:
    """Whether this machine holds a domain machine account.

    NTLM needs a machine account: winbind must have joined the domain, which
    creates the same domain trust a Windows host creates. Without it every
    authentication attempt fails with an error that looks like a wrong
    password, so it is reported as its own prerequisite.
    """
    if not winbind_installed():
        return False
    return Path("/var/lib/samba/private/secrets.tdb").exists()


def probe() -> list[Prerequisite]:
    """Report each local prerequisite for AD authentication."""
    ldap_ok = ldap_module_exists()
    ntlm_ok = ntlm_auth_available()
    wb_ok = winbind_installed()
    joined = winbind_joined()
    return [
        Prerequisite(
            "freeradius-ldap",
            ldap_ok,
            "rlm_ldap is installed" if ldap_ok else "Install the freeradius-ldap package.",
        ),
        Prerequisite(
            "ntlm_auth module",
            ntlm_ok,
            "ntlm_auth is installed and enabled"
            if ntlm_ok
            else "Enable ntlm_auth in mods-enabled; MSCHAPv1 and PAP cannot be verified without it.",
        ),
        Prerequisite(
            "winbind",
            wb_ok,
            "winbindd is present"
            if wb_ok
            else "Install samba/winbind. FreeRADIUS cannot verify AD passwords without it.",
        ),
        Prerequisite(
            "domain membership",
            joined,
            "The machine account is joined"
            if joined
            else "Run 'net ads join -U <administrator>' to join the domain.",
        ),
    ]


def ldap_block_installed() -> bool:
    module = _module_path("ldap")
    return module.exists() and _LDAP_BEGIN in module.read_text("utf-8", "replace")


def _child_container(base_dn: str, child: str) -> str:
    """Prepend a container to the domain base DN, e.g. ``CN=Users,dc=corp,...``.

    rlm_ldap needs an explicit search base. Deriving it from the domain root
    rather than hard-coding ``CN=Users``/``OU=Groups`` is not a guess either way:
    those names are conventions and are renamed in real domains, so the
    operator has to be able to point the search wherever their directory
    actually keeps user objects.
    """
    parts = [p.strip() for p in base_dn.split(",") if p.strip()]
    return ",".join([child, *parts])


def install_ldap_block(settings: AdSettings, current: str) -> str:
    """Return ``mods-available/ldap`` with the managed AD block installed.

    Replaces the whole managed block rather than editing individual directives:
    the panel owns the settings inside it, so a leftover ``base_dn`` or
    ``group`` filter from an older domain is worse than rewriting it.
    """
    if not settings.bind_password:
        # Refuse rather than write a module with an empty bind password, which
        # would fail every lookup at runtime and look like a network problem.
        raise AdConfigError("A bind password is required.")

    text = strip_ldap_block(current)
    if not text.endswith("\n"):
        text += "\n"

    server_list = ", ".join(f'"{s.strip()}"' for s in settings.servers)
    membership = settings.membership_attribute

    block = f"""{_LDAP_BEGIN}
# Added by the FreeRADIUS Web Management Panel.
# This block reads directory data only. AD user passwords are verified by
# ntlm_auth (Samba/winbind), never here - a bind as the user would send the
# password in the clear.
#
# Manage this through the panel's Active Directory page rather than editing
# this file by hand: the panel rewrites everything between the markers.
ldap_ad {{
server = {server_list.split(',')[0]}
port = {settings.port}
identity = {_quote(settings.bind_dn.strip())}
password = {_quote(settings.bind_password)}
base_dn = {_quote(settings.base_dn.strip())}
user_dn = "AD-LDAP-UserDn"

ldap_version = 3
timeout = 5

#
# TLS. A domain controller refuses an unencrypted bind, and the bind DN
# password must not cross the network in the clear. require_cert and
# verify_hostname stay on so a rogue DC cannot silently take the bind.
#
tls {{
	start_tls = {"yes" if settings.start_tls else "no"}
	ca_file = {_quote(settings.tls_ca) if settings.tls_ca else "${certsdir}"}
	ca_dir = {_quote(str(Path(settings.tls_ca).parent)) if settings.tls_ca else "${certsdir}"}
	require_cert = "yes"
	verify_hostname = "yes"
}}

#
# User lookup. sAMAccountName is the AD sAMAccountName attribute, which is
# what Netlogon domain logins use; uid is the generic LDAP attribute and many
# AD directories leave it empty.
#
user {{
	base_dn = "${{..base_dn}}"
	filter = "(&(objectClass=user)(sAMAccountName=%{{%{{Stripped-User-Name}}:-%{{User-Name}}}}))"
}}

#
# Group membership. The ldap_ad instance exposes its standard group comparison
# to the post-auth mapping below.
#
group {{
	base_dn = "${{..base_dn}}"
	filter = "(objectClass=group)"
	name_attribute = "cn"
	membership_filter = "(member=%{{control:${{..user_dn}}}})"
}}

#
# AD returns every memberOf value in one attribute, semicolon-separated;
# rlm_ldap wants a list.
#
options {{
	user_object_class = "user"
}}
}}
{_LDAP_END}"""

    # Exactly the separators :func:`strip_ldap_block` removes: one newline
    # before the block and one after it. Any other arrangement makes install
    # and strip asymmetric, so a save/strip cycle cannot restore the original.
    return text + "\n" + block + "\n"


def strip_ldap_block(current: str) -> str:
    """Remove the managed AD block, leaving the shipped module untouched."""
    pattern = re.compile(
        rf"\n?{re.escape(_LDAP_BEGIN)}.*?{re.escape(_LDAP_END)}\n", re.DOTALL
    )
    return pattern.sub("", current)


def install_authorize_block(current: str) -> str:
    """Add the AD module references to the ``authorize`` section.

    The distro ``ldap`` instance is left untouched. AD uses a separate
    ``ldap_ad`` instance so enabling this feature cannot change an unrelated
    LDAP setup.

    The insertion is confined to the ``authorize`` section.
    """
    text = _remove_block(current, _AUTHZ_BEGIN, _AUTHZ_END)
    block = f"""{_AUTHZ_BEGIN}
	#
	# Added by the FreeRADIUS Web Management Panel.
	# ldap_ad reads the user's AD record and group membership. Password
	# verification is wired separately in authenticate via ntlm_auth.
	#
	ldap_ad
    {_AUTHZ_END}"""
    text = _insert_at_section_top(text, r"^authorize\s*\{", block)
    return text


def strip_authorize_block(current: str) -> str:
    """Undo :func:`install_authorize_block`."""
    return _remove_block(current, _AUTHZ_BEGIN, _AUTHZ_END)


def install_authenticate_block(current: str) -> str:
    """Make PAP and MS-CHAP use the existing ``ntlm_auth`` exec instance."""
    if _AUTH_BEGIN in current:
        return current
    text = current
    for auth_type in ("PAP", "MS-CHAP"):
        text = _remove_block(
            text,
            f"{_AUTH_BEGIN} {auth_type}",
            f"{_AUTH_END} {auth_type}",
        )
    start, end = _section_bounds(text, r"^authenticate\s*\{")
    body = text[start:end]
    for auth_type, old_module in (("PAP", "pap"), ("MS-CHAP", "mschap")):
        header = body.find(f"Auth-Type {auth_type} {{")
        if header < 0:
            raise AdConfigError(
                f"No Auth-Type {auth_type} handler found in authenticate; "
                "refusing to enable AD on a customised site definition."
            )
        close = body.find("}", header)
        if close < 0:
            raise AdConfigError(f"Auth-Type {auth_type} has no closing brace.")
        section = body[header:close]
        line_start = None
        line_end = None
        cursor = 0
        for line in section.splitlines(keepends=True):
            if line.strip() == old_module:
                line_start = header + cursor
                line_end = line_start + len(line)
                break
            cursor += len(line)
        if line_start is None or line_end is None:
            raise AdConfigError(
                f"No {old_module} handler found in Auth-Type {auth_type}; "
                "refusing to edit a customised site definition."
            )
        original_line = body[line_start:line_end]
        indent = original_line[: len(original_line) - len(original_line.lstrip())]
        marker = (
            f"{_AUTH_BEGIN} {auth_type}\n"
            f"{indent}ntlm_auth\n"
            f"{_AUTH_END} {auth_type}\n"
        )
        body = body[:line_start] + indent + marker + body[line_end:]
    return text[:start] + body + text[end:]


def strip_authenticate_block(current: str) -> str:
    """Restore the shipped PAP/MS-CHAP handlers."""
    text = current
    for auth_type, old_module in (("PAP", "pap"), ("MS-CHAP", "mschap")):
        marker = re.compile(
            rf"{re.escape(_AUTH_BEGIN)} {auth_type}\n\s*ntlm_auth\n"
            rf"{re.escape(_AUTH_END)} {auth_type}",
            re.MULTILINE,
        )
        text = marker.sub(old_module, text)
    return text


def install_postauth_block(settings: AdSettings, current: str) -> str:
    """Map AD group membership onto RADIUS groups in ``post-auth``.

    rlm_ldap registers an instance-scoped ``ldap_ad:group`` comparison. Each
    comparison asks the module whether the authenticated user's DN is a member
    of that AD group, which connects an AD group to the same ``Group``
    attribute the panel's own groups file consumes.
    """
    text = _remove_block(current, _POSTAUTH_BEGIN, _POSTAUTH_END)
    if not settings.group_map:
        return text

    lines = []
    for ad_dn, radius_group in sorted(settings.group_map.items(), key=lambda kv: kv[1]):
        # The module comparison performs the LDAP membership lookup. Do not
        # compare a raw control attribute: the instance-scoped pair attribute
        # is only populated when the module's group check runs.
        lines.append(
            f"\tif (ldap_ad:group == {_quote(ad_dn)}) {{\n"
            "\t\tupdate control {\n"
            f"\t\t\t&Group += {_quote(radius_group)}\n"
            "\t\t}\n"
            "\t}"
        )
    body = "\n".join(lines)

    block = f"""{_POSTAUTH_BEGIN}
	#
	# Added by the FreeRADIUS Web Management Panel.
	# AD group membership becomes RADIUS group membership, so what an AD user
	# is entitled to is defined by the groups file entries they land in.
	#
{body}
{_POSTAUTH_END}"""
    return _insert_at_section_bottom(text, r"^post-auth\s*\{", block)


def strip_postauth_block(current: str) -> str:
    """Undo :func:`install_postauth_block` exactly."""
    return _remove_block(current, _POSTAUTH_BEGIN, _POSTAUTH_END)


def _remove_block(text: str, begin: str, end: str) -> str:
    """Remove a managed block together with the newlines introduced with it.

    Must stay exactly symmetric with the insertion helpers. A leading ``\\n?``
    plus a *mandatory* trailing ``\\n`` mirrors ``"\\n" + block + "\\n"``, so
    removing what was inserted restores the surrounding bytes byte-for-byte and
    repeated install/strip cycles are stable. Making the trailing newline
    optional instead would let strip consume the file's own line break, which
    is how the marker ends up glued to the following line after a round trip.
    """
    pattern = re.compile(rf"\n?{re.escape(begin)}.*?{re.escape(end)}\n", re.DOTALL)
    return pattern.sub("", text)


def _uncomment_reference(text: str, module: str) -> tuple[str, bool]:
    """Turn ``-module`` into ``module`` inside ``authorize``.

    Returns the text and whether anything changed. Returning ``False`` for an
    already-active reference is what makes installation idempotent: a re-save
    finds ``ldap`` active, changes nothing, and is accepted.
    """
    pattern = re.compile(rf"^([ \t]*)-{re.escape(module)}[ \t]*$", re.MULTILINE)
    match = pattern.search(text)
    if match is None:
        return text, False
    indent = match.group(1)
    return text[: match.start()] + f"{indent}{module}" + text[match.end() :], True


def _has_active_reference(text: str, module: str) -> bool:
    """Whether an active (non-commented) module reference already exists."""
    return (
        re.search(rf"^[ \t]*{re.escape(module)}[ \t]*$", text, re.MULTILINE) is not None
    )


def _comment_reference(text: str, module: str) -> str:
    """Turn ``module`` back into ``-module``, first occurrence only.

    First occurrence rather than all: ``ldap`` also appears inside the
    ``post-auth`` and ``Auth-Type LDAP`` sub-sections, and disabling those
    would change behaviour the panel does not own.
    """
    pattern = re.compile(rf"^([ \t]*){re.escape(module)}[ \t]*$", re.MULTILINE)
    match = pattern.search(text)
    if match is None:
        return text
    indent = match.group(1)
    return text[: match.start()] + f"{indent}-{module}" + text[match.end() :]


def _mask_comments(text: str) -> str:
    """Replace comment bodies with spaces, preserving every offset.

    Brace counting has to ignore comments, and Debian's shipped site file is
    full of commented-out unlang: ``post-auth`` contains a commented
    ``if (!&reply:State) {`` whose closing brace is commented out too. Counting
    naively makes the section look unterminated, and the block gets appended
    after the end of the file - which unlang reports as "Invalid location for
    'if'" pointing at an unrelated line.
    """
    out = list(text)
    line_start = 0
    while line_start < len(text):
        line_end = text.find("\n", line_start)
        if line_end < 0:
            line_end = len(text)
        quote: str | None = None
        index = line_start
        while index < line_end:
            char = text[index]
            if quote is None and char == "#":
                # FreeRADIUS comments run to the end of the line. Masking the
                # remainder also prevents commented-out braces from changing
                # the section depth.
                for position in range(index, line_end):
                    out[position] = " "
                break
            if char in "'\"":
                if quote is None:
                    quote = char
                elif quote == char:
                    quote = None
                else:
                    out[index] = " "
            elif quote is not None:
                # Keep offsets, but hide braces and comment markers inside a
                # quoted value. Quotes themselves are harmless to the brace
                # counter, so retaining them makes debugging the mask easier.
                out[index] = " "
            index += 1
        line_start = line_end + 1
    return "".join(out)


def _section_bounds(text: str, pattern: str) -> tuple[int, int]:
    """Locate a section's opening brace and matching close.

    Comments and quoted values are masked out first; see
    :func:`_mask_comments`.
    """
    match = re.search(pattern, text, re.MULTILINE)
    if match is None:
        raise AdConfigError(
            f"No section matching {pattern!r} was found, so the site definition "
            "was left unchanged."
        )
    masked = _mask_comments(text)
    start = text.index("{", match.start())
    depth = 0
    for index in range(start, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return start, index
    raise AdConfigError(f"Unterminated section matching {pattern!r}; refusing to edit it.")


def _insert_at_section_top(text: str, pattern: str, block: str) -> str:
    start, end = _section_bounds(text, pattern)
    # Symmetric with :func:`_insert_at_section_bottom` and with
    # :func:`_remove_block`: exactly one newline on each side of the block, so
    # removing it restores the original bytes.
    return text[: start + 1] + "\n" + block + "\n" + text[start + 1 : end] + text[end:]


def _insert_at_section_bottom(text: str, pattern: str, block: str) -> str:
    start, end = _section_bounds(text, pattern)
    # The trailing newline is load-bearing twice over: without it the block's
    # closing marker butts against the section's '}', which unlang rejects with
    # "Invalid location for 'if'" pointing at an unrelated line; with it,
    # :func:`_remove_block` has exactly the newline to match on.
    return text[:end] + "\n" + block + "\n" + text[end:]


async def apply(
    settings: AdSettings,
    operation: str,
    administrator: str,
    source_ip: str | None = None,
    notes: str | None = None,
) -> None:
    """Install or update the AD configuration across both files.

    Applied as one group: an rlm_ldap module with no ``authorize`` reference
    authenticates nobody, and a ``post-auth`` mapping with no module resolves
    no groups. A partial application would leave the server running a
    configuration the panel did not intend.
    """
    settings.validate()
    if not settings.bind_password:
        raise AdConfigError("A bind password is required.")

    module = _module_path("ldap")
    site = paths.SITES_AVAILABLE / "default"
    if not module.exists():
        raise AdConfigError(
            f"{module} does not exist. Install the freeradius-ldap package "
            "before enabling Active Directory."
        )
    if not site.exists():
        raise AdConfigError(f"{site} does not exist; refusing to edit the site definition.")

    original_module = module.read_text("utf-8", "replace")
    original_site = site.read_text("utf-8", "replace")

    module_text = install_ldap_block(settings, original_module)
    site_text = install_authorize_block(original_site)
    site_text = install_authenticate_block(site_text)
    site_text = install_postauth_block(settings, site_text)

    transaction = ConfigTransaction()
    await transaction.apply_group(
        entries=[
            ("mods-available/ldap", module, module_text),
            ("sites-available/default", site, site_text),
        ],
        operation=operation,
        administrator=administrator,
        source_ip=source_ip,
        notes=notes,
    )


async def remove(
    operation: str,
    administrator: str,
    source_ip: str | None = None,
    notes: str | None = None,
) -> None:
    """Remove the managed AD configuration, restoring the shipped behaviour."""
    module = _module_path("ldap")
    site = paths.SITES_AVAILABLE / "default"

    entries: list[tuple[str, Path, str]] = []

    if module.exists():
        original = module.read_text("utf-8", "replace")
        stripped = strip_ldap_block(original)
        if stripped != original:
            entries.append(("mods-available/ldap", module, stripped))

    if site.exists():
        original = site.read_text("utf-8", "replace")
        site_text = strip_postauth_block(original)
        site_text = strip_authenticate_block(site_text)
        site_text = strip_authorize_block(site_text)
        if site_text != original:
            entries.append(("sites-available/default", site, site_text))

    if not entries:
        return

    transaction = ConfigTransaction()
    await transaction.apply_group(
        entries=entries,
        operation=operation,
        administrator=administrator,
        source_ip=source_ip,
        notes=notes,
    )
