"""Lossless parser/serialiser for the FreeRADIUS ``users`` file.

The file is *not* treated as free text. It is split into ordered segments so
that anything the application does not understand - comments, ``DEFAULT``
entries, vendor blocks, hand-written policy - is preserved byte for byte.

Grammar handled (the subset the panel manages)::

    # comment
    <username> <Attr> := "value", <Attr2> = "v2"
    <username> Auth-Type := Reject
    <continuation lines are indented and may hold reply attributes>

Anything else is kept verbatim as an ``UnknownSegment``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

#: Attributes that carry a secret. Values are never surfaced by the API.
PASSWORD_ATTRIBUTES = {
    "Cleartext-Password",
    "NT-Password",
    "Crypt-Password",
    "SHA512-Password",
    "SHA256-Password",
    "MD5-Password",
    "LM-Hash",
    "NT-Hash",
    "SMD5-Password",
    "mschap",
    "MS-CHAP-Response",
    "CHAP-Password",
    "User-Password",
}

#: Cisco AVPair carrying the shell privilege level.
CISCO_PRIV_RE = re.compile(r"^\s*shell:priv-lvl\s*=\s*(\d+)\s*$", re.IGNORECASE)
CISCO_PRIV_AVPAIR = "shell:priv-lvl"

#: Leading comment marker used to disable a managed user without losing data.
DISABLE_MARKER = "#freeradius-web-disabled:"

_ASSIGN_RE = re.compile(
    r"""
    (?P<key>[A-Za-z0-9_.:\-]+)      # attribute name
    \s*
    (?P<op>:=|==|=)                  # assignment operator
    \s*
    (?P<value>
        "(?:[^"\\]|\\.)*"            # quoted value
        |
        \S+?                         # bare value
    )
    \s*
    (?=,|$)
    """,
    re.VERBOSE,
)

_TOP_LEVEL_RE = re.compile(r"^\S")
DEFAULT_USERNAME = "DEFAULT"


@dataclass
class Assignment:
    """A single ``key op value`` triple."""

    key: str
    op: str
    value: str
    quoted: bool = True

    @property
    def unquoted_value(self) -> str:
        if self.quoted and len(self.value) >= 2 and self.value[0] == '"':
            return _unescape(self.value[1:-1])
        return self.value

    @property
    def is_secret(self) -> bool:
        return self.key in PASSWORD_ATTRIBUTES

    def render(self) -> str:
        if self.quoted:
            body = _escape(self.unquoted_value)
            return f"{self.key} {self.op} \"{body}\""
        return f"{self.key} {self.op} {self.value}"


@dataclass
class Segment:
    """Base segment: raw lines kept verbatim."""

    lines: list[str] = field(default_factory=list)

    @property
    def render(self) -> str:
        return "\n".join(self.lines)


@dataclass
class UnknownSegment(Segment):
    """A block the panel will never rewrite."""


@dataclass
class UserEntry:
    """A recognised top-level user entry."""

    username: str
    conditions: list[Assignment] = field(default_factory=list)
    attributes: list[Assignment] = field(default_factory=list)
    reply: list[Assignment] = field(default_factory=list)
    enabled: bool = True
    managed: bool = False
    line_number: int = 0
    #: Original text of the entry. Emitted verbatim unless ``dirty``.
    raw_lines: list[str] = field(default_factory=list)
    dirty: bool = False

    # -- introspection ---------------------------------------------------
    @property
    def auth_method(self) -> str:
        for a in self.attributes:
            if a.key in PASSWORD_ATTRIBUTES:
                return a.key
        for a in self.attributes:
            if a.key == "Auth-Type":
                return f"Auth-Type:{a.unquoted_value}"
        return "unknown"

    @property
    def is_default(self) -> bool:
        return self.username == DEFAULT_USERNAME

    @property
    def has_password(self) -> bool:
        return any(a.is_secret for a in self.attributes)

    @property
    def cisco_privilege(self) -> int | None:
        for a in self.reply:
            if a.key == "Cisco-AVPair":
                m = CISCO_PRIV_RE.match(a.unquoted_value)
                if m:
                    return int(m.group(1))
        return None

    @property
    def cisco_avpairs(self) -> list[str]:
        return [a.unquoted_value for a in self.reply if a.key == "Cisco-AVPair"]

    @property
    def rejects(self) -> bool:
        for a in self.attributes:
            if a.key == "Auth-Type" and a.unquoted_value.lower() == "reject":
                return True
        return False

    # -- mutation --------------------------------------------------------
    def set_password(self, password: str) -> None:
        """Set (or replace) the cleartext password in place."""
        self.attributes = [a for a in self.attributes if not a.is_secret]
        self.attributes.append(Assignment("Cleartext-Password", ":=", password))
        self.dirty = True

    def set_cisco_privilege(self, level: int) -> None:
        """Set ``Cisco-AVPair = "shell:priv-lvl=N"``, replacing any existing."""
        self.reply = [a for a in self.reply if a.key != "Cisco-AVPair"]
        self.reply.append(
            Assignment("Cisco-AVPair", "=", f"{CISCO_PRIV_AVPAIR}={level}")
        )
        self.dirty = True

    def clear_cisco(self) -> None:
        self.reply = [a for a in self.reply if a.key != "Cisco-AVPair"]
        self.dirty = True

    # -- serialisation ---------------------------------------------------
    def render(self, indent: str = "\t") -> str:
        # Untouched entries must be emitted byte-for-byte.
        if not self.dirty and self.raw_lines:
            return "\n".join(self.raw_lines)

        head = self.username
        if self.conditions:
            head += "\t" + ", ".join(a.render() for a in self.conditions)
        head += "\t" + ", ".join(a.render() for a in self.attributes)

        out: list[str] = []
        if not self.enabled:
            for line in _render_block(head, self.reply, indent):
                out.append(f"{DISABLE_MARKER} {line}")
            return "\n".join(out)

        out.extend(_render_block(head, self.reply, indent))
        return "\n".join(out)


def _render_block(head: str, reply: list[Assignment], indent: str) -> list[str]:
    lines = [head]
    # Continuation lines carry reply attributes, comma separated.
    if reply:
        rendered = ", ".join(a.render() for a in reply)
        lines.append(f"{indent}{rendered}")
    return lines


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _unescape(value: str) -> str:
    return value.replace('\\"', '"').replace("\\\\", "\\")


def parse_assignments(text: str) -> list[Assignment]:
    """Parse a comma separated list of ``key op value`` assignments."""
    result: list[Assignment] = []
    for m in _ASSIGN_RE.finditer(text):
        raw = m.group("value")
        quoted = raw.startswith('"')
        result.append(
            Assignment(
                key=m.group("key"),
                op=m.group("op"),
                value=raw,
                quoted=quoted,
            )
        )
    return result


def _strip_marker(line: str) -> tuple[str, bool]:
    """Remove a leading disable marker, reporting whether it was present."""
    if line.lstrip().startswith(DISABLE_MARKER):
        return line.lstrip()[len(DISABLE_MARKER) :].lstrip(), True
    return line, False


def _is_top_level(line: str) -> bool:
    """True for an unindented, non-comment line.

    A line commented out by the panel (disable marker) still counts as a
    top-level entry so a disabled user remains visible and re-parsable.
    """
    candidate, _ = _strip_marker(line)
    if not candidate.strip():
        return False
    if candidate.lstrip().startswith("#"):
        return False
    return bool(_TOP_LEVEL_RE.match(candidate))


def split_segments(text: str) -> list[Segment]:
    """Split raw file text into ordered segments.

    A segment is either a run of blank/comment lines, a single unindented
    non-comment line (an entry), or the indented continuation lines that
    belong to it.
    """
    lines = text.splitlines()
    segments: list[Segment] = []
    buf: list[str] = []
    i = 0

    def flush_raw() -> None:
        if buf:
            segments.append(UnknownSegment(lines=list(buf)))
            buf.clear()

    while i < len(lines):
        line = lines[i]
        if not _is_top_level(line):
            buf.append(line)
            i += 1
            continue

        # Start of an entry: collect the head line plus its indented
        # continuations. Continuation lines of a disabled entry carry the
        # same disable marker, so the marker is stripped before testing.
        flush_raw()
        start = i
        entry_lines = [line]
        line_no = i + 1
        i += 1
        while i < len(lines):
            nxt = lines[i]
            bare, _ = _strip_marker(nxt)
            if _is_top_level(nxt):
                break
            if bare.strip() == "" or bare.lstrip().startswith("#"):
                break
            entry_lines.append(nxt)
            i += 1

        parsed = _interpret_entry(entry_lines, line_no)
        if parsed is not None:
            segments.append(parsed)
        else:
            segments.append(UnknownSegment(lines=entry_lines))

    flush_raw()
    return segments


def _interpret_entry(lines: list[str], line_number: int) -> UserEntry | None:
    disabled = False
    body: list[str] = []
    for line in lines:
        bare, was_disabled = _strip_marker(line)
        disabled = disabled or was_disabled
        body.append(bare)

    head = body[0]
    if "\t" in head:
        username_part, rest = head.split("\t", 1)
    else:
        parts = head.split(None, 1)
        if len(parts) != 2:
            return None
        username_part, rest = parts

    username = username_part.strip()
    if not username:
        return None

    assignments = parse_assignments(rest)
    if not assignments:
        return None

    conditions: list[Assignment] = []
    attributes: list[Assignment] = []
    first = assignments[0]
    if first.op == "==":
        conditions.append(first)
        attributes.extend(assignments[1:])
    else:
        attributes.extend(assignments)

    reply: list[Assignment] = []
    for line in body[1:]:
        reply.extend(parse_assignments(line.strip()))

    return UserEntry(
        username=username,
        conditions=conditions,
        attributes=attributes,
        reply=reply,
        enabled=not disabled,
        # Every entry this parser recognises is a plain file-based entry the
        # panel can safely edit. Being *disabled* is orthogonal to being
        # manageable, otherwise a disabled user would disappear from the list
        # and could never be re-enabled.
        managed=True,
        line_number=line_number,
        raw_lines=list(lines),
    )


def _looks_managed(lines: list[str]) -> bool:
    """Retained for callers that inspect raw lines; see ``managed`` above."""
    return any("Cisco-AVPair" in ln for ln in lines)


@dataclass
class UsersDocument:
    """Parsed ``users`` file: ordered segments plus helper accessors."""

    segments: list[Segment]
    raw: str

    # -- accessors -------------------------------------------------------
    @property
    def entries(self) -> list[UserEntry]:
        return [s for s in self.segments if isinstance(s, UserEntry)]

    @property
    def users(self) -> list[UserEntry]:
        """Managed, non-DEFAULT users (what the Users page lists)."""
        return [
            e
            for e in self.entries
            if not e.is_default and e.managed and not e.conditions
        ]

    def find(self, username: str) -> list[UserEntry]:
        return [e for e in self.entries if e.username == username]

    def unique_find(self, username: str) -> UserEntry | None:
        matches = [e for e in self.users if e.username == username]
        return matches[0] if matches else None

    # -- mutation --------------------------------------------------------
    def upsert(self, entry: UserEntry) -> UserEntry:
        """Replace the first managed entry with ``username`` or append."""
        for seg in self.segments:
            if isinstance(seg, UserEntry) and seg.managed and seg.username == entry.username:
                seg.conditions = entry.conditions
                seg.attributes = entry.attributes
                seg.reply = entry.reply
                seg.enabled = entry.enabled
                seg.dirty = True
                return seg

        entry.managed = True
        self.segments.append(entry)
        self._ensure_trailing_newline()
        return entry

    def delete(self, username: str) -> int:
        removed = 0
        keep: list[Segment] = []
        for seg in self.segments:
            if isinstance(seg, UserEntry) and seg.username == username and seg.managed:
                removed += 1
                continue
            keep.append(seg)
        self.segments = keep
        return removed

    def _ensure_trailing_newline(self) -> None:
        if self.segments and isinstance(self.segments[-1], UserEntry):
            self.segments.append(UnknownSegment(lines=[""]))

    # -- serialisation ---------------------------------------------------
    def render(self) -> str:
        chunks: list[str] = []
        for seg in self.segments:
            rendered = seg.render() if isinstance(seg, UserEntry) else seg.render
            chunks.append(rendered)
        text = "\n".join(c for c in chunks if c != "")
        return text.rstrip("\n") + "\n" if text.strip() else ""


def parse_users(text: str) -> UsersDocument:
    return UsersDocument(segments=split_segments(text), raw=text)