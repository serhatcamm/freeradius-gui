"""Lossless parser/serialiser for FreeRADIUS ``clients.conf``.

A ``clients.conf`` file is a sequence of comments plus ``client <name> { ... }``
blocks. Blocks may contain nested blocks (``limit { ... }``) and arbitrary
vendor directives.

Each block is modelled as an ordered list of *items* so that unknown
directives, comments and nested blocks survive a round-trip untouched. A block
is only re-rendered when it was actually modified; otherwise the original text
is emitted verbatim.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

DISABLE_MARKER = "#freeradius-web-disabled:"

#: Directives the panel understands. Everything else is preserved opaquely.
KNOWN_DIRECTIVES = {
    "ipaddr",
    "ipv4addr",
    "ipv6addr",
    "secret",
    "nas_type",
    "description",
    "virtual_server",
    "require_message_authenticator",
    "limit",
    "login",
    "password",
    "status_check",
    "force_to_192",
}

_DIRECTIVE_RE = re.compile(
    r"^(?P<key>[A-Za-z0-9_.\-]+)\s*(?P<op>=|:=|==)?\s*(?P<value>.*?)\s*$"
)
_CLIENT_RE = re.compile(r"^client\s+(?P<name>\S+)\s*(?P<open>\{)?\s*(?:#.*)?$")


@dataclass
class RawItem:
    """A comment, blank line or otherwise unrecognised content."""

    lines: list[str] = field(default_factory=list)

    kind = "raw"

    @property
    def render(self) -> str:
        return "\n".join(self.lines)


@dataclass
class Directive:
    key: str
    value: str
    op: str = "="
    inline_comment: str = ""

    kind = "directive"


@dataclass
class NestedBlock:
    name: str
    lines: list[str] = field(default_factory=list)

    kind = "nested"


@dataclass
class ClientEntry:
    name: str
    items: list = field(default_factory=list)
    enabled: bool = True
    managed: bool = False
    line_number: int = 0
    dirty: bool = False
    raw_lines: list[str] = field(default_factory=list)

    # -- introspection ---------------------------------------------------
    def directive(self, key: str) -> Directive | None:
        for item in self.items:
            if isinstance(item, Directive) and item.key == key:
                return item
        return None

    @property
    def address(self) -> str | None:
        for key in ("ipaddr", "ipv4addr", "ipv6addr"):
            d = self.directive(key)
            if d:
                return d.value
        # 1.x style: the client "name" was the address.
        try:
            ipaddress.ip_network(self.name, strict=False)
        except ValueError:
            return None
        return self.name

    @property
    def address_kind(self) -> str:
        """``host``, ``network`` or ``unknown`` for the address field."""
        addr = self.address
        if not addr:
            return "unknown"
        try:
            net = ipaddress.ip_network(addr, strict=False)
        except ValueError:
            return "unknown"
        if "/" in addr or net.num_addresses > 1:
            return "network"
        return "host"

    @property
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
        addr = self.address
        if not addr:
            return None
        try:
            return ipaddress.ip_network(addr, strict=False)
        except ValueError:
            return None

    @property
    def has_secret(self) -> bool:
        d = self.directive("secret")
        return bool(d and d.value)

    @property
    def nas_type(self) -> str:
        d = self.directive("nas_type")
        return d.value if d else "other"

    @property
    def description(self) -> str:
        d = self.directive("description")
        return d.value if d else ""

    @property
    def require_message_authenticator(self) -> bool:
        d = self.directive("require_message_authenticator")
        return bool(d and d.value.strip().lower() == "true")

    # -- mutation --------------------------------------------------------
    def set_directive(self, key: str, value: str, op: str = "=") -> None:
        for item in self.items:
            if isinstance(item, Directive) and item.key == key:
                item.value = value
                item.op = op
                item.inline_comment = ""
                self.dirty = True
                return
        self.items.append(Directive(key=key, value=value, op=op))
        self.dirty = True

    def remove_directive(self, key: str) -> None:
        before = len(self.items)
        self.items = [
            i for i in self.items if not (isinstance(i, Directive) and i.key == key)
        ]
        if len(self.items) != before:
            self.dirty = True

    def set_secret(self, secret: str) -> None:
        self.set_directive("secret", secret)

    # -- serialisation ---------------------------------------------------
    def render(self) -> str:
        if not self.dirty:
            return "\n".join(self.raw_lines)

        head = f"client {self.name} {{"
        body: list[str] = [head]
        for item in self.items:
            if isinstance(item, Directive):
                line = f"\t{item.key} {item.op or '='} {item.value}"
                if item.inline_comment:
                    line += f"\t# {item.inline_comment}"
                body.append(line)
            elif isinstance(item, NestedBlock):
                body.append(f"\t{item.name} {{")
                body.extend(f"\t\t{ln}" if ln.strip() else "" for ln in item.lines)
                body.append("\t}")
            else:
                body.extend(item.lines)
        body.append("}")
        rendered = "\n".join(body)

        if not self.enabled:
            rendered = "\n".join(f"{DISABLE_MARKER} {ln}" for ln in rendered.split("\n"))
        return rendered


@dataclass
class ClientsDocument:
    segments: list = field(default_factory=list)
    raw: str = ""

    @property
    def clients(self) -> list[ClientEntry]:
        return [s for s in self.segments if isinstance(s, ClientEntry)]

    @property
    def managed_clients(self) -> list[ClientEntry]:
        return [c for c in self.clients if c.managed]

    def find(self, name: str) -> list[ClientEntry]:
        return [c for c in self.clients if c.name == name]

    def unique_find(self, name: str) -> ClientEntry | None:
        matches = [c for c in self.clients if c.name == name]
        return matches[0] if matches else None

    def upsert(self, entry: ClientEntry) -> ClientEntry:
        for seg in self.segments:
            if isinstance(seg, ClientEntry) and seg.name == entry.name and seg.managed:
                entry.managed = True
                self.segments[self.segments.index(seg)] = entry
                return entry
        entry.managed = True
        if self.segments and isinstance(self.segments[-1], ClientEntry):
            self.segments.append(RawItem(lines=[""]))
        self.segments.append(entry)
        return entry

    def delete(self, name: str) -> int:
        removed = 0
        keep = []
        for seg in self.segments:
            if isinstance(seg, ClientEntry) and seg.name == name and seg.managed:
                removed += 1
                continue
            keep.append(seg)
        self.segments = keep
        return removed

    def render(self) -> str:
        chunks: list[str] = []
        for seg in self.segments:
            rendered = seg.render() if isinstance(seg, ClientEntry) else seg.render
            if rendered != "":
                chunks.append(rendered)
        text = "\n".join(chunks)
        return text.rstrip("\n") + "\n" if text.strip() else ""


def _strip_comment(line: str) -> tuple[str, str]:
    """Split a directive line into (code, inline_comment)."""
    out: list[str] = []
    quote = ""
    for idx, ch in enumerate(line):
        if quote:
            out.append(ch)
            if ch == quote and line[idx - 1] != "\\":
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            continue
        if ch == "#":
            return "".join(out).rstrip(), line[idx + 1 :].strip()
        out.append(ch)
    return "".join(out).rstrip(), ""


def _parse_block_items(body: list[str]) -> list:
    items: list = []
    i = 0
    while i < len(body):
        # A disabled block has the marker on every line; strip it so the
        # directives are still parsed and the block stays editable.
        line, _ = _strip_marker(body[i])
        stripped = line.strip()

        if stripped == "" or stripped.startswith("#"):
            items.append(RawItem(lines=[line]))
            i += 1
            continue

        if stripped.endswith("{"):
            name = stripped[:-1].strip()
            depth = 1
            nested: list[str] = []
            i += 1
            while i < len(body):
                s = body[i].strip()
                depth += s.count("{") - s.count("}")
                if depth <= 0:
                    break
                nested.append(body[i].strip())
                i += 1
            items.append(NestedBlock(name=name, lines=nested))
            i += 1
            continue

        code, comment = _strip_comment(line)
        m = _DIRECTIVE_RE.match(code.strip())
        if m and m.group("key"):
            items.append(
                Directive(
                    key=m.group("key"),
                    value=m.group("value") or "",
                    op=m.group("op") or "=",
                    inline_comment=comment,
                )
            )
        else:
            items.append(RawItem(lines=[body[i]]))
        i += 1
    return items


def _strip_marker(line: str) -> tuple[str, bool]:
    """Remove a leading disable marker, reporting whether it was present."""
    if line.lstrip().startswith(DISABLE_MARKER):
        return line.lstrip()[len(DISABLE_MARKER) :].lstrip(), True
    return line, False


def _find_block_end(lines: list[str], start: int) -> int:
    """Return index of the closing brace for a block opened at ``start``.

    The disable marker is stripped first, otherwise a commented-out block
    would appear to contain no braces.
    """
    depth = 0
    for idx in range(start, len(lines)):
        bare, _ = _strip_marker(lines[idx])
        code, _ = _strip_comment(bare)
        depth += code.count("{") - code.count("}")
        if depth == 0:
            return idx
    return len(lines) - 1


def parse_clients(text: str) -> ClientsDocument:
    lines = text.splitlines()
    segments: list = []
    buf: list[str] = []
    i = 0

    def flush() -> None:
        if buf:
            segments.append(RawItem(lines=list(buf)))
            buf.clear()

    while i < len(lines):
        line = lines[i]
        bare, disabled = _strip_marker(line)
        code, _ = _strip_comment(bare)
        m = _CLIENT_RE.match(code.strip())
        if not m:
            buf.append(line)
            i += 1
            continue

        flush()
        line_no = i + 1
        name = m.group("name")
        enabled = not disabled

        end = _find_block_end(lines, i)
        raw_lines = lines[i : end + 1]
        body = [ln for ln in raw_lines[1:-1]] if raw_lines[-1].strip() == "}" else raw_lines[1:]
        segments.append(
            ClientEntry(
                name=name,
                items=_parse_block_items(body),
                enabled=enabled,
                managed=True,
                line_number=line_no,
                raw_lines=raw_lines,
            )
        )
        i = end + 1

    flush()
    return ClientsDocument(segments=segments, raw=text)