"""Parser for the FreeRADIUS ``groups`` file.

The format is deliberately tiny compared with ``authorize``: one group per
top-level line, a name, then a comma-separated list of attribute
assignments::

    staff          Reply-Message = "welcome", Max-Monthly-Session = 36000
    DEFAULT        Reply-Message = "welcome"

``DEFAULT`` is a valid, meaningful name - FreeRADIUS applies it to every
request that no other group matched - so it is modelled as an ordinary entry
rather than being special-cased out.

Round-tripping matters more than usual here because the panel rewrites the
whole file through the privileged writer: anything the parser does not
understand has to be preserved byte-for-byte. Comments and blank lines are
therefore kept as verbatim segments rather than discarded, exactly like
``users_parser`` does for ``authorize``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .users_parser import Assignment, parse_assignments

#: The catch-all group name FreeRADIUS supports in this file.
DEFAULT_GROUP = "DEFAULT"

#: Maximum length of a group name, matching what the UI will accept.
MAX_NAME_LENGTH = 64

#: A group name is a bare token. Anything outside this set is not a group
#: definition we can reason about, so the line is preserved verbatim instead
#: of being silently reinterpreted as a (probably wrong) group.
_NAME_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.@-]+)\s*(?P<attrs>.*)$"
)


@dataclass
class GroupEntry:
    """One group: a name plus its attribute assignments.

    ``reply_indices`` marks which entries in ``attributes`` were written with
    an explicit ``reply:`` prefix, so rendering can reproduce the original
    spelling byte-for-byte.
    """

    name: str
    attributes: list[Assignment] = field(default_factory=list)
    reply_indices: set[int] = field(default_factory=set)
    line_number: int = 0
    comment: str = ""

    @property
    def is_default(self) -> bool:
        return self.name == DEFAULT_GROUP

    def to_dict(self) -> dict:
        """API representation.

        Values are reported unquoted. The panel edits and resubmits exactly
        what it is shown, and the writer rejects quotes in a value, so handing
        back the raw ``"x"`` token would make every edit of an existing group
        fail validation. Rendering is unaffected: it uses the stored
        :class:`Assignment`, which still holds the original token.
        """
        return {
            "name": self.name,
            "is_default": self.is_default,
            "line_number": self.line_number,
            "comment": self.comment,
            "attributes": [
                {
                    "key": a.key,
                    "op": a.op,
                    "value": a.unquoted_value,
                    "reply": index in self.reply_indices,
                }
                for index, a in enumerate(self.attributes)
            ],
        }

    def render(self) -> str:
        """Render back to a single top-level line."""
        parts = []
        for index, assignment in enumerate(self.attributes):
            prefix = "reply:" if index in self.reply_indices else ""
            parts.append(f"{prefix}{assignment.render()}")
        if not parts:
            return self.name
        return f"{self.name}\t" + ", ".join(parts)


@dataclass
class RawSegment:
    """A comment or blank line, preserved verbatim."""

    text: str
    line_number: int = 0

    def render(self) -> str:
        return self.text


def _is_comment_or_blank(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def parse_groups(text: str) -> GroupsDocument:
    """Parse a ``groups`` file into ordered segments."""
    segments: list[GroupEntry | RawSegment] = []
    raw_lines = text.splitlines()

    for index, line in enumerate(raw_lines):
        if _is_comment_or_blank(line):
            segments.append(RawSegment(text=line, line_number=index + 1))
            continue

        match = _NAME_RE.match(line.strip())
        if not match:
            # Not a group we understand; keep it rather than lose it.
            segments.append(RawSegment(text=line, line_number=index + 1))
            continue

        name = match.group("name")
        attributes: list[Assignment] = []
        reply_indices: set[int] = set()

        # An explicit 'reply:' prefix is recorded so rendering can reproduce
        # the original spelling; plain attributes keep their own meaning.
        for chunk in _split_attr_chunks(match.group("attrs")):
            stripped = chunk.strip()
            lowered = stripped.lower()
            is_reply = lowered.startswith("reply:")
            if is_reply:
                stripped = stripped[len("reply:") :]
            for assignment in parse_assignments(stripped):
                if is_reply:
                    reply_indices.add(len(attributes))
                attributes.append(assignment)

        segments.append(
            GroupEntry(
                name=name,
                attributes=attributes,
                reply_indices=reply_indices,
                line_number=index + 1,
            )
        )

    return GroupsDocument(segments=segments, raw=text)


def _split_attr_chunks(text: str) -> list[str]:
    """Split on commas that are not inside a quoted value."""
    chunks: list[str] = []
    current: list[str] = []
    in_quotes = False
    escaped = False
    for ch in text:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_quotes:
            current.append(ch)
            escaped = True
            continue
        if ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
            continue
        if ch == "," and not in_quotes:
            chunks.append("".join(current))
            current = []
            continue
        current.append(ch)
    if current:
        chunks.append("".join(current))
    return [c for c in chunks if c.strip()]


@dataclass
class GroupsDocument:
    """Parsed ``groups`` file: ordered segments plus helpers."""

    segments: list[GroupEntry | RawSegment]
    raw: str

    @property
    def groups(self) -> list[GroupEntry]:
        return [s for s in self.segments if isinstance(s, GroupEntry)]

    def find(self, name: str) -> list[GroupEntry]:
        return [g for g in self.groups if g.name == name]

    def unique_find(self, name: str) -> GroupEntry | None:
        matches = self.find(name)
        return matches[0] if matches else None

    def upsert(self, entry: GroupEntry) -> GroupEntry:
        """Replace the first group with this name, or append a new one.

        Comments stay at the top of the file and existing trailing comments
        stay at the bottom, so a rewrite does not shuffle documentation
        around the entries.
        """
        for index, segment in enumerate(self.segments):
            if isinstance(segment, GroupEntry) and segment.name == entry.name:
                entry.line_number = segment.line_number
                self.segments[index] = entry
                self._ensure_trailing_newline()
                return entry

        # Append after the last group so trailing comments stay trailing.
        insert_at = len(self.segments)
        for index in range(len(self.segments) - 1, -1, -1):
            if isinstance(self.segments[index], GroupEntry):
                insert_at = index + 1
                break
        entry.line_number = 0
        self.segments.insert(insert_at, entry)
        self._ensure_trailing_newline()
        return entry

    def delete(self, name: str) -> int:
        kept = [
            s for s in self.segments if not (isinstance(s, GroupEntry) and s.name == name)
        ]
        removed = len(self.segments) - len(kept)
        self.segments = kept
        self._ensure_trailing_newline()
        return removed

    def render(self) -> str:
        rendered = "\n".join(segment.render() for segment in self.segments)
        return rendered + "\n" if rendered else ""

    def _ensure_trailing_newline(self) -> None:
        if self.segments and not isinstance(self.segments[-1], RawSegment):
            self.segments.append(RawSegment(text=""))


def load_groups(path: Path) -> GroupsDocument:
    """Read and parse a groups file; a missing file is an empty document."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return GroupsDocument(segments=[], raw="")
    return parse_groups(text)