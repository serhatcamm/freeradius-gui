"""``freeradius -XC`` configuration validation.

``-X`` runs in debug mode and ``-C`` checks the configuration without
serving. The command only reads configuration, so it is always safe to run
and is the gate every modification must pass.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .paths import FREERADIUS_BIN
from .runner import CommandResult, run_command

#: FreeRADIUS prints "Configuration appears to be OK" on success.
_OK_MARKER = "Configuration appears to be OK"

_ERROR_RE = re.compile(
    r"^(?P<file>[^\s:][^:]*):(?P<line>\d+):\s*(?P<sev>Error|Fatal):\s*(?P<msg>.*)$"
)
_INLINE_ERROR_RE = re.compile(
    r"^.*?:(?P<line>\d+):\s*(?P<sev>Error|Fatal):\s*(?P<msg>.*)$"
)


@dataclass
class ConfigIssue:
    severity: str
    message: str
    file: str | None = None
    line: int | None = None

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
            "line": self.line,
        }


@dataclass
class ValidationResult:
    ok: bool
    returncode: int
    issues: list[ConfigIssue] = field(default_factory=list)
    output: str = ""

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "returncode": self.returncode,
            "issues": [i.as_dict() for i in self.issues],
        }

    @property
    def summary(self) -> str:
        if self.ok:
            return "Configuration appears to be OK"
        if not self.issues:
            return "Configuration validation failed"
        head = self.issues[0]
        loc = f" ({head.file}:{head.line})" if head.file else ""
        more = f" (+{len(self.issues) - 1} more)" if len(self.issues) > 1 else ""
        return f"{head.severity}{loc}: {head.message}{more}"


def parse_validation_output(result: CommandResult) -> ValidationResult:
    """Turn a ``-XC`` result into structured issues.

    Debug output is verbose; we only surface real errors and the OK marker.
    """
    text = result.stdout + ("\n" + result.stderr if result.stderr else "")
    issues: list[ConfigIssue] = []

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        m = _ERROR_RE.match(stripped) or _INLINE_ERROR_RE.match(stripped)
        if m:
            issues.append(
                ConfigIssue(
                    severity=m.group("sev"),
                    message=m.group("msg").strip(),
                    line=int(m.group("line")),
                )
            )

    ok = result.returncode == 0 and _OK_MARKER in text
    return ValidationResult(
        ok=ok,
        returncode=result.returncode,
        issues=issues,
        output=text,
    )


async def validate_config(binary: str | None = None) -> ValidationResult:
    """Run ``freeradius -XC``. Never raises on failure - inspect ``ok``."""
    argv = [binary or str(FREERADIUS_BIN), "-XC"]
    result = await run_command(argv, timeout=120)
    return parse_validation_output(result)