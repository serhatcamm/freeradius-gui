"""A ``ConfigWriter`` that delegates the write to a privileged helper.

The application runs as the unprivileged ``freeradius-web`` user, which cannot
write into ``/etc/freeradius/3.0``. Rather than giving the web process write
access to the whole configuration tree, the write is delegated to a tiny
root-owned helper that accepts *only* a fixed list of target paths.

The helper has no setuid bit: elevation comes from a sudoers rule that names
this one program, so a compromised web process cannot borrow root for anything
else. Because of that, the service unit must not set ``NoNewPrivileges=yes`` -
that flag makes sudo refuse to run at all.

The helper is invoked as::

    sudo --non-interactive -- /usr/local/libexec/freeradius-web/frw-write <path> <mode>

with the new content on stdin. It resolves the path against an allow-list and
refuses anything else, so a compromised web process cannot turn this into
arbitrary root file write.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shlex
from pathlib import Path

from .config_tx import PermissionDeniedError

logger = logging.getLogger(__name__)

#: Absolute path of the privileged helper.
WRAPPER = os.environ.get("FRW_WRITE_WRAPPER", "/usr/local/libexec/freeradius-web/frw-write")

#: How long the helper may take before we treat it as hung.
TIMEOUT = 20


class PrivilegedAtomicWriter:
    """Write a managed file by invoking the root-owned helper via sudo."""

    def __init__(self, wrapper: str | None = None) -> None:
        self.wrapper = wrapper or WRAPPER

    async def write(self, path: Path, content: bytes, mode: int | None = None) -> None:
        path = Path(path)
        if not Path(self.wrapper).exists():
            raise PermissionDeniedError(
                f"privileged helper {self.wrapper} is not installed; "
                "run scripts/install.sh or set FRW_WRITE_WRAPPER"
            )

        target = path
        if target.is_symlink():
            # Resolve through the symlink so the helper writes the real file
            # and the link itself is preserved.
            target = target.resolve(strict=True)

        perms = f"{mode:o}" if mode is not None else "-"

        # The helper is root-owned but not setuid; elevation comes from a
        # sudoers rule that names this one program, so a compromised web
        # process cannot borrow root for anything else.
        argv = [self.wrapper, str(target), perms]
        if os.geteuid() != 0:
            argv = ["sudo", "--non-interactive", "--", *argv]

        logger.info(
            "delegating write of %s via %s", target, shlex.join(argv)
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise PermissionDeniedError(f"cannot execute helper: {exc}") from exc

        try:
            _, stderr = await asyncio.wait_for(
                proc.communicate(content), timeout=TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            raise PermissionDeniedError("privileged helper timed out")

        if proc.returncode != 0:
            detail = (stderr or b"").decode("utf-8", "replace").strip()[:400]
            logger.error("helper rejected write of %s: %s", target, detail)
            raise PermissionDeniedError(
                f"privileged helper refused to write {target}: {detail or 'unknown error'}"
            )


def default_writer():
    """Pick the writer appropriate to the current privileges.

    Running as root (development, tests) writes directly; otherwise the
    privileged helper is used.
    """
    if os.geteuid() == 0:
        from .config_tx import LocalAtomicWriter

        return LocalAtomicWriter()
    return PrivilegedAtomicWriter()