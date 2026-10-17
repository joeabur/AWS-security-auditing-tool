"""Protected report file output."""

from __future__ import annotations

import os
from pathlib import Path

from ..errors import AuditorError


def write_report_file(path: Path, content: str, *, overwrite: bool = False) -> None:
    """Write ``content`` with owner-only permissions; refuse to clobber unless asked."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise AuditorError(f"{path} exists; use --force to overwrite") from exc
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(content)
    os.chmod(path, 0o600)
