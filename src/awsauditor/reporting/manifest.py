"""SHA-256 manifest for tamper evidence of written reports."""

from __future__ import annotations

import hashlib
from pathlib import Path

from ..errors import ConfigError


def digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def build_manifest(files: dict[str, str]) -> str:
    """``sha256sum``-compatible text for ``{filename: content}``."""
    return "".join(f"{digest(text)}  {name}\n" for name, text in sorted(files.items()))


def verify_manifest(path: Path) -> list[tuple[str, str]]:
    """Return ``(filename, OK|MISMATCH|MISSING)`` for every entry, files resolved next to it."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ConfigError(f"cannot read manifest {path}: {exc}") from exc
    results: list[tuple[str, str]] = []
    for line in lines:
        if not line.strip():
            continue
        expected, sep, name = line.partition("  ")
        if not sep or len(expected) != 64 or "/" in name or "\\" in name or name in ("", ".", ".."):
            raise ConfigError(f"malformed manifest line: {line[:80]!r}")
        target = path.parent / name
        if not target.is_file():
            results.append((name, "MISSING"))
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        results.append((name, "OK" if actual == expected else "MISMATCH"))
    if not results:
        raise ConfigError("manifest has no entries")
    return results
