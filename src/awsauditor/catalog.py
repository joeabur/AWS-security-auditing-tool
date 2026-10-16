"""Loading and querying the versioned control catalog."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from pydantic import ValidationError

from .errors import ConfigError
from .models import Catalog, Control, Severity


def _default_path() -> Path:
    """Repository checkout copy first, then the copy bundled in an installed wheel."""
    repo_copy = Path(__file__).resolve().parents[2] / "controls" / "catalog.json"
    if repo_copy.is_file():
        return repo_copy
    return Path(str(resources.files("awsauditor") / "data" / "catalog.json"))


def load_catalog(path: Path | None = None) -> Catalog:
    target = path or _default_path()
    try:
        return Catalog.model_validate(json.loads(target.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ConfigError(f"cannot load control catalog {target}: {exc}") from exc


def select_controls(
    catalog: Catalog,
    *,
    services: list[str] | None = None,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    min_severity: Severity | None = None,
) -> list[Control]:
    known = {c.id for c in catalog.controls}
    unknown = sorted((set(include or []) | set(exclude or [])) - known)
    if unknown:
        raise ConfigError(f"unknown control id(s): {', '.join(unknown)}")
    out: list[Control] = []
    for c in catalog.controls:
        if include and c.id not in include:
            continue
        if exclude and c.id in exclude:
            continue
        if services and c.service not in services:
            continue
        if min_severity and c.severity.rank < min_severity.rank:
            continue
        out.append(c)
    return out
