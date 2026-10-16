"""The serialized report envelope and finding filters."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from .. import __version__
from ..errors import ConfigError
from ..models import Finding, Severity, Status
from ..runner import AuditResult

SCHEMA_VERSION = 1
DISCLAIMER = (
    "Point-in-time, read-only configuration assessment. Controls are inspired by, but are not a "
    "certified implementation of, the CIS AWS Foundations Benchmark. PASS means the evidence "
    "gathered met the control's criteria, not that the account is secure. ERROR and NOT_ASSESSED "
    "mean the result is unknown."
)


class Report(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    tool: dict[str, str]
    catalog_version: str
    generated_at: datetime
    started_at: datetime
    account_id: str
    regions: list[str]
    audit_profile: str
    controls_evaluated: list[str]
    summary: dict[str, Any]
    api_actions: dict[str, int]
    warnings: list[str]
    disclaimer: str
    findings: list[Finding]


def summarize(findings: list[Finding]) -> dict[str, Any]:
    by_status = Counter(f.status.value for f in findings)
    fail_by_sev = Counter(f.severity.value for f in findings if f.status is Status.FAIL)
    incomplete: dict[str, int] = {}
    for f in findings:
        if f.status in (Status.ERROR, Status.NOT_ASSESSED):
            incomplete[f.control_id] = incomplete.get(f.control_id, 0) + 1
    return {
        "total_findings": len(findings),
        "by_status": {s.value: by_status.get(s.value, 0) for s in Status},
        "failed_by_severity": {s.value: fail_by_sev.get(s.value, 0) for s in Severity},
        "controls_with_unknown_results": dict(sorted(incomplete.items())),
    }


def build_report(result: AuditResult) -> Report:
    return Report(
        schema_version=SCHEMA_VERSION,
        tool={"name": "aws-security-auditing-tool", "version": __version__},
        catalog_version=result.catalog_version,
        generated_at=result.finished_at,
        started_at=result.started_at,
        account_id=result.account_id,
        regions=result.regions,
        audit_profile=result.profile,
        controls_evaluated=result.control_ids,
        summary=summarize(result.findings),
        api_actions=result.api_actions,
        warnings=result.warnings,
        disclaimer=DISCLAIMER,
        findings=result.findings,
    )


def load_report(path: Path) -> Report:
    try:
        return Report.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ConfigError(f"cannot load report {path}: {exc}") from exc


def filter_findings(
    findings: list[Finding],
    *,
    statuses: list[Status] | None = None,
    min_severity: Severity | None = None,
    control_ids: list[str] | None = None,
    regions: list[str] | None = None,
    resource_contains: str | None = None,
) -> list[Finding]:
    out = []
    for f in findings:
        if statuses and f.status not in statuses:
            continue
        if min_severity and f.severity.rank < min_severity.rank:
            continue
        if control_ids and f.control_id not in control_ids:
            continue
        if regions and f.region not in regions:
            continue
        if resource_contains and resource_contains.lower() not in f.resource_id.lower():
            continue
        out.append(f)
    return out
