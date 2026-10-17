"""SARIF 2.1.0 output. AWS resources have no source location, so results use logical locations."""

from __future__ import annotations

import json
from typing import Any

from .. import __version__
from ..models import Severity, Status
from ..redaction import Redactor
from .model import Report

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_KIND = {Status.FAIL: "fail", Status.ERROR: "review", Status.NOT_ASSESSED: "review"}


def to_sarif(report: Report, redactor: Redactor) -> str:
    """FAIL findings plus unknown results (ERROR/NOT_ASSESSED, kind ``review``).

    PASS and NOT_APPLICABLE are omitted; the JSON report remains the complete record.
    """
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in report.findings:
        if f.status not in _KIND:
            continue
        rules.setdefault(
            f.control_id,
            {
                "id": f.control_id,
                "name": f.control_id.replace("-", ""),
                "shortDescription": {"text": f.title},
                "help": {"text": f.remediation},
                "defaultConfiguration": {"level": _LEVEL[f.severity]},
                "properties": {"security-severity": _SECURITY_SEVERITY[f.severity]},
            },
        )
        text = f.message + (" Uncertainty: " + " ".join(f.uncertainty) if f.uncertainty else "")
        result: dict[str, Any] = {
            "ruleId": f.control_id,
            "kind": _KIND[f.status],
            "level": _LEVEL[f.severity] if f.status is Status.FAIL else "note",
            "message": {"text": text},
            "locations": [
                {
                    "logicalLocations": [
                        {
                            "name": f.resource_id,
                            "kind": "resource",
                            "fullyQualifiedName": (f"{f.account_id}/{f.region}/{f.resource_id}"),
                        }
                    ]
                }
            ],
            "partialFingerprints": {"findingId/v1": f.finding_id},
            "properties": {
                "status": f.status.value,
                "region": f.region,
                "severity": f.severity.value,
            },
        }
        if f.suppression:
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": f"{f.suppression.reason} (owner {f.suppression.owner}, "
                    f"expires {f.suppression.expires})",
                }
            ]
        results.append(result)
    doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aws-security-auditing-tool",
                        "version": __version__,
                        "rules": sorted(rules.values(), key=lambda r: r["id"]),
                    }
                },
                "automationDetails": {"id": f"aws-audit/{report.audit_profile}/"},
                "properties": {"catalogVersion": report.catalog_version},
                "results": results,
            }
        ],
    }
    return json.dumps(redactor.apply(doc), indent=2) + "\n"


_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}
