"""Report building, JSON/CSV/HTML output, redaction, filtering and file protection."""

from __future__ import annotations

import csv
import io
import json
import os
import stat
from pathlib import Path

import pytest

from awsauditor.config import RedactionSettings
from awsauditor.errors import AuditorError, ConfigError
from awsauditor.models import Finding, Severity, Status
from awsauditor.redaction import Redactor
from awsauditor.reporting import (
    build_report,
    filter_findings,
    load_report,
    to_csv,
    to_html,
    to_json,
    write_report_file,
)
from awsauditor.runner import AuditResult

from .conftest import ACCOUNT, NOW

OFF = Redactor(RedactionSettings())
ON = Redactor(RedactionSettings(enabled=True, ip_addresses=True))


def finding(
    cid: str = "NET-001",
    status: Status = Status.FAIL,
    resource: str = "sg-1",
    region: str = "us-east-1",
    severity: Severity = Severity.HIGH,
    message: str = "m",
    **kw,
) -> Finding:  # type: ignore[no-untyped-def]
    return Finding(
        control_id=cid,
        title="t",
        account_id=ACCOUNT,
        region=region,
        resource_id=resource,
        resource_type="x",
        severity=severity,
        status=status,
        message=message,
        observed_at=NOW,
        remediation="Fix it.",
        **kw,
    )


def result(findings: list[Finding]) -> AuditResult:
    return AuditResult(
        findings,
        NOW,
        NOW,
        ACCOUNT,
        ["us-east-1"],
        "baseline",
        "2026.10.0",
        sorted({f.control_id for f in findings}),
        {"ec2:DescribeVolumes": 2},
        ["warn"],
    )


MIXED = [
    finding(),
    finding("EBS-002", Status.PASS, "vol-1", severity=Severity.MEDIUM),
    finding(
        "LOG-011",
        Status.ERROR,
        "region/eu-west-1",
        "eu-west-1",
        Severity.MEDIUM,
        uncertainty=["unknown"],
    ),
    finding("RDS-001", Status.NOT_APPLICABLE, "region/us-east-1", severity=Severity.HIGH),
    finding("LOG-012", Status.NOT_ASSESSED, "r", severity=Severity.MEDIUM, uncertainty=["u"]),
]


def test_summary_counts_and_unknown_controls() -> None:
    rep = build_report(result(MIXED))
    s = rep.summary
    assert s["by_status"] == {
        "PASS": 1,
        "FAIL": 1,
        "ERROR": 1,
        "NOT_APPLICABLE": 1,
        "NOT_ASSESSED": 1,
    }
    assert s["failed_by_severity"]["high"] == 1 and s["failed_by_severity"]["critical"] == 0
    assert s["controls_with_unknown_results"] == {"LOG-011": 1, "LOG-012": 1}
    assert rep.tool["name"] == "aws-security-auditing-tool"
    assert "not a certified" in rep.disclaimer or "certified" in rep.disclaimer


def test_json_roundtrip_and_stable_fields(tmp_path: Path) -> None:
    rep = build_report(result(MIXED))
    text = to_json(rep, OFF)
    data = json.loads(text)
    for key in (
        "control_id",
        "resource_id",
        "region",
        "severity",
        "status",
        "evidence",
        "observed_at",
        "remediation",
        "uncertainty",
        "finding_id",
    ):
        assert key in data["findings"][0]
    p = tmp_path / "r.json"
    p.write_text(text)
    assert load_report(p).findings == rep.findings


def test_load_report_rejects_garbage(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text('{"schema_version": 1}')
    with pytest.raises(ConfigError):
        load_report(p)
    with pytest.raises(ConfigError):
        load_report(tmp_path / "missing.json")


def test_csv_columns_and_injection_defence() -> None:
    evil = finding(message='=HYPERLINK("http://x")', resource="+cmd|' /C calc'!A0")
    rows = list(csv.DictReader(io.StringIO(to_csv(build_report(result([evil])), OFF))))
    assert rows[0]["message"].startswith("'=") and rows[0]["resource_id"].startswith("'+")
    assert rows[0]["control_id"] == "NET-001" and rows[0]["severity"] == "high"


def test_html_escapes_untrusted_values_and_is_self_contained() -> None:
    evil = finding(message="<script>alert(1)</script>", resource='"><img src=x onerror=1>')
    html = to_html(build_report(result([evil])), OFF)
    assert "<script>" not in html and "<img" not in html
    assert "&lt;script&gt;" in html
    assert "default-src 'none'" in html and "http://" not in html and "https://" not in html
    assert "Fix it." in html  # remediation shown for failures


def test_html_orders_failures_first() -> None:
    html = to_html(build_report(result(MIXED)), OFF)
    assert html.index(">FAIL<") < html.index(">PASS<")


def test_redaction_applies_to_all_formats() -> None:
    f = finding(resource=f"arn:aws:iam::{ACCOUNT}:user/a", evidence={"cidr": "10.1.2.3/32"})
    rep = build_report(result([f]))
    for render in (to_json, to_csv, to_html):
        out = render(rep, ON)
        assert ACCOUNT not in out and "10.1.2.3" not in out
        assert "3333" in out  # last four digits kept for correlation
    assert ACCOUNT in to_json(rep, OFF)


def test_report_file_permissions_and_overwrite_protection(tmp_path: Path) -> None:
    target = tmp_path / "out" / "r.json"
    write_report_file(target, "one")
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(target.parent).st_mode) == 0o700
    with pytest.raises(AuditorError, match="--force"):
        write_report_file(target, "two")
    assert target.read_text() == "one"
    write_report_file(target, "two", overwrite=True)
    assert target.read_text() == "two" and stat.S_IMODE(os.stat(target).st_mode) == 0o600


def test_filter_findings() -> None:
    assert [f.control_id for f in filter_findings(MIXED, statuses=[Status.FAIL, Status.ERROR])] == [
        "NET-001",
        "LOG-011",
    ]
    assert {f.control_id for f in filter_findings(MIXED, min_severity=Severity.HIGH)} == {
        "NET-001",
        "RDS-001",
    }
    assert [f.control_id for f in filter_findings(MIXED, control_ids=["EBS-002"])] == ["EBS-002"]
    assert [f.region for f in filter_findings(MIXED, regions=["eu-west-1"])] == ["eu-west-1"]
    assert [f.resource_id for f in filter_findings(MIXED, resource_contains="VOL")] == ["vol-1"]
    assert filter_findings(MIXED, statuses=[Status.FAIL], control_ids=["EBS-002"]) == []
    assert len(filter_findings(MIXED)) == len(MIXED)


def test_committed_sample_report_is_schema_valid_synthetic_and_redacted() -> None:
    sample = Path(__file__).resolve().parents[2] / "examples" / "sample-report.json"
    rep = load_report(sample)
    assert any("SYNTHETIC" in w for w in rep.warnings)
    assert ACCOUNT not in sample.read_text()
    assert {f.status for f in rep.findings} >= {Status.PASS, Status.FAIL, Status.ERROR}
