"""Suppressions, SARIF, report manifest/verify and LOG-013."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from awsauditor import cli
from awsauditor.checks import logging_
from awsauditor.cli import app
from awsauditor.config import REPORT_FORMATS, RedactionSettings, Suppression, parse_config
from awsauditor.errors import ConfigError
from awsauditor.models import Severity, Status
from awsauditor.redaction import Redactor
from awsauditor.reporting import (
    RENDERERS,
    build_manifest,
    build_report,
    to_csv,
    to_html,
    to_json,
    to_sarif,
    verify_manifest,
)
from awsauditor.suppressions import apply_suppressions

from .conftest import ACCOUNT, Harness, statuses
from .test_checks_logging import ARN, stub_status, stub_trails, trail
from .test_reporting import finding, result

runner = CliRunner()
OFF = Redactor(RedactionSettings())
TODAY = date(2026, 10, 16)


def sup(**kw: Any) -> Suppression:
    base = {"control_id": "NET-004", "reason": "Egress filtered by firewall", "owner": "secops",
            "expires": date(2027, 1, 1)}  # fmt: skip
    return Suppression(**{**base, **kw})


# ------------------------------------------------------------- suppressions


def test_matching_suppression_annotates_but_keeps_fail() -> None:
    f = finding("NET-004", Status.FAIL, "sg-1", severity=Severity.LOW)
    warnings = apply_suppressions([f], [sup(resource="sg-*")], TODAY)
    assert f.status is Status.FAIL and f.suppression is not None
    assert (f.suppression.owner, f.suppression.expires) == ("secops", date(2027, 1, 1))
    assert warnings == []


def test_suppression_matching_rules() -> None:
    fails = [
        finding("NET-004", Status.FAIL, "sg-1", region="us-east-1"),
        finding("NET-004", Status.FAIL, "sg-2", region="eu-west-1"),
        finding("NET-001", Status.FAIL, "sg-1"),
        finding("NET-004", Status.PASS, "sg-1"),
        finding("NET-004", Status.ERROR, "sg-1", uncertainty=["u"]),
    ]
    apply_suppressions(fails, [sup(resource="sg-1", region="us-*")], TODAY)
    assert [bool(f.suppression) for f in fails] == [True, False, False, False, False]


def test_expired_suppression_is_ignored_and_reported() -> None:
    f = finding("NET-004", Status.FAIL, "sg-1")
    warnings = apply_suppressions([f], [sup(expires=date(2026, 10, 15))], TODAY)
    assert f.suppression is None and len(warnings) == 1 and "expired on 2026-10-15" in warnings[0]
    # the expiry day itself is still valid
    g = finding("NET-004", Status.FAIL, "sg-1")
    assert apply_suppressions([g], [sup(expires=TODAY)], TODAY) == [] and g.suppression


def test_valid_entry_wins_after_an_expired_one() -> None:
    f = finding("NET-004", Status.FAIL, "sg-1")
    warnings = apply_suppressions(
        [f], [sup(expires=date(2026, 1, 1)), sup(owner="other-owner")], TODAY
    )
    assert f.suppression and f.suppression.owner == "other-owner" and len(warnings) == 1


def test_stale_suppression_is_reported() -> None:
    f = finding("NET-004", Status.PASS, "sg-1")
    warnings = apply_suppressions([f], [sup()], TODAY)
    assert f.suppression is None and "matched no failing finding" in warnings[0]


@pytest.mark.parametrize(
    "bad",
    [
        {"reason": "short"},
        {"owner": "x"},
        {"control_id": "nope"},
        {"expires": "never"},
        {"unknown_key": 1},
    ],
)
def test_suppression_validation(bad: dict[str, Any]) -> None:
    entry = {"control_id": "NET-004", "reason": "long enough reason", "owner": "secops",
             "expires": "2027-01-01", **bad}  # fmt: skip
    with pytest.raises(ConfigError):
        parse_config({"suppressions": [entry]})
    ok = {"control_id": "NET-004", "reason": "long enough reason", "owner": "secops",
          "expires": "2027-01-01"}  # fmt: skip
    assert parse_config({"suppressions": [ok]}).suppressions[0].expires == date(2027, 1, 1)


def test_secrets_inside_list_tables_are_rejected() -> None:
    with pytest.raises(ConfigError, match="credentials must not be stored"):
        parse_config({"suppressions": [{"control_id": "NET-004", "password": "x"}]})


def test_summary_separates_active_from_suppressed() -> None:
    a = finding("NET-004", Status.FAIL, "sg-1", severity=Severity.LOW)
    b = finding("NET-004", Status.FAIL, "sg-2", severity=Severity.LOW)
    apply_suppressions([a, b], [sup(resource="sg-1")], TODAY)
    s = build_report(result([a, b])).summary
    assert s["by_status"]["FAIL"] == 2 and s["active_failures"] == 1
    assert s["suppressed_failures"] == 1 and s["failed_by_severity"]["low"] == 1


def test_suppression_visible_in_every_format() -> None:
    f = finding("NET-004", Status.FAIL, "sg-1")
    apply_suppressions([f], [sup()], TODAY)
    rep = build_report(result([f]))
    assert json.loads(to_json(rep, OFF))["findings"][0]["suppression"]["owner"] == "secops"
    assert "SUPPRESSED until 2027-01-01 by secops" in to_html(rep, OFF)
    assert "secops" in to_csv(rep, OFF)
    sarif = json.loads(to_sarif(rep, OFF))
    assert sarif["runs"][0]["results"][0]["suppressions"][0]["status"] == "accepted"


# ------------------------------------------------------------- SARIF


def test_sarif_structure_levels_and_scope() -> None:
    findings = [
        finding("IAM-001", Status.FAIL, "root", severity=Severity.CRITICAL),
        finding("NET-004", Status.FAIL, "sg-1", severity=Severity.LOW),
        finding("LOG-011", Status.ERROR, "region/x", severity=Severity.MEDIUM, uncertainty=["u"]),
        finding("EBS-002", Status.PASS, "vol-1", severity=Severity.MEDIUM),
        finding("RDS-001", Status.NOT_APPLICABLE, "r", severity=Severity.HIGH),
    ]
    doc = json.loads(to_sarif(build_report(result(findings)), OFF))
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"IAM-001", "NET-004", "LOG-011"}
    by_rule = {r["ruleId"]: r for r in run["results"]}
    assert by_rule["IAM-001"]["level"] == "error" and by_rule["IAM-001"]["kind"] == "fail"
    assert by_rule["NET-004"]["level"] == "note"
    assert (
        by_rule["LOG-011"]["kind"] == "review"
        and "Uncertainty: u" in by_rule["LOG-011"]["message"]["text"]
    )
    assert all("findingId/v1" in r["partialFingerprints"] for r in run["results"])
    assert "EBS-002" not in by_rule and "RDS-001" not in by_rule
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "IAM-001")
    assert float(rule["properties"]["security-severity"]) > 9


def test_sarif_respects_redaction() -> None:
    f = finding("IAM-001", Status.FAIL, f"arn:aws:iam::{ACCOUNT}:root", severity=Severity.CRITICAL)
    out = to_sarif(build_report(result([f])), Redactor(RedactionSettings(enabled=True)))
    assert ACCOUNT not in out


def test_renderer_registry_matches_supported_formats() -> None:
    assert tuple(RENDERERS) == REPORT_FORMATS


# ------------------------------------------------------------- manifest


def test_manifest_roundtrip_and_tamper_detection(tmp_path: Path) -> None:
    files = {"a.json": '{"x": 1}\n', "b.csv": "id\n1\n"}
    for name, text in files.items():
        (tmp_path / name).write_text(text, newline="")
    m = tmp_path / "audit.sha256"
    m.write_text(build_manifest(files))
    assert dict(verify_manifest(m)) == {"a.json": "OK", "b.csv": "OK"}
    (tmp_path / "a.json").write_text('{"x": 2}\n')
    (tmp_path / "b.csv").unlink()
    assert dict(verify_manifest(m)) == {"a.json": "MISMATCH", "b.csv": "MISSING"}


@pytest.mark.parametrize(
    "line",
    ["nothash  file.json", "a" * 64 + " file.json", "a" * 64 + "  ../escape", "a" * 64 + "  a/b"],
)
def test_malformed_or_traversing_manifest_is_rejected(tmp_path: Path, line: str) -> None:
    m = tmp_path / "m.sha256"
    m.write_text(line + "\n")
    with pytest.raises(ConfigError):
        verify_manifest(m)


def test_empty_or_missing_manifest(tmp_path: Path) -> None:
    (tmp_path / "e.sha256").write_text("\n")
    with pytest.raises(ConfigError):
        verify_manifest(tmp_path / "e.sha256")
    with pytest.raises(ConfigError):
        verify_manifest(tmp_path / "nope.sha256")


# ------------------------------------------------------------- CLI end to end

CONFIG = """
[audit]
profile = "tiny"
regions = ["us-east-1"]
workers = 1
[profiles.tiny]
include = ["IAM-001"]
[output]
formats = ["json", "sarif"]

[[suppressions]]
control_id = "IAM-001"
resource = "*"
reason = "Root MFA enforced by hardware token held in the safe"
owner = "secops@example.com"
expires = 2099-01-01
"""


def wire(monkeypatch: pytest.MonkeyPatch) -> Harness:
    h = Harness()
    h.ok(
        "sts",
        "get_caller_identity",
        {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/a", "UserId": "x"},
        region=None,
    )
    h.ok(
        "ec2", "describe_regions", {"Regions": [{"RegionName": "us-east-1"}]}, {"AllRegions": False}
    )
    h.ok(
        "iam",
        "get_account_summary",
        {"SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}},
    )
    monkeypatch.setattr(cli, "make_factory", lambda *_a, **_k: h.factory)
    return h


def test_suppressed_failure_is_shown_but_does_not_trip_fail_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = tmp_path / "c.toml"
    cfg.write_text(CONFIG)
    wire(monkeypatch)
    out = tmp_path / "o"
    res = runner.invoke(
        app,
        [
            "audit",
            "run",
            "-c",
            str(cfg),
            "--output-dir",
            str(out),
            "--fail-on",
            "critical",
            "--confirm-account",
            ACCOUNT,
        ],
    )
    assert res.exit_code == 0, res.output
    assert "suppressed (still shown)" in res.output
    data = json.loads(next(out.glob("*.json")).read_text())
    f = data["findings"][0]
    assert f["status"] == "FAIL" and f["suppression"]["owner"] == "secops@example.com"
    assert data["summary"]["active_failures"] == 0 and data["summary"]["suppressed_failures"] == 1
    assert json.loads(next(out.glob("*.sarif")).read_text())["version"] == "2.1.0"
    manifest = next(out.glob("*.sha256"))
    ok = runner.invoke(app, ["report", "verify", str(manifest)])
    assert ok.exit_code == 0 and ok.output.count("OK") == 2
    next(out.glob("*.json")).write_text("tampered")
    bad = runner.invoke(app, ["report", "verify", str(manifest)])
    assert bad.exit_code == 1 and "MISMATCH" in bad.output


def test_expired_suppression_warns_and_fails_the_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = tmp_path / "c.toml"
    cfg.write_text(CONFIG.replace("2099-01-01", "2020-01-01"))
    wire(monkeypatch)
    res = runner.invoke(
        app,
        [
            "audit",
            "run",
            "-c",
            str(cfg),
            "--output-dir",
            str(tmp_path / "o"),
            "--formats",
            "json",
            "--fail-on",
            "critical",
            "--confirm-account",
            ACCOUNT,
        ],
    )
    assert res.exit_code == 1 and "expired on 2020-01-01" in res.output


def test_config_validate_rejects_unknown_suppression_control(tmp_path: Path) -> None:
    cfg = tmp_path / "c.toml"
    cfg.write_text(
        CONFIG.replace('control_id = "IAM-001"\nresource', 'control_id = "ZZZ-999"\nresource')
    )
    res = runner.invoke(app, ["config", "validate", str(cfg)])
    assert res.exit_code == 2 and "ZZZ-999" in res.output
    cfg.write_text(CONFIG)
    ok = runner.invoke(app, ["config", "validate", str(cfg)])
    assert ok.exit_code == 0 and "1 suppression(s)" in ok.stdout


def test_export_to_sarif_and_verify_errors(tmp_path: Path) -> None:
    rep = tmp_path / "r.json"
    rep.write_text(to_json(build_report(result([finding()])), OFF))
    dest = tmp_path / "r.sarif"
    res = runner.invoke(
        app, ["report", "export", str(rep), "--format", "sarif", "--output", str(dest)]
    )
    assert res.exit_code == 0 and json.loads(dest.read_text())["runs"][0]["results"]
    assert runner.invoke(app, ["report", "verify", str(tmp_path / "missing.sha256")]).exit_code == 2


def test_written_report_bytes_match_manifest_hash(tmp_path: Path) -> None:
    from awsauditor.reporting import write_report_file
    from awsauditor.reporting.manifest import digest

    text = "line1\nline2\r\nunicode ✓\n"
    p = tmp_path / "x.txt"
    write_report_file(p, text)
    import hashlib

    assert hashlib.sha256(p.read_bytes()).hexdigest() == digest(text)


# ------------------------------------------------------------- LOG-013


def stub_selectors(h: Harness, **sel: Any) -> None:
    h.ok("cloudtrail", "get_event_selectors", {"TrailARN": ARN, **sel}, {"TrailName": ARN})


def selector(rw: str, include: bool) -> dict[str, Any]:
    return {"EventSelectors": [{"ReadWriteType": rw, "IncludeManagementEvents": include}]}


BASIC_ALL = {"EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": True}]}
ADV_ALL = {"AdvancedEventSelectors": [{"Name": "m", "FieldSelectors": [
    {"Field": "eventCategory", "Equals": ["Management"]}]}]}  # fmt: skip


@pytest.mark.parametrize(
    ("selectors", "expected"),
    [
        (BASIC_ALL, "PASS"),
        (ADV_ALL, "PASS"),
        (selector("WriteOnly", True), "FAIL"),
        (selector("ReadOnly", True), "FAIL"),
        (selector("All", False), "FAIL"),
        ({"EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": True,
                              "ExcludeManagementEventSources": ["kms.amazonaws.com"]}]}, "FAIL"),
        ({"AdvancedEventSelectors": [{"Name": "m", "FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Management"]},
            {"Field": "readOnly", "Equals": ["false"]}]}]}, "FAIL"),
        ({"AdvancedEventSelectors": [{"Name": "d", "FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Data"]}]}]}, "FAIL"),
        ({}, "FAIL"),
    ],
)  # fmt: skip
def test_log013_selector_shapes(h: Harness, selectors: dict[str, Any], expected: str) -> None:
    stub_trails(h, [trail()], shadow=True)
    stub_status(h)
    stub_selectors(h, **selectors)
    f = logging_.management_events(h.ctx(account_scope=True))
    assert statuses(f) == [expected] and f[0].region == "global"
    h.assert_all_consumed()


def test_log013_one_good_trail_among_bad_passes(h: Harness) -> None:
    other = trail(Name="other", TrailARN=ARN + "o")
    stub_trails(h, [other, trail()], shadow=True)
    h.ok("cloudtrail", "get_trail_status", {"IsLogging": True}, {"Name": ARN + "o"})
    h.ok(
        "cloudtrail",
        "get_event_selectors",
        {
            "TrailARN": ARN + "o",
            "EventSelectors": [{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True}],
        },
        {"TrailName": ARN + "o"},
    )
    stub_status(h)
    stub_selectors(h, **BASIC_ALL)
    assert statuses(logging_.management_events(h.ctx(account_scope=True))) == ["PASS"]


def test_log013_skips_stopped_and_single_region_trails(h: Harness) -> None:
    stopped = trail(Name="s", TrailARN=ARN + "s")
    single = trail(Name="one", TrailARN=ARN + "1", IsMultiRegionTrail=False)
    stub_trails(h, [stopped, single], shadow=True)
    h.ok("cloudtrail", "get_trail_status", {"IsLogging": False}, {"Name": ARN + "s"})
    f = logging_.management_events(h.ctx(account_scope=True))
    assert statuses(f) == ["FAIL"] and f[0].evidence["logging_multi_region_trails"] == []


def test_log013_denied_selectors_is_error_not_fail(h: Harness) -> None:
    stub_trails(h, [trail()], shadow=True)
    stub_status(h)
    h.err("cloudtrail", "get_event_selectors")
    assert statuses(logging_.management_events(h.ctx(account_scope=True))) == ["ERROR"]
    h.err("cloudtrail", "describe_trails")
    assert statuses(logging_.management_events(h.ctx(account_scope=True))) == ["ERROR"]


def test_log013_queries_the_trail_home_region(h: Harness) -> None:
    stub_trails(h, [trail(HomeRegion="eu-west-1")], shadow=True)
    stub_status(h, region="eu-west-1")
    h.ok("cloudtrail", "get_event_selectors", {"TrailARN": ARN, **BASIC_ALL}, {"TrailName": ARN},
         region="eu-west-1")  # fmt: skip
    assert statuses(logging_.management_events(h.ctx(account_scope=True))) == ["PASS"]
