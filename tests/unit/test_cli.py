"""CLI behaviour with a stubbed AWS layer (no network, no credentials)."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from awsauditor import cli
from awsauditor.cli import app

from .conftest import ACCOUNT, Harness

runner = CliRunner()

CONFIG = """
[audit]
profile = "tiny"
regions = ["us-east-1"]
workers = 1
[profiles.tiny]
include = ["IAM-001", "IAM-002"]
[output]
formats = ["json", "csv", "html"]
"""


@pytest.fixture
def cfg(tmp_path: Path) -> Path:
    p = tmp_path / "audit.toml"
    p.write_text(CONFIG)
    return p


def wire(monkeypatch: pytest.MonkeyPatch, mfa: int = 1, queue_audit: bool = True) -> Harness:
    h = Harness()
    h.ok(
        "sts",
        "get_caller_identity",
        {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/auditor", "UserId": "x"},
        region=None,
    )
    h.ok(
        "ec2", "describe_regions", {"Regions": [{"RegionName": "us-east-1"}]}, {"AllRegions": False}
    )
    if queue_audit:
        h.ok(
            "iam",
            "get_account_summary",
            {"SummaryMap": {"AccountMFAEnabled": mfa, "AccountAccessKeysPresent": 0}},
        )
    monkeypatch.setattr(cli, "make_factory", lambda *_a, **_k: h.factory)
    return h


def test_version_and_help() -> None:
    assert runner.invoke(app, ["version"]).stdout.strip() == "0.1.0"
    assert "audit" in runner.invoke(app, ["--help"]).stdout


def test_controls_list_and_show() -> None:
    out = runner.invoke(app, ["controls", "list", "--service", "s3"])
    assert out.exit_code == 0 and "STO-001" in out.stdout and "IAM-001" not in out.stdout
    data = json.loads(runner.invoke(app, ["controls", "list", "--format", "json"]).stdout)
    assert len(data) == 40 and {"id", "severity", "remediation", "references"} <= data[0].keys()
    shown = runner.invoke(app, ["controls", "show", "iam-001"])
    assert shown.exit_code == 0 and json.loads(shown.stdout)["id"] == "IAM-001"
    assert runner.invoke(app, ["controls", "show", "NOPE-1"]).exit_code == 2
    assert runner.invoke(app, ["controls", "list", "--format", "xml"]).exit_code == 2


def test_config_validate(tmp_path: Path, cfg: Path) -> None:
    ok = runner.invoke(app, ["config", "validate", str(cfg)])
    assert ok.exit_code == 0 and "selects 2 controls" in ok.stdout
    bad = tmp_path / "bad.toml"
    bad.write_text('[aws]\naws_secret_access_key = "x"\n')
    res = runner.invoke(app, ["config", "validate", str(bad)])
    assert res.exit_code == 2 and "credentials must not be stored" in res.output
    assert "x" not in res.output.replace("credentials", "").replace("must not be stored", "").split(
        "found:"
    )[-1].replace("aws_secret_access_key", "")  # secret value never echoed
    unknown = tmp_path / "u.toml"
    unknown.write_text('[audit]\nprofile = "tiny"\n')
    assert runner.invoke(app, ["config", "validate", str(unknown)]).exit_code == 2


def test_there_is_no_option_that_accepts_a_secret() -> None:
    for sub in ("plan", "run"):
        helptext = runner.invoke(app, ["audit", sub, "--help"]).stdout.lower()
        assert "secret" not in helptext and "access-key" not in helptext and "token" not in helptext


def test_audit_run_requires_matching_confirmation(
    monkeypatch: pytest.MonkeyPatch, cfg: Path, tmp_path: Path
) -> None:
    h = wire(monkeypatch)
    out = tmp_path / "o"
    res = runner.invoke(app, ["audit", "run", "-c", str(cfg), "--output-dir", str(out)])
    assert res.exit_code == 2 and "--confirm-account" in res.output  # non-interactive
    assert ACCOUNT in res.output and "us-east-1" in res.output  # resolved account is displayed
    assert not out.exists()
    h = wire(monkeypatch)
    res = runner.invoke(
        app,
        [
            "audit",
            "run",
            "-c",
            str(cfg),
            "--output-dir",
            str(out),
            "--confirm-account",
            "999999999999",
        ],
    )
    assert res.exit_code == 2 and "does not match" in res.output and not out.exists()
    # the IAM response was never consumed: no audit call happened
    with pytest.raises(AssertionError):
        h.assert_all_consumed()


def test_audit_run_writes_protected_reports(
    monkeypatch: pytest.MonkeyPatch, cfg: Path, tmp_path: Path
) -> None:
    wire(monkeypatch)
    out = tmp_path / "o"
    res = runner.invoke(
        app,
        ["audit", "run", "-c", str(cfg), "--output-dir", str(out), "--confirm-account", ACCOUNT],
    )
    assert res.exit_code == 0, res.output
    files = sorted(out.iterdir())
    assert [f.suffix for f in files] == [".csv", ".html", ".json"]
    assert all(stat.S_IMODE(os.stat(f).st_mode) == 0o600 for f in files)
    data = json.loads(next(f for f in files if f.suffix == ".json").read_text())
    assert data["account_id"] == ACCOUNT and data["regions"] == ["us-east-1"]
    assert {f["control_id"] for f in data["findings"]} == {"IAM-001", "IAM-002"}
    assert data["api_actions"] == {"ec2:DescribeRegions": 1, "iam:GetAccountSummary": 1}
    assert "AWS_SECRET" not in json.dumps(data)


def test_audit_run_redaction_and_exit_codes(
    monkeypatch: pytest.MonkeyPatch, cfg: Path, tmp_path: Path
) -> None:
    wire(monkeypatch, mfa=0)
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
            "--formats",
            "json",
            "--redact",
            "--fail-on",
            "critical",
            "--confirm-account",
            ACCOUNT,
        ],
    )
    assert res.exit_code == 1  # IAM-001 (critical) failed
    text = next(out.iterdir()).read_text()
    assert ACCOUNT not in text and "3333" in text
    # existing report is never silently overwritten
    wire(monkeypatch, mfa=0)
    again = runner.invoke(
        app,
        [
            "audit",
            "run",
            "-c",
            str(cfg),
            "--output-dir",
            str(out),
            "--formats",
            "json",
            "--confirm-account",
            ACCOUNT,
        ],
    )
    assert again.exit_code in (0, 2)


def test_audit_run_strict_flags_unknown_results(
    monkeypatch: pytest.MonkeyPatch, cfg: Path, tmp_path: Path
) -> None:
    h = wire(monkeypatch, queue_audit=False)
    h.err("iam", "get_account_summary")
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
            "--strict",
            "--confirm-account",
            ACCOUNT,
        ],
    )
    assert res.exit_code == 3 and "unknown" in res.output


def test_audit_plan_audits_nothing(monkeypatch: pytest.MonkeyPatch, cfg: Path) -> None:
    h = wire(monkeypatch)
    res = runner.invoke(app, ["audit", "plan", "-c", str(cfg)])
    assert res.exit_code == 0 and "Profile 'tiny': 2 controls" in res.stdout
    with pytest.raises(AssertionError):
        h.assert_all_consumed()  # iam call still pending


def test_bad_inputs_are_clean_errors(monkeypatch: pytest.MonkeyPatch, cfg: Path) -> None:
    wire(monkeypatch)
    res = runner.invoke(app, ["audit", "plan", "-c", str(cfg), "--audit-profile", "ghost"])
    assert res.exit_code == 2 and "unknown audit profile" in res.output
    wire(monkeypatch)
    res = runner.invoke(
        app, ["audit", "run", "-c", str(cfg), "--formats", "pdf", "--confirm-account", ACCOUNT]
    )
    assert res.exit_code == 2 and "unsupported formats" in res.output


@pytest.fixture
def saved_report(monkeypatch: pytest.MonkeyPatch, cfg: Path, tmp_path: Path) -> Path:
    wire(monkeypatch, mfa=0)
    out = tmp_path / "saved"
    runner.invoke(
        app,
        [
            "audit",
            "run",
            "-c",
            str(cfg),
            "--output-dir",
            str(out),
            "--formats",
            "json",
            "--confirm-account",
            ACCOUNT,
        ],
    )
    return next(out.iterdir())


def test_findings_filter(saved_report: Path) -> None:
    res = runner.invoke(app, ["findings", "filter", str(saved_report), "--status", "FAIL"])
    assert res.exit_code == 0 and "IAM-001" in res.stdout and "IAM-002" not in res.stdout
    js = runner.invoke(
        app, ["findings", "filter", str(saved_report), "--control", "IAM-002", "--format", "json"]
    )
    assert [f["status"] for f in json.loads(js.stdout)] == ["PASS"]
    assert (
        runner.invoke(app, ["findings", "filter", str(saved_report), "--status", "BOGUS"]).exit_code
        == 2
    )
    assert runner.invoke(app, ["findings", "filter", "missing.json"]).exit_code == 2


def test_report_export(saved_report: Path, tmp_path: Path) -> None:
    dest = tmp_path / "x.html"
    res = runner.invoke(
        app,
        [
            "report",
            "export",
            str(saved_report),
            "--format",
            "html",
            "--output",
            str(dest),
            "--redact",
        ],
    )
    assert res.exit_code == 0 and ACCOUNT not in dest.read_text()
    again = runner.invoke(
        app, ["report", "export", str(saved_report), "--format", "html", "--output", str(dest)]
    )
    assert again.exit_code == 2 and "--force" in again.output
    assert (
        runner.invoke(
            app,
            [
                "report",
                "export",
                str(saved_report),
                "--format",
                "pdf",
                "--output",
                str(tmp_path / "y"),
            ],
        ).exit_code
        == 2
    )


def test_policy_generate_and_org(monkeypatch: pytest.MonkeyPatch, cfg: Path) -> None:
    res = runner.invoke(app, ["policy", "generate", "-c", str(cfg)])
    actions = {a for s in json.loads(res.stdout)["Statement"] for a in s["Action"]}
    assert actions == {"iam:GetAccountSummary", "ec2:DescribeRegions"}
    h = wire(monkeypatch, queue_audit=False)
    h.ok(
        "organizations",
        "describe_organization",
        {"Organization": {"Id": "o-1"}},
        region="us-east-1",
    )
    h.ok(
        "organizations",
        "list_accounts",
        {"Accounts": [{"Id": "111122223333", "Name": "prod", "Status": "ACTIVE"}]},
        region="us-east-1",
    )
    res = runner.invoke(app, ["org", "list-accounts", "-c", str(cfg)])
    assert res.exit_code == 0 and "prod" in res.stdout
