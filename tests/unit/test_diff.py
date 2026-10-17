"""report diff: regressions, resolutions, unknowns and CLI behaviour."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from typer.testing import CliRunner

from awsauditor.cli import app
from awsauditor.config import RedactionSettings
from awsauditor.models import Severity, Status
from awsauditor.redaction import Redactor
from awsauditor.reporting import build_report, diff_reports, to_json

from .conftest import ACCOUNT, NOW
from .test_reporting import finding, result

runner = CliRunner()


def rep(*findings, account: str = ACCOUNT, catalog: str = "2026.10.0", later: int = 0):  # type: ignore[no-untyped-def]
    r = result(list(findings))
    r.account_id, r.catalog_version = account, catalog
    r.finished_at = NOW + timedelta(days=later)
    return build_report(r)


def fnd(cid: str, status: Status, resource: str = "r1", **kw):  # type: ignore[no-untyped-def]
    return finding(cid, status, resource, severity=kw.pop("severity", Severity.HIGH), **kw)


def test_classification() -> None:
    old = rep(
        fnd("A-001", Status.FAIL, "fixed"),
        fnd("A-001", Status.FAIL, "still"),
        fnd("A-001", Status.FAIL, "gone"),
        fnd("A-001", Status.FAIL, "now-unknown"),
        fnd("A-001", Status.PASS, "was-ok"),
        fnd("A-001", Status.PASS, "now-unknown2"),
        fnd("A-001", Status.ERROR, "was-error", uncertainty=["u"]),
    )
    new = rep(
        fnd("A-001", Status.PASS, "fixed"),
        fnd("A-001", Status.FAIL, "still"),
        fnd("A-001", Status.ERROR, "now-unknown", uncertainty=["u"]),
        fnd("A-001", Status.FAIL, "was-ok"),
        fnd("A-001", Status.NOT_ASSESSED, "now-unknown2", uncertainty=["u"]),
        fnd("A-001", Status.FAIL, "was-error"),
        fnd("A-001", Status.FAIL, "brand-new"),
        later=7,
    )
    d = diff_reports(old, new)
    ids = {
        k: sorted(i["resource_id"] for i in d[k])
        for k in ("regressions", "resolved", "became_unknown", "not_reported")
    }
    assert ids == {
        "regressions": ["brand-new", "was-error", "was-ok"],
        "resolved": ["fixed"],
        "became_unknown": ["now-unknown", "now-unknown2"],
        "not_reported": ["gone"],
    }
    assert d["counts"]["unchanged"] == 1  # "still" failing is unchanged
    assert (
        next(i for i in d["regressions"] if i["resource_id"] == "was-ok")["previous_status"]
        == "PASS"
    )
    assert "previous_status" not in next(
        i for i in d["regressions"] if i["resource_id"] == "brand-new"
    )


def test_notes_for_mismatched_reports() -> None:
    d = diff_reports(
        rep(fnd("A-001", Status.PASS)),
        rep(fnd("A-001", Status.PASS), account="999999999999", catalog="2026.11.0"),
    )
    assert len(d["notes"]) == 2 and d["counts"]["unchanged"] == 1


def test_identical_reports_have_no_changes() -> None:
    a = rep(fnd("A-001", Status.FAIL), fnd("A-002", Status.PASS))
    d = diff_reports(a, a)
    assert d["counts"] == {"regressions": 0, "resolved": 0, "became_unknown": 0,
                           "not_reported": 0, "unchanged": 2}  # fmt: skip


def save(tmp_path: Path, name: str, report) -> Path:  # type: ignore[no-untyped-def]
    p = tmp_path / name
    p.write_text(to_json(report, Redactor(RedactionSettings())))
    return p


def test_cli_diff(tmp_path: Path) -> None:
    old = save(
        tmp_path,
        "old.json",
        rep(fnd("NET-001", Status.PASS, "sg-1"), fnd("NET-001", Status.FAIL, "sg-2")),
    )
    new = save(
        tmp_path,
        "new.json",
        rep(fnd("NET-001", Status.FAIL, "sg-1"), fnd("NET-001", Status.PASS, "sg-2"), later=1),
    )
    res = runner.invoke(app, ["report", "diff", str(old), str(new)])
    assert res.exit_code == 0 and "NEW FAILURES: 1" in res.stdout and "RESOLVED: 1" in res.stdout
    js = runner.invoke(app, ["report", "diff", str(old), str(new), "--format", "json"])
    assert json.loads(js.stdout)["regressions"][0]["resource_id"] == "sg-1"
    gate = runner.invoke(app, ["report", "diff", str(old), str(new), "--fail-on-regression"])
    assert gate.exit_code == 1
    clean = runner.invoke(app, ["report", "diff", str(new), str(old), "--fail-on-regression"])
    assert clean.exit_code == 1  # reversed direction regresses sg-2
    same = runner.invoke(app, ["report", "diff", str(old), str(old), "--fail-on-regression"])
    assert same.exit_code == 0
    assert runner.invoke(app, ["report", "diff", str(old), "missing.json"]).exit_code == 2
    assert (
        runner.invoke(app, ["report", "diff", str(old), str(new), "--format", "x"]).exit_code == 2
    )


def test_cli_workers_option_is_validated(tmp_path: Path) -> None:
    assert runner.invoke(app, ["audit", "run", "--workers", "0"]).exit_code == 2
    assert runner.invoke(app, ["audit", "run", "--workers", "99"]).exit_code == 2


def test_region_difference_is_noted_and_printed(tmp_path: Path) -> None:
    a = rep(fnd("A-001", Status.PASS))
    b = rep(fnd("A-001", Status.PASS))
    b.regions = ["eu-west-1"]
    assert any("regions differ" in n for n in diff_reports(a, b)["notes"])
    res = runner.invoke(
        app, ["report", "diff", str(save(tmp_path, "a.json", a)), str(save(tmp_path, "b.json", b))]
    )
    assert res.exit_code == 0 and "note: Audited regions differ" in res.output
