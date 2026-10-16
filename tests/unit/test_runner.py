"""Runner: scheduling, partial results, coverage guarantees, determinism."""

from __future__ import annotations

from typing import Any

import pytest

import awsauditor.checks  # noqa: F401
from awsauditor import runner
from awsauditor.catalog import select_controls
from awsauditor.config import AuditConfig, AuditSettings
from awsauditor.context import CheckContext, CheckSpec
from awsauditor.models import Finding, Status
from awsauditor.regions import RegionPlan
from awsauditor.session import Identity

from .conftest import ACCOUNT, NOW, Harness, assert_wellformed, error_payload


def identity() -> Identity:
    return Identity(ACCOUNT, f"arn:aws:iam::{ACCOUNT}:user/auditor", "aws")


def run(h: Harness, controls: list[str] | None, regions: list[str], workers: int = 4) -> Any:
    cfg = AuditConfig(audit=AuditSettings(workers=workers))
    selected = (
        select_controls(h.catalog, include=controls) if controls else list(h.catalog.controls)
    )
    plan = RegionPlan(audited=regions, enabled=regions)
    return runner.run_audit(
        h.factory,
        identity(),
        cfg,
        h.catalog,
        selected,
        plan,
        home_region=regions[0],
        profile_name="test",
        sleep=lambda _s: None,
        now=lambda: NOW,
    )


def test_full_catalog_with_every_call_denied_yields_only_unknown_results() -> None:
    h = Harness()
    h.factory.fault = error_payload("AccessDenied", 403)
    result = run(h, None, ["us-east-1", "eu-west-1"], workers=8)
    by_control = {c.id for c in h.catalog.controls}
    assert {f.control_id for f in result.findings} == by_control
    bad = [
        f
        for f in result.findings
        if f.status not in (Status.ERROR, Status.NOT_ASSESSED) and f.control_id != "COV-001"
    ]
    assert not bad, [(f.control_id, f.status) for f in bad]
    assert_wellformed(result.findings)
    # region-scoped controls ran once per region, account-scoped exactly once
    iam003 = [f for f in result.findings if f.control_id == "IAM-003"]
    assert len(iam003) == 1 and iam003[0].region == "global"
    assert {f.region for f in result.findings if f.control_id == "EBS-001"} == {
        "us-east-1",
        "eu-west-1",
    }


def test_results_are_sorted_and_deterministic_across_worker_counts() -> None:
    outs = []
    for workers in (1, 8):
        h = Harness()
        h.factory.fault = error_payload("AccessDenied", 403)
        r = run(h, ["EBS-001", "NET-001", "IAM-001"], ["us-east-1", "eu-west-1"], workers)
        outs.append([(f.control_id, f.region, f.resource_id, f.status) for f in r.findings])
    assert outs[0] == outs[1] == sorted(outs[0], key=lambda t: t[:3])


def test_only_selected_controls_run_and_metadata_is_recorded() -> None:
    h = Harness()
    h.ok(
        "iam",
        "get_account_summary",
        {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}},
    )
    r = run(h, ["IAM-001"], ["us-east-1"])
    assert [f.control_id for f in r.findings] == ["IAM-001"]
    assert r.control_ids == ["IAM-001"] and r.catalog_version == h.catalog.catalog_version
    assert r.api_actions == {"iam:GetAccountSummary": 1}
    assert r.started_at == NOW and r.account_id == ACCOUNT


def test_partial_results_when_one_check_crashes(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness()

    def good(ctx: CheckContext) -> list[Finding]:
        return [ctx.finding("IAM-001", Status.PASS, "r", "t", "ok")]

    def crash(_ctx: CheckContext) -> list[Finding]:
        raise ValueError("unexpected shape")

    monkeypatch.setattr(
        runner, "REGISTRY", [CheckSpec(("IAM-001",), good), CheckSpec(("IAM-002",), crash)]
    )
    r = run(h, ["IAM-001", "IAM-002"], ["us-east-1"])
    got = {f.control_id: f.status for f in r.findings}
    assert got == {"IAM-001": Status.PASS, "IAM-002": Status.ERROR}


def test_check_that_forgets_a_control_is_reported_not_assessed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    h = Harness()

    def partial(ctx: CheckContext) -> list[Finding]:
        return [ctx.finding("IAM-001", Status.PASS, "r", "t", "ok")]

    monkeypatch.setattr(runner, "REGISTRY", [CheckSpec(("IAM-001", "IAM-002"), partial)])
    r = run(h, ["IAM-001", "IAM-002"], ["us-east-1"])
    got = {f.control_id: f.status for f in r.findings}
    assert got["IAM-002"] is Status.NOT_ASSESSED


def test_findings_for_unselected_controls_are_dropped(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness()

    def both(ctx: CheckContext) -> list[Finding]:
        return [ctx.finding(c, Status.PASS, "r", "t", "ok") for c in ("IAM-001", "IAM-002")]

    monkeypatch.setattr(runner, "REGISTRY", [CheckSpec(("IAM-001", "IAM-002"), both)])
    assert [f.control_id for f in run(h, ["IAM-001"], ["us-east-1"]).findings] == ["IAM-001"]


def test_progress_callback_and_warnings() -> None:
    h = Harness()
    h.factory.fault = error_payload("AccessDenied", 403)
    seen: list[str] = []
    plan = RegionPlan(["us-east-1"], ["us-east-1"], warnings=["w1"])
    r = runner.run_audit(
        h.factory,
        identity(),
        AuditConfig(),
        h.catalog,
        select_controls(h.catalog, include=["IAM-001"]),
        plan,
        home_region="us-east-1",
        profile_name="p",
        progress=seen.append,
    )
    assert seen and r.warnings == ["w1"]
