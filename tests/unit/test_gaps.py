"""Branches and behaviours found untested during the gap review."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import ClientError, NoCredentialsError, ParamValidationError
from typer.testing import CliRunner

from awsauditor import catalog as catalog_mod
from awsauditor import cli
from awsauditor.checks import iam, logging_, monitoring, s3
from awsauditor.cli import app
from awsauditor.config import parse_config
from awsauditor.context import SharedCache
from awsauditor.errors import AuditorError, classify_exception
from awsauditor.models import Catalog, Control, Status

from .conftest import ACCOUNT, Harness, fixture_text, statuses
from .test_checks_iam import CR, stub_report
from .test_checks_logging import (
    CIS_UNAUTH,
    LG_ARN,
    PAB_NONE,
    stub_filters,
    stub_trail_and_location,
    stub_trails,
)
from .test_checks_network_storage import ALL, stub_buckets

runner = CliRunner()


# ------------------------------------------------------------- error classification


def test_expired_credentials_and_missing_credentials_are_explicit_errors() -> None:
    expired = ClientError({"Error": {"Code": "ExpiredToken", "Message": "m"}}, "GetThing")
    status, msg, unc = classify_exception(expired)
    assert status is Status.ERROR and "expired" in msg and "re-run" in unc.lower()
    for exc in (NoCredentialsError(), ParamValidationError(report="bad")):
        status, msg, _ = classify_exception(exc)
        assert status is Status.ERROR
    assert "credentials" in classify_exception(NoCredentialsError())[1]
    assert "ParamValidationError" in classify_exception(ParamValidationError(report="x"))[1]


# ------------------------------------------------------------- shared cache


def test_cache_computes_once_across_threads_and_caches_failures() -> None:
    cache = SharedCache()
    calls: list[int] = []

    def compute() -> int:
        calls.append(1)
        return 7

    threads = [threading.Thread(target=cache.get_or_compute, args=("k", compute)) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert calls == [1] and cache.get_or_compute("k", compute) == 7

    def boom() -> None:
        calls.append(2)
        raise ValueError("denied")

    for _ in range(3):
        with pytest.raises(ValueError, match="denied"):
            cache.get_or_compute("bad", boom)
    assert calls.count(2) == 1


def test_slow_computation_does_not_block_other_keys() -> None:
    cache = SharedCache()
    started, release = threading.Event(), threading.Event()

    def slow() -> str:
        started.set()
        release.wait(5)
        return "slow"

    t = threading.Thread(target=cache.get_or_compute, args=("slow", slow))
    t.start()
    assert started.wait(5)
    # would deadlock/timeout with a single global lock
    assert cache.get_or_compute("fast", lambda: "fast") == "fast"
    release.set()
    t.join()


# ------------------------------------------------------------- models / config / catalog


def test_duplicate_control_ids_rejected_and_valid_role_arn_accepted(catalog: Catalog) -> None:
    dup = catalog.model_dump(mode="json")
    dup["controls"].append(dup["controls"][0])
    with pytest.raises(ValueError, match="duplicate control ids"):
        Catalog.model_validate(dup)
    cfg = parse_config({"aws": {"role_arn": "arn:aws:iam::111122223333:role/Audit"}})
    assert cfg.aws.role_arn == "arn:aws:iam::111122223333:role/Audit"
    assert isinstance(catalog.controls[0], Control)


def test_catalog_falls_back_to_bundled_copy_when_not_in_a_checkout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / "site-packages" / "awsauditor" / "catalog.py"
    fake.parent.mkdir(parents=True)
    monkeypatch.setattr(catalog_mod, "__file__", str(fake))
    path = catalog_mod._default_path()
    assert path.parts[-3:] == ("awsauditor", "data", "catalog.json")


# ------------------------------------------------------------- IAM credential report edge cases


def csv_with(*mutations: tuple[str, str]) -> str:
    text = fixture_text(CR)
    for old, new in mutations:
        assert old in text
        text = text.replace(old, new, 1)
    return text


def test_iam004_not_applicable_when_no_active_credentials(h: Harness) -> None:
    lines = fixture_text(CR).splitlines()
    ci = lines[4].replace(",true,2025-06-01", ",false,2025-06-01")  # svc-ci key 1 inactive
    stub_report(h, "\n".join([lines[0], lines[1], ci]) + "\n")
    f = iam.unused_credentials(h.ctx(account_scope=True))
    assert statuses(f) == ["NOT_APPLICABLE"]


def test_report_fetch_failure_other_than_not_ready_is_error(h: Harness) -> None:
    h.ok("iam", "generate_credential_report", {"State": "COMPLETE"})
    h.err("iam", "get_credential_report", "AccessDenied", 403)
    f = iam.console_mfa(h.ctx(account_scope=True))
    assert statuses(f) == ["ERROR"] and h.sleeps == []


def test_timestamp_without_timezone_and_active_key_without_rotation_are_errors(h: Harness) -> None:
    stub_report(h, csv_with(("2026-10-10T00:00:00+00:00", "2026-10-10T00:00:00")))
    assert "ERROR" in statuses(iam.unused_credentials(h.ctx(account_scope=True)))
    stub_report(h, csv_with(("true,2026-08-01T00:00:00+00:00", "true,N/A")))
    assert "ERROR" in statuses(iam.key_rotation(h.ctx(account_scope=True)))


# ------------------------------------------------------------- S3 / trail bucket error paths


def test_sto002_bucket_level_denied_is_error_not_pass(h: Harness) -> None:
    stub_buckets(h, ["b"], {"b": "us-east-1"})
    h.err("s3", "get_public_access_block", "AccessDenied", 403)
    assert statuses(s3.bucket_pab(h.ctx())) == ["ERROR"]


def test_log005_policy_status_denied_is_error(h: Harness) -> None:
    stub_trail_and_location(h)
    h.err("s3", "get_public_access_block", PAB_NONE, 404)
    h.err("s3control", "get_public_access_block", PAB_NONE, 404)
    h.err("s3", "get_bucket_policy_status", "AccessDenied", 403)
    ctx = h.ctx()
    ctx.selected = frozenset({"LOG-005"})
    assert statuses(logging_.trail_bucket(ctx)) == ["ERROR"]


def test_sto004_other_encryption_errors_are_errors(h: Harness) -> None:
    stub_buckets(h, ["b"], {"b": "us-east-1"})
    h.err("s3", "get_bucket_encryption", "AccessDenied", 403)
    assert statuses(s3.bucket_encryption(h.ctx())) == ["ERROR"]


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        (
            {
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": {"AWS": "arn:aws:iam::1:root"},
                        "Action": "s3:*",
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    }
                ]
            },
            "FAIL",
        ),  # deny scoped to one principal does not protect everyone
        (
            {
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    }
                ]
            },
            "FAIL",
        ),
        (
            {
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                    }
                ]
            },
            "FAIL",
        ),
        (
            {
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": ["*"],
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    }
                ]
            },
            "PASS",
        ),
        ("a bare string", "ERROR"),
        ([1, 2], "ERROR"),
    ],
)
def test_sto006_policy_shapes(h: Harness, policy: Any, expected: str) -> None:
    stub_buckets(h, ["b"], {"b": "us-east-1"})
    h.ok("s3", "get_bucket_policy", {"Policy": json.dumps(policy)})
    assert statuses(s3.bucket_tls(h.ctx())) == [expected]


def test_sto006_missing_policy_field_is_error(h: Harness) -> None:
    stub_buckets(h, ["b"], {"b": "us-east-1"})
    h.ok("s3", "get_bucket_policy", {})
    assert statuses(s3.bucket_tls(h.ctx())) == ["ERROR"]


def test_sto006_other_policy_errors_are_errors(h: Harness) -> None:
    stub_buckets(h, ["b"], {"b": "us-east-1"})
    h.err("s3", "get_bucket_policy", "AccessDenied", 403)
    assert statuses(s3.bucket_tls(h.ctx())) == ["ERROR"]


def test_unused_but_present_all_pab_fixture_is_complete() -> None:
    assert all(ALL.values()) and len(ALL) == 4


# ------------------------------------------------------------- monitoring malformed transformation


def test_metric_transformation_without_name_is_error(h: Harness) -> None:
    stub_trails(
        h,
        [
            logging_
            and {
                "Name": "main",
                "TrailARN": "arn:aws:cloudtrail:us-east-1:1:trail/m",
                "HomeRegion": "us-east-1",
                "CloudWatchLogsLogGroupArn": LG_ARN,
            }
        ],
    )
    h.factory.op_faults = {
        "DescribeMetricFilters": {
            "status": 200,
            "parsed": {
                "metricFilters": [
                    {"filterName": "f", "filterPattern": CIS_UNAUTH, "metricTransformations": [{}]}
                ]
            },
        }
    }
    assert statuses(monitoring.unauthorized_calls(h.ctx())) == ["ERROR"]
    h.factory.op_faults = {}
    assert stub_filters  # imported helper still available for other suites


# ------------------------------------------------------------- CLI gaps


CONFIG = (
    '[audit]\nprofile = "tiny"\nregions = ["us-east-1"]\nworkers = 1\n'
    '[profiles.tiny]\ninclude = ["IAM-002"]\n'
)


def wire(monkeypatch: pytest.MonkeyPatch, *, warn: bool = False) -> Harness:
    h = Harness()
    h.ok(
        "sts",
        "get_caller_identity",
        {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/a", "UserId": "x"},
        region=None,
    )
    if warn:
        h.err("ec2", "describe_regions")  # explicit regions + denied discovery => warning
    else:
        h.ok(
            "ec2",
            "describe_regions",
            {"Regions": [{"RegionName": "us-east-1"}]},
            {"AllRegions": False},
        )
    monkeypatch.setattr(cli, "make_factory", lambda *_a, **_k: h.factory)
    return h


@pytest.fixture
def cfg(tmp_path: Path) -> Path:
    p = tmp_path / "c.toml"
    p.write_text(CONFIG)
    return p


def test_interactive_confirmation_accepts_only_the_exact_account_id(
    monkeypatch: pytest.MonkeyPatch, cfg: Path, tmp_path: Path
) -> None:
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    h = wire(monkeypatch)
    h.ok(
        "iam",
        "get_account_summary",
        {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}},
    )
    out = tmp_path / "o"
    bad = runner.invoke(
        app, ["audit", "run", "-c", str(cfg), "--output-dir", str(out)], input="123456789012\n"
    )
    assert bad.exit_code == 2 and "does not match" in bad.output and not out.exists()
    h = wire(monkeypatch)
    h.ok(
        "iam",
        "get_account_summary",
        {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}},
    )
    good = runner.invoke(
        app,
        ["audit", "run", "-c", str(cfg), "--output-dir", str(out), "--formats", "json"],
        input=f"  {ACCOUNT}  \n",
    )
    assert good.exit_code == 0, good.output
    assert "Type the account ID" in good.output and len(list(out.iterdir())) == 1


@pytest.mark.parametrize("sub", ["plan", "run"])
def test_region_discovery_warning_is_shown(
    monkeypatch: pytest.MonkeyPatch, cfg: Path, tmp_path: Path, sub: str
) -> None:
    h = wire(monkeypatch, warn=True)
    h.ok(
        "iam",
        "get_account_summary",
        {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}},
    )
    args = ["audit", sub, "-c", str(cfg)]
    if sub == "run":
        args += [
            "--output-dir",
            str(tmp_path / "o"),
            "--formats",
            "json",
            "--confirm-account",
            ACCOUNT,
        ]
    res = runner.invoke(app, args)
    assert res.exit_code == 0 and "warning: Region discovery failed" in res.output


def test_policy_generate_and_org_error_paths(
    monkeypatch: pytest.MonkeyPatch, cfg: Path, tmp_path: Path
) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text("[audit]\nprofile = 'ghost'\n")
    assert runner.invoke(app, ["policy", "generate", "-c", str(bad)]).exit_code == 2

    def raise_auditor(*_a: Any, **_k: Any) -> None:
        raise AuditorError("could not assume role: ClientError")

    monkeypatch.setattr(cli, "make_factory", raise_auditor)
    res = runner.invoke(app, ["org", "list-accounts", "-c", str(cfg)])
    assert res.exit_code == 2 and "could not assume role" in res.output

    h = wire(monkeypatch)
    h.err("organizations", "describe_organization", "AWSOrganizationsNotInUseException", 400)
    res = runner.invoke(app, ["org", "list-accounts", "-c", str(cfg)])
    assert res.exit_code == 2 and "Organizations discovery failed" in res.output


def test_workers_option_overrides_config(monkeypatch: pytest.MonkeyPatch, cfg: Path,
                                         tmp_path: Path) -> None:  # fmt: skip
    seen: list[int] = []
    real = cli.run_audit

    def spy(_f: Any, _i: Any, config: Any, *a: Any, **k: Any) -> Any:
        seen.append(config.audit.workers)
        return real(_f, _i, config, *a, **k)

    monkeypatch.setattr(cli, "run_audit", spy)
    h = wire(monkeypatch)
    h.ok(
        "iam",
        "get_account_summary",
        {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}},
    )
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
            "--workers",
            "3",
            "--confirm-account",
            ACCOUNT,
        ],
    )
    assert res.exit_code == 0, res.output
    assert seen == [3]
