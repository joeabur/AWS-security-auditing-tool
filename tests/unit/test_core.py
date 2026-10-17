"""Config, models, catalog, error classification, read-only guard, regions, redaction."""

from __future__ import annotations

import json
from datetime import datetime

import boto3
import pytest
from botocore.exceptions import ClientError, ConnectTimeoutError, EndpointConnectionError
from pydantic import ValidationError

import awsauditor.session as session_mod
from awsauditor.catalog import load_catalog, select_controls
from awsauditor.config import RedactionSettings, load_config, parse_config
from awsauditor.errors import (
    AuditorError,
    ConfigError,
    ParseError,
    ReadOnlyViolation,
    classify_exception,
)
from awsauditor.models import Finding, Severity, Status
from awsauditor.redaction import Redactor
from awsauditor.regions import plan_regions
from awsauditor.session import (
    ClientFactory,
    build_session,
    iam_action_for,
    is_read_only_operation,
    resolve_identity,
)

from .conftest import ACCOUNT, NOW, Harness

# AWS documentation example key, assembled so secret scanners do not flag the literal.
EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"

# ----------------------------------------------------------------------- config


def test_defaults_are_valid_and_baseline() -> None:
    cfg = parse_config({})
    assert cfg.audit.profile == "baseline"
    assert cfg.thresholds.unused_credential_days == 45
    assert 22 in cfg.thresholds.sensitive_ports


@pytest.mark.parametrize(
    "bad",
    [
        {"aws": {"aws_secret_access_key": "x"}},
        {"aws": {"aws_access_key_id": "x"}},
        {"aws": {"aws_session_token": "x"}},
        {"aws": {"external_id": "x"}},
        {"deep": {"nested": {"password": "x"}}},
    ],
)
def test_secrets_in_config_are_rejected(bad: dict[str, object]) -> None:
    with pytest.raises(ConfigError, match="credentials must not be stored"):
        parse_config(bad)


@pytest.mark.parametrize(
    "bad",
    [
        {"unknown_section": {}},
        {"audit": {"workers": 0}},
        {"audit": {"workers": 99}},
        {"audit": {"profile": "nope"}},
        {"thresholds": {"sensitive_ports": [70000]}},
        {"thresholds": {"password_reuse_prevention": 25}},
        {"aws": {"role_arn": "not-an-arn"}},
        {"output": {"formats": ["pdf"]}},
    ],
)
def test_invalid_config_rejected(bad: dict[str, object]) -> None:
    with pytest.raises(ConfigError):
        parse_config(bad)


def test_load_config_from_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    p = tmp_path / "c.toml"
    p.write_text('[audit]\nprofile = "mine"\n[profiles.mine]\ninclude = ["IAM-001"]\n')
    cfg = load_config(p)
    assert cfg.all_profiles()["mine"].include == ["IAM-001"]
    p.write_text("not = [valid")
    with pytest.raises(ConfigError):
        load_config(p)
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.toml")
    assert load_config(None).audit.profile == "baseline"


def test_sample_config_is_valid() -> None:
    from pathlib import Path

    sample = Path(__file__).resolve().parents[2] / "examples" / "config.sample.toml"
    assert load_config(sample).audit.profile


# ----------------------------------------------------------------------- models


def test_finding_id_is_stable_and_requires_tz() -> None:
    def make(resource: str, tz: bool = True) -> Finding:
        return Finding(
            control_id="IAM-001",
            title="t",
            account_id=ACCOUNT,
            region="global",
            resource_id=resource,
            resource_type="x",
            severity=Severity.HIGH,
            status=Status.PASS,
            message="m",
            observed_at=NOW if tz else datetime(2026, 1, 1),
            remediation="r",
        )

    assert make("a").finding_id == make("a").finding_id
    assert make("a").finding_id != make("b").finding_id
    with pytest.raises(ValidationError):
        make("a", tz=False)


def test_all_five_states_exist() -> None:
    assert {s.value for s in Status} == {"PASS", "FAIL", "ERROR", "NOT_APPLICABLE", "NOT_ASSESSED"}


# ----------------------------------------------------------------------- catalog


def test_catalog_is_versioned_and_complete(catalog) -> None:  # type: ignore[no-untyped-def]
    assert catalog.catalog_version
    assert "not a CIS-certified" in catalog.disclaimer
    for c in catalog.controls:
        assert c.rationale and c.remediation and c.evidence_requirements and c.references
        assert all(r.startswith("https://") for r in c.references)
        assert all(":" in p for p in c.permissions)


def test_select_controls_filters(catalog) -> None:  # type: ignore[no-untyped-def]
    high = select_controls(catalog, min_severity=Severity.HIGH)
    assert high and all(c.severity.rank >= Severity.HIGH.rank for c in high)
    assert {c.service for c in select_controls(catalog, services=["s3"])} == {"s3"}
    assert [
        c.id for c in select_controls(catalog, include=["IAM-001", "IAM-002"], exclude=["IAM-002"])
    ] == ["IAM-001"]
    with pytest.raises(ConfigError):
        select_controls(catalog, include=["NOPE-999"])


def test_load_catalog_rejects_bad_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"schema_version": 1}))
    with pytest.raises(ConfigError):
        load_catalog(p)


def test_every_control_has_exactly_the_checks_that_cover_it(catalog) -> None:  # type: ignore[no-untyped-def]
    import awsauditor.checks  # noqa: F401  (registers checks)
    from awsauditor.context import REGISTRY

    covered: dict[str, int] = {}
    for spec in REGISTRY:
        scopes = {
            next(c for c in catalog.controls if c.id == cid).scope for cid in spec.control_ids
        }
        assert len(scopes) == 1, f"{spec.fn.__name__} mixes scopes"
        for cid in spec.control_ids:
            covered[cid] = covered.get(cid, 0) + 1
    assert set(covered) == {c.id for c in catalog.controls}
    assert all(n == 1 for n in covered.values())


# ----------------------------------------------------------------------- errors


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "m"}}, "DescribeThings")


@pytest.mark.parametrize(
    ("exc", "status"),
    [
        (_client_error("AccessDenied"), Status.ERROR),
        (_client_error("UnauthorizedOperation"), Status.ERROR),
        (_client_error("ThrottlingException"), Status.ERROR),
        (_client_error("RequestLimitExceeded"), Status.ERROR),
        (_client_error("OptInRequired"), Status.NOT_ASSESSED),
        (_client_error("UnrecognizedClientException"), Status.NOT_ASSESSED),
        (_client_error("SomethingElse"), Status.ERROR),
        (EndpointConnectionError(endpoint_url="https://x"), Status.NOT_ASSESSED),
        (ConnectTimeoutError(endpoint_url="https://x"), Status.ERROR),
        (ParseError("x"), Status.ERROR),
        (KeyError("x"), Status.ERROR),
        (ReadOnlyViolation("x"), Status.ERROR),
        (RuntimeError("x"), Status.ERROR),
    ],
)
def test_classification_never_passes(exc: BaseException, status: Status) -> None:
    got, message, uncertainty = classify_exception(exc)
    assert got is status
    assert got is not Status.PASS
    assert message and uncertainty


def test_classification_messages_distinguish_causes() -> None:
    assert "Permission denied" in classify_exception(_client_error("AccessDenied"))[1]
    assert "throttled" in classify_exception(_client_error("Throttling"))[1]


# ----------------------------------------------------------------------- read-only guard


@pytest.mark.parametrize(
    "op", ["GetAccountSummary", "ListBuckets", "DescribeRegions", "GenerateCredentialReport"]
)
def test_read_operations_allowed(op: str) -> None:
    assert is_read_only_operation(op)


@pytest.mark.parametrize(
    "op",
    [
        "CreateUser",
        "DeleteBucket",
        "PutBucketPolicy",
        "UpdateTrail",
        "ModifyDBInstance",
        "AttachUserPolicy",
        "StartLogging",
        "StopLogging",
        "GenerateServiceLastAccessedDetails",
    ],
)
def test_mutating_operations_blocked(op: str) -> None:
    assert not is_read_only_operation(op)


def test_guard_blocks_real_client_call_before_any_request(h: Harness) -> None:
    iam = h.factory.client("iam", "us-east-1")
    with pytest.raises(ReadOnlyViolation, match="iam:CreateUser"):
        iam.create_user(UserName="x")
    with pytest.raises(ReadOnlyViolation):
        h.factory.client("s3", "us-east-1").put_bucket_policy(Bucket="b", Policy="{}")
    with pytest.raises(ReadOnlyViolation):
        h.factory.client("ec2", "us-east-1").delete_volume(VolumeId="vol-1")


def test_guard_records_exercised_actions(h: Harness) -> None:
    h.ok("iam", "get_account_summary", {"SummaryMap": {}})
    h.factory.client("iam", "us-east-1").get_account_summary()
    assert h.factory.oplog.snapshot() == {"iam:GetAccountSummary": 1}


@pytest.mark.parametrize(
    ("service", "op", "action"),
    [
        ("s3", "ListBuckets", "s3:ListAllMyBuckets"),
        ("s3", "GetBucketEncryption", "s3:GetEncryptionConfiguration"),
        ("s3", "GetPublicAccessBlock", "s3:GetBucketPublicAccessBlock"),
        ("s3control", "GetPublicAccessBlock", "s3:GetAccountPublicAccessBlock"),
        ("accessanalyzer", "ListAnalyzers", "access-analyzer:ListAnalyzers"),
        ("ec2", "DescribeVolumes", "ec2:DescribeVolumes"),
        ("sts", "GetCallerIdentity", ""),
    ],
)
def test_iam_action_mapping(service: str, op: str, action: str) -> None:
    assert iam_action_for(service, op) == action


def test_factory_caches_clients_and_sets_user_agent(h: Harness) -> None:
    a = h.factory.client("iam", "us-east-1")
    assert a is h.factory.client("iam", "us-east-1")
    assert a is not h.factory.client("iam", "eu-west-1")
    assert "aws-security-auditing-tool" in a.meta.config.user_agent_extra
    assert a.meta.config.retries["mode"] == "adaptive"
    assert a.meta.config.retries["total_max_attempts"] == 8


# ----------------------------------------------------------------------- identity / role


def test_resolve_identity(h: Harness) -> None:
    h.ok(
        "sts",
        "get_caller_identity",
        {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/a", "UserId": "x"},
    )
    ident = resolve_identity(h.factory, "us-east-1")
    assert (ident.account_id, ident.partition) == (ACCOUNT, "aws")


def test_resolve_identity_failure_is_an_error(h: Harness) -> None:
    h.err("sts", "get_caller_identity", "ExpiredToken", 403)
    with pytest.raises(AuditorError, match="could not resolve"):
        resolve_identity(h.factory, "us-east-1")


def test_build_session_assume_role(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, object] = {}

    class FakeSts:
        def assume_role(self, **kw: object) -> dict[str, object]:
            calls.update(kw)
            return {
                "Credentials": {
                    "AccessKeyId": "ASIAFAKE",
                    "SecretAccessKey": "s",
                    "SessionToken": "t",
                }
            }

    class FakeSession:
        def __init__(self, **kw: object) -> None:
            self.kw = kw
            self.region_name = "eu-west-1"

        def client(self, name: str) -> FakeSts:
            assert name == "sts"
            return FakeSts()

    monkeypatch.setattr(boto3, "Session", FakeSession)
    sess = build_session("prof", "arn:aws:iam::1:role/r", "sess", 3600, "ext-id")
    assert calls["RoleArn"] == "arn:aws:iam::1:role/r"
    assert calls["ExternalId"] == "ext-id"
    assert sess.kw["aws_session_token"] == "t"  # type: ignore[attr-defined]


def test_build_session_without_role_uses_standard_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    class FakeSession:
        def __init__(self, **kw: object) -> None:
            seen.update(kw)

    monkeypatch.setattr(boto3, "Session", FakeSession)
    build_session("p", None, "s", 3600)
    assert seen == {"profile_name": "p"}  # no static credentials are ever passed


def test_assume_role_failure_does_not_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSts:
        def assume_role(self, **_kw: object) -> None:
            raise _client_error("AccessDenied")

    class FakeSession:
        region_name = None

        def __init__(self, **_kw: object) -> None: ...

        def client(self, _n: str) -> FakeSts:
            return FakeSts()

    monkeypatch.setattr(boto3, "Session", FakeSession)
    with pytest.raises(AuditorError, match="could not assume role: ClientError"):
        build_session(None, "arn:aws:iam::1:role/r", "s", 3600)


def test_session_module_exposes_no_secret_parameters() -> None:
    import inspect

    params = set(inspect.signature(build_session).parameters)
    assert not params & {"access_key", "secret_key", "aws_secret_access_key", "token"}
    assert ClientFactory is session_mod.ClientFactory


# ----------------------------------------------------------------------- regions


def _regions(h: Harness, names: list[str]) -> None:
    h.ok(
        "ec2",
        "describe_regions",
        {"Regions": [{"RegionName": n} for n in names]},
        {"AllRegions": False},
    )


def test_all_regions_discovered(h: Harness) -> None:
    _regions(h, ["us-east-1", "eu-west-1"])
    plan = plan_regions(h.factory, ["all"], "us-east-1", "aws")
    assert plan.audited == ["eu-west-1", "us-east-1"] and plan.discovery_ok


def test_explicit_regions_validated(h: Harness) -> None:
    _regions(h, ["us-east-1", "eu-west-1"])
    assert plan_regions(h.factory, ["eu-west-1"], "us-east-1", "aws").audited == ["eu-west-1"]
    _regions(h, ["us-east-1"])
    with pytest.raises(AuditorError, match="not enabled"):
        plan_regions(h.factory, ["ap-south-2"], "us-east-1", "aws")


def test_discovery_denied_with_explicit_regions_degrades_with_warning(h: Harness) -> None:
    h.err("ec2", "describe_regions")
    plan = plan_regions(h.factory, ["us-east-1"], "us-east-1", "aws")
    assert not plan.discovery_ok and plan.warnings and plan.enabled == []


def test_discovery_denied_for_all_is_fatal_and_unknown_region_rejected(h: Harness) -> None:
    h.err("ec2", "describe_regions")
    with pytest.raises(AuditorError, match="cannot discover"):
        plan_regions(h.factory, [], "us-east-1", "aws")
    h.err("ec2", "describe_regions")
    with pytest.raises(AuditorError, match="unknown region"):
        plan_regions(h.factory, ["mars-north-1"], "us-east-1", "aws")


# ----------------------------------------------------------------------- redaction


def test_redaction_disabled_is_identity() -> None:
    r = Redactor(RedactionSettings(enabled=False))
    assert r.text(f"arn:aws:iam::{ACCOUNT}:root") == f"arn:aws:iam::{ACCOUNT}:root"


def test_redaction_masks_accounts_keys_and_ips() -> None:
    r = Redactor(RedactionSettings(enabled=True, ip_addresses=True))
    out = r.apply(
        {
            "a": [
                f"arn:aws:iam::{ACCOUNT}:user/x",
                EXAMPLE_KEY,
                "10.1.2.3/32",
                "0.0.0.0/0",
                "vol-123456789012345",
            ],
            "n": 5,
        }
    )
    text = json.dumps(out)
    assert ACCOUNT not in text and "3333" in text
    assert EXAMPLE_KEY not in text and EXAMPLE_KEY[:8] in text
    assert "10.x.x.x/32" in text and "0.0.0.0/0" in text
    assert out["n"] == 5


def test_redaction_options_are_independent() -> None:
    r = Redactor(RedactionSettings(enabled=True, account_ids=False, access_key_ids=False))
    assert r.text(ACCOUNT) == ACCOUNT and r.text("10.1.2.3") == "10.1.2.3"
