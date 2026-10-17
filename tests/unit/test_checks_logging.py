"""CloudTrail, trail-bucket, retention, monitoring, GuardDuty and Config controls."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from awsauditor.checks import logging_, monitoring
from awsauditor.config import AuditConfig, Thresholds
from awsauditor.models import Status

from .conftest import ACCOUNT, Harness, assert_wellformed, statuses

ARN = f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/main"
LG_ARN = f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:trail-logs:*"


def trail(**kw: Any) -> dict[str, Any]:
    base = {
        "Name": "main",
        "TrailARN": ARN,
        "HomeRegion": "us-east-1",
        "S3BucketName": "logs-b",
        "IsMultiRegionTrail": True,
        "LogFileValidationEnabled": True,
    }
    return {**base, **kw}


def stub_trails(
    h: Harness, trails: list[dict[str, Any]], shadow: bool = False, region: str = "us-east-1"
) -> None:
    h.ok(
        "cloudtrail",
        "describe_trails",
        {"trailList": trails},
        {"includeShadowTrails": shadow},
        region=region,
    )


def stub_status(h: Harness, region: str = "us-east-1", **kw: Any) -> None:
    h.ok("cloudtrail", "get_trail_status", {"IsLogging": True, **kw}, {"Name": ARN}, region=region)


# ---------------------------------------------------------------- LOG-001


def test_log001_pass_with_logging_multi_region_trail(h: Harness) -> None:
    stub_trails(
        h,
        [trail(), trail(Name="single", TrailARN=ARN + "2", IsMultiRegionTrail=False)],
        shadow=True,
    )
    stub_status(h)
    f = logging_.multi_region_trail(h.ctx(account_scope=True))
    assert statuses(f) == ["PASS"] and f[0].evidence["multi_region_logging"] == ["main"]
    assert_wellformed(f)
    h.assert_all_consumed()


def test_log001_fail_when_not_logging(h: Harness) -> None:
    stub_trails(h, [trail()], shadow=True)
    h.ok("cloudtrail", "get_trail_status", {"IsLogging": False}, {"Name": ARN})
    f = logging_.multi_region_trail(h.ctx(account_scope=True))
    assert statuses(f) == ["FAIL"] and f[0].uncertainty


@pytest.mark.parametrize("trails", [[], [dict(trail(), IsMultiRegionTrail=False)]])
def test_log001_fail_without_multi_region_trail(h: Harness, trails: list[dict[str, Any]]) -> None:
    stub_trails(h, trails, shadow=True)
    assert statuses(logging_.multi_region_trail(h.ctx(account_scope=True))) == ["FAIL"]


def test_log001_status_denied_is_error_not_fail(h: Harness) -> None:
    stub_trails(h, [trail()], shadow=True)
    h.err("cloudtrail", "get_trail_status")
    assert statuses(logging_.multi_region_trail(h.ctx(account_scope=True))) == ["ERROR"]


def test_log001_other_trail_logging_wins_over_one_error(h: Harness) -> None:
    other = trail(Name="o", TrailARN=ARN + "o")
    stub_trails(h, [trail(), other], shadow=True)
    h.err("cloudtrail", "get_trail_status")
    h.ok("cloudtrail", "get_trail_status", {"IsLogging": True}, {"Name": ARN + "o"})
    assert statuses(logging_.multi_region_trail(h.ctx(account_scope=True))) == ["PASS"]


def test_log001_queries_status_in_trail_home_region(h: Harness) -> None:
    stub_trails(h, [trail(HomeRegion="eu-west-1")], shadow=True)
    stub_status(h, region="eu-west-1")
    assert statuses(logging_.multi_region_trail(h.ctx(account_scope=True))) == ["PASS"]
    h.assert_all_consumed()


def test_log001_malformed_trail_list_is_error(h: Harness) -> None:
    h.factory.fault = {"status": 200, "parsed": {"trailList": "oops"}}
    assert statuses(logging_.multi_region_trail(h.ctx(account_scope=True))) == ["ERROR"]


# ---------------------------------------------------------------- LOG-002..004


@pytest.mark.parametrize(("enabled", "status"), [(True, "PASS"), (False, "FAIL")])
def test_log002(h: Harness, enabled: bool, status: str) -> None:
    stub_trails(h, [trail(LogFileValidationEnabled=enabled)])
    f = logging_.log_file_validation(h.ctx())
    assert statuses(f) == [status] and f[0].resource_id == ARN


def test_log002_no_trails_is_not_applicable_and_denied_is_error(h: Harness) -> None:
    stub_trails(h, [])
    assert statuses(logging_.log_file_validation(h.ctx())) == ["NOT_APPLICABLE"]
    h.err("cloudtrail", "describe_trails")
    assert statuses(logging_.log_file_validation(h.ctx())) == ["ERROR"]


@pytest.mark.parametrize(
    ("bucket", "status_kw", "expected"),
    [
        ("logs-b", {}, "PASS"),
        (None, {}, "FAIL"),
        ("logs-b", {"IsLogging": False}, "FAIL"),
        ("logs-b", {"LatestDeliveryError": "AccessDenied"}, "FAIL"),
    ],
)
def test_log003_delivery(
    h: Harness, bucket: str | None, status_kw: dict[str, Any], expected: str
) -> None:
    tr = trail()
    if bucket is None:
        tr.pop("S3BucketName")
    stub_trails(h, [tr])
    stub_status(h, LatestDeliveryTime=datetime(2026, 10, 16, tzinfo=UTC), **status_kw)
    f = logging_.delivery(h.ctx())
    assert statuses(f) == [expected]
    assert "IsLogging" in f[0].evidence


def test_log003_status_denied(h: Harness) -> None:
    stub_trails(h, [trail()])
    h.err("cloudtrail", "get_trail_status")
    assert statuses(logging_.delivery(h.ctx())) == ["ERROR"]


@pytest.mark.parametrize(
    ("group", "err", "expected"),
    [(LG_ARN, None, "PASS"), (None, None, "FAIL"), (LG_ARN, "delivery failed", "FAIL")],
)
def test_log004(h: Harness, group: str | None, err: str | None, expected: str) -> None:
    stub_trails(h, [trail(**({"CloudWatchLogsLogGroupArn": group} if group else {}))])
    if group:
        kw = {"LatestCloudWatchLogsDeliveryError": err} if err else {}
        stub_status(h, **kw)
    assert statuses(logging_.cloudwatch_integration(h.ctx())) == [expected]
    h.assert_all_consumed()


# ---------------------------------------------------------------- LOG-005 / LOG-006

PAB_NONE = "NoSuchPublicAccessBlockConfiguration"
ALL = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}
PARTIAL = {**ALL, "RestrictPublicBuckets": False}


def run_bucket(h: Harness, controls: list[str] | None = None) -> list:  # type: ignore[type-arg]
    ctx = h.ctx()
    if controls:
        ctx.selected = frozenset(controls)
    return logging_.trail_bucket(ctx)


def stub_trail_and_location(h: Harness) -> None:
    stub_trails(h, [trail()])
    h.ok("s3", "get_bucket_location", {}, {"Bucket": "logs-b"})


def test_log005_pass_bucket_level_block(h: Harness) -> None:
    stub_trail_and_location(h)
    h.ok("s3", "get_public_access_block", {"PublicAccessBlockConfiguration": ALL})
    h.ok("s3", "get_bucket_logging", {"LoggingEnabled": {"TargetBucket": "t", "TargetPrefix": "p"}})
    f = run_bucket(h)
    assert statuses(f, "LOG-005") == ["PASS"] and statuses(f, "LOG-006") == ["PASS"]
    assert f[0].resource_id == "arn:aws:s3:::logs-b"
    assert_wellformed(f)
    h.assert_all_consumed()


def test_log005_effective_block_via_account_level(h: Harness) -> None:
    stub_trail_and_location(h)
    h.ok("s3", "get_public_access_block", {"PublicAccessBlockConfiguration": PARTIAL})
    h.ok(
        "s3control",
        "get_public_access_block",
        {"PublicAccessBlockConfiguration": ALL},
        {"AccountId": ACCOUNT},
    )
    h.ok("s3", "get_bucket_logging", {})
    f = run_bucket(h)
    assert statuses(f, "LOG-005") == ["PASS"] and statuses(f, "LOG-006") == ["FAIL"]


def test_log005_public_policy_fails(h: Harness) -> None:
    stub_trail_and_location(h)
    h.err("s3", "get_public_access_block", PAB_NONE, 404)
    h.err("s3control", "get_public_access_block", PAB_NONE, 404)
    h.ok("s3", "get_bucket_policy_status", {"PolicyStatus": {"IsPublic": True}})
    f = run_bucket(h, ["LOG-005"])
    assert statuses(f) == ["FAIL"] and f[0].evidence["policy_is_public"] is True


ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def acl(*group_uris: str) -> dict[str, Any]:
    grants = [{"Grantee": {"Type": "Group", "URI": u}, "Permission": "READ"} for u in group_uris]
    grants.append(
        {"Grantee": {"Type": "CanonicalUser", "ID": "owner"}, "Permission": "FULL_CONTROL"}
    )
    return {"Owner": {"ID": "owner"}, "Grants": grants}


def stub_unblocked(h: Harness, policy_resp: str) -> None:
    stub_trail_and_location(h)
    h.err("s3", "get_public_access_block", PAB_NONE, 404)
    h.err("s3control", "get_public_access_block", PAB_NONE, 404)
    if policy_resp == "status":
        h.ok("s3", "get_bucket_policy_status", {"PolicyStatus": {"IsPublic": False}})
    else:
        h.err("s3", "get_bucket_policy_status", "NoSuchBucketPolicy", 404)


@pytest.mark.parametrize("policy_resp", ["status", "nopolicy"])
def test_log005_private_policy_and_acl_pass_with_access_point_caveat(
    h: Harness, policy_resp: str
) -> None:
    stub_unblocked(h, policy_resp)
    h.ok("s3", "get_bucket_acl", acl())
    f = run_bucket(h, ["LOG-005"])
    assert statuses(f) == ["PASS"]
    assert "access points" in f[0].uncertainty[0] and f[0].evidence["public_acl_grants"] == []


@pytest.mark.parametrize("uri", [ALL_USERS, AUTH_USERS])
def test_log005_public_acl_fails(h: Harness, uri: str) -> None:
    stub_unblocked(h, "status")
    h.ok("s3", "get_bucket_acl", acl(uri))
    f = run_bucket(h, ["LOG-005"])
    assert statuses(f) == ["FAIL"] and f[0].evidence["public_acl_grants"][0]["permission"] == "READ"


def test_log005_acl_unreadable_is_error(h: Harness) -> None:
    stub_unblocked(h, "status")
    h.err("s3", "get_bucket_acl", "AccessDenied", 403)
    assert statuses(run_bucket(h, ["LOG-005"])) == ["ERROR"]


def test_log005_account_level_unreadable_is_error_not_pass(h: Harness) -> None:
    stub_trail_and_location(h)
    h.ok("s3", "get_public_access_block", {"PublicAccessBlockConfiguration": PARTIAL})
    h.err("s3control", "get_public_access_block")
    h.ok("s3", "get_bucket_policy_status", {"PolicyStatus": {"IsPublic": False}})
    f = run_bucket(h, ["LOG-005"])
    # account level unreadable: effective protection unknown, so never PASS
    assert statuses(f) == ["ERROR"]


def test_log005_only_selected_controls_call_their_apis(h: Harness) -> None:
    stub_trail_and_location(h)
    h.ok("s3", "get_bucket_logging", {})
    f = run_bucket(h, ["LOG-006"])  # no PAB stubs queued: LOG-005 calls would raise
    assert statuses(f, "LOG-006") == ["FAIL"] and not statuses(f, "LOG-005")


def test_log005_log006_cross_account_bucket_is_error_with_explanation(h: Harness) -> None:
    stub_trails(h, [trail()])
    h.err("s3", "get_bucket_location")
    f = run_bucket(h)
    assert statuses(f) == ["ERROR", "ERROR"]


def test_log005_no_bucket_and_no_trail(h: Harness) -> None:
    tr = trail()
    tr.pop("S3BucketName")
    stub_trails(h, [tr])
    assert statuses(run_bucket(h)) == ["FAIL", "FAIL"]
    stub_trails(h, [])
    assert statuses(run_bucket(h)) == ["NOT_APPLICABLE", "NOT_APPLICABLE"]


def test_normalize_location() -> None:
    from awsauditor.checks._s3common import normalize_location as n

    assert (n(None), n(""), n("EU"), n("eu-west-2")) == (
        "us-east-1",
        "us-east-1",
        "eu-west-1",
        "eu-west-2",
    )


# ---------------------------------------------------------------- LOG-007


def lg(name: str, days: int | None) -> dict[str, Any]:
    d: dict[str, Any] = {"logGroupName": name}
    if days is not None:
        d["retentionInDays"] = days
    return d


def test_log007_boundaries_and_pagination(h: Harness) -> None:
    h.ok(
        "logs", "describe_log_groups", {"logGroups": [lg("a", 364), lg("b", 365)], "nextToken": "n"}
    )
    h.ok("logs", "describe_log_groups", {"logGroups": [lg("c", None), lg("d", 3653)]})
    f = logging_and_retention(h)
    got = {x.resource_id: x.status for x in f}
    assert got == {"a": Status.FAIL, "b": Status.PASS, "c": Status.PASS, "d": Status.PASS}
    assert next(x for x in f if x.resource_id == "a").evidence == {
        "retentionInDays": 364,
        "minimum_days": 365,
    }


def logging_and_retention(h: Harness):  # type: ignore[no-untyped-def]
    return monitoring.log_retention(h.ctx())


def test_log007_threshold_configurable_none_and_denied(h: Harness) -> None:
    h.config = AuditConfig(thresholds=Thresholds(log_retention_min_days=30))
    h.ok("logs", "describe_log_groups", {"logGroups": [lg("a", 30)]})
    assert statuses(logging_and_retention(h)) == ["PASS"]
    h.ok("logs", "describe_log_groups", {"logGroups": []})
    assert statuses(logging_and_retention(h)) == ["NOT_APPLICABLE"]
    h.err("logs", "describe_log_groups")
    assert statuses(logging_and_retention(h)) == ["ERROR"]


# ---------------------------------------------------------------- LOG-008..010

CIS_UNAUTH = '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'
CIS_ROOT = (
    '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && '
    '$.eventType != "AwsServiceEvent" }'
)
CIS_NOMFA = '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }'
CASES = [
    ("LOG-008", monitoring.unauthorized_calls, CIS_UNAUTH, '{ $.errorCode = "Throttling" }'),
    ("LOG-009", monitoring.root_usage, CIS_ROOT, '{ $.userIdentity.type = "IAMUser" }'),
    ("LOG-010", monitoring.console_without_mfa, CIS_NOMFA, '{ $.eventName = "CreateUser" }'),
]


def stub_filters(h: Harness, pattern: str) -> None:
    stub_trails(h, [trail(CloudWatchLogsLogGroupArn=LG_ARN)])
    h.ok(
        "logs",
        "describe_metric_filters",
        {
            "metricFilters": [
                {
                    "filterName": "f",
                    "filterPattern": pattern,
                    "metricTransformations": [
                        {"metricName": "m", "metricNamespace": "N", "metricValue": "1"}
                    ],
                }
            ]
        },
        {"logGroupName": "trail-logs"},
    )


def stub_alarm(h: Harness, actions: list[str], enabled: bool = True) -> None:
    alarms = [{"AlarmName": "a", "AlarmActions": actions, "ActionsEnabled": enabled}]
    h.ok(
        "cloudwatch",
        "describe_alarms_for_metric",
        {"MetricAlarms": alarms},
        {"MetricName": "m", "Namespace": "N"},
    )


@pytest.mark.parametrize(("cid", "fn", "good", "other"), CASES)
def test_monitoring_pass_when_filter_and_alarm_exist(h, cid, fn, good, other) -> None:  # type: ignore[no-untyped-def]
    stub_filters(h, good)
    stub_alarm(h, ["arn:aws:sns:us-east-1:1:topic"])
    f = fn(h.ctx())
    assert statuses(f) == ["PASS"] and f[0].control_id == cid
    assert f[0].evidence["alarm_with_actions"] is True and f[0].uncertainty
    assert_wellformed(f)


@pytest.mark.parametrize(("cid", "fn", "good", "other"), CASES)
def test_monitoring_fail_variants(h, cid, fn, good, other) -> None:  # type: ignore[no-untyped-def]
    stub_filters(h, other)  # wrong pattern
    assert statuses(fn(h.ctx())) == ["FAIL"]
    stub_filters(h, good)
    stub_alarm(h, [])  # alarm without action
    assert statuses(fn(h.ctx())) == ["FAIL"]
    stub_filters(h, good)
    stub_alarm(h, ["arn:aws:sns:us-east-1:1:t"], enabled=False)
    assert statuses(fn(h.ctx())) == ["FAIL"]
    h.assert_all_consumed()


@pytest.mark.parametrize(("cid", "fn", "good", "other"), CASES)
def test_monitoring_edge_cases(h, cid, fn, good, other) -> None:  # type: ignore[no-untyped-def]
    stub_trails(h, [])
    assert statuses(fn(h.ctx())) == ["NOT_APPLICABLE"]
    stub_trails(h, [trail()])  # no log group
    f = fn(h.ctx())
    assert statuses(f) == ["FAIL"] and "CloudWatch" in f[0].message
    stub_trails(h, [trail(CloudWatchLogsLogGroupArn=LG_ARN)])
    h.err("logs", "describe_metric_filters")
    assert statuses(fn(h.ctx())) == ["ERROR"]
    stub_filters(h, good)
    h.err("cloudwatch", "describe_alarms_for_metric")
    assert statuses(fn(h.ctx())) == ["ERROR"]


def test_monitoring_malformed_log_group_arn_is_error(h: Harness) -> None:
    stub_trails(h, [trail(CloudWatchLogsLogGroupArn="not-an-arn")])
    assert statuses(monitoring.root_usage(h.ctx())) == ["ERROR"]


@pytest.mark.parametrize(
    ("arn", "name"),
    [
        (LG_ARN, "trail-logs"),
        (f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/aws/ct:*", "/aws/ct"),
        (f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:plain", "plain"),
    ],
)
def test_log_group_name(arn: str, name: str) -> None:
    assert monitoring.log_group_name(arn) == name


# ---------------------------------------------------------------- LOG-011


def test_log011_states(h: Harness) -> None:
    h.ok("guardduty", "list_detectors", {"DetectorIds": ["d1"]})
    h.ok(
        "guardduty",
        "get_detector",
        {"Status": "ENABLED", "ServiceRole": "r", "CreatedAt": "2026-01-01", "UpdatedAt": "x"},
        {"DetectorId": "d1"},
    )
    f = monitoring.guardduty(h.ctx())
    assert statuses(f) == ["PASS"] and f[0].evidence == {"detectors": 1, "enabled": 1}
    h.ok("guardduty", "list_detectors", {"DetectorIds": ["d1"]})
    h.ok(
        "guardduty",
        "get_detector",
        {"Status": "DISABLED", "ServiceRole": "r", "CreatedAt": "x", "UpdatedAt": "x"},
    )
    assert statuses(monitoring.guardduty(h.ctx())) == ["FAIL"]
    h.ok("guardduty", "list_detectors", {"DetectorIds": []})
    assert statuses(monitoring.guardduty(h.ctx())) == ["FAIL"]


def test_log011_pagination_denied_and_unsupported(h: Harness) -> None:
    h.ok("guardduty", "list_detectors", {"DetectorIds": [], "NextToken": "t"})
    h.ok("guardduty", "list_detectors", {"DetectorIds": ["d2"]})
    h.ok(
        "guardduty",
        "get_detector",
        {"Status": "ENABLED", "ServiceRole": "r", "CreatedAt": "x", "UpdatedAt": "x"},
    )
    assert statuses(monitoring.guardduty(h.ctx())) == ["PASS"]
    h.err("guardduty", "list_detectors")
    assert statuses(monitoring.guardduty(h.ctx())) == ["ERROR"]
    h.err("guardduty", "list_detectors", "UnrecognizedClientException", 403)
    assert statuses(monitoring.guardduty(h.ctx())) == ["NOT_ASSESSED"]


# ---------------------------------------------------------------- LOG-012


def stub_config(
    h: Harness,
    *,
    recorders: bool = True,
    recording: bool = True,
    rec_status: str = "SUCCESS",
    channel: bool = True,
    delivery_status: str = "SUCCESS",
) -> None:
    h.ok(
        "config",
        "describe_configuration_recorders",
        {"ConfigurationRecorders": [{"name": "default"}] if recorders else []},
    )
    if not recorders:
        return
    h.ok(
        "config",
        "describe_configuration_recorder_status",
        {
            "ConfigurationRecordersStatus": [
                {"name": "default", "recording": recording, "lastStatus": rec_status}
            ]
        },
    )
    h.ok(
        "config",
        "describe_delivery_channels",
        {"DeliveryChannels": [{"name": "d", "s3BucketName": "b"}] if channel else []},
    )
    if channel:
        h.ok(
            "config",
            "describe_delivery_channel_status",
            {
                "DeliveryChannelsStatus": [
                    {"name": "d", "configHistoryDeliveryInfo": {"lastStatus": delivery_status}}
                ]
            },
        )


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({}, "PASS"),
        ({"recorders": False}, "FAIL"),
        ({"recording": False}, "FAIL"),
        ({"rec_status": "FAILURE"}, "FAIL"),
        ({"channel": False}, "FAIL"),
        ({"delivery_status": "FAILURE"}, "FAIL"),
    ],
)
def test_log012_states(h: Harness, kw: dict[str, Any], expected: str) -> None:
    stub_config(h, **kw)
    f = aws_config(h)
    assert statuses(f) == [expected]
    h.assert_all_consumed()


def aws_config(h: Harness):  # type: ignore[no-untyped-def]
    return monitoring.aws_config(h.ctx())


def test_log012_denied_and_unsupported(h: Harness) -> None:
    h.err("config", "describe_configuration_recorders")
    assert statuses(aws_config(h)) == ["ERROR"]
    h.err("config", "describe_configuration_recorders", "OptInRequired", 403)
    assert statuses(aws_config(h)) == ["NOT_ASSESSED"]
