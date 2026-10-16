"""CloudWatch log retention, metric-filter/alarm, GuardDuty and AWS Config checks."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from ..context import CheckContext, check
from ..errors import ParseError
from ..evidence import optional, paginate, paginate_scalars, require
from ..models import Finding, Status
from .logging_ import TRAIL, trails_in_region

LOGS = "AWS::Logs::LogGroup"
_NOTE = (
    "Metric-filter patterns are matched heuristically on key tokens, and alarm "
    "notification targets (for example SNS subscriptions) are not verified."
)


@check("LOG-007")
def log_retention(ctx: CheckContext) -> list[Finding]:
    src = ["logs:DescribeLogGroups"]
    out: list[Finding] = []
    resource = f"region/{ctx.region}"
    minimum = ctx.config.thresholds.log_retention_min_days
    with ctx.capture(out, "LOG-007", resource, LOGS, src):
        groups = list(paginate(ctx.client("logs"), "describe_log_groups", "logGroups"))
        for g in groups:
            name = require(g, "logGroupName", str)
            days = optional(g, "retentionInDays", int)
            ok = days is None or days >= minimum
            out.append(
                ctx.finding(
                    "LOG-007",
                    Status.PASS if ok else Status.FAIL,
                    name,
                    LOGS,
                    (
                        "Log group retains logs indefinitely."
                        if days is None
                        else f"Retention is {days} days (minimum {minimum})."
                    ),
                    evidence={"retentionInDays": days, "minimum_days": minimum},
                    sources=src,
                )
            )
        if not groups:
            out.append(
                ctx.finding(
                    "LOG-007",
                    Status.NOT_APPLICABLE,
                    resource,
                    LOGS,
                    "No log groups in this region.",
                    sources=src,
                )
            )
    return out


def log_group_name(arn: str) -> str:
    """Extract the log group name from a CloudTrail ``CloudWatchLogsLogGroupArn``."""
    parts = arn.split(":", 6)
    if len(parts) < 7 or parts[2] != "logs" or parts[5] != "log-group":
        raise ParseError("unexpected CloudWatch Logs log group ARN")
    name = parts[6]
    return name[:-2] if name.endswith(":*") else name


def _norm(pattern: str) -> str:
    return re.sub(r"\s+", "", pattern).lower().replace("'", '"')


def _unauthorized(p: str) -> bool:
    return "unauthorizedoperation" in p and "accessdenied" in p and "errorcode" in p


def _root_usage(p: str) -> bool:
    return "useridentity.type" in p and '"root"' in p


def _no_mfa(p: str) -> bool:
    return "consolelogin" in p and "mfaused" in p and ('!="yes"' in p or '="no"' in p)


_MATCHERS: dict[str, Callable[[str], bool]] = {
    "LOG-008": _unauthorized,
    "LOG-009": _root_usage,
    "LOG-010": _no_mfa,
}
_MSRC = [
    "cloudtrail:DescribeTrails",
    "logs:DescribeMetricFilters",
    "cloudwatch:DescribeAlarmsForMetric",
]


def _has_alarm(ctx: CheckContext, filters: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    metrics: list[str] = []
    for f in filters:
        for t in f.get("metricTransformations", []) or []:
            name, ns = t.get("metricName"), t.get("metricNamespace")
            if not name or not ns:
                raise ParseError("metric transformation without name/namespace")
            metrics.append(f"{ns}/{name}")
            resp = ctx.client("cloudwatch").describe_alarms_for_metric(
                MetricName=name, Namespace=ns
            )
            for alarm in require(resp, "MetricAlarms", list):
                if alarm.get("AlarmActions") and alarm.get("ActionsEnabled", True) is not False:
                    return True, metrics
    return False, metrics


def _monitoring_check(ctx: CheckContext, control_id: str) -> list[Finding]:
    matcher = _MATCHERS[control_id]
    out: list[Finding] = []
    resource = f"region/{ctx.region}"
    try:
        trails = trails_in_region(ctx)
    except Exception as exc:
        return [ctx.error_finding(control_id, exc, resource, TRAIL, _MSRC)]
    for trail in trails:
        arn = str(trail["TrailARN"])
        with ctx.capture(out, control_id, arn, TRAIL, _MSRC):
            group_arn = optional(trail, "CloudWatchLogsLogGroupArn", str)
            if not group_arn:
                out.append(
                    ctx.finding(
                        control_id,
                        Status.FAIL,
                        arn,
                        TRAIL,
                        "Trail does not deliver to CloudWatch Logs, so no metric filter can exist.",
                        sources=_MSRC,
                    )
                )
                continue
            group = log_group_name(group_arn)
            filters = list(
                paginate(
                    ctx.client("logs"),
                    "describe_metric_filters",
                    "metricFilters",
                    logGroupName=group,
                )
            )
            matching = [f for f in filters if matcher(_norm(str(f.get("filterPattern", ""))))]
            alarmed, metrics = _has_alarm(ctx, matching) if matching else (False, [])
            evidence = {
                "log_group": group,
                "filters_total": len(filters),
                "matching_filters": [f.get("filterName") for f in matching],
                "metrics": metrics,
                "alarm_with_actions": alarmed,
            }
            if alarmed:
                status, msg = Status.PASS, "A matching metric filter with an alarm action exists."
            elif matching:
                status, msg = Status.FAIL, "Matching metric filter exists but has no alarm action."
            else:
                status, msg = Status.FAIL, "No matching metric filter found."
            out.append(
                ctx.finding(
                    control_id,
                    status,
                    arn,
                    TRAIL,
                    msg,
                    evidence=evidence,
                    sources=_MSRC,
                    uncertainty=[_NOTE],
                )
            )
    if not trails:
        out.append(
            ctx.finding(
                control_id,
                Status.NOT_APPLICABLE,
                resource,
                TRAIL,
                "No CloudTrail trail is homed in this region.",
                sources=_MSRC,
            )
        )
    return out


@check("LOG-008")
def unauthorized_calls(ctx: CheckContext) -> list[Finding]:
    return _monitoring_check(ctx, "LOG-008")


@check("LOG-009")
def root_usage(ctx: CheckContext) -> list[Finding]:
    return _monitoring_check(ctx, "LOG-009")


@check("LOG-010")
def console_without_mfa(ctx: CheckContext) -> list[Finding]:
    return _monitoring_check(ctx, "LOG-010")


@check("LOG-011")
def guardduty(ctx: CheckContext) -> list[Finding]:
    src = ["guardduty:ListDetectors", "guardduty:GetDetector"]
    resource = f"region/{ctx.region}"
    out: list[Finding] = []
    with ctx.capture(out, "LOG-011", resource, "AWS::GuardDuty::Detector", src):
        client = ctx.client("guardduty")
        ids = list(paginate_scalars(client, "list_detectors", "DetectorIds"))
        statuses = {}
        for det in ids:
            statuses[str(det)] = require(client.get_detector(DetectorId=det), "Status", str)
        enabled = [d for d, s in statuses.items() if s == "ENABLED"]
        out.append(
            ctx.finding(
                "LOG-011",
                Status.PASS if enabled else Status.FAIL,
                resource,
                "AWS::GuardDuty::Detector",
                "GuardDuty is enabled." if enabled else "GuardDuty is not enabled in this region.",
                evidence={"detectors": len(ids), "enabled": len(enabled)},
                sources=src,
                uncertainty=["Delegated-administrator or suppressed findings are not evaluated."],
            )
        )
    return out


@check("LOG-012")
def aws_config(ctx: CheckContext) -> list[Finding]:
    src = [
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "config:DescribeDeliveryChannels",
        "config:DescribeDeliveryChannelStatus",
    ]
    resource = f"region/{ctx.region}"
    rtype = "AWS::Config::ConfigurationRecorder"
    out: list[Finding] = []
    with ctx.capture(out, "LOG-012", resource, rtype, src):
        cfg = ctx.client("config")
        recorders = require(cfg.describe_configuration_recorders(), "ConfigurationRecorders", list)
        problems: list[str] = []
        recording_names: list[str] = []
        channels: list[Any] = []
        if not recorders:
            problems.append("no configuration recorder")
        else:
            statuses = require(
                cfg.describe_configuration_recorder_status(), "ConfigurationRecordersStatus", list
            )
            recording_names = [str(s.get("name")) for s in statuses if s.get("recording") is True]
            if not recording_names:
                problems.append("recorder is not recording")
            if any(s.get("lastStatus") == "FAILURE" for s in statuses):
                problems.append("recorder reports a failure")
            channels = require(cfg.describe_delivery_channels(), "DeliveryChannels", list)
            if not any(c.get("s3BucketName") for c in channels):
                problems.append("no delivery channel with an S3 bucket")
            else:
                dstat = require(
                    cfg.describe_delivery_channel_status(), "DeliveryChannelsStatus", list
                )
                for s in dstat:
                    info = s.get("configHistoryDeliveryInfo") or {}
                    if info.get("lastStatus") == "FAILURE":
                        problems.append("configuration history delivery failed")
                        break
        out.append(
            ctx.finding(
                "LOG-012",
                Status.FAIL if problems else Status.PASS,
                resource,
                rtype,
                ("AWS Config problem: " + "; ".join(problems))
                if problems
                else "AWS Config is recording and delivering.",
                evidence={
                    "recorders": len(recorders),
                    "recording": recording_names,
                    "delivery_channels": len(channels),
                },
                sources=src,
                uncertainty=[
                    "Recorded resource types (allSupported / exclusions) are not evaluated."
                ],
            )
        )
    return out
