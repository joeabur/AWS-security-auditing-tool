"""CloudTrail checks."""

from __future__ import annotations

from typing import Any

from ..context import CheckContext, check
from ..evidence import error_code, optional, require
from ..models import Finding, Status
from . import _s3common as s3c

TRAIL = "AWS::CloudTrail::Trail"
ACCT = "AWS::::Account"
S3 = "AWS::S3::Bucket"
_TS = ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"]
_DT = ["cloudtrail:DescribeTrails"]


def trails_in_region(ctx: CheckContext) -> list[dict[str, Any]]:
    """Trails homed in the current region (shadow trails excluded to avoid duplicates)."""

    def fetch() -> list[dict[str, Any]]:
        resp = ctx.client("cloudtrail").describe_trails(includeShadowTrails=False)
        trails = require(resp, "trailList", list)
        for t in trails:
            require(t, "TrailARN", str)
            require(t, "Name", str)
        return list(trails)

    result: list[dict[str, Any]] = ctx.cache.get_or_compute(f"ct.trails.{ctx.client_region}", fetch)
    return result


def trail_status(ctx: CheckContext, trail: dict[str, Any]) -> dict[str, Any]:
    home = optional(trail, "HomeRegion", str) or ctx.client_region
    arn = require(trail, "TrailARN", str)

    def fetch() -> dict[str, Any]:
        return dict(ctx.factory.client("cloudtrail", home).get_trail_status(Name=arn))

    result: dict[str, Any] = ctx.cache.get_or_compute(f"ct.status.{arn}", fetch)
    return result


def _per_trail(
    ctx: CheckContext, control_id: str, sources: list[str], evaluate: Any
) -> list[Finding]:
    out: list[Finding] = []
    resource = f"region/{ctx.region}"
    try:
        trails = trails_in_region(ctx)
    except Exception as exc:
        return [ctx.error_finding(control_id, exc, resource, TRAIL, sources)]
    for trail in trails:
        arn = str(trail["TrailARN"])
        with ctx.capture(out, control_id, arn, TRAIL, sources):
            out.append(evaluate(trail, arn))
    if not trails:
        out.append(
            ctx.finding(
                control_id,
                Status.NOT_APPLICABLE,
                resource,
                TRAIL,
                "No CloudTrail trail is homed in this region.",
                sources=sources,
            )
        )
    return out


@check("LOG-001")
def multi_region_trail(ctx: CheckContext) -> list[Finding]:
    resource = f"account/{ctx.account_id}"
    out: list[Finding] = []
    with ctx.capture(out, "LOG-001", resource, ACCT, _TS):
        resp = ctx.client("cloudtrail").describe_trails(includeShadowTrails=True)
        trails = require(resp, "trailList", list)
        multi = [t for t in trails if t.get("IsMultiRegionTrail") is True]
        logging_names: list[str] = []
        first_error: Exception | None = None
        for t in multi:
            try:
                status = trail_status(ctx, t)
                if status.get("IsLogging") is True:
                    logging_names.append(str(t["Name"]))
            except Exception as exc:
                first_error = first_error or exc
        evidence = {
            "trails_visible": len(trails),
            "multi_region_trails": [str(t.get("Name")) for t in multi],
            "multi_region_logging": logging_names,
        }
        if logging_names:
            out.append(
                ctx.finding(
                    "LOG-001",
                    Status.PASS,
                    resource,
                    ACCT,
                    "A multi-region trail is logging.",
                    evidence=evidence,
                    sources=_TS,
                )
            )
        elif first_error is not None:
            raise first_error
        else:
            out.append(
                ctx.finding(
                    "LOG-001",
                    Status.FAIL,
                    resource,
                    ACCT,
                    "No multi-region CloudTrail trail is actively logging.",
                    evidence=evidence,
                    sources=_TS,
                    uncertainty=["Organization trails owned by another account may not be listed."],
                )
            )
    return out


@check("LOG-002")
def log_file_validation(ctx: CheckContext) -> list[Finding]:
    def evaluate(trail: dict[str, Any], arn: str) -> Finding:
        enabled = optional(trail, "LogFileValidationEnabled", bool) or False
        return ctx.finding(
            "LOG-002",
            Status.PASS if enabled else Status.FAIL,
            arn,
            TRAIL,
            "Log file validation is enabled." if enabled else "Log file validation is disabled.",
            evidence={"trail": trail["Name"], "LogFileValidationEnabled": enabled},
            sources=_DT,
        )

    return _per_trail(ctx, "LOG-002", _DT, evaluate)


@check("LOG-003")
def delivery(ctx: CheckContext) -> list[Finding]:
    def evaluate(trail: dict[str, Any], arn: str) -> Finding:
        status = trail_status(ctx, trail)
        bucket = optional(trail, "S3BucketName", str)
        logging_on = status.get("IsLogging") is True
        err = status.get("LatestDeliveryError")
        problems = []
        if not bucket:
            problems.append("no S3 bucket configured")
        if not logging_on:
            problems.append("trail is not logging")
        if err:
            problems.append("latest S3 delivery reported an error")
        evidence = {
            "trail": trail["Name"],
            "s3_bucket_configured": bool(bucket),
            "IsLogging": logging_on,
            "has_delivery_error": bool(err),
            "LatestDeliveryTime": str(status.get("LatestDeliveryTime", "")) or None,
            "LatestDeliveryError": str(err) if err else None,
        }
        return ctx.finding(
            "LOG-003",
            Status.FAIL if problems else Status.PASS,
            arn,
            TRAIL,
            ("Trail delivery problem: " + "; ".join(problems))
            if problems
            else "Trail is logging and delivering to S3.",
            evidence=evidence,
            sources=_TS,
        )

    return _per_trail(ctx, "LOG-003", _TS, evaluate)


@check("LOG-004")
def cloudwatch_integration(ctx: CheckContext) -> list[Finding]:
    def evaluate(trail: dict[str, Any], arn: str) -> Finding:
        group = optional(trail, "CloudWatchLogsLogGroupArn", str)
        status = trail_status(ctx, trail) if group else {}
        err = status.get("LatestCloudWatchLogsDeliveryError")
        ok = bool(group) and not err
        msg = (
            "Trail delivers to CloudWatch Logs."
            if ok
            else "Trail is not configured for CloudWatch Logs."
            if not group
            else "CloudWatch Logs delivery reported an error."
        )
        return ctx.finding(
            "LOG-004",
            Status.PASS if ok else Status.FAIL,
            arn,
            TRAIL,
            msg,
            evidence={
                "trail": trail["Name"],
                "log_group_configured": bool(group),
                "has_delivery_error": bool(err),
            },
            sources=_TS,
        )

    return _per_trail(ctx, "LOG-004", _TS, evaluate)


@check("LOG-005", "LOG-006")
def trail_bucket(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    resource = f"region/{ctx.region}"
    ids = ["LOG-005", "LOG-006"]
    try:
        trails = trails_in_region(ctx)
    except Exception as exc:
        return [ctx.error_finding(c, exc, resource, TRAIL, _DT) for c in ids]
    for trail in trails:
        bucket = optional(trail, "S3BucketName", str)
        arn = str(trail["TrailARN"])
        if not bucket:
            for cid in ids:
                out.append(
                    ctx.finding(
                        cid,
                        Status.FAIL,
                        arn,
                        TRAIL,
                        "Trail has no S3 bucket configured.",
                        sources=_DT,
                    )
                )
            continue
        res = f"arn:{ctx.partition}:s3:::{bucket}"
        try:
            region = s3c.bucket_region(ctx, bucket)
        except Exception as exc:
            out.extend(ctx.error_finding(c, exc, res, S3, ["s3:GetBucketLocation"]) for c in ids)
            continue
        cross = (
            "The bucket may belong to another account; cross-account buckets can "
            "only be assessed with permissions granted by the bucket owner."
        )
        if ctx.wants("LOG-005"):
            with ctx.capture(out, "LOG-005", res, S3, ["s3:GetBucketPublicAccessBlock"]):
                out.append(_bucket_exposure(ctx, "LOG-005", bucket, region, res, cross))
        if not ctx.wants("LOG-006"):
            continue
        src = ["s3:GetBucketLogging"]
        with ctx.capture(out, "LOG-006", res, S3, src):
            resp = ctx.client("s3", region).get_bucket_logging(Bucket=bucket)
            on = "LoggingEnabled" in resp
            out.append(
                ctx.finding(
                    "LOG-006",
                    Status.PASS if on else Status.FAIL,
                    res,
                    S3,
                    "Server access logging is enabled." if on else "Server access logging is off.",
                    evidence={"trail": trail["Name"], "logging_enabled": on},
                    sources=src,
                    uncertainty=[cross] if not on else [],
                )
            )
    if not trails:
        for cid in ids:
            out.append(
                ctx.finding(
                    cid,
                    Status.NOT_APPLICABLE,
                    resource,
                    TRAIL,
                    "No CloudTrail trail is homed in this region.",
                    sources=_DT,
                )
            )
    return out


def _bucket_exposure(
    ctx: CheckContext, control_id: str, bucket: str, region: str, res: str, note: str
) -> Finding:
    src = [
        "s3:GetBucketPublicAccessBlock",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketPolicyStatus",
    ]
    pab = s3c.assess_pab(ctx, bucket, region)
    evidence: dict[str, Any] = {"bucket": bucket, "effective_block_public_access": pab.effective}
    if pab.fully_blocked:
        return ctx.finding(
            control_id,
            Status.PASS,
            res,
            S3,
            "Block Public Access is fully enabled (bucket or account level).",
            evidence=evidence,
            sources=src,
        )
    try:
        resp = ctx.client("s3", region).get_bucket_policy_status(Bucket=bucket)
        public = bool(require(resp, "PolicyStatus", dict).get("IsPublic"))
    except Exception as exc:
        if error_code(exc) != "NoSuchBucketPolicy":
            raise
        public = False
    evidence["policy_is_public"] = public
    if public:
        return ctx.finding(
            control_id,
            Status.FAIL,
            res,
            S3,
            "Bucket policy makes the bucket public.",
            evidence=evidence,
            sources=src,
        )
    return ctx.finding(
        control_id,
        Status.NOT_ASSESSED,
        res,
        S3,
        "Policy is not public, but Block Public Access is incomplete and bucket ACLs were not "
        "evaluated.",
        evidence=evidence,
        sources=src,
        uncertainty=[note],
    )
