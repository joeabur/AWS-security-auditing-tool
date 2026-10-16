"""S3 account- and bucket-level checks."""

from __future__ import annotations

import json
from typing import Any

from ..context import CheckContext, check
from ..errors import ParseError
from ..evidence import error_code, optional, require
from ..models import Finding, Status
from . import _s3common as s3c

S3 = "AWS::S3::Bucket"
ACCT = "AWS::::Account"
_LIST = ["s3:ListAllMyBuckets", "s3:GetBucketLocation"]


@check("STO-001")
def account_pab(ctx: CheckContext) -> list[Finding]:
    src = ["s3:GetAccountPublicAccessBlock"]
    resource = f"account/{ctx.account_id}"
    out: list[Finding] = []
    with ctx.capture(out, "STO-001", resource, ACCT, src):
        pab = s3c.account_pab(ctx)
        if pab is None:
            out.append(
                ctx.finding(
                    "STO-001",
                    Status.FAIL,
                    resource,
                    ACCT,
                    "Account-level Block Public Access is not configured.",
                    sources=src,
                )
            )
        else:
            ok = all(pab.values())
            out.append(
                ctx.finding(
                    "STO-001",
                    Status.PASS if ok else Status.FAIL,
                    resource,
                    ACCT,
                    "All account-level Block Public Access settings are on."
                    if ok
                    else "Some account-level Block Public Access settings are off.",
                    evidence=pab,
                    sources=src,
                )
            )
    return out


def _per_bucket(
    ctx: CheckContext, control_id: str, sources: list[str], evaluate: Any
) -> list[Finding]:
    out: list[Finding] = []
    resource = f"region/{ctx.region}"
    try:
        buckets = s3c.buckets_in_region(ctx, ctx.region)
    except Exception as exc:
        return [ctx.error_finding(control_id, exc, resource, S3, _LIST + sources)]
    for name in buckets:
        res = f"arn:{ctx.partition}:s3:::{name}"
        with ctx.capture(out, control_id, res, S3, sources):
            out.append(evaluate(name, res))
    if not buckets:
        out.append(
            ctx.finding(
                control_id,
                Status.NOT_APPLICABLE,
                resource,
                S3,
                "No S3 buckets located in this region.",
                sources=_LIST,
            )
        )
    return out


@check("STO-002")
def bucket_pab(ctx: CheckContext) -> list[Finding]:
    src = ["s3:GetBucketPublicAccessBlock", "s3:GetAccountPublicAccessBlock"]

    def evaluate(name: str, res: str) -> Finding:
        pab = s3c.assess_pab(ctx, name, ctx.region)
        return ctx.finding(
            "STO-002",
            Status.PASS if pab.fully_blocked else Status.FAIL,
            res,
            S3,
            "Block Public Access is effectively fully enabled."
            if pab.fully_blocked
            else "Block Public Access is not fully enabled for this bucket.",
            evidence={
                "bucket": name,
                "effective": pab.effective,
                "bucket_level_configured": pab.bucket_level is not None,
            },
            sources=src,
        )

    return _per_bucket(ctx, "STO-002", src, evaluate)


@check("STO-003")
def bucket_policy_public(ctx: CheckContext) -> list[Finding]:
    src = ["s3:GetBucketPolicyStatus"]

    def evaluate(name: str, res: str) -> Finding:
        try:
            resp = ctx.client("s3", ctx.region).get_bucket_policy_status(Bucket=name)
            public = bool(require(resp, "PolicyStatus", dict).get("IsPublic"))
            has_policy = True
        except Exception as exc:
            if error_code(exc) != "NoSuchBucketPolicy":
                raise
            public, has_policy = False, False
        return ctx.finding(
            "STO-003",
            Status.FAIL if public else Status.PASS,
            res,
            S3,
            "Bucket policy makes the bucket public."
            if public
            else "Bucket policy does not make the bucket public."
            if has_policy
            else "Bucket has no policy.",
            evidence={"bucket": name, "has_policy": has_policy, "is_public": public},
            sources=src,
            uncertainty=["Bucket ACLs and access points are not evaluated."],
        )

    return _per_bucket(ctx, "STO-003", src, evaluate)


@check("STO-004")
def bucket_encryption(ctx: CheckContext) -> list[Finding]:
    src = ["s3:GetEncryptionConfiguration"]
    caveat = (
        "Configured default encryption is not proof of effective protection: existing "
        "objects, KMS key policy/grants, and key state are not verified."
    )

    def evaluate(name: str, res: str) -> Finding:
        try:
            resp = ctx.client("s3", ctx.region).get_bucket_encryption(Bucket=name)
        except Exception as exc:
            if error_code(exc) != "ServerSideEncryptionConfigurationNotFoundError":
                raise
            return ctx.finding(
                "STO-004",
                Status.FAIL,
                res,
                S3,
                "No default encryption configuration.",
                evidence={"bucket": name},
                sources=src,
            )
        rules = require(require(resp, "ServerSideEncryptionConfiguration", dict), "Rules", list)
        if not rules:
            raise ParseError("encryption configuration has no rules")
        default = require(rules[0], "ApplyServerSideEncryptionByDefault", dict)
        algo = require(default, "SSEAlgorithm", str)
        return ctx.finding(
            "STO-004",
            Status.PASS,
            res,
            S3,
            f"Default encryption configured ({algo}).",
            evidence={
                "bucket": name,
                "algorithm": algo,
                "kms_key_specified": bool(default.get("KMSMasterKeyID")),
            },
            sources=src,
            uncertainty=[caveat],
        )

    return _per_bucket(ctx, "STO-004", src, evaluate)


@check("STO-005")
def bucket_logging(ctx: CheckContext) -> list[Finding]:
    src = ["s3:GetBucketLogging"]

    def evaluate(name: str, res: str) -> Finding:
        resp = ctx.client("s3", ctx.region).get_bucket_logging(Bucket=name)
        on = "LoggingEnabled" in resp
        return ctx.finding(
            "STO-005",
            Status.PASS if on else Status.FAIL,
            res,
            S3,
            "Server access logging is enabled." if on else "Server access logging is not enabled.",
            evidence={"bucket": name, "logging_enabled": on},
            sources=src,
            uncertainty=[]
            if on
            else [
                "CloudTrail S3 data events may provide equivalent coverage; they are not evaluated."
            ],
        )

    return _per_bucket(ctx, "STO-005", src, evaluate)


def _denies_insecure_transport(policy: Any) -> bool:
    doc = json.loads(policy) if isinstance(policy, str) else policy
    if not isinstance(doc, dict):
        raise ParseError("bucket policy is not an object")
    statements = doc.get("Statement", [])
    for st in statements if isinstance(statements, list) else [statements]:
        if not isinstance(st, dict) or st.get("Effect") != "Deny":
            continue
        principal = st.get("Principal")
        if principal != "*" and not (isinstance(principal, dict) and principal.get("AWS") == "*"):
            continue
        actions = st.get("Action")
        actions = actions if isinstance(actions, list) else [actions]
        if not any(a in ("*", "s3:*") for a in actions):
            continue
        cond = st.get("Condition") or {}
        for op in ("Bool", "BoolIfExists"):
            val = (cond.get(op) or {}).get("aws:SecureTransport")
            if str(val).lower() == "false":
                return True
    return False


@check("STO-006")
def bucket_tls(ctx: CheckContext) -> list[Finding]:
    src = ["s3:GetBucketPolicy"]

    def evaluate(name: str, res: str) -> Finding:
        try:
            resp = ctx.client("s3", ctx.region).get_bucket_policy(Bucket=name)
            policy = optional(resp, "Policy", str)
            if policy is None:
                raise ParseError("missing Policy")
            denies = _denies_insecure_transport(policy)
        except json.JSONDecodeError as exc:
            raise ParseError("bucket policy is not valid JSON") from exc
        except ParseError:
            raise
        except Exception as exc:
            if error_code(exc) != "NoSuchBucketPolicy":
                raise
            denies = False
        return ctx.finding(
            "STO-006",
            Status.PASS if denies else Status.FAIL,
            res,
            S3,
            "Policy denies non-TLS requests."
            if denies
            else "No policy statement denies non-TLS requests.",
            evidence={"bucket": name, "denies_insecure_transport": denies},
            sources=src,
            uncertainty=[
                "Only the common Deny/aws:SecureTransport=false pattern is recognised; "
                "equivalent custom policies may be reported as FAIL."
            ],
        )

    return _per_bucket(ctx, "STO-006", src, evaluate)
