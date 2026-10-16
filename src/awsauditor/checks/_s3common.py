"""S3 evidence helpers shared by the CloudTrail-bucket and S3 checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..context import CheckContext
from ..evidence import error_code, optional, paginate, require

PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
_NO_PAB = "NoSuchPublicAccessBlockConfiguration"


def normalize_location(constraint: str | None) -> str:
    """Map a GetBucketLocation constraint to a region name."""
    if not constraint:
        return "us-east-1"
    if constraint == "EU":
        return "eu-west-1"
    return constraint


def bucket_region(ctx: CheckContext, bucket: str) -> str:
    def fetch() -> str:
        resp = ctx.client("s3").get_bucket_location(Bucket=bucket)
        return normalize_location(optional(resp, "LocationConstraint", str))

    result: str = ctx.cache.get_or_compute(f"s3.region.{bucket}", fetch)
    return result


def list_buckets(ctx: CheckContext) -> list[dict[str, Any]]:
    def fetch() -> list[dict[str, Any]]:
        return list(paginate(ctx.client("s3"), "list_buckets", "Buckets"))

    result: list[dict[str, Any]] = ctx.cache.get_or_compute("s3.buckets", fetch)
    return result


def buckets_in_region(ctx: CheckContext, region: str) -> list[str]:
    """Names of buckets located in ``region``; resolves location lazily per bucket."""
    names: list[str] = []
    for entry in list_buckets(ctx):
        name = require(entry, "Name", str)
        located = optional(entry, "BucketRegion", str) or bucket_region(ctx, name)
        if located == region:
            names.append(name)
    return sorted(names)


def _pab_from(resp: Any) -> dict[str, bool]:
    cfg = require(resp, "PublicAccessBlockConfiguration", dict)
    return {k: bool(cfg.get(k, False)) for k in PAB_KEYS}


def account_pab(ctx: CheckContext) -> dict[str, bool] | None:
    """Account-level Block Public Access (None if never configured)."""

    def fetch() -> dict[str, bool] | None:
        client = ctx.factory.client("s3control", ctx.client_region)
        try:
            return _pab_from(client.get_public_access_block(AccountId=ctx.account_id))
        except Exception as exc:
            if error_code(exc) == _NO_PAB:
                return None
            raise

    result: dict[str, bool] | None = ctx.cache.get_or_compute("s3.account_pab", fetch)
    return result


def bucket_pab(ctx: CheckContext, bucket: str, region: str) -> dict[str, bool] | None:
    client = ctx.client("s3", region)
    try:
        return _pab_from(client.get_public_access_block(Bucket=bucket))
    except Exception as exc:
        if error_code(exc) == _NO_PAB:
            return None
        raise


@dataclass
class PabAssessment:
    effective: dict[str, bool]
    bucket_level: dict[str, bool] | None
    account_level: dict[str, bool] | None

    @property
    def fully_blocked(self) -> bool:
        return all(self.effective.values())


def assess_pab(ctx: CheckContext, bucket: str, region: str) -> PabAssessment:
    """Effective Block Public Access = union of bucket and account settings.

    Raises if either level cannot be read and the bucket level alone is not conclusive, so
    that an unreadable account setting is never treated as 'not blocking'.
    """
    bucket_level = bucket_pab(ctx, bucket, region)
    if bucket_level is not None and all(bucket_level.values()):
        return PabAssessment(dict(bucket_level), bucket_level, None)
    account_level = account_pab(ctx)
    effective = {
        k: bool((bucket_level or {}).get(k)) or bool((account_level or {}).get(k)) for k in PAB_KEYS
    }
    return PabAssessment(effective, bucket_level, account_level)
