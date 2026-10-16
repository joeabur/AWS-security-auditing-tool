"""Regional discovery and validation of the requested region set."""

from __future__ import annotations

from dataclasses import dataclass, field

from botocore.exceptions import BotoCoreError, ClientError

from .errors import AuditorError
from .session import ClientFactory


@dataclass
class RegionPlan:
    audited: list[str]
    enabled: list[str]  # all regions enabled for the account (empty if discovery failed)
    warnings: list[str] = field(default_factory=list)
    discovery_ok: bool = True


def discover_enabled_regions(factory: ClientFactory, home_region: str) -> list[str]:
    ec2 = factory.client("ec2", home_region)
    resp = ec2.describe_regions(AllRegions=False)
    return sorted(r["RegionName"] for r in resp["Regions"])


def plan_regions(
    factory: ClientFactory, requested: list[str], home_region: str, partition: str
) -> RegionPlan:
    want_all = not requested or [r.lower() for r in requested] == ["all"]
    try:
        enabled = discover_enabled_regions(factory, home_region)
    except (ClientError, BotoCoreError, KeyError) as exc:
        if want_all:
            raise AuditorError(
                "cannot discover enabled regions (ec2:DescribeRegions failed: "
                f"{type(exc).__name__}); specify regions explicitly"
            ) from exc
        known = set(factory.available_partition_regions("ec2", partition))
        unknown = sorted(set(requested) - known)
        if unknown:
            raise AuditorError(f"unknown region(s): {', '.join(unknown)}") from exc
        return RegionPlan(
            audited=sorted(set(requested)),
            enabled=[],
            warnings=[
                "Region discovery failed; requested regions could not be confirmed as enabled "
                "and coverage gaps cannot be computed."
            ],
            discovery_ok=False,
        )
    if want_all:
        return RegionPlan(audited=enabled, enabled=enabled)
    unknown = sorted(set(requested) - set(enabled))
    if unknown:
        raise AuditorError(
            f"region(s) not enabled for this account or unknown: {', '.join(unknown)}"
        )
    return RegionPlan(audited=sorted(set(requested)), enabled=enabled)
