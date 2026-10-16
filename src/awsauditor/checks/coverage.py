"""Account and region coverage gaps."""

from __future__ import annotations

from ..context import CheckContext, check
from ..models import Finding, Status


@check("COV-001")
def region_coverage(ctx: CheckContext) -> list[Finding]:
    src = ["ec2:DescribeRegions"]
    resource = f"account/{ctx.account_id}"
    rtype = "AWS::::Account"
    if not ctx.region_discovery_ok:
        return [
            ctx.finding(
                "COV-001",
                Status.NOT_ASSESSED,
                resource,
                rtype,
                "Enabled regions could not be discovered, so coverage is unknown.",
                evidence={"audited_regions": ctx.audited_regions},
                sources=src,
            )
        ]
    missing = sorted(set(ctx.enabled_regions) - set(ctx.audited_regions))
    if missing:
        return [
            ctx.finding(
                "COV-001",
                Status.NOT_ASSESSED,
                resource,
                rtype,
                f"{len(missing)} enabled region(s) were not audited.",
                evidence={"unaudited_regions": missing, "audited_regions": ctx.audited_regions},
                sources=src,
                uncertainty=["Resources in unaudited regions are unassessed."],
            )
        ]
    return [
        ctx.finding(
            "COV-001",
            Status.PASS,
            resource,
            rtype,
            "All enabled regions were audited.",
            evidence={"audited_regions": ctx.audited_regions},
            sources=src,
        )
    ]
