"""Least-privilege IAM policy generation from the control catalog."""

from __future__ import annotations

from typing import Any

from .models import Control

# Needed by every run for region discovery and the COV-001 coverage check.
REQUIRED_ACTIONS = ["ec2:DescribeRegions"]
_SERVICE_SIDS = {
    "access-analyzer": "AccessAnalyzer",
    "cloudtrail": "CloudTrail",
    "cloudwatch": "CloudWatch",
    "config": "Config",
    "ec2": "Ec2",
    "guardduty": "GuardDuty",
    "iam": "Iam",
    "logs": "Logs",
    "rds": "Rds",
    "s3": "S3",
}


def required_actions(controls: list[Control]) -> list[str]:
    return sorted({a for c in controls for a in c.permissions} | set(REQUIRED_ACTIONS))


def build_policy(controls: list[Control]) -> dict[str, Any]:
    actions = required_actions(controls)
    by_service: dict[str, list[str]] = {}
    for a in actions:
        by_service.setdefault(a.split(":")[0], []).append(a)
    statements = [
        {
            "Sid": f"ReadOnly{_SERVICE_SIDS.get(svc, svc.title().replace('-', ''))}",
            "Effect": "Allow",
            "Action": acts,
            "Resource": "*",
        }
        for svc, acts in sorted(by_service.items())
    ]
    return {"Version": "2012-10-17", "Statement": statements}
