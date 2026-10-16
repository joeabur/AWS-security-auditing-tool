"""Regenerate the SYNTHETIC sample reports in this directory.

The reports are produced by running the real runner, checks and report writers against
botocore-stubbed API responses for the fictional account 111122223333. No AWS account was
contacted. Run from the project root:  uv run python examples/generate_sample_report.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.unit.conftest import ACCOUNT, NOW, Harness  # noqa: E402

from awsauditor.catalog import select_controls  # noqa: E402
from awsauditor.config import AuditConfig, RedactionSettings  # noqa: E402
from awsauditor.redaction import Redactor  # noqa: E402
from awsauditor.regions import RegionPlan  # noqa: E402
from awsauditor.reporting import build_report, to_csv, to_html, to_json  # noqa: E402
from awsauditor.runner import run_audit  # noqa: E402
from awsauditor.session import Identity  # noqa: E402

CONTROLS = ["IAM-001", "IAM-002", "IAM-007", "NET-001", "EBS-002", "LOG-011", "LOG-012", "STO-002"]
ALL = dict.fromkeys(
    ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), True
)


def main() -> None:
    h = Harness(AuditConfig(audit={"workers": 1}))  # type: ignore[arg-type]
    h.ok(
        "iam",
        "get_account_summary",
        {"SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}},
    )
    h.ok(
        "iam",
        "get_account_password_policy",
        {
            "PasswordPolicy": {
                "MinimumPasswordLength": 8,
                "PasswordReusePrevention": 5,
                "RequireSymbols": False,
                "RequireNumbers": True,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "AllowUsersToChangePassword": True,
                "ExpirePasswords": False,
            }
        },
    )
    h.ok(
        "ec2",
        "describe_volumes",
        {
            "Volumes": [
                {"VolumeId": "vol-0a1b2c3d4e5f60001", "Encrypted": True, "State": "in-use"},
                {"VolumeId": "vol-0a1b2c3d4e5f60002", "Encrypted": False, "State": "available"},
            ]
        },
    )
    h.ok(
        "ec2",
        "describe_security_groups",
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-0a1b2c3d4e5f60001",
                    "GroupName": "bastion",
                    "VpcId": "vpc-01",
                    "Description": "d",
                    "IpPermissionsEgress": [],
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            "Ipv6Ranges": [],
                        }
                    ],
                },
                {
                    "GroupId": "sg-0a1b2c3d4e5f60002",
                    "GroupName": "app",
                    "VpcId": "vpc-01",
                    "Description": "d",
                    "IpPermissionsEgress": [],
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            "Ipv6Ranges": [],
                        }
                    ],
                },
            ]
        },
    )
    h.ok("guardduty", "list_detectors", {"DetectorIds": []})
    h.err("config", "describe_configuration_recorders", "AccessDeniedException", 400)
    h.ok(
        "s3",
        "list_buckets",
        {
            "Buckets": [
                {"Name": "example-private-bucket", "BucketRegion": "us-east-1"},
                {"Name": "example-open-bucket", "BucketRegion": "us-east-1"},
            ],
            "Owner": {"ID": "x"},
        },
    )
    h.err("s3", "get_public_access_block", "NoSuchPublicAccessBlockConfiguration", 404)
    h.ok("s3", "get_public_access_block", {"PublicAccessBlockConfiguration": ALL})
    h.err("s3control", "get_public_access_block", "NoSuchPublicAccessBlockConfiguration", 404)
    # Controls run in registration order; the stub queue per client follows that order.

    catalog = h.catalog
    plan = RegionPlan(
        ["us-east-1"],
        ["us-east-1"],
        warnings=[
            "SYNTHETIC EXAMPLE: generated from stubbed API responses for a "
            "fictional account; no AWS account was contacted."
        ],
    )
    result = run_audit(
        h.factory,
        Identity(ACCOUNT, f"arn:aws:iam::{ACCOUNT}:user/auditor", "aws"),
        h.config,
        catalog,
        select_controls(catalog, include=CONTROLS),
        plan,
        home_region="us-east-1",
        profile_name="example",
        now=lambda: NOW,
    )
    report = build_report(result)
    redactor = Redactor(RedactionSettings(enabled=True, ip_addresses=True))
    out = Path(__file__).parent
    for name, render in (("json", to_json), ("csv", to_csv), ("html", to_html)):
        (out / f"sample-report.{name}").write_text(render(report, redactor), encoding="utf-8")
    print(report.summary["by_status"])


if __name__ == "__main__":
    main()
