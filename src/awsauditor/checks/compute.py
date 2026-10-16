"""EBS and RDS checks."""

from __future__ import annotations

from ..context import CheckContext, check
from ..evidence import optional, paginate, require
from ..models import Finding, Status

_EBS_NOTE = (
    "Encrypted=true shows configured encryption only; KMS key policy, grants and key "
    "state are not verified."
)


@check("EBS-001")
def ebs_default_encryption(ctx: CheckContext) -> list[Finding]:
    src = ["ec2:GetEbsEncryptionByDefault"]
    resource = f"region/{ctx.region}"
    out: list[Finding] = []
    with ctx.capture(out, "EBS-001", resource, "AWS::EC2::Region", src):
        resp = ctx.client("ec2").get_ebs_encryption_by_default()
        on = require(resp, "EbsEncryptionByDefault", bool)
        out.append(
            ctx.finding(
                "EBS-001",
                Status.PASS if on else Status.FAIL,
                resource,
                "AWS::EC2::Region",
                "EBS encryption by default is on." if on else "EBS encryption by default is off.",
                evidence={"EbsEncryptionByDefault": on},
                sources=src,
            )
        )
    return out


@check("EBS-002")
def ebs_volumes(ctx: CheckContext) -> list[Finding]:
    src = ["ec2:DescribeVolumes"]
    resource = f"region/{ctx.region}"
    out: list[Finding] = []
    with ctx.capture(out, "EBS-002", resource, "AWS::EC2::Volume", src):
        vols = list(paginate(ctx.client("ec2"), "describe_volumes", "Volumes"))
        for v in vols:
            vid = require(v, "VolumeId", str)
            enc = require(v, "Encrypted", bool)
            out.append(
                ctx.finding(
                    "EBS-002",
                    Status.PASS if enc else Status.FAIL,
                    vid,
                    "AWS::EC2::Volume",
                    "Volume is encrypted." if enc else "Volume is not encrypted.",
                    evidence={
                        "Encrypted": enc,
                        "state": v.get("State"),
                        "kms_key_present": bool(v.get("KmsKeyId")),
                    },
                    sources=src,
                    uncertainty=[_EBS_NOTE] if enc else [],
                )
            )
        if not vols:
            out.append(
                ctx.finding(
                    "EBS-002",
                    Status.NOT_APPLICABLE,
                    resource,
                    "AWS::EC2::Volume",
                    "No EBS volumes in this region.",
                    sources=src,
                )
            )
    return out


def _rds(
    ctx: CheckContext,
    control_id: str,
    field: str,
    good: bool,
    ok_msg: str,
    bad_msg: str,
    note: str | None,
) -> list[Finding]:
    src = ["rds:DescribeDBInstances"]
    resource = f"region/{ctx.region}"
    rtype = "AWS::RDS::DBInstance"
    out: list[Finding] = []
    with ctx.capture(out, control_id, resource, rtype, src):
        dbs = list(paginate(ctx.client("rds"), "describe_db_instances", "DBInstances"))
        for db in dbs:
            ident = require(db, "DBInstanceIdentifier", str)
            value = optional(db, field, bool)
            if value is None:
                raise_missing = ctx.finding(
                    control_id,
                    Status.ERROR,
                    ident,
                    rtype,
                    f"Response lacks {field}.",
                    sources=src,
                    uncertainty=["Result unknown."],
                )
                out.append(raise_missing)
                continue
            ok = value is good
            out.append(
                ctx.finding(
                    control_id,
                    Status.PASS if ok else Status.FAIL,
                    ident,
                    rtype,
                    ok_msg if ok else bad_msg,
                    evidence={field: value, "engine": db.get("Engine")},
                    sources=src,
                    uncertainty=[note] if note and ok else [],
                )
            )
        if not dbs:
            out.append(
                ctx.finding(
                    control_id,
                    Status.NOT_APPLICABLE,
                    resource,
                    rtype,
                    "No RDS DB instances in this region.",
                    sources=src,
                )
            )
    return out


@check("RDS-001")
def rds_public(ctx: CheckContext) -> list[Finding]:
    return _rds(
        ctx,
        "RDS-001",
        "PubliclyAccessible",
        False,
        "DB instance is not publicly accessible.",
        "DB instance is publicly accessible.",
        "Security group and routing exposure are not evaluated.",
    )


@check("RDS-002")
def rds_encrypted(ctx: CheckContext) -> list[Finding]:
    return _rds(
        ctx,
        "RDS-002",
        "StorageEncrypted",
        True,
        "Storage encryption is enabled.",
        "Storage encryption is not enabled.",
        _EBS_NOTE,
    )
