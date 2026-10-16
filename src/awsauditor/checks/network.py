"""Security group exposure and public snapshot/AMI checks."""

from __future__ import annotations

from typing import Any

from ..context import CheckContext, check
from ..errors import ParseError
from ..evidence import optional, paginate, require
from ..models import Finding, Status

SG = "AWS::EC2::SecurityGroup"
_SRC = ["ec2:DescribeSecurityGroups"]
_PROTO = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}
_PUBLIC_V4 = "0.0.0.0/0"
_PUBLIC_V6 = "::/0"


def public_sources(rule: dict[str, Any]) -> list[str]:
    """CIDRs in the rule that are the entire IPv4 or IPv6 internet."""
    found: list[str] = []
    for r in rule.get("IpRanges", []) or []:
        if r.get("CidrIp") == _PUBLIC_V4:
            found.append(_PUBLIC_V4)
    for r in rule.get("Ipv6Ranges", []) or []:
        if r.get("CidrIpv6") == _PUBLIC_V6:
            found.append(_PUBLIC_V6)
    return found


def rule_port_span(rule: dict[str, Any]) -> tuple[str, int, int] | None:
    """Return ``(protocol, from_port, to_port)``; all protocols are reported as ``-1``.

    Returns None for protocols without ports (ICMP) which cannot expose TCP/UDP services.
    """
    proto = str(rule.get("IpProtocol", ""))
    if proto == "-1":
        return "-1", 0, 65535
    proto = _PROTO.get(proto, proto)
    if proto not in ("tcp", "udp"):
        return None
    lo, hi = rule.get("FromPort"), rule.get("ToPort")
    if not isinstance(lo, int) or not isinstance(hi, int) or lo > hi:
        raise ParseError("security group rule has invalid port range")
    return proto, lo, hi


def _groups(ctx: CheckContext) -> list[dict[str, Any]]:
    def fetch() -> list[dict[str, Any]]:
        groups = list(paginate(ctx.client("ec2"), "describe_security_groups", "SecurityGroups"))
        for g in groups:
            require(g, "GroupId", str)
        return groups

    result: list[dict[str, Any]] = ctx.cache.get_or_compute(f"ec2.sg.{ctx.region}", fetch)
    return result


def _per_group(
    ctx: CheckContext, control_id: str, evaluate: Any, only_default: bool = False
) -> list[Finding]:
    out: list[Finding] = []
    resource = f"region/{ctx.region}"
    try:
        groups = _groups(ctx)
    except Exception as exc:
        return [ctx.error_finding(control_id, exc, resource, SG, _SRC)]
    if only_default:
        groups = [g for g in groups if g.get("GroupName") == "default"]
    for g in groups:
        gid = str(g["GroupId"])
        with ctx.capture(out, control_id, gid, SG, _SRC):
            out.append(evaluate(g, gid))
    if not groups:
        out.append(
            ctx.finding(
                control_id,
                Status.NOT_APPLICABLE,
                resource,
                SG,
                "No applicable security groups in this region.",
                sources=_SRC,
            )
        )
    return out


@check("NET-001")
def sensitive_ports(ctx: CheckContext) -> list[Finding]:
    sensitive = set(ctx.config.thresholds.sensitive_ports)

    def evaluate(g: dict[str, Any], gid: str) -> Finding:
        exposed: list[dict[str, Any]] = []
        for rule in g.get("IpPermissions", []) or []:
            srcs = public_sources(rule)
            span = rule_port_span(rule) if srcs else None
            if not span:
                continue
            proto, lo, hi = span
            ports = sorted(p for p in sensitive if lo <= p <= hi)
            if ports:
                exposed.append(
                    {
                        "protocol": proto,
                        "from_port": lo,
                        "to_port": hi,
                        "sources": srcs,
                        "sensitive_ports": ports,
                    }
                )
        return ctx.finding(
            "NET-001",
            Status.FAIL if exposed else Status.PASS,
            gid,
            SG,
            "Sensitive ports are open to the internet."
            if exposed
            else "No sensitive port is open to the internet.",
            evidence={
                "group_name": g.get("GroupName"),
                "vpc_id": g.get("VpcId"),
                "open_rules": exposed,
                "sensitive_ports_checked": sorted(sensitive),
            },
            sources=_SRC,
            uncertainty=[
                "Only exact 0.0.0.0/0 and ::/0 are treated as public; broad CIDRs and "
                "attachment to a resource are not evaluated."
            ],
        )

    return _per_group(ctx, "NET-001", evaluate)


@check("NET-002")
def default_sg(ctx: CheckContext) -> list[Finding]:
    def evaluate(g: dict[str, Any], gid: str) -> Finding:
        ing = len(g.get("IpPermissions", []) or [])
        egr = len(g.get("IpPermissionsEgress", []) or [])
        bad = ing + egr > 0
        return ctx.finding(
            "NET-002",
            Status.FAIL if bad else Status.PASS,
            gid,
            SG,
            "Default security group has rules." if bad else "Default security group has no rules.",
            evidence={"vpc_id": g.get("VpcId"), "inbound_rules": ing, "outbound_rules": egr},
            sources=_SRC,
        )

    return _per_group(ctx, "NET-002", evaluate, only_default=True)


@check("NET-003")
def all_ports_open(ctx: CheckContext) -> list[Finding]:
    def evaluate(g: dict[str, Any], gid: str) -> Finding:
        bad: list[dict[str, Any]] = []
        for rule in g.get("IpPermissions", []) or []:
            srcs = public_sources(rule)
            span = rule_port_span(rule) if srcs else None
            if span and span[1] == 0 and span[2] == 65535:
                bad.append({"protocol": span[0], "sources": srcs})
        return ctx.finding(
            "NET-003",
            Status.FAIL if bad else Status.PASS,
            gid,
            SG,
            "All ports are open to the internet."
            if bad
            else "No all-port rule is open to the internet.",
            evidence={"group_name": g.get("GroupName"), "open_rules": bad},
            sources=_SRC,
        )

    return _per_group(ctx, "NET-003", evaluate)


@check("NET-004")
def unrestricted_egress(ctx: CheckContext) -> list[Finding]:
    def evaluate(g: dict[str, Any], gid: str) -> Finding:
        bad = [
            r
            for r in g.get("IpPermissionsEgress", []) or []
            if str(r.get("IpProtocol")) == "-1" and public_sources(r)
        ]
        is_default = g.get("GroupName") == "default"
        if is_default:
            return ctx.finding(
                "NET-004",
                Status.NOT_APPLICABLE,
                gid,
                SG,
                "Default groups are evaluated by NET-002.",
                sources=_SRC,
            )
        return ctx.finding(
            "NET-004",
            Status.FAIL if bad else Status.PASS,
            gid,
            SG,
            "Group allows all outbound traffic to the internet."
            if bad
            else "Outbound traffic is restricted.",
            evidence={"group_name": g.get("GroupName"), "unrestricted_egress_rules": len(bad)},
            sources=_SRC,
        )

    return _per_group(ctx, "NET-004", evaluate)


@check("NET-005")
def public_snapshots(ctx: CheckContext) -> list[Finding]:
    src = ["ec2:DescribeSnapshots"]
    resource = f"region/{ctx.region}"
    out: list[Finding] = []
    with ctx.capture(out, "NET-005", resource, "AWS::EC2::Snapshot", src):
        snaps = list(
            paginate(
                ctx.client("ec2"),
                "describe_snapshots",
                "Snapshots",
                OwnerIds=["self"],
                RestorableByUserIds=["all"],
            )
        )
        for s in snaps:
            sid = require(s, "SnapshotId", str)
            out.append(
                ctx.finding(
                    "NET-005",
                    Status.FAIL,
                    sid,
                    "AWS::EC2::Snapshot",
                    "Snapshot is public.",
                    evidence={
                        "volume_size_gib": optional(s, "VolumeSize", int),
                        "encrypted": optional(s, "Encrypted", bool),
                    },
                    sources=src,
                )
            )
        if not snaps:
            out.append(
                ctx.finding(
                    "NET-005",
                    Status.PASS,
                    resource,
                    "AWS::EC2::Snapshot",
                    "No public snapshots owned by this account.",
                    evidence={"public_snapshots": 0},
                    sources=src,
                )
            )
    return out


@check("NET-006")
def public_amis(ctx: CheckContext) -> list[Finding]:
    src = ["ec2:DescribeImages"]
    resource = f"region/{ctx.region}"
    out: list[Finding] = []
    with ctx.capture(out, "NET-006", resource, "AWS::EC2::Image", src):
        resp = ctx.client("ec2").describe_images(
            Owners=["self"], Filters=[{"Name": "is-public", "Values": ["true"]}]
        )
        images = require(resp, "Images", list)
        for im in images:
            out.append(
                ctx.finding(
                    "NET-006",
                    Status.FAIL,
                    require(im, "ImageId", str),
                    "AWS::EC2::Image",
                    "AMI is public.",
                    evidence={"state": im.get("State")},
                    sources=src,
                )
            )
        if not images:
            out.append(
                ctx.finding(
                    "NET-006",
                    Status.PASS,
                    resource,
                    "AWS::EC2::Image",
                    "No public AMIs owned by this account.",
                    evidence={"public_images": 0},
                    sources=src,
                )
            )
    return out
