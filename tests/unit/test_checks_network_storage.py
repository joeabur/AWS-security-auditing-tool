"""Network (NET-*), storage (STO-*), EBS/RDS and coverage controls."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from awsauditor.checks import compute, coverage, network, s3
from awsauditor.config import AuditConfig, Thresholds
from awsauditor.models import Status

from .conftest import ACCOUNT, Harness, assert_wellformed, fixture_text, statuses

ANY4 = {"CidrIp": "0.0.0.0/0"}
ANY6 = {"CidrIpv6": "::/0"}


def rule(
    proto: str = "tcp",
    lo: int | None = None,
    hi: int | None = None,
    v4: list[dict[str, str]] | None = None,
    v6: list[dict[str, str]] | None = None,
) -> dict:  # type: ignore[type-arg]
    r: dict[str, Any] = {"IpProtocol": proto, "IpRanges": v4 or [], "Ipv6Ranges": v6 or []}
    if lo is not None:
        r["FromPort"], r["ToPort"] = lo, hi
    return r


def sg(
    gid: str,
    ingress: list[dict[str, Any]],
    egress: list[dict[str, Any]] | None = None,
    name: str = "web",
) -> dict[str, Any]:
    return {
        "GroupId": gid,
        "GroupName": name,
        "VpcId": "vpc-1",
        "Description": "d",
        "IpPermissions": ingress,
        "IpPermissionsEgress": egress or [],
    }


def stub_sgs(h: Harness, groups: list[dict[str, Any]]) -> None:
    h.ok("ec2", "describe_security_groups", {"SecurityGroups": groups})


# ---------------------------------------------------------------- NET-001


@pytest.mark.parametrize(
    ("r", "expected", "ports"),
    [
        (rule("tcp", 22, 22, [ANY4]), "FAIL", [22]),
        (rule("tcp", 22, 22, v6=[ANY6]), "FAIL", [22]),
        (rule("tcp", 3389, 3389, [ANY4]), "FAIL", [3389]),
        (rule("tcp", 21, 23, [ANY4]), "FAIL", [21, 22, 23]),  # range covering several
        (rule("tcp", 0, 65535, [ANY4]), "FAIL", None),
        (rule("-1", None, None, [ANY4]), "FAIL", None),
        (rule("6", 22, 22, [ANY4]), "FAIL", [22]),  # numeric protocol
        (rule("udp", 2049, 2049, [ANY4]), "FAIL", [2049]),
        (rule("tcp", 80, 80, [ANY4]), "PASS", None),
        (rule("tcp", 23, 21, [ANY4]), "ERROR", None),  # invalid range -> malformed
        (rule("tcp", 20, 20, [ANY4]), "PASS", None),  # just below 21
        (rule("tcp", 24, 444, [ANY4]), "PASS", None),  # between sensitive ports
        (rule("tcp", 22, 22, [{"CidrIp": "10.0.0.0/8"}]), "PASS", None),
        (rule("tcp", 22, 22, [{"CidrIp": "203.0.113.0/24"}]), "PASS", None),
        (rule("icmp", -1, -1, [ANY4]), "PASS", None),
    ],
)
def test_net001_rules(h: Harness, r: dict, expected: str, ports: list[int] | None) -> None:  # type: ignore[type-arg]
    stub_sgs(h, [sg("sg-1", [r])])
    f = network.sensitive_ports(h.ctx())
    assert statuses(f) == [expected]
    if ports is not None:
        assert f[0].evidence["open_rules"][0]["sensitive_ports"] == ports
    assert_wellformed(f)


def test_net001_custom_ports_pagination_and_empty(h: Harness) -> None:
    h.config = AuditConfig(thresholds=Thresholds(sensitive_ports=[8080]))
    h.ok(
        "ec2",
        "describe_security_groups",
        {"SecurityGroups": [sg("sg-1", [rule("tcp", 8080, 8080, [ANY4])])], "NextToken": "n"},
    )
    h.ok(
        "ec2",
        "describe_security_groups",
        {"SecurityGroups": [sg("sg-2", [rule("tcp", 22, 22, [ANY4])])]},
    )
    f = network.sensitive_ports(h.ctx())
    assert {x.resource_id: x.status for x in f} == {"sg-1": Status.FAIL, "sg-2": Status.PASS}
    stub_sgs(h, [])
    assert statuses(network.sensitive_ports(h.ctx())) == ["NOT_APPLICABLE"]


def test_net001_denied_and_unsupported(h: Harness) -> None:
    h.err("ec2", "describe_security_groups", "UnauthorizedOperation", 403)
    assert statuses(network.sensitive_ports(h.ctx())) == ["ERROR"]
    h.err("ec2", "describe_security_groups", "AuthFailure", 401)
    assert statuses(network.sensitive_ports(h.ctx())) == ["NOT_ASSESSED"]


# ---------------------------------------------------------------- NET-002..004


def test_net002_default_group(h: Harness) -> None:
    stub_sgs(
        h,
        [
            sg("sg-d1", [rule("-1", None, None, [ANY4])], name="default"),
            sg("sg-d2", [], [], name="default"),
            sg("sg-x", [rule("tcp", 22, 22, [ANY4])]),
        ],
    )
    f = network.default_sg(h.ctx())
    assert {x.resource_id: x.status for x in f} == {"sg-d1": Status.FAIL, "sg-d2": Status.PASS}


def test_net002_egress_only_rules_fail_and_none_is_na(h: Harness) -> None:
    stub_sgs(h, [sg("sg-d", [], [rule("-1", None, None, [ANY4])], name="default")])
    assert statuses(network.default_sg(h.ctx())) == ["FAIL"]
    stub_sgs(h, [sg("sg-x", [])])
    assert statuses(network.default_sg(h.ctx())) == ["NOT_APPLICABLE"]


@pytest.mark.parametrize(
    ("r", "expected"),
    [
        (rule("-1", None, None, [ANY4]), "FAIL"),
        (rule("tcp", 0, 65535, v6=[ANY6]), "FAIL"),
        (rule("udp", 0, 65535, [ANY4]), "FAIL"),
        (rule("tcp", 1, 65535, [ANY4]), "PASS"),  # boundary: not the full range
        (rule("tcp", 0, 65534, [ANY4]), "PASS"),
        (rule("-1", None, None, [{"CidrIp": "10.0.0.0/8"}]), "PASS"),
    ],
)
def test_net003_all_ports(h: Harness, r: dict, expected: str) -> None:  # type: ignore[type-arg]
    stub_sgs(h, [sg("sg-1", [r])])
    assert statuses(network.all_ports_open(h.ctx())) == [expected]


def test_net004_unrestricted_egress(h: Harness) -> None:
    stub_sgs(
        h,
        [
            sg("sg-open", [], [rule("-1", None, None, [ANY4])]),
            sg("sg-v6", [], [rule("-1", None, None, v6=[ANY6])]),
            sg("sg-https", [], [rule("tcp", 443, 443, [ANY4])]),
            sg("sg-none", [], []),
            sg("sg-def", [], [rule("-1", None, None, [ANY4])], name="default"),
        ],
    )
    got = {x.resource_id: x.status for x in network.unrestricted_egress(h.ctx())}
    assert got == {
        "sg-open": Status.FAIL,
        "sg-v6": Status.FAIL,
        "sg-https": Status.PASS,
        "sg-none": Status.PASS,
        "sg-def": Status.NOT_APPLICABLE,
    }


def test_sg_description_is_not_in_evidence(h: Harness) -> None:
    stub_sgs(h, [sg("sg-1", [rule("tcp", 22, 22, [ANY4])])])
    assert "Description" not in json.dumps(network.sensitive_ports(h.ctx())[0].evidence)


# ---------------------------------------------------------------- NET-005 / NET-006


def test_net005_public_snapshots(h: Harness) -> None:
    snap = {
        "SnapshotId": "snap-1",
        "VolumeSize": 8,
        "Encrypted": False,
        "State": "completed",
        "StartTime": datetime(2026, 1, 1, tzinfo=UTC),
        "Progress": "100%",
        "OwnerId": ACCOUNT,
        "VolumeId": "vol-1",
        "Description": "SECRET DESCRIPTION",
    }
    h.ok(
        "ec2",
        "describe_snapshots",
        {"Snapshots": [snap]},
        {"OwnerIds": ["self"], "RestorableByUserIds": ["all"]},
    )
    f = network.public_snapshots(h.ctx())
    assert statuses(f) == ["FAIL"] and f[0].resource_id == "snap-1"
    assert "SECRET" not in f[0].model_dump_json()
    h.ok("ec2", "describe_snapshots", {"Snapshots": []})
    f = network.public_snapshots(h.ctx())
    assert statuses(f) == ["PASS"] and f[0].evidence == {"public_snapshots": 0}


def test_net005_net006_denied(h: Harness) -> None:
    h.err("ec2", "describe_snapshots", "UnauthorizedOperation", 403)
    assert statuses(network.public_snapshots(h.ctx())) == ["ERROR"]
    h.err("ec2", "describe_images", "UnauthorizedOperation", 403)
    assert statuses(network.public_amis(h.ctx())) == ["ERROR"]


def test_net006_public_amis(h: Harness) -> None:
    h.ok(
        "ec2",
        "describe_images",
        {"Images": [{"ImageId": "ami-1", "State": "available"}]},
        {"Owners": ["self"], "Filters": [{"Name": "is-public", "Values": ["true"]}]},
    )
    assert statuses(network.public_amis(h.ctx())) == ["FAIL"]
    h.ok("ec2", "describe_images", {"Images": []})
    assert statuses(network.public_amis(h.ctx())) == ["PASS"]


# ---------------------------------------------------------------- STO-001


@pytest.mark.parametrize(
    ("cfg", "expected"),
    [
        (
            {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "PASS",
        ),
        (
            {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": False,
            },
            "FAIL",
        ),
        ({}, "FAIL"),
    ],
)
def test_sto001(h: Harness, cfg: dict[str, bool], expected: str) -> None:
    h.ok(
        "s3control",
        "get_public_access_block",
        {"PublicAccessBlockConfiguration": cfg},
        {"AccountId": ACCOUNT},
    )
    assert statuses(s3.account_pab(h.ctx(account_scope=True))) == [expected]


def test_sto001_not_configured_and_denied(h: Harness) -> None:
    h.err("s3control", "get_public_access_block", "NoSuchPublicAccessBlockConfiguration", 404)
    f = s3.account_pab(h.ctx(account_scope=True))
    assert statuses(f) == ["FAIL"] and "not configured" in f[0].message
    h.err("s3control", "get_public_access_block")
    assert statuses(s3.account_pab(h.ctx(account_scope=True))) == ["ERROR"]


# ---------------------------------------------------------------- bucket-level


def stub_buckets(
    h: Harness,
    names: list[str],
    regions: dict[str, str | None] | None = None,
    client_region: str = "us-east-1",
) -> None:
    entries = []
    for n in names:
        e: dict[str, Any] = {"Name": n, "CreationDate": datetime(2026, 1, 1, tzinfo=UTC)}
        if regions and regions.get(n):
            e["BucketRegion"] = regions[n]
        entries.append(e)
    h.ok("s3", "list_buckets", {"Buckets": entries, "Owner": {"ID": "x"}}, region=client_region)


ALL = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def test_buckets_filtered_by_region_with_and_without_bucketregion(h: Harness) -> None:
    stub_buckets(h, ["a", "b", "c"], {"a": "us-east-1", "b": "eu-west-1"}, "eu-west-1")
    h.ok(
        "s3",
        "get_bucket_location",
        {"LocationConstraint": "eu-west-1"},
        {"Bucket": "c"},
        region="eu-west-1",
    )
    f = s3.bucket_encryption  # evaluated region = eu-west-1
    h.ok(
        "s3",
        "get_bucket_encryption",
        {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        },
        region="eu-west-1",
    )
    h.ok(
        "s3",
        "get_bucket_encryption",
        {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        },
        region="eu-west-1",
    )
    out = f(h.ctx("eu-west-1"))
    assert sorted(x.resource_id for x in out) == ["arn:aws:s3:::b", "arn:aws:s3:::c"]


def test_bucket_checks_na_when_no_buckets_in_region(h: Harness) -> None:
    stub_buckets(h, ["a"], {"a": "eu-west-1"})
    assert statuses(s3.bucket_pab(h.ctx())) == ["NOT_APPLICABLE"]


def test_bucket_listing_denied_and_pagination(h: Harness) -> None:
    h.err("s3", "list_buckets")
    assert statuses(s3.bucket_logging(h.ctx())) == ["ERROR"]
    h.ok(
        "s3",
        "list_buckets",
        {
            "Buckets": [{"Name": "a", "BucketRegion": "us-east-1"}],
            "ContinuationToken": "t",
            "Owner": {"ID": "x"},
        },
    )
    h.ok(
        "s3",
        "list_buckets",
        {"Buckets": [{"Name": "b", "BucketRegion": "us-east-1"}], "Owner": {"ID": "x"}},
    )
    h.ok("s3", "get_bucket_logging", {})
    h.ok("s3", "get_bucket_logging", {"LoggingEnabled": {"TargetBucket": "t", "TargetPrefix": "p"}})
    assert statuses(s3.bucket_logging(h.ctx())) == ["FAIL", "PASS"]


@pytest.mark.parametrize(
    ("bucket_cfg", "account_cfg", "expected"),
    [
        (ALL, None, "PASS"),
        ({**ALL, "BlockPublicPolicy": False}, ALL, "PASS"),  # account covers
        ({**ALL, "BlockPublicPolicy": False}, {**ALL, "BlockPublicPolicy": False}, "FAIL"),
        # each level blocks complementary settings -> union is complete
        (
            {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
            {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "PASS",
        ),
        (None, None, "FAIL"),
    ],
)
def test_sto002_effective_block(h: Harness, bucket_cfg, account_cfg, expected: str) -> None:  # type: ignore[no-untyped-def]
    stub_buckets(h, ["b"], {"b": "us-east-1"})
    if bucket_cfg is None:
        h.err("s3", "get_public_access_block", "NoSuchPublicAccessBlockConfiguration", 404)
    else:
        h.ok("s3", "get_public_access_block", {"PublicAccessBlockConfiguration": bucket_cfg})
    if bucket_cfg != ALL:
        if account_cfg is None:
            h.err(
                "s3control", "get_public_access_block", "NoSuchPublicAccessBlockConfiguration", 404
            )
        else:
            h.ok(
                "s3control",
                "get_public_access_block",
                {"PublicAccessBlockConfiguration": account_cfg},
            )
    f = s3.bucket_pab(h.ctx())
    assert statuses(f) == [expected]
    h.assert_all_consumed()


def test_sto002_account_pab_fetched_once_for_many_buckets(h: Harness) -> None:
    stub_buckets(h, ["a", "b"], {"a": "us-east-1", "b": "us-east-1"})
    for _ in range(2):
        h.err("s3", "get_public_access_block", "NoSuchPublicAccessBlockConfiguration", 404)
    h.ok("s3control", "get_public_access_block", {"PublicAccessBlockConfiguration": ALL})
    assert statuses(s3.bucket_pab(h.ctx())) == ["PASS", "PASS"]
    h.assert_all_consumed()


def test_sto002_unreadable_account_level_is_error(h: Harness) -> None:
    stub_buckets(h, ["b"], {"b": "us-east-1"})
    h.err("s3", "get_public_access_block", "NoSuchPublicAccessBlockConfiguration", 404)
    h.err("s3control", "get_public_access_block")
    assert statuses(s3.bucket_pab(h.ctx())) == ["ERROR"]


@pytest.mark.parametrize(
    ("kind", "expected"),
    [("public", "FAIL"), ("private", "PASS"), ("nopolicy", "PASS")],
)
def test_sto003_policy_status(h: Harness, kind: str, expected: str) -> None:
    stub_buckets(h, ["b"], {"b": "us-east-1"})
    if kind == "nopolicy":
        h.err("s3", "get_bucket_policy_status", "NoSuchBucketPolicy", 404)
    else:
        h.ok("s3", "get_bucket_policy_status", {"PolicyStatus": {"IsPublic": kind == "public"}})
    f = s3.bucket_policy_public(h.ctx())
    assert statuses(f) == [expected] and f[0].uncertainty
    assert f[0].evidence["has_policy"] is (kind != "nopolicy")


def test_sto003_denied(h: Harness) -> None:
    stub_buckets(h, ["b"], {"b": "us-east-1"})
    h.err("s3", "get_bucket_policy_status")
    assert statuses(s3.bucket_policy_public(h.ctx())) == ["ERROR"]


def test_sto004_encryption_configured_vs_effective(h: Harness) -> None:
    stub_buckets(h, ["kms", "sse", "none"], dict.fromkeys(("kms", "sse", "none"), "us-east-1"))

    def rules(algo: str, **kw: str) -> dict[str, Any]:
        default = {"SSEAlgorithm": algo, **kw}
        return {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": default}]
            }
        }

    h.ok("s3", "get_bucket_encryption", rules("aws:kms", KMSMasterKeyID="arn:aws:kms:k"))
    h.err("s3", "get_bucket_encryption", "ServerSideEncryptionConfigurationNotFoundError", 404)
    h.ok("s3", "get_bucket_encryption", rules("AES256"))
    f = {x.resource_id.split(":::")[1]: x for x in s3.bucket_encryption(h.ctx())}
    assert f["kms"].status is Status.PASS and f["kms"].evidence["kms_key_specified"] is True
    assert f["none"].status is Status.FAIL
    assert f["sse"].status is Status.PASS and f["sse"].evidence["kms_key_specified"] is False
    assert "not proof of effective protection" in f["kms"].uncertainty[0]
    assert "arn:aws:kms" not in f["kms"].model_dump_json()  # key identifiers are not collected


def test_sto004_empty_rules_is_error(h: Harness) -> None:
    stub_buckets(h, ["b"], {"b": "us-east-1"})
    h.ok("s3", "get_bucket_encryption", {"ServerSideEncryptionConfiguration": {"Rules": []}})
    assert statuses(s3.bucket_encryption(h.ctx())) == ["ERROR"]


@pytest.mark.parametrize(
    ("resp", "expected"),
    [({"LoggingEnabled": {"TargetBucket": "t", "TargetPrefix": "p"}}, "PASS"), ({}, "FAIL")],
)
def test_sto005(h: Harness, resp: dict[str, Any], expected: str) -> None:
    stub_buckets(h, ["b"], {"b": "us-east-1"})
    h.ok("s3", "get_bucket_logging", resp)
    assert statuses(s3.bucket_logging(h.ctx())) == [expected]


def test_sto006_tls_policy(h: Harness) -> None:
    stub_buckets(h, ["a", "b", "c", "d"], dict.fromkeys("abcd", "us-east-1"))
    h.ok("s3", "get_bucket_policy", {"Policy": fixture_text("bucket_policy_tls.json")})
    h.ok(
        "s3",
        "get_bucket_policy",
        {
            "Policy": json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "*",
                        }
                    ]
                }
            )
        },
    )
    h.err("s3", "get_bucket_policy", "NoSuchBucketPolicy", 404)
    h.ok(
        "s3",
        "get_bucket_policy",
        {
            "Policy": json.dumps(
                {
                    "Statement": {
                        "Effect": "Deny",
                        "Principal": {"AWS": "*"},
                        "Action": ["s3:*"],
                        "Resource": "*",
                        "Condition": {"BoolIfExists": {"aws:SecureTransport": "FALSE"}},
                    }
                }
            )
        },
    )
    got = [x.status for x in s3.bucket_tls(h.ctx())]
    assert got == [Status.PASS, Status.FAIL, Status.FAIL, Status.PASS]


def test_sto006_malformed_policy_is_error(h: Harness) -> None:
    stub_buckets(h, ["b"], {"b": "us-east-1"})
    h.ok("s3", "get_bucket_policy", {"Policy": "{not json"})
    assert statuses(s3.bucket_tls(h.ctx())) == ["ERROR"]


# ---------------------------------------------------------------- EBS / RDS / coverage


@pytest.mark.parametrize(("flag", "expected"), [(True, "PASS"), (False, "FAIL")])
def test_ebs001(h: Harness, flag: bool, expected: str) -> None:
    h.ok("ec2", "get_ebs_encryption_by_default", {"EbsEncryptionByDefault": flag})
    assert statuses(compute.ebs_default_encryption(h.ctx())) == [expected]


def test_ebs001_denied_and_unsupported(h: Harness) -> None:
    h.err("ec2", "get_ebs_encryption_by_default", "UnauthorizedOperation", 403)
    assert statuses(compute.ebs_default_encryption(h.ctx())) == ["ERROR"]
    h.err("ec2", "get_ebs_encryption_by_default", "OptInRequired", 403)
    assert statuses(compute.ebs_default_encryption(h.ctx())) == ["NOT_ASSESSED"]


def test_ebs002_volumes_paginated(h: Harness) -> None:

    def vol(i: int, enc: bool) -> dict[str, Any]:
        return {
            "VolumeId": f"vol-{i}",
            "Encrypted": enc,
            "State": "in-use",
            **({"KmsKeyId": "arn:aws:kms:secret"} if enc else {}),
        }

    h.ok("ec2", "describe_volumes", {"Volumes": [vol(1, True)], "NextToken": "n"})
    h.ok("ec2", "describe_volumes", {"Volumes": [vol(2, False)]})
    f = compute.ebs_volumes(h.ctx())
    assert [(x.resource_id, x.status.value) for x in f] == [("vol-1", "PASS"), ("vol-2", "FAIL")]
    assert f[0].evidence["kms_key_present"] is True and "secret" not in f[0].model_dump_json()
    assert f[0].uncertainty  # configured vs effective caveat
    h.ok("ec2", "describe_volumes", {"Volumes": []})
    assert statuses(compute.ebs_volumes(h.ctx())) == ["NOT_APPLICABLE"]


def db(i: str, public: bool, enc: bool) -> dict[str, Any]:
    return {
        "DBInstanceIdentifier": i,
        "PubliclyAccessible": public,
        "StorageEncrypted": enc,
        "Engine": "postgres",
    }


def test_rds_controls(h: Harness) -> None:
    dbs = [db("a", True, False), db("b", False, True)]
    h.ok("rds", "describe_db_instances", {"DBInstances": dbs})
    h.ok("rds", "describe_db_instances", {"DBInstances": dbs})
    assert statuses(compute.rds_public(h.ctx())) == ["FAIL", "PASS"]
    assert statuses(compute.rds_encrypted(h.ctx())) == ["FAIL", "PASS"]


def test_rds_none_denied_unsupported_and_missing_field(h: Harness) -> None:
    h.ok("rds", "describe_db_instances", {"DBInstances": []})
    assert statuses(compute.rds_public(h.ctx())) == ["NOT_APPLICABLE"]
    h.err("rds", "describe_db_instances")
    assert statuses(compute.rds_encrypted(h.ctx())) == ["ERROR"]
    h.err("rds", "describe_db_instances", "InvalidClientTokenId", 403)
    assert statuses(compute.rds_public(h.ctx())) == ["NOT_ASSESSED"]
    h.ok("rds", "describe_db_instances", {"DBInstances": [{"DBInstanceIdentifier": "x"}]})
    assert statuses(compute.rds_public(h.ctx())) == ["ERROR"]


def test_cov001(h: Harness) -> None:
    ctx = h.ctx(account_scope=True, audited=["us-east-1"], enabled=["us-east-1", "eu-west-1"])
    f = coverage.region_coverage(ctx)
    assert statuses(f) == ["NOT_ASSESSED"] and f[0].evidence["unaudited_regions"] == ["eu-west-1"]
    full = h.ctx(
        account_scope=True, audited=["us-east-1", "eu-west-1"], enabled=["eu-west-1", "us-east-1"]
    )
    assert statuses(coverage.region_coverage(full)) == ["PASS"]
    unknown = h.ctx(account_scope=True, audited=["us-east-1"], enabled=[], discovery_ok=False)
    assert statuses(coverage.region_coverage(unknown)) == ["NOT_ASSESSED"]
