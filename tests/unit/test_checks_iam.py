"""IAM controls: IAM-001 .. IAM-009."""

from __future__ import annotations

import json
from urllib.parse import quote

import pytest

from awsauditor.checks import iam
from awsauditor.config import AuditConfig, Thresholds
from awsauditor.models import Status

from .conftest import ACCOUNT, Harness, assert_wellformed, fixture_json, fixture_text, statuses

CR = "credential_report.csv"


def stub_report(h: Harness, csv_text: str | None = None) -> None:
    h.ok("iam", "generate_credential_report", {"State": "COMPLETE"})
    h.ok(
        "iam",
        "get_credential_report",
        {"Content": (csv_text or fixture_text(CR)).encode(), "ReportFormat": "text/csv"},
    )


def results(findings, cid):  # type: ignore[no-untyped-def]
    return {f.resource_id.split("/")[-1]: f.status for f in findings if f.control_id == cid}


# ------------------------------------------------------------- IAM-001 / IAM-002


@pytest.mark.parametrize(
    ("mfa", "keys", "s1", "s2"),
    [
        (1, 0, "PASS", "PASS"),
        (0, 1, "FAIL", "FAIL"),
        (1, 1, "PASS", "FAIL"),
        (0, 0, "FAIL", "PASS"),
    ],
)
def test_root_account_states(h: Harness, mfa: int, keys: int, s1: str, s2: str) -> None:
    h.ok(
        "iam",
        "get_account_summary",
        {"SummaryMap": {"AccountMFAEnabled": mfa, "AccountAccessKeysPresent": keys}},
    )
    f = iam.root_account(h.ctx(account_scope=True))
    assert statuses(f, "IAM-001") == [s1] and statuses(f, "IAM-002") == [s2]
    assert_wellformed(f)
    one = next(x for x in f if x.control_id == "IAM-001")
    assert one.evidence == {"AccountMFAEnabled": mfa} and one.sources == ["iam:GetAccountSummary"]
    assert one.region == "global"
    h.assert_all_consumed()


def test_root_account_missing_field_is_error_not_pass(h: Harness) -> None:
    h.ok("iam", "get_account_summary", {"SummaryMap": {"AccountMFAEnabled": 1}})
    f = iam.root_account(h.ctx(account_scope=True))
    assert statuses(f, "IAM-001") == ["PASS"] and statuses(f, "IAM-002") == ["ERROR"]


def test_root_account_denied_reports_error_for_both(h: Harness) -> None:
    h.err("iam", "get_account_summary")
    f = iam.root_account(h.ctx(account_scope=True))
    assert sorted(statuses(f)) == ["ERROR", "ERROR"]
    assert "Permission denied" in f[0].message and f[0].uncertainty


# ------------------------------------------------------------- credential report


def test_iam003_console_mfa(h: Harness) -> None:
    stub_report(h)
    f = iam.console_mfa(h.ctx(account_scope=True))
    assert results(f, "IAM-003") == {"alice": Status.PASS, "bob": Status.FAIL}
    bob = next(x for x in f if x.resource_id.endswith("bob"))
    assert bob.evidence == {"user": "bob", "password_enabled": True, "mfa_active": False}
    assert_wellformed(f)


def test_iam003_not_applicable_without_console_users(h: Harness) -> None:
    lines = fixture_text(CR).splitlines()
    stub_report(h, "\n".join([lines[0], lines[1], lines[4]]) + "\n")
    assert statuses(iam.console_mfa(h.ctx(account_scope=True))) == ["NOT_APPLICABLE"]


def test_iam004_unused_credentials_with_boundary(h: Harness) -> None:
    stub_report(h)
    f = iam.unused_credentials(h.ctx(account_scope=True))
    got = {x.resource_id.split(":user/")[1]: x.status for x in f}
    assert got == {
        "alice#password": Status.PASS,
        "alice#access_key_1": Status.PASS,
        "bob#password": Status.FAIL,
        "bob#access_key_1": Status.FAIL,
        "bob#access_key_2": Status.PASS,  # exactly 45 days: boundary is inclusive
        "svc-ci#access_key_1": Status.FAIL,
    }
    ci = next(x for x in f if x.resource_id.endswith("svc-ci#access_key_1"))
    assert ci.evidence["ever_used"] is False and ci.evidence["threshold_days"] == 45


def test_iam004_threshold_is_configurable(h: Harness) -> None:
    h.config = AuditConfig(thresholds=Thresholds(unused_credential_days=44))
    stub_report(h)
    f = iam.unused_credentials(h.ctx(account_scope=True))
    assert next(x for x in f if x.resource_id.endswith("bob#access_key_2")).status is Status.FAIL


def test_iam005_key_rotation(h: Harness) -> None:
    stub_report(h)
    f = iam.key_rotation(h.ctx(account_scope=True))
    got = {x.resource_id.split(":user/")[1]: x.status for x in f}
    assert got == {
        "alice#access_key_1": Status.PASS,
        "bob#access_key_1": Status.FAIL,
        "bob#access_key_2": Status.PASS,
        "svc-ci#access_key_1": Status.FAIL,
    }
    assert next(x for x in f if "bob#access_key_1" in x.resource_id).evidence["key_age_days"] > 90


def test_iam005_not_applicable_without_active_keys(h: Harness) -> None:
    lines = fixture_text(CR).splitlines()
    stub_report(h, "\n".join(lines[:2]) + "\n")
    assert statuses(iam.key_rotation(h.ctx(account_scope=True))) == ["NOT_APPLICABLE"]


def test_report_is_fetched_once_for_three_checks(h: Harness) -> None:
    stub_report(h)  # a second fetch would fail: only one response is queued
    ctx = h.ctx(account_scope=True)
    for fn in (iam.console_mfa, iam.unused_credentials, iam.key_rotation):
        assert all(x.status is not Status.ERROR for x in fn(ctx))
    h.assert_all_consumed()


def test_report_polls_with_backoff_until_complete(h: Harness) -> None:
    h.ok("iam", "generate_credential_report", {"State": "STARTED"})
    h.ok("iam", "generate_credential_report", {"State": "INPROGRESS"})
    stub_report(h)
    f = iam.console_mfa(h.ctx(account_scope=True))
    assert f[0].status is not Status.ERROR
    assert h.sleeps == [1.0, 2.0]


def test_report_retries_when_get_says_in_progress(h: Harness) -> None:
    h.ok("iam", "generate_credential_report", {"State": "COMPLETE"})
    h.err("iam", "get_credential_report", "ReportInProgress", 404)
    stub_report(h)
    assert iam.console_mfa(h.ctx(account_scope=True))[0].status is not Status.ERROR
    assert h.sleeps == [1.0]


def test_report_never_ready_is_error(h: Harness) -> None:
    for _ in range(8):
        h.ok("iam", "generate_credential_report", {"State": "STARTED"})
    f = iam.console_mfa(h.ctx(account_scope=True))
    assert statuses(f) == ["ERROR"] and "ReportNotReady" in f[0].evidence["error_type"]
    assert max(h.sleeps) <= 15.0


@pytest.mark.parametrize("fn", [iam.console_mfa, iam.unused_credentials, iam.key_rotation])
def test_report_denied_is_error(h: Harness, fn) -> None:  # type: ignore[no-untyped-def]
    h.err("iam", "generate_credential_report")
    assert statuses(fn(h.ctx(account_scope=True))) == ["ERROR"]


@pytest.mark.parametrize(
    "text",
    [
        "garbage,only\n1,2\n",
        fixture_text(CR).replace("true,2026-10-10", "maybe,2026-10-10", 1),
        fixture_text(CR).replace("2026-10-10T00:00:00+00:00", "yesterday", 1),
    ],
)
def test_malformed_report_never_passes(h: Harness, text: str) -> None:
    stub_report(h, text)
    f = iam.unused_credentials(h.ctx(account_scope=True))
    assert Status.ERROR in {x.status for x in f}


def test_report_with_invalid_utf8_is_error(h: Harness) -> None:
    h.ok("iam", "generate_credential_report", {"State": "COMPLETE"})
    h.ok("iam", "get_credential_report", {"Content": b"\xff\xfe\x00bad"})
    assert statuses(iam.console_mfa(h.ctx(account_scope=True))) == ["ERROR"]


# ------------------------------------------------------------- policies


def policy_summary(arn: str) -> dict:  # type: ignore[type-arg]
    return {"Arn": arn, "PolicyName": arn.split("/")[-1], "DefaultVersionId": "v1"}


def enc(doc: object) -> str:
    """IAM returns policy documents URL-encoded; botocore decodes them after the call."""
    return quote(doc if isinstance(doc, str) else json.dumps(doc))


def stub_policies(h: Harness, docs: dict[str, object]) -> None:
    h.ok(
        "iam",
        "list_policies",
        {"Policies": [policy_summary(f"arn:aws:iam::{ACCOUNT}:policy/{n}") for n in docs]},
        {"Scope": "Local", "OnlyAttached": True},
    )
    for n, doc in docs.items():
        h.ok(
            "iam",
            "get_policy_version",
            {"PolicyVersion": {"Document": enc(doc), "VersionId": "v1"}},
            {"PolicyArn": f"arn:aws:iam::{ACCOUNT}:policy/{n}", "VersionId": "v1"},
        )


def test_policy_patterns(h: Harness) -> None:
    stub_policies(
        h,
        {
            "admin": fixture_json("policy_admin.json"),
            "svc": fixture_json("policy_service_wildcard.json"),
            "notact": fixture_json("policy_notaction.json"),
            "scoped": fixture_json("policy_scoped.json"),
        },
    )
    f = iam.risky_policies(h.ctx(account_scope=True))
    r6, r9 = results(f, "IAM-006"), results(f, "IAM-009")
    assert r6 == {
        "admin": Status.FAIL,
        "svc": Status.PASS,
        "notact": Status.PASS,
        "scoped": Status.PASS,
    }
    assert r9 == {
        "admin": Status.PASS,
        "svc": Status.FAIL,
        "notact": Status.FAIL,
        "scoped": Status.PASS,
    }
    admin = next(x for x in f if x.control_id == "IAM-006" and x.resource_id.endswith("admin"))
    assert admin.evidence["statements"][0]["sid"] == "All"
    assert_wellformed(f)


def test_policy_evidence_excludes_full_document(h: Harness) -> None:
    stub_policies(h, {"admin": fixture_json("policy_admin.json")})
    f = iam.risky_policies(h.ctx(account_scope=True))
    assert "Statement" not in str(f[0].evidence) and "Version" not in f[0].evidence


def test_policy_none_attached_is_not_applicable(h: Harness) -> None:
    stub_policies(h, {})
    assert sorted(statuses(iam.risky_policies(h.ctx(account_scope=True)))) == [
        "NOT_APPLICABLE",
        "NOT_APPLICABLE",
    ]


def test_policy_pagination(h: Harness) -> None:
    def p(n: str) -> dict:  # type: ignore[type-arg]
        return policy_summary(f"arn:aws:iam::{ACCOUNT}:policy/{n}")

    h.ok("iam", "list_policies", {"Policies": [p("a")], "IsTruncated": True, "Marker": "m1"})
    h.ok("iam", "list_policies", {"Policies": [p("b")]})
    for _ in "ab":
        h.ok(
            "iam",
            "get_policy_version",
            {"PolicyVersion": {"Document": enc({"Statement": []}), "VersionId": "v1"}},
        )
    f = iam.risky_policies(h.ctx(account_scope=True))
    assert len([x for x in f if x.control_id == "IAM-006"]) == 2
    h.assert_all_consumed()


def test_policy_partial_failure_keeps_other_results(h: Harness) -> None:
    arn_a, arn_b = (f"arn:aws:iam::{ACCOUNT}:policy/{n}" for n in "ab")
    h.ok("iam", "list_policies", {"Policies": [policy_summary(arn_a), policy_summary(arn_b)]})
    h.err("iam", "get_policy_version")
    h.ok("iam", "get_policy_version", {"PolicyVersion": {"Document": enc({"Statement": []})}})
    f = iam.risky_policies(h.ctx(account_scope=True))
    assert sorted(statuses(f, "IAM-006")) == ["ERROR", "PASS"]


@pytest.mark.parametrize("doc", ["not json", [1, 2], {"Version": "x"}, {"Statement": ["x"]}])
def test_malformed_policy_document_is_error(h: Harness, doc: object) -> None:
    stub_policies(h, {"bad": doc})
    assert set(statuses(iam.risky_policies(h.ctx(account_scope=True)))) == {"ERROR"}


def test_policy_document_as_json_string_is_parsed(h: Harness) -> None:
    stub_policies(h, {"admin": fixture_text("policy_admin.json")})
    assert statuses(iam.risky_policies(h.ctx(account_scope=True)), "IAM-006") == ["FAIL"]


def test_policy_list_denied(h: Harness) -> None:
    h.err("iam", "list_policies")
    assert statuses(iam.risky_policies(h.ctx(account_scope=True))) == ["ERROR", "ERROR"]


@pytest.mark.parametrize(
    ("statement", "admin", "broad"),
    [
        ({"Effect": "Allow", "Action": "*", "Resource": "*"}, 1, 0),
        ({"Effect": "Allow", "Action": ["*"], "Resource": ["arn:aws:s3:::x", "*"]}, 1, 0),
        ({"Effect": "Allow", "Action": "*:*", "Resource": "*"}, 1, 0),
        ({"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::x"}, 0, 0),
        ({"Effect": "Deny", "Action": "*", "Resource": "*"}, 0, 0),
        ({"Effect": "Allow", "Action": "iam:*", "Resource": "*"}, 0, 1),
        ({"Effect": "Allow", "Action": "iam:*", "Resource": "arn:aws:iam::1:role/x"}, 0, 0),
        ({"Effect": "Allow", "Action": "iam:Get*", "Resource": "*"}, 0, 0),
        (
            {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"Bool": {"a": "b"}}},
            0,
            0,
        ),
        ({"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}, 0, 1),
    ],
)
def test_analyze_policy_document_boundaries(statement: dict, admin: int, broad: int) -> None:  # type: ignore[type-arg]
    out = iam.analyze_policy_document({"Statement": statement})
    assert (len(out["admin"]), len(out["broad"])) == (admin, broad)


# ------------------------------------------------------------- IAM-007


@pytest.mark.parametrize(
    ("policy", "status"),
    [
        ({"MinimumPasswordLength": 14, "PasswordReusePrevention": 24}, "PASS"),
        ({"MinimumPasswordLength": 20, "PasswordReusePrevention": 24}, "PASS"),
        ({"MinimumPasswordLength": 13, "PasswordReusePrevention": 24}, "FAIL"),
        ({"MinimumPasswordLength": 14, "PasswordReusePrevention": 23}, "FAIL"),
        ({"MinimumPasswordLength": 14}, "FAIL"),
        ({}, "FAIL"),
    ],
)
def test_password_policy_boundaries(h: Harness, policy: dict, status: str) -> None:  # type: ignore[type-arg]
    full = {
        "MinimumPasswordLength": 6,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "AllowUsersToChangePassword": True,
        "ExpirePasswords": False,
        "HardExpiry": False,
        **policy,
    }
    if "MinimumPasswordLength" not in policy:
        full.pop("MinimumPasswordLength")
    h.ok("iam", "get_account_password_policy", {"PasswordPolicy": full})
    f = iam.password_policy(h.ctx(account_scope=True))
    assert statuses(f) == [status]
    assert f[0].evidence["required_length"] == 14


def test_password_policy_absent_fails(h: Harness) -> None:
    h.err("iam", "get_account_password_policy", "NoSuchEntity", 404)
    f = iam.password_policy(h.ctx(account_scope=True))
    assert statuses(f) == ["FAIL"] and "No account password policy" in f[0].message


def test_password_policy_denied(h: Harness) -> None:
    h.err("iam", "get_account_password_policy")
    assert statuses(iam.password_policy(h.ctx(account_scope=True))) == ["ERROR"]


# ------------------------------------------------------------- IAM-008


def analyzer(status: str, kind: str) -> dict:  # type: ignore[type-arg]
    from datetime import UTC, datetime

    return {
        "arn": "arn:aws:access-analyzer:us-east-1:1:analyzer/a",
        "name": "a",
        "type": kind,
        "createdAt": datetime(2026, 1, 1, tzinfo=UTC),
        "status": status,
    }


@pytest.mark.parametrize(
    ("analyzers", "status"),
    [
        ([analyzer("ACTIVE", "ACCOUNT")], "PASS"),
        ([analyzer("ACTIVE", "ORGANIZATION")], "PASS"),
        ([analyzer("DISABLED", "ACCOUNT")], "FAIL"),
        ([analyzer("ACTIVE", "ACCOUNT_UNUSED_ACCESS")], "FAIL"),
        ([], "FAIL"),
    ],
)
def test_access_analyzer(h: Harness, analyzers: list, status: str) -> None:  # type: ignore[type-arg]
    h.ok("accessanalyzer", "list_analyzers", {"analyzers": analyzers})
    f = iam.access_analyzer(h.ctx())
    assert statuses(f) == [status] and f[0].region == "us-east-1"


def test_access_analyzer_pagination_and_unsupported_region(h: Harness) -> None:
    h.ok(
        "accessanalyzer",
        "list_analyzers",
        {"analyzers": [analyzer("DISABLED", "ACCOUNT")], "nextToken": "t"},
    )
    h.ok("accessanalyzer", "list_analyzers", {"analyzers": [analyzer("ACTIVE", "ACCOUNT")]})
    assert statuses(iam.access_analyzer(h.ctx())) == ["PASS"]
    h.err("accessanalyzer", "list_analyzers", "UnrecognizedClientException", 403)
    f = iam.access_analyzer(h.ctx())
    assert statuses(f) == ["NOT_ASSESSED"]
