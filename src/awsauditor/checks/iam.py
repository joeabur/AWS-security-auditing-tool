"""Identity and access management checks."""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime
from typing import Any

from ..context import CheckContext, check
from ..errors import AuditorError, ParseError
from ..evidence import error_code, optional, paginate, require
from ..models import Finding, Status

ACCT = "AWS::::Account"
USER = "AWS::IAM::User"
POLICY = "AWS::IAM::Policy"

_REQUIRED_COLUMNS = {
    "user",
    "arn",
    "user_creation_time",
    "password_enabled",
    "password_last_used",
    "password_last_changed",
    "mfa_active",
    "access_key_1_active",
    "access_key_1_last_rotated",
    "access_key_1_last_used_date",
    "access_key_2_active",
    "access_key_2_last_rotated",
    "access_key_2_last_used_date",
}
_ROOT = "<root_account>"
_REPORT_RETRY_CODES = {"ReportInProgress", "ReportNotPresent", "ReportExpired"}


class ReportNotReady(AuditorError):
    """The IAM credential report did not become available in time."""


# ---------------------------------------------------------------- root account


@check("IAM-001", "IAM-002")
def root_account(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    src = ["iam:GetAccountSummary"]
    resource = f"arn:{ctx.partition}:iam::{ctx.account_id}:root"
    summary: dict[str, Any] | None = None
    try:
        summary = require(ctx.client("iam").get_account_summary(), "SummaryMap", dict)
    except Exception as exc:
        for cid in ("IAM-001", "IAM-002"):
            out.append(ctx.error_finding(cid, exc, resource, ACCT, src))
    if summary is None:
        return out
    for cid, key, ok_when, ok_msg, bad_msg in (
        ("IAM-001", "AccountMFAEnabled", 1, "Root MFA is enabled.", "Root MFA is not enabled."),
        (
            "IAM-002",
            "AccountAccessKeysPresent",
            0,
            "No root access keys exist.",
            "Root access keys exist.",
        ),
    ):
        with ctx.capture(out, cid, resource, ACCT, src):
            value = summary.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value not in (0, 1):
                raise ParseError(f"SummaryMap.{key} missing or not 0/1")
            ok = value == ok_when
            out.append(
                ctx.finding(
                    cid,
                    Status.PASS if ok else Status.FAIL,
                    resource,
                    ACCT,
                    ok_msg if ok else bad_msg,
                    evidence={key: value},
                    sources=src,
                    uncertainty=(
                        ["Hardware vs virtual MFA type is not distinguished."]
                        if cid == "IAM-001" and ok
                        else []
                    ),
                )
            )
    return out


# ------------------------------------------------------------ credential report


def _fetch_credential_report(ctx: CheckContext) -> list[dict[str, str]]:
    iam = ctx.client("iam")
    delay = 1.0
    for _ in range(8):
        state = iam.generate_credential_report().get("State")
        if state == "COMPLETE":
            try:
                content = require(iam.get_credential_report(), "Content", bytes)
            except Exception as exc:
                if error_code(exc) in _REPORT_RETRY_CODES:
                    ctx.sleep(delay)
                    delay = min(delay * 2, 15.0)
                    continue
                raise
            return _parse_credential_report(content)
        ctx.sleep(delay)
        delay = min(delay * 2, 15.0)
    raise ReportNotReady("IAM credential report was not ready after polling")


def _parse_credential_report(content: bytes) -> list[dict[str, str]]:
    try:
        reader = csv.DictReader(io.StringIO(content.decode("utf-8")))
        rows = list(reader)
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ParseError("credential report is not valid CSV") from exc
    missing = _REQUIRED_COLUMNS - set(reader.fieldnames or [])
    if missing:
        raise ParseError(f"credential report missing columns: {sorted(missing)}")
    return rows


def credential_report(ctx: CheckContext) -> list[dict[str, str]]:
    result: list[dict[str, str]] = ctx.cache.get_or_compute(
        "iam.credential_report", lambda: _fetch_credential_report(ctx)
    )
    return result


def _ts(value: str | None) -> datetime | None:
    """Parse a credential-report timestamp; N/A and similar markers become None."""
    if value is None or value in {"", "N/A", "no_information", "not_supported"}:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ParseError("unparseable timestamp in credential report") from exc
    if parsed.tzinfo is None:
        raise ParseError("timestamp without timezone in credential report")
    return parsed


def _bool(value: str | None) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise ParseError(f"unexpected boolean value {value!r} in credential report")


_CR_SRC = ["iam:GenerateCredentialReport", "iam:GetCredentialReport"]


def _users(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [r for r in rows if r["user"] != _ROOT]


@check("IAM-003")
def console_mfa(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    fallback = f"account/{ctx.account_id}"
    try:
        users = _users(credential_report(ctx))
    except Exception as exc:
        return [ctx.error_finding("IAM-003", exc, fallback, ACCT, _CR_SRC)]
    for row in users:
        with ctx.capture(out, "IAM-003", row.get("arn") or fallback, USER, _CR_SRC):
            if not _bool(row["password_enabled"]):
                continue
            mfa = _bool(row["mfa_active"])
            out.append(
                ctx.finding(
                    "IAM-003",
                    Status.PASS if mfa else Status.FAIL,
                    row["arn"],
                    USER,
                    "Console user has MFA." if mfa else "Console user has no MFA device.",
                    evidence={"user": row["user"], "password_enabled": True, "mfa_active": mfa},
                    sources=_CR_SRC,
                )
            )
    if not out:
        out.append(
            ctx.finding(
                "IAM-003",
                Status.NOT_APPLICABLE,
                fallback,
                ACCT,
                "No IAM users with console access.",
                sources=_CR_SRC,
            )
        )
    return out


def _age_days(ctx: CheckContext, ts: datetime) -> int:
    return (ctx.now - ts).days


@check("IAM-004")
def unused_credentials(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    fallback = f"account/{ctx.account_id}"
    limit = ctx.config.thresholds.unused_credential_days
    try:
        users = _users(credential_report(ctx))
    except Exception as exc:
        return [ctx.error_finding("IAM-004", exc, fallback, ACCT, _CR_SRC)]
    for row in users:
        arn = row.get("arn") or fallback
        with ctx.capture(out, "IAM-004", arn, USER, _CR_SRC):
            created = _ts(row["user_creation_time"])
            if _bool(row["password_enabled"]):
                last_used_raw = row["password_last_used"]
                last = _ts(last_used_raw)
                basis = last or _ts(row["password_last_changed"]) or created
                out.append(
                    _unused_finding(
                        ctx,
                        f"{arn}#password",
                        "console password",
                        last,
                        basis,
                        limit,
                        last_used_raw == "no_information",
                    )
                )
            for n in (1, 2):
                if _bool(row[f"access_key_{n}_active"]):
                    last = _ts(row[f"access_key_{n}_last_used_date"])
                    basis = last or _ts(row[f"access_key_{n}_last_rotated"]) or created
                    out.append(
                        _unused_finding(
                            ctx,
                            f"{arn}#access_key_{n}",
                            f"access key {n}",
                            last,
                            basis,
                            limit,
                            False,
                        )
                    )
    if not out:
        out.append(
            ctx.finding(
                "IAM-004",
                Status.NOT_APPLICABLE,
                fallback,
                ACCT,
                "No active IAM user passwords or access keys.",
                sources=_CR_SRC,
            )
        )
    return out


def _unused_finding(
    ctx: CheckContext,
    resource: str,
    label: str,
    last: datetime | None,
    basis: datetime | None,
    limit: int,
    no_info: bool,
) -> Finding:
    if basis is None:
        raise ParseError("no usable timestamp for credential")
    idle = _age_days(ctx, basis)
    stale = idle > limit
    unc = ["AWS reported no last-use information; creation/change date used."] if no_info else []
    evidence = {
        "credential": label,
        "ever_used": last is not None,
        "days_since_last_use_or_creation": idle,
        "threshold_days": limit,
    }
    return ctx.finding(
        "IAM-004",
        Status.FAIL if stale else Status.PASS,
        resource,
        "AWS::IAM::Credential",
        (
            f"The {label} has been unused for {idle} days (limit {limit})."
            if stale
            else f"The {label} was used or created within {limit} days."
        ),
        evidence=evidence,
        sources=_CR_SRC,
        uncertainty=unc,
    )


@check("IAM-005")
def key_rotation(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    fallback = f"account/{ctx.account_id}"
    limit = ctx.config.thresholds.access_key_max_age_days
    try:
        users = _users(credential_report(ctx))
    except Exception as exc:
        return [ctx.error_finding("IAM-005", exc, fallback, ACCT, _CR_SRC)]
    for row in users:
        arn = row.get("arn") or fallback
        for n in (1, 2):
            with ctx.capture(out, "IAM-005", f"{arn}#access_key_{n}", USER, _CR_SRC):
                if not _bool(row[f"access_key_{n}_active"]):
                    continue
                rotated = _ts(row[f"access_key_{n}_last_rotated"])
                if rotated is None:
                    raise ParseError("active key without last_rotated")
                age = _age_days(ctx, rotated)
                ok = age <= limit
                out.append(
                    ctx.finding(
                        "IAM-005",
                        Status.PASS if ok else Status.FAIL,
                        f"{arn}#access_key_{n}",
                        "AWS::IAM::AccessKey",
                        (
                            f"Access key {n} is {age} days old (limit {limit})."
                            if not ok
                            else f"Access key {n} was rotated within {limit} days."
                        ),
                        evidence={"key_age_days": age, "threshold_days": limit},
                        sources=_CR_SRC,
                    )
                )
    if not out:
        out.append(
            ctx.finding(
                "IAM-005",
                Status.NOT_APPLICABLE,
                fallback,
                ACCT,
                "No active IAM user access keys.",
                sources=_CR_SRC,
            )
        )
    return out


# ---------------------------------------------------------------- policies

_SERVICE_WILDCARD = re.compile(r"^[A-Za-z0-9-]+:\*$")
_POLICY_SRC = ["iam:ListPolicies", "iam:GetPolicyVersion"]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def analyze_policy_document(doc: Any) -> dict[str, Any]:
    """Return the risky statement patterns found in a policy document.

    Only Allow statements are considered. Statements with a Condition are not flagged
    because the condition may legitimately narrow the grant (reported as lower risk by
    omission; see docs).
    """
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except json.JSONDecodeError as exc:
            raise ParseError("policy document is not valid JSON") from exc
    if not isinstance(doc, dict):
        raise ParseError("policy document is not an object")
    statements = _as_list(doc.get("Statement"))
    if not statements and "Statement" not in doc:
        raise ParseError("policy document has no Statement")
    admin: list[dict[str, Any]] = []
    broad: list[dict[str, Any]] = []
    for index, st in enumerate(statements):
        if not isinstance(st, dict):
            raise ParseError("policy statement is not an object")
        if st.get("Effect") != "Allow" or st.get("Condition"):
            continue
        actions = [str(a) for a in _as_list(st.get("Action"))]
        resources = [str(r) for r in _as_list(st.get("Resource"))]
        label = {"index": index, "sid": st.get("Sid")}
        all_resources = "*" in resources
        if "NotAction" in st:
            broad.append({**label, "pattern": "Allow with NotAction"})
        elif all_resources and any(a in ("*", "*:*") for a in actions):
            admin.append({**label, "actions": actions[:10]})
        elif all_resources:
            wild = [a for a in actions if _SERVICE_WILDCARD.match(a)]
            if wild:
                broad.append(
                    {**label, "pattern": "service wildcard on all resources", "actions": wild[:10]}
                )
    return {"admin": admin, "broad": broad}


@check("IAM-006", "IAM-009")
def risky_policies(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    fallback = f"account/{ctx.account_id}"
    iam = ctx.client("iam")
    try:
        policies = list(
            paginate(iam, "list_policies", "Policies", Scope="Local", OnlyAttached=True)
        )
    except Exception as exc:
        return [
            ctx.error_finding(c, exc, fallback, ACCT, _POLICY_SRC) for c in ("IAM-006", "IAM-009")
        ]
    for pol in policies:
        arn = str(pol.get("Arn", fallback))
        with ctx.capture(out, ["IAM-006", "IAM-009"], arn, POLICY, _POLICY_SRC):
            version = require(pol, "DefaultVersionId", str)
            resp = iam.get_policy_version(PolicyArn=arn, VersionId=version)
            doc = require(resp, "PolicyVersion", dict).get("Document")
            result = analyze_policy_document(doc)
            base = {"policy_arn": arn, "version_id": version}
            for cid, key, ok_msg, bad_msg in (
                (
                    "IAM-006",
                    "admin",
                    "Policy does not grant full administrative access.",
                    "Policy allows all actions on all resources.",
                ),
                (
                    "IAM-009",
                    "broad",
                    "Policy has no broad wildcard or NotAction grants.",
                    "Policy contains broad wildcard or Allow/NotAction statements.",
                ),
            ):
                hits = result[key]
                out.append(
                    ctx.finding(
                        cid,
                        Status.FAIL if hits else Status.PASS,
                        arn,
                        POLICY,
                        bad_msg if hits else ok_msg,
                        evidence={**base, "statements": hits},
                        sources=_POLICY_SRC,
                        uncertainty=[
                            "Only attached customer-managed policies are evaluated; "
                            "inline and AWS-managed policies are not."
                        ],
                    )
                )
    if not policies:
        for cid in ("IAM-006", "IAM-009"):
            out.append(
                ctx.finding(
                    cid,
                    Status.NOT_APPLICABLE,
                    fallback,
                    ACCT,
                    "No attached customer-managed policies.",
                    sources=_POLICY_SRC,
                )
            )
    return out


# ---------------------------------------------------------------- password policy


@check("IAM-007")
def password_policy(ctx: CheckContext) -> list[Finding]:
    src = ["iam:GetAccountPasswordPolicy"]
    resource = f"account/{ctx.account_id}"
    out: list[Finding] = []
    with ctx.capture(out, "IAM-007", resource, ACCT, src):
        try:
            resp = ctx.client("iam").get_account_password_policy()
        except Exception as exc:
            if error_code(exc) != "NoSuchEntity":
                raise
            out.append(
                ctx.finding(
                    "IAM-007",
                    Status.FAIL,
                    resource,
                    ACCT,
                    "No account password policy is set (AWS defaults apply).",
                    sources=src,
                )
            )
            return out
        pol = require(resp, "PasswordPolicy", dict)
        t = ctx.config.thresholds
        length = optional(pol, "MinimumPasswordLength", int) or 0
        reuse = optional(pol, "PasswordReusePrevention", int) or 0
        problems = []
        if length < t.password_min_length:
            problems.append(f"minimum length {length} < {t.password_min_length}")
        if reuse < t.password_reuse_prevention:
            problems.append(f"reuse prevention {reuse} < {t.password_reuse_prevention}")
        out.append(
            ctx.finding(
                "IAM-007",
                Status.FAIL if problems else Status.PASS,
                resource,
                ACCT,
                ("Password policy is weaker than baseline: " + "; ".join(problems))
                if problems
                else "Password policy meets the configured baseline.",
                evidence={
                    "MinimumPasswordLength": length,
                    "PasswordReusePrevention": reuse,
                    "required_length": t.password_min_length,
                    "required_reuse_prevention": t.password_reuse_prevention,
                },
                sources=src,
                uncertainty=["Only length and reuse prevention are evaluated."],
            )
        )
    return out


# ---------------------------------------------------------------- Access Analyzer


@check("IAM-008")
def access_analyzer(ctx: CheckContext) -> list[Finding]:
    src = ["access-analyzer:ListAnalyzers"]
    resource = f"region/{ctx.region}"
    out: list[Finding] = []
    with ctx.capture(out, "IAM-008", resource, "AWS::AccessAnalyzer::Analyzer", src):
        analyzers = list(paginate(ctx.client("accessanalyzer"), "list_analyzers", "analyzers"))
        active = [
            a
            for a in analyzers
            if a.get("status") == "ACTIVE" and a.get("type") in ("ACCOUNT", "ORGANIZATION")
        ]
        out.append(
            ctx.finding(
                "IAM-008",
                Status.PASS if active else Status.FAIL,
                resource,
                "AWS::AccessAnalyzer::Analyzer",
                "An active external-access analyzer exists."
                if active
                else "No active external-access analyzer in this region.",
                evidence={"analyzers_total": len(analyzers), "active_external_access": len(active)},
                sources=src,
            )
        )
    return out
