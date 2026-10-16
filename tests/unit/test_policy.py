"""IAM policy generation and the committed sample policies."""

from __future__ import annotations

import json
from pathlib import Path

from awsauditor.catalog import select_controls
from awsauditor.models import Severity
from awsauditor.policy import REQUIRED_ACTIONS, build_policy, required_actions

from .conftest import ALL_HARNESSES

ROOT = Path(__file__).resolve().parents[2]
READ_ONLY_PREFIXES = ("Get", "List", "Describe")


def all_actions(policy: dict) -> set[str]:  # type: ignore[type-arg]
    return {a for st in policy["Statement"] for a in st["Action"]}


def test_policy_is_read_only_and_has_no_wildcards(catalog) -> None:  # type: ignore[no-untyped-def]
    policy = build_policy(catalog.controls)
    for st in policy["Statement"]:
        assert st["Effect"] == "Allow" and st["Resource"] == "*"
    for action in all_actions(policy):
        name = action.split(":", 1)[1]
        assert "*" not in action
        assert name.startswith(READ_ONLY_PREFIXES) or name == "GenerateCredentialReport", action
    assert not any(a.endswith(("Admin", "FullAccess")) for a in all_actions(policy))


def test_policy_fits_managed_policy_size_limit(catalog) -> None:  # type: ignore[no-untyped-def]
    assert len(json.dumps(build_policy(catalog.controls), separators=(",", ":"))) < 6144


def test_baseline_policy_is_smaller_than_full(catalog) -> None:  # type: ignore[no-untyped-def]
    baseline = select_controls(catalog, min_severity=Severity.HIGH)
    assert all_actions(build_policy(baseline)) < all_actions(build_policy(catalog.controls))
    assert set(REQUIRED_ACTIONS) <= set(required_actions(baseline))


def test_committed_policies_match_the_catalog(catalog) -> None:  # type: ignore[no-untyped-def]
    full = json.loads((ROOT / "policies" / "audit-full.json").read_text())
    baseline = json.loads((ROOT / "policies" / "audit-baseline.json").read_text())
    assert full == build_policy(catalog.controls)
    assert baseline == build_policy(select_controls(catalog, min_severity=Severity.HIGH))


def test_org_policy_is_separate_and_read_only() -> None:
    org = json.loads((ROOT / "policies" / "optional-organizations.json").read_text())
    assert all_actions(org) == {"organizations:DescribeOrganization", "organizations:ListAccounts"}


def test_zz_policy_covers_exactly_the_actions_the_tests_exercised(catalog) -> None:  # type: ignore[no-untyped-def]
    """Runs last (alphabetical): the policy must equal the APIs the checks really call."""
    used: set[str] = set()
    for factory in ALL_HARNESSES:
        used |= set(factory.oplog.snapshot())
    used -= {a for a in used if a.startswith("organizations:")}  # separate optional extension
    if len(used) < 30:
        import pytest

        pytest.skip("run the whole unit suite to exercise every check")
    policy_actions = all_actions(build_policy(catalog.controls))
    assert used - policy_actions == set(), "API actions used but missing from the policy"
    assert policy_actions - used == set(), "policy grants actions no check uses"
