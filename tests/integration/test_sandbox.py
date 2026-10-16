"""Opt-in tests against a real sandbox account. Skipped unless explicitly enabled."""

from __future__ import annotations

import os

import boto3
import pytest

from awsauditor.catalog import load_catalog, select_controls
from awsauditor.config import AuditConfig
from awsauditor.models import Status
from awsauditor.regions import plan_regions
from awsauditor.runner import run_audit
from awsauditor.session import ClientFactory, resolve_identity

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("AWSAUDITOR_INTEGRATION") != "1",
        reason="set AWSAUDITOR_INTEGRATION=1 to run against a sandbox AWS account",
    ),
]


@pytest.fixture(scope="module")
def live():  # type: ignore[no-untyped-def]
    expected = os.environ.get("AWSAUDITOR_INTEGRATION_ACCOUNT")
    if not expected:
        pytest.fail("AWSAUDITOR_INTEGRATION_ACCOUNT must name the sandbox account")
    factory = ClientFactory(boto3.Session())
    identity = resolve_identity(factory)
    if identity.account_id != expected:
        pytest.fail("resolved account does not match AWSAUDITOR_INTEGRATION_ACCOUNT; refusing")
    return factory, identity


def test_identity_and_region_discovery(live):  # type: ignore[no-untyped-def]
    factory, identity = live
    home = factory.default_region or "us-east-1"
    plan = plan_regions(factory, [home], home, identity.partition)
    assert plan.audited == [home] and plan.discovery_ok


def test_identity_controls_run_read_only(live):  # type: ignore[no-untyped-def]
    """Requires the identity-related permissions from policies/audit-full.json."""
    factory, identity = live
    home = factory.default_region or "us-east-1"
    catalog = load_catalog()
    controls = select_controls(catalog, include=["IAM-001", "IAM-002", "IAM-007", "COV-001"])
    plan = plan_regions(factory, [home], home, identity.partition)
    result = run_audit(factory, identity, AuditConfig(), catalog, controls, plan,
                       home_region=home, profile_name="integration")  # fmt: skip
    assert {f.control_id for f in result.findings} == {c.id for c in controls}
    # Expected states depend on the sandbox's configuration; what must hold everywhere:
    assert all(f.status in set(Status) for f in result.findings)
    assert all(a.split(":")[1].startswith(("Get", "List", "Describe", "Generate"))
               for a in result.api_actions)  # fmt: skip


def test_regional_controls_return_a_verdict_per_region(live):  # type: ignore[no-untyped-def]
    factory, identity = live
    home = factory.default_region or "us-east-1"
    catalog = load_catalog()
    controls = select_controls(catalog, include=["EBS-001", "LOG-011", "NET-002"])
    plan = plan_regions(factory, [home], home, identity.partition)
    result = run_audit(factory, identity, AuditConfig(), catalog, controls, plan,
                       home_region=home, profile_name="integration")  # fmt: skip
    for cid in ("EBS-001", "LOG-011", "NET-002"):
        assert any(f.control_id == cid and f.region == home for f in result.findings)
