"""Every check, under injected AWS failures, must report unknown - never PASS."""

from __future__ import annotations

import pytest

import awsauditor.checks  # noqa: F401  (registers checks)
from awsauditor.context import REGISTRY
from awsauditor.models import Scope, Status

from .conftest import Harness, assert_wellformed, error_payload

SPECS = [s for s in REGISTRY if s.control_ids != ("COV-001",)]


def run_spec(h: Harness, spec) -> list:  # type: ignore[no-untyped-def,type-arg]
    scope = next(c.scope for c in h.catalog.controls if c.id == spec.control_ids[0])
    ctx = h.ctx(account_scope=scope is Scope.ACCOUNT)
    return spec.fn(ctx)


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: "+".join(s.control_ids))
@pytest.mark.parametrize(
    ("code", "status", "http"),
    [
        ("AccessDenied", Status.ERROR, 403),
        ("UnauthorizedOperation", Status.ERROR, 403),
        ("ThrottlingException", Status.ERROR, 400),
        ("RequestLimitExceeded", Status.ERROR, 503),
        ("InternalError", Status.ERROR, 500),
        ("OptInRequired", Status.NOT_ASSESSED, 403),
    ],
)
def test_api_failure_is_never_a_pass(spec, code: str, status: Status, http: int) -> None:  # type: ignore[no-untyped-def]
    h = Harness()
    h.factory.fault = error_payload(code, http)
    findings = run_spec(h, spec)
    assert_wellformed(findings)
    assert {f.control_id for f in findings} >= set(spec.control_ids)
    assert {f.status for f in findings} == {status}, [f.message for f in findings]
    # error findings never carry resource data from the failed call
    assert all(f.evidence.keys() <= {"error_type"} for f in findings)


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: "+".join(s.control_ids))
def test_unexpected_exception_type_propagates_to_runner_as_error(spec) -> None:  # type: ignore[no-untyped-def]
    """A programming error inside a check is converted by the runner, not swallowed."""
    from awsauditor.runner import _run_unit

    h = Harness()

    def boom(_ctx):  # type: ignore[no-untyped-def]
        raise RuntimeError("bug")

    from awsauditor.context import CheckSpec

    out = _run_unit(CheckSpec(spec.control_ids, boom), list(spec.control_ids), h.ctx())
    assert {f.status for f in out} == {Status.ERROR}
    assert {f.control_id for f in out} == set(spec.control_ids)


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: "+".join(s.control_ids))
def test_checks_only_issue_read_only_calls(spec) -> None:  # type: ignore[no-untyped-def]
    """With a fault that records nothing, the guard would raise on any mutating call."""
    h = Harness()
    h.factory.fault = error_payload("AccessDenied", 403)
    findings = run_spec(h, spec)
    assert all("blocked non-read-only" not in f.message for f in findings)
