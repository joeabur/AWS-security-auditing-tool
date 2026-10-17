"""Shared test harness: real botocore clients with Stubber or injected faults. No network."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber

from awsauditor.catalog import load_catalog
from awsauditor.config import AuditConfig
from awsauditor.context import GLOBAL_REGION, CheckContext, SharedCache
from awsauditor.models import Catalog, Finding, Status
from awsauditor.session import ClientFactory

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
ACCOUNT = "111122223333"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def fixture_json(name: str) -> Any:
    return json.loads(fixture_text(name))


class FaultFactory(ClientFactory):
    """Factory whose clients can answer every call with an injected AWS error or payload."""

    fault: dict[str, Any] | None = None  # applies to every operation
    op_faults: dict[str, dict[str, Any]] = {}  # noqa: RUF012 - reassigned per test via attribute

    def client(self, service: str, region: str | None = None) -> Any:
        key = (service, region)
        fresh = key not in self._cache
        client = super().client(service, region)
        if fresh:
            client.meta.events.register("before-call.*.*", self._inject)
            # Last resort: a call nobody stubbed must fail loudly, never reach the network.
            client.meta.events.register_last("before-call.*.*", self._no_network)
        return client

    @staticmethod
    def _no_network(model: Any, **_kwargs: Any) -> None:
        raise AssertionError(f"unstubbed AWS call: {model.service_model.service_name}.{model.name}")

    def _inject(self, model: Any, **_kwargs: Any) -> Any:
        fault = self.op_faults.get(model.name) or self.fault
        if fault is None:
            return None
        status = int(fault.get("status", 400))
        return SimpleNamespace(status_code=status), fault["parsed"]


def error_payload(code: str, status: int = 400) -> dict[str, Any]:
    return {
        "status": status,
        "parsed": {
            "Error": {"Code": code, "Message": "injected"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
    }


ALL_HARNESSES: list[ClientFactory] = []


class Harness:
    def __init__(self, config: AuditConfig | None = None) -> None:
        session = boto3.Session(
            aws_access_key_id="testing", aws_secret_access_key="testing", region_name="us-east-1"
        )
        self.factory = FaultFactory(session)
        ALL_HARNESSES.append(self.factory)
        self.config = config or AuditConfig()
        self.catalog: Catalog = load_catalog()
        self._stubbers: dict[tuple[str, str | None], Stubber] = {}
        self.sleeps: list[float] = []

    def stubber(self, service: str, region: str | None = "us-east-1") -> Stubber:
        key = (service, region)
        if key not in self._stubbers:
            stub = Stubber(self.factory.client(service, region))
            stub.activate()
            self._stubbers[key] = stub
        return self._stubbers[key]

    def ok(
        self,
        service: str,
        op: str,
        response: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        region: str | None = "us-east-1",
    ) -> None:
        self.stubber(service, region).add_response(op, response or {}, params)

    def err(
        self,
        service: str,
        op: str,
        code: str = "AccessDenied",
        status: int = 403,
        region: str | None = "us-east-1",
    ) -> None:
        self.stubber(service, region).add_client_error(
            op, service_error_code=code, service_message="injected", http_status_code=status
        )

    def ctx(
        self,
        region: str = "us-east-1",
        *,
        account_scope: bool = False,
        audited: list[str] | None = None,
        enabled: list[str] | None = None,
        discovery_ok: bool = True,
    ) -> CheckContext:
        return CheckContext(
            account_id=ACCOUNT,
            partition="aws",
            region=GLOBAL_REGION if account_scope else region,
            client_region=region,
            audited_regions=audited or [region],
            enabled_regions=enabled if enabled is not None else (audited or [region]),
            region_discovery_ok=discovery_ok,
            factory=self.factory,
            config=self.config,
            controls={c.id: c for c in self.catalog.controls},
            cache=SharedCache(),
            now=NOW,
            sleep=self.sleeps.append,
        )

    def assert_all_consumed(self) -> None:
        for stub in self._stubbers.values():
            stub.assert_no_pending_responses()


@pytest.fixture
def h() -> Harness:
    return Harness()


@pytest.fixture(scope="session")
def catalog() -> Catalog:
    return load_catalog()


def by_status(findings: list[Finding]) -> dict[Status, list[Finding]]:
    out: dict[Status, list[Finding]] = {}
    for f in findings:
        out.setdefault(f.status, []).append(f)
    return out


def statuses(findings: list[Finding], control_id: str | None = None) -> list[str]:
    return [f.status.value for f in findings if control_id in (None, f.control_id)]


def assert_wellformed(findings: list[Finding]) -> None:
    """Every finding carries the mandatory fields; failures carry actionable remediation."""
    assert findings
    for f in findings:
        assert f.control_id and f.resource_id and f.region and f.message
        assert f.observed_at.tzinfo is not None
        assert f.finding_id
        if f.status in (Status.FAIL, Status.ERROR, Status.NOT_ASSESSED):
            assert f.remediation
        if f.status in (Status.ERROR, Status.NOT_ASSESSED):
            assert f.uncertainty
