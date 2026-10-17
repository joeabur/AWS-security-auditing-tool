"""Execution context handed to each check, plus the check registry."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .config import AuditConfig
from .errors import classify_exception
from .models import Control, Finding, Status, utcnow
from .session import ClientFactory

GLOBAL_REGION = "global"


class SharedCache:
    """Thread-safe memoization, including of failures (so denied calls are made once).

    Each key has its own lock so a slow computation (for example the IAM credential report)
    never blocks unrelated cache users.
    """

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._locks: dict[str, threading.RLock] = {}
        self._values: dict[str, Any] = {}
        self._errors: dict[str, Exception] = {}

    def get_or_compute(self, key: str, fn: Callable[[], Any]) -> Any:
        with self._guard:
            lock = self._locks.setdefault(key, threading.RLock())
        with lock:
            with self._guard:
                if key in self._errors:
                    raise self._errors[key]
                if key in self._values:
                    return self._values[key]
            try:
                value = fn()
            except Exception as exc:
                with self._guard:
                    self._errors[key] = exc
                raise
            with self._guard:
                self._values[key] = value
            return value


@dataclass
class CheckContext:
    account_id: str
    partition: str
    region: str  # region reported on findings ("global" for account-scope checks)
    client_region: str  # region used for API clients
    audited_regions: list[str]
    enabled_regions: list[str]
    region_discovery_ok: bool
    factory: ClientFactory
    config: AuditConfig
    controls: dict[str, Control]
    cache: SharedCache
    now: datetime = field(default_factory=utcnow)
    sleep: Callable[[float], None] = time.sleep
    selected: frozenset[str] | None = None  # None means every control is selected

    def wants(self, control_id: str) -> bool:
        return self.selected is None or control_id in self.selected

    def client(self, service: str, region: str | None = None) -> Any:
        return self.factory.client(service, region or self.client_region)

    def finding(
        self,
        control_id: str,
        status: Status,
        resource_id: str,
        resource_type: str,
        message: str,
        *,
        evidence: dict[str, Any] | None = None,
        sources: list[str] | None = None,
        uncertainty: list[str] | None = None,
    ) -> Finding:
        control = self.controls[control_id]
        return Finding(
            control_id=control_id,
            title=control.title,
            account_id=self.account_id,
            region=self.region,
            resource_id=resource_id,
            resource_type=resource_type,
            severity=control.severity,
            status=status,
            message=message,
            evidence=evidence or {},
            sources=sources or [],
            observed_at=self.now,
            remediation=control.remediation,
            uncertainty=uncertainty or [],
        )

    def error_finding(
        self,
        control_id: str,
        exc: BaseException,
        resource_id: str,
        resource_type: str,
        sources: list[str] | None = None,
    ) -> Finding:
        status, message, uncertainty = classify_exception(exc)
        return self.finding(
            control_id,
            status,
            resource_id,
            resource_type,
            message,
            evidence={"error_type": type(exc).__name__},
            sources=sources,
            uncertainty=[uncertainty],
        )

    @contextmanager
    def capture(
        self,
        out: list[Finding],
        control_ids: str | list[str],
        resource_id: str,
        resource_type: str,
        sources: list[str] | None = None,
    ) -> Iterator[None]:
        """Turn any failure inside the block into ERROR/NOT_ASSESSED findings (never PASS)."""
        ids = [control_ids] if isinstance(control_ids, str) else control_ids
        try:
            yield
        except Exception as exc:
            for cid in ids:
                out.append(self.error_finding(cid, exc, resource_id, resource_type, sources))


CheckFn = Callable[[CheckContext], list[Finding]]


@dataclass(frozen=True)
class CheckSpec:
    control_ids: tuple[str, ...]
    fn: CheckFn


REGISTRY: list[CheckSpec] = []


def check(*control_ids: str) -> Callable[[CheckFn], CheckFn]:
    """Register a check function that produces findings for the given control ids."""

    def decorator(fn: CheckFn) -> CheckFn:
        REGISTRY.append(CheckSpec(tuple(control_ids), fn))
        return fn

    return decorator
