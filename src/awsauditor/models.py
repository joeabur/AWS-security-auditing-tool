"""Typed data models shared by every module."""

from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Status(StrEnum):
    PASS = "PASS"  # noqa: S105 - status label, not a credential
    FAIL = "FAIL"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_ASSESSED = "NOT_ASSESSED"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Scope(StrEnum):
    ACCOUNT = "account"
    REGION = "region"


class Control(BaseModel):
    """One entry of the versioned control catalog."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[A-Z]{2,4}-\d{3}$")
    title: str
    service: str
    severity: Severity
    scope: Scope
    benchmark_theme: str
    rationale: str
    evidence_requirements: list[str] = Field(min_length=1)
    remediation: str
    references: list[str] = Field(min_length=1)
    permissions: list[str] = Field(min_length=1)


class Catalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    catalog_version: str
    disclaimer: str
    controls: list[Control]

    @model_validator(mode="after")
    def _unique_ids(self) -> Catalog:
        ids = [c.id for c in self.controls]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate control ids in catalog")
        return self


class SuppressionRef(BaseModel):
    """Why an active FAIL finding is accepted. The finding keeps its FAIL status."""

    model_config = ConfigDict(extra="forbid")

    reason: str
    owner: str
    expires: date


class Finding(BaseModel):
    """A normalized, evidence-backed result for one control and one resource."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = ""
    control_id: str
    title: str
    account_id: str
    region: str
    resource_id: str
    resource_type: str
    severity: Severity
    status: Status
    message: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list)
    observed_at: datetime
    remediation: str
    uncertainty: list[str] = Field(default_factory=list)
    suppression: SuppressionRef | None = None

    @model_validator(mode="after")
    def _stable_id(self) -> Finding:
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        if not self.finding_id:
            raw = "|".join([self.control_id, self.account_id, self.region, self.resource_id])
            self.finding_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return self


def utcnow() -> datetime:
    return datetime.now(UTC)
