"""Control execution: schedules checks across regions and assembles partial results."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime

from . import checks as _checks  # noqa: F401  (imports register all checks)
from .config import AuditConfig
from .context import GLOBAL_REGION, REGISTRY, CheckContext, CheckSpec, SharedCache
from .errors import classify_exception
from .models import Catalog, Control, Finding, Scope, Status, utcnow
from .regions import RegionPlan
from .session import ClientFactory, Identity

log = logging.getLogger(__name__)


@dataclass
class AuditResult:
    findings: list[Finding]
    started_at: datetime
    finished_at: datetime
    account_id: str
    regions: list[str]
    profile: str
    catalog_version: str
    control_ids: list[str]
    api_actions: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def _unit_error(ctx: CheckContext, ids: list[str], exc: BaseException) -> list[Finding]:
    status, message, uncertainty = classify_exception(exc)
    return [
        ctx.finding(
            cid,
            status,
            ctx.region if ctx.region != GLOBAL_REGION else f"account/{ctx.account_id}",
            "check",
            message,
            evidence={"error_type": type(exc).__name__},
            uncertainty=[uncertainty],
        )
        for cid in ids
    ]


def _run_unit(spec: CheckSpec, ids: list[str], ctx: CheckContext) -> list[Finding]:
    try:
        produced = spec.fn(ctx)
    except Exception as exc:
        log.warning("check %s failed in %s: %s", ids, ctx.region, type(exc).__name__)
        return _unit_error(ctx, ids, exc)
    selected = [f for f in produced if f.control_id in ids]
    seen = {f.control_id for f in selected}
    for cid in ids:
        if cid not in seen:
            selected.append(
                ctx.finding(
                    cid,
                    Status.NOT_ASSESSED,
                    ctx.region,
                    "check",
                    "The check produced no result for this control.",
                    uncertainty=["Internal: every check must report a status for each control."],
                )
            )
    return selected


def run_audit(
    factory: ClientFactory,
    identity: Identity,
    config: AuditConfig,
    catalog: Catalog,
    selected: list[Control],
    plan: RegionPlan,
    *,
    home_region: str,
    profile_name: str,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], datetime] = utcnow,
    progress: Callable[[str], None] | None = None,
) -> AuditResult:
    started = now()
    by_id = {c.id: c for c in catalog.controls}
    selected_ids = {c.id for c in selected}
    cache = SharedCache()
    units: list[tuple[CheckSpec, list[str], CheckContext]] = []
    for spec in REGISTRY:
        ids = [cid for cid in spec.control_ids if cid in selected_ids]
        if not ids:
            continue
        if by_id[ids[0]].scope is Scope.ACCOUNT:
            regions = [(GLOBAL_REGION, home_region)]
        else:
            regions = [(r, r) for r in plan.audited]
        for report_region, client_region in regions:
            ctx = CheckContext(
                account_id=identity.account_id,
                partition=identity.partition,
                region=report_region,
                client_region=client_region,
                audited_regions=plan.audited,
                enabled_regions=plan.enabled,
                region_discovery_ok=plan.discovery_ok,
                factory=factory,
                config=config,
                controls=by_id,
                cache=cache,
                now=started,
                sleep=sleep,
                selected=frozenset(selected_ids),
            )
            units.append((spec, ids, ctx))

    def work(unit: tuple[CheckSpec, list[str], CheckContext]) -> list[Finding]:
        spec, ids, ctx = unit
        if progress:
            progress(f"{'+'.join(ids)} [{ctx.region}]")
        return _run_unit(spec, ids, ctx)

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=config.audit.workers) as pool:
        for batch in pool.map(work, units):
            findings.extend(batch)
    findings.sort(key=lambda f: (f.control_id, f.region, f.resource_id))
    return AuditResult(
        findings=findings,
        started_at=started,
        finished_at=now(),
        account_id=identity.account_id,
        regions=plan.audited,
        profile=profile_name,
        catalog_version=catalog.catalog_version,
        control_ids=sorted(selected_ids),
        api_actions=factory.oplog.snapshot(),
        warnings=list(plan.warnings),
    )
