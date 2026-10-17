"""Compare two saved reports using the stable finding IDs."""

from __future__ import annotations

from typing import Any

from ..models import Finding, Status
from .model import Report

_UNKNOWN = (Status.ERROR, Status.NOT_ASSESSED)
_OK = (Status.PASS, Status.NOT_APPLICABLE)


def _brief(f: Finding, previous: Finding | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "finding_id": f.finding_id,
        "control_id": f.control_id,
        "severity": f.severity.value,
        "region": f.region,
        "resource_id": f.resource_id,
        "status": f.status.value,
        "message": f.message,
    }
    if previous is not None:
        out["previous_status"] = previous.status.value
    return out


def diff_reports(old: Report, new: Report) -> dict[str, Any]:
    """Classify what changed between two audits of the same account.

    - ``regressions``: FAIL now, and not FAIL before (new failures included).
    - ``resolved``: FAIL before, now PASS or NOT_APPLICABLE.
    - ``became_unknown``: previously FAIL/PASS, now ERROR/NOT_ASSESSED. This is *not* an
      improvement: the control can no longer be evaluated.
    - ``not_reported``: FAIL before and absent now (resource deleted, control or region no
      longer audited). Not counted as resolved because that cannot be established.
    """
    before = {f.finding_id: f for f in old.findings}
    after = {f.finding_id: f for f in new.findings}
    regressions, resolved, unknown, missing = [], [], [], []
    unchanged = 0
    for fid, cur in after.items():
        prev = before.get(fid)
        if cur.status is Status.FAIL and (prev is None or prev.status is not Status.FAIL):
            regressions.append(_brief(cur, prev))
        elif prev and prev.status is Status.FAIL and cur.status in _OK:
            resolved.append(_brief(cur, prev))
        elif prev and prev.status in (Status.FAIL, Status.PASS) and cur.status in _UNKNOWN:
            unknown.append(_brief(cur, prev))
        else:
            unchanged += 1
    for fid, prev in before.items():
        if fid not in after and prev.status is Status.FAIL:
            missing.append(_brief(prev))
    notes = []
    if old.account_id != new.account_id:
        notes.append("Reports are from different accounts; comparison may not be meaningful.")
    if old.catalog_version != new.catalog_version:
        notes.append(
            f"Catalog versions differ ({old.catalog_version} vs {new.catalog_version}); "
            "new controls appear as regressions if they fail."
        )
    if set(old.regions) != set(new.regions):
        notes.append("Audited regions differ between the reports.")

    def order(item: dict[str, Any]) -> tuple[Any, ...]:
        return (item["control_id"], item["region"], item["resource_id"])

    return {
        "old_generated_at": old.generated_at.isoformat(),
        "new_generated_at": new.generated_at.isoformat(),
        "notes": notes,
        "counts": {
            "regressions": len(regressions),
            "resolved": len(resolved),
            "became_unknown": len(unknown),
            "not_reported": len(missing),
            "unchanged": unchanged,
        },
        "regressions": sorted(regressions, key=order),
        "resolved": sorted(resolved, key=order),
        "became_unknown": sorted(unknown, key=order),
        "not_reported": sorted(missing, key=order),
    }
