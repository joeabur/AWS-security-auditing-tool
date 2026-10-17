"""Explicit, expiring suppressions of FAIL findings.

A suppression never removes or downgrades a finding: the finding stays ``FAIL`` in every
report and carries who accepted it, why, and until when. It only stops the finding from
counting toward ``--fail-on`` and the active-failure totals. Expired suppressions are ignored
(the finding is active again) and reported, as are suppressions that match nothing.
"""

from __future__ import annotations

from datetime import date
from fnmatch import fnmatchcase

from .config import Suppression
from .models import Finding, Status, SuppressionRef


def apply_suppressions(
    findings: list[Finding], suppressions: list[Suppression], today: date
) -> list[str]:
    """Annotate matching FAIL findings in place; return human-readable warnings."""
    matched: set[int] = set()
    expired_hit: dict[int, int] = {}
    for f in findings:
        if f.status is not Status.FAIL:
            continue
        for i, s in enumerate(suppressions):
            if (
                s.control_id != f.control_id
                or not fnmatchcase(f.resource_id, s.resource)
                or not fnmatchcase(f.region, s.region)
            ):
                continue
            matched.add(i)
            if s.expires < today:
                expired_hit[i] = expired_hit.get(i, 0) + 1
                continue  # an expired entry never suppresses; a later valid one may
            f.suppression = SuppressionRef(reason=s.reason, owner=s.owner, expires=s.expires)
            break
    warnings: list[str] = []
    for i, s in enumerate(suppressions):
        label = f"{s.control_id} resource={s.resource!r} region={s.region!r}"
        if i in expired_hit:
            warnings.append(
                f"Suppression ({label}, owner {s.owner}) expired on {s.expires}; "
                f"{expired_hit[i]} finding(s) are reported as active again."
            )
        elif i not in matched:
            warnings.append(
                f"Suppression ({label}, owner {s.owner}) matched no failing finding; "
                "remove it if the issue is fixed."
            )
    return warnings
