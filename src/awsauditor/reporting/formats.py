"""JSON, CSV and HTML renderers. Output is built from already-redacted data."""

from __future__ import annotations

import csv
import html
import io
import json
from typing import Any

from ..models import Severity, Status
from ..redaction import Redactor
from .model import Report

_CSV_COLUMNS = [
    "finding_id",
    "control_id",
    "title",
    "status",
    "severity",
    "account_id",
    "region",
    "resource_id",
    "resource_type",
    "message",
    "observed_at",
    "remediation",
    "uncertainty",
    "sources",
    "evidence",
    "suppression",
]


def report_dict(report: Report, redactor: Redactor) -> dict[str, Any]:
    data = json.loads(report.model_dump_json())
    return dict(redactor.apply(data))


def to_json(report: Report, redactor: Redactor) -> str:
    return json.dumps(report_dict(report, redactor), indent=2, sort_keys=False) + "\n"


def _csv_safe(value: Any) -> str:
    """Neutralize spreadsheet formula injection from AWS-controlled strings."""
    text = str(value)
    if text and text[0] in "=+-@\t\r":
        return "'" + text
    return text


def to_csv(report: Report, redactor: Redactor) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(_CSV_COLUMNS)
    for f in report_dict(report, redactor)["findings"]:
        row = dict(f)
        row["uncertainty"] = " | ".join(f["uncertainty"])
        row["sources"] = " ".join(f["sources"])
        row["evidence"] = json.dumps(f["evidence"], sort_keys=True)
        row["suppression"] = (
            json.dumps(f["suppression"], sort_keys=True) if f["suppression"] else ""
        )
        writer.writerow([_csv_safe(row[c]) for c in _CSV_COLUMNS])
    return buf.getvalue()


_STATUS_ORDER = {
    s: i
    for i, s in enumerate(
        [Status.FAIL, Status.ERROR, Status.NOT_ASSESSED, Status.PASS, Status.NOT_APPLICABLE]
    )
}

_CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;
--fail:#cf222e;--err:#9a6700;--pass:#1a7f37;--na:#6e7781}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;--line:#30363d;
--fail:#ff7b72;--err:#e3b341;--pass:#56d364;--na:#8b949e}}
body{font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0 auto;
max-width:1100px;padding:16px}
h1{font-size:1.4rem}table{border-collapse:collapse;width:100%}
th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top;
word-break:break-word}
.muted{color:var(--muted)}.FAIL{color:var(--fail);font-weight:600}
.ERROR,.NOT_ASSESSED{color:var(--err);font-weight:600}.PASS{color:var(--pass)}
.NOT_APPLICABLE{color:var(--na)}.wrap{overflow-x:auto}
"""


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def to_html(report: Report, redactor: Redactor) -> str:
    data = report_dict(report, redactor)
    summary = data["summary"]
    findings = sorted(
        data["findings"],
        key=lambda f: (
            _STATUS_ORDER[Status(f["status"])],
            -Severity(f["severity"]).rank,
            f["control_id"],
            f["resource_id"],
        ),
    )
    rows = []
    for f in findings:
        detail = f["message"]
        if f["status"] in ("FAIL", "ERROR", "NOT_ASSESSED"):
            detail += f"\nRemediation: {f['remediation']}"
        if f["uncertainty"]:
            detail += "\nUncertainty: " + " ".join(f["uncertainty"])
        if f["suppression"]:
            sup = f["suppression"]
            detail += f"\nSUPPRESSED until {sup['expires']} by {sup['owner']}: {sup['reason']}"
        rows.append(
            f"<tr><td class='{_e(f['status'])}'>{_e(f['status'])}</td><td>{_e(f['severity'])}</td>"
            f"<td>{_e(f['control_id'])}</td><td>{_e(f['region'])}</td>"
            f"<td>{_e(f['resource_id'])}</td>"
            f"<td style='white-space:pre-wrap'>{_e(detail)}</td></tr>"
        )
    status_cells = " · ".join(f"{_e(k)}: {_e(v)}" for k, v in summary["by_status"].items())
    warnings = "".join(f"<li>{_e(w)}</li>" for w in data["warnings"])
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'unsafe-inline'\">"
        "<title>AWS Security Audit Report</title>"
        f"<style>{_CSS}</style></head><body>"
        "<h1>AWS Security Audit Report</h1>"
        f"<p class='muted'>Account {_e(data['account_id'])} · profile {_e(data['audit_profile'])}"
        f" · regions {_e(', '.join(data['regions']))} · generated {_e(data['generated_at'])}"
        f" · catalog {_e(data['catalog_version'])}</p>"
        f"<p>{status_cells}</p>"
        f"<p class='muted'>{_e(data['disclaimer'])}</p>"
        + (f"<h2>Warnings</h2><ul>{warnings}</ul>" if warnings else "")
        + "<div class='wrap'><table><thead><tr><th>Status</th><th>Severity</th><th>Control</th>"
        "<th>Region</th><th>Resource</th><th>Detail</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div></body></html>\n"
    )
