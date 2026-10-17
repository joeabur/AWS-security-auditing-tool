"""Report model, filtering and export."""

from collections.abc import Callable

from ..redaction import Redactor
from .diff import diff_reports
from .files import write_report_file
from .formats import to_csv, to_html, to_json
from .manifest import build_manifest, verify_manifest
from .model import Report, build_report, filter_findings, load_report
from .sarif import to_sarif

RENDERERS: dict[str, Callable[[Report, Redactor], str]] = {
    "json": to_json,
    "csv": to_csv,
    "html": to_html,
    "sarif": to_sarif,
}

__all__ = [
    "RENDERERS",
    "Report",
    "build_manifest",
    "build_report",
    "diff_reports",
    "filter_findings",
    "load_report",
    "to_csv",
    "to_html",
    "to_json",
    "to_sarif",
    "verify_manifest",
    "write_report_file",
]
