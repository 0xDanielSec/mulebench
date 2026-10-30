"""Reports: deterministic JSON (schema v2, reads v1) and a terminal summary table."""

from mulebench.reports.json_report import (
    LIMITATIONS,
    build_report,
    report_json_schema,
    report_to_json,
    schema_to_json,
    write_report,
)
from mulebench.reports.reader import UnsupportedReportVersion, load_report, parse_report
from mulebench.reports.table import render_table

__all__ = [
    "LIMITATIONS",
    "UnsupportedReportVersion",
    "build_report",
    "load_report",
    "parse_report",
    "render_table",
    "report_json_schema",
    "report_to_json",
    "schema_to_json",
    "write_report",
]
