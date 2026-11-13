"""`mulebench monitor` subcommands (argparse; wired from mulebench.cli).

    mulebench monitor run [--in TRACE.jsonl|-] [--out ALERTS.jsonl|-]
                          [--enforced-confirmation-cents N]
    mulebench monitor schema [--out monitor-trace.schema.json]

Exit codes for `run`: 0 = no applicable alert of severity high or above;
1 = at least one; 2 = usage or trace format error. An alert is a finding.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import TextIO, cast

from mulebench.monitor.alerts import Alert, at_least, write_alerts
from mulebench.monitor.engine import SessionConfig, constant_config, run_batch
from mulebench.monitor.events import trace_json_schema
from mulebench.monitor.ingest import TraceFormatError, read_events


def add_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    monitor = sub.add_parser("monitor", help="detect invariant violations in agent traces")
    msub = monitor.add_subparsers(dest="monitor_command", required=True)

    run = msub.add_parser("run", help="read a JSONL trace and write JSONL alerts")
    run.add_argument("--in", dest="input", default="-", help="trace file, or - for stdin")
    run.add_argument("--out", default="-", help="alerts file, or - for stdout")
    run.add_argument(
        "--enforced-confirmation-cents",
        type=int,
        default=None,
        help="lowest amount the deployment always sends to customer confirmation "
        "(makes INV-4 applicable)",
    )

    schema = msub.add_parser("schema", help="print the trace event JSON Schema")
    schema.add_argument("--out", type=Path, help="write the schema here instead")


def schema_text() -> str:
    return json.dumps(trace_json_schema(), indent=2, sort_keys=True) + "\n"


@contextlib.contextmanager
def _open(path: str, mode: str) -> Iterator[TextIO]:
    if path == "-":
        yield sys.stdin if "r" in mode else sys.stdout
        return
    with open(path, mode, encoding="utf-8", newline="\n") as f:
        yield cast(TextIO, f)


def config_from(args: argparse.Namespace) -> SessionConfig:
    return SessionConfig(enforced_confirmation_cents=args.enforced_confirmation_cents)


def exit_code(alerts: list[Alert]) -> int:
    return int(any(a.applicable and a.status == "firm" and at_least(a, "high") for a in alerts))


def main(args: argparse.Namespace) -> int:
    if args.monitor_command == "schema":
        text = schema_text()
        if args.out:
            args.out.write_bytes(text.encode("utf-8"))
        else:
            sys.stdout.write(text)
        return 0
    try:
        with _open(args.input, "r") as f:
            alerts = run_batch(read_events(f), constant_config(config_from(args)))
    except (TraceFormatError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    with _open(args.out, "w") as out:
        write_alerts(alerts, out)
    return exit_code(alerts)
