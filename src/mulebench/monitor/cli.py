"""`mulebench monitor` subcommands (argparse; wired from mulebench.cli).

    mulebench monitor run [--in TRACE.jsonl|-] [--out ALERTS.jsonl|-]
                          [--enforced-confirmation-cents N]
                          [--stream [--grace-seconds S]]
    mulebench monitor schema [--out monitor-trace.schema.json]
    mulebench monitor adapt REPORT.json --out DIR [--scenario ID ...]
    mulebench monitor rules --out DIR [--format sigma|kql]

Batch mode (default) reads every event, then writes the alerts once, all
`firm`. `--stream` processes events as they arrive (pipe a live log into
stdin, e.g. `tail -f trace.jsonl | mulebench monitor run --stream`) and writes
every alert transition (provisional, firm, retracted) as soon as it happens;
keep the latest line per alert_id.

Exit codes for `run`: 0 = no applicable alert of severity high or above;
1 = at least one; 2 = usage or trace format error. An alert is a finding.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import TextIO, cast

from mulebench.monitor.alerts import Alert, at_least, write_alerts
from mulebench.monitor.engine import SessionConfig, constant_config, run_batch
from mulebench.monitor.events import trace_json_schema
from mulebench.monitor.ingest import TraceFormatError, read_events
from mulebench.monitor.stream import DEFAULT_GRACE, StreamingMonitor


def add_parser(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
) -> argparse._SubParsersAction[argparse.ArgumentParser]:
    """Add `monitor` and return its subcommand parsers (mulebench.cli adds
    `eval`, which lives in the harness)."""
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

    run.add_argument(
        "--stream", action="store_true", help="streaming mode: emit alerts as events arrive"
    )
    run.add_argument(
        "--grace-seconds",
        type=float,
        default=DEFAULT_GRACE.total_seconds(),
        help="streaming: event-time lateness tolerated before an alert is firm (default 300)",
    )

    adapt = msub.add_parser("adapt", help="write each trial of a mulebench report as a JSONL trace")
    adapt.add_argument("report", type=Path, help="mulebench JSON report")
    adapt.add_argument("--out", type=Path, required=True, help="output directory")
    adapt.add_argument(
        "--scenario", dest="scenario_ids", action="append", help="only this scenario id"
    )

    rules = msub.add_parser(
        "rules",
        help="write the rule documents: Sigma-like (documentation) or Microsoft Sentinel KQL "
        "analytic rules (starting point, not production-validated)",
    )
    rules.add_argument("--out", type=Path, required=True, help="output directory")
    rules.add_argument("--format", choices=("sigma", "kql"), default="sigma")

    schema = msub.add_parser("schema", help="print the trace event JSON Schema")
    schema.add_argument("--out", type=Path, help="write the schema here instead")
    return msub


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
    """1 when the latest version of some alert is a firm, applicable finding
    of severity high or above."""
    latest = {a.alert_id: a for a in alerts}
    return int(
        any(a.applicable and a.status == "firm" and at_least(a, "high") for a in latest.values())
    )


def _stream(args: argparse.Namespace) -> int:
    monitor = StreamingMonitor(
        constant_config(config_from(args)), grace=timedelta(seconds=args.grace_seconds)
    )
    emitted: list[Alert] = []
    with _open(args.input, "r") as f, _open(args.out, "w") as out:
        try:
            for alert in monitor.run(read_events(f)):
                write_alerts([alert], out)
                out.flush()
                emitted.append(alert)
        except KeyboardInterrupt:
            final = monitor.flush()
            write_alerts(final, out)
            emitted += final
    return exit_code(emitted)


def _adapt(args: argparse.Namespace) -> int:
    from mulebench.attacks import load_builtin
    from mulebench.monitor.adapters.pilot import adapt_report, iter_events, trial_file_name
    from mulebench.monitor.ingest import write_events

    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.scenario_ids:
        wanted = set(args.scenario_ids)
        report["scenarios"] = [s for s in report["scenarios"] if s["scenario_id"] in wanted]
    result = adapt_report(report, {s.id: s for s in load_builtin()})
    args.out.mkdir(parents=True, exist_ok=True)
    for t in result.trials:
        path = args.out / trial_file_name(t)
        with path.open("w", encoding="utf-8", newline="\n") as f:
            write_events(iter_events(t), f)
    for scenario_id, reason in result.skipped:
        print(f"skipped {scenario_id}: {reason}", file=sys.stderr)
    print(f"wrote {len(result.trials)} trace(s) to {args.out}", file=sys.stderr)
    return 0


def main(args: argparse.Namespace) -> int:
    if args.monitor_command == "adapt":
        return _adapt(args)
    if args.monitor_command == "rules":
        if args.format == "kql":
            from mulebench.monitor.kql import write_kql_rules

            n = write_kql_rules(args.out)
            print(f"wrote {n} KQL analytic rule(s) to {args.out}", file=sys.stderr)
            return 0
        from mulebench.monitor.sigma import write_rules

        print(f"wrote {write_rules(args.out)} rule document(s) to {args.out}", file=sys.stderr)
        return 0
    if args.monitor_command == "schema":
        text = schema_text()
        if args.out:
            args.out.write_bytes(text.encode("utf-8"))
        else:
            sys.stdout.write(text)
        return 0
    try:
        if args.stream:
            return _stream(args)
        with _open(args.input, "r") as f:
            alerts = run_batch(read_events(f), constant_config(config_from(args)))
    except (TraceFormatError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    with _open(args.out, "w") as out:
        write_alerts(alerts, out)
    return exit_code(alerts)
