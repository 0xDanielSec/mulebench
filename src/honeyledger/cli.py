"""Command-line interface (argparse only).

    honeyledger run <dir> [--out report.json] [--max-steps N]
    honeyledger schema [--out report.schema.json]

Exit codes for `run`: 0 = completed and every scenario valid; 1 = at least one
attack cell was not_exposed (invalid scenario); 2 = load/validation error or
unsupported invariant. A successful attack is a finding, not an error.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from honeyledger.agents import ScriptedAgent
from honeyledger.agents.scripted import DEFAULT_MAX_STEPS
from honeyledger.attacks import ScenarioError, load_all
from honeyledger.harness import UnsupportedInvariant, run_all
from honeyledger.reports import build_report, render_table, schema_to_json, write_report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="honeyledger",
        description="Test whether AI agents can be manipulated into violating financial "
        "invariants.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run every scenario in a directory")
    run.add_argument("directory", type=Path, help="directory of scenario *.yaml files")
    run.add_argument("--out", type=Path, help="write the JSON report here")
    run.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS, help="agent step cap")

    schema = sub.add_parser("schema", help="print the report JSON Schema")
    schema.add_argument("--out", type=Path, help="write the schema here instead")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "schema":
        text = schema_to_json()
        if args.out:
            args.out.write_bytes(text.encode("utf-8"))
        else:
            sys.stdout.write(text)
        return 0

    directory: Path = args.directory
    if not directory.is_dir():
        print(f"error: not a directory: {directory}", file=sys.stderr)
        return 2
    try:
        scenarios = load_all(directory)
    except ScenarioError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not scenarios:
        print(f"error: no scenarios found in {directory}", file=sys.stderr)
        return 2

    agent = ScriptedAgent(max_steps=args.max_steps)
    try:
        results = run_all(scenarios, agent)
    except UnsupportedInvariant as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = build_report(results, agent)
    if args.out:
        write_report(report, args.out)
    print(render_table(report))
    return 1 if report.summary.totals.not_exposed else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
