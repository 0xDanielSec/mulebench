"""Real spend so far, from run reports, and the pilot 10 phase-2 budget gate.

Usage:
    python scripts/pilot_spend.py [--cap 9.00] [--next 1.40] [REPORT ...]

With no REPORT, every `runs/pilot-10-*.json` is read. For each report it prints
OpenRouter's own cost (`routing.provider_cost_usd`, the real spend); when a
report has no provider cost (a call without `usage.cost`), its table cost
(`cost_totals.cost_usd`, never lower than the price paid) is used instead and
marked. With `--next X` it adds X (the next run's x2 cap) and exits 0 when the
spend so far plus X is at most `--cap`, 1 otherwise ("not run: budget").

Doctor probe calls are not in any report; they are a few cents at most and are
not counted.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_GLOB = "runs/pilot-10-*.json"


def spend_of(report: dict[str, Any]) -> tuple[float, str]:
    """(US$, source): provider cost, or table cost when the provider cost is missing."""
    provider = (report.get("routing") or {}).get("provider_cost_usd")
    if isinstance(provider, int | float):
        return float(provider), "provider"
    table = (report.get("cost_totals") or {}).get("cost_usd")
    return float(table or 0.0), "table (provider cost missing)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scripts/pilot_spend.py")
    parser.add_argument("reports", nargs="*", type=Path)
    parser.add_argument("--cap", type=float, default=9.00, help="total real-spend cap (US$)")
    parser.add_argument("--next", type=float, help="the next run's cap (US$): gate on it")
    args = parser.parse_args(argv)
    paths = args.reports or sorted(ROOT.glob(DEFAULT_GLOB))
    paths = [p for p in paths if not p.name.endswith(".checkpoint.jsonl")]
    total = 0.0
    for path in paths:
        report = json.loads(path.read_text(encoding="utf-8"))
        usd, source = spend_of(report)
        total += usd
        print(f"{path.name}: US$ {usd:.4f} ({source}; run status {report.get('run_status')})")
    print(f"spend so far: US$ {total:.4f} over {len(paths)} report(s); cap US$ {args.cap:.2f}")
    if args.next is None:
        return 0
    after = round(total + args.next, 6)  # no float noise at the cap
    if after <= args.cap:
        print(f"GO: US$ {total:.4f} + next cap US$ {args.next:.2f} = US$ {after:.4f} <= cap")
        return 0
    print(
        f"STOP (not run: budget): US$ {total:.4f} + next cap US$ {args.next:.2f} = "
        f"US$ {after:.4f} > cap"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
