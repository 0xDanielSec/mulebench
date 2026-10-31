"""Command-line interface (argparse only).

    mulebench run [<dir> | --builtin] [--out report.json]
                  [--agent scripted|llm] [--trials N] [--max-steps N]
                  [--model M] [--effort E] [--prompt-variants a,b]
                  [--cassettes DIR] [--record] [--max-cost-usd X]
    mulebench schema [--out report.schema.json]

LLM runs replay recorded cassettes by default. `--record` makes live calls and
stores them; it requires MB_LIVE=1, ANTHROPIC_API_KEY and --max-cost-usd.

Exit codes for `run`: 0 = completed and every attack trial exposed the payload;
1 = at least one attack trial was not_exposed (invalid scenario); 2 = usage,
load/validation error, unsupported invariant, missing cassette or invalid model
request; 3 = run aborted by the cost cap (partial report still written).
A successful attack is a finding, not an error.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from mulebench.agents import Agent, ScriptedAgent
from mulebench.agents.scripted import DEFAULT_MAX_STEPS
from mulebench.attacks import ScenarioError, load_all, load_builtin
from mulebench.harness import NO_PROMPT, UnsupportedInvariant, run_all
from mulebench.harness.models import LLMConfig, PricingInfo
from mulebench.harness.presets import DEFAULT_PRESETS, UnknownPreset, preset_guard_names
from mulebench.reports import build_report, render_table, schema_to_json, write_report

DEFAULT_LLM_TRIALS = 10


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mulebench",
        description="Test whether AI agents can be manipulated into violating financial "
        "invariants.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run scenarios (packaged ones by default)")
    source = run.add_mutually_exclusive_group()
    source.add_argument(
        "directory", nargs="?", type=Path, help="directory of scenario *.yaml files"
    )
    source.add_argument(
        "--builtin", action="store_true", help="run the packaged scenarios (default)"
    )
    run.add_argument("--out", type=Path, help="write the JSON report here")
    run.add_argument("--agent", choices=("scripted", "llm"), default="scripted")
    run.add_argument(
        "--trials", type=int, help=f"trials per cell (scripted: 1, llm: {DEFAULT_LLM_TRIALS})"
    )
    run.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS, help="agent step cap")
    run.add_argument(
        "--preset",
        action="append",
        dest="presets",
        metavar="NAME",
        help="guard preset to run (repeatable; default: vulnerable and hardened). Names: "
        "vulnerable, hardened, strict, none, all, only:<guard>, all-minus:<guard>",
    )
    ablate = sub.add_parser(
        "ablate",
        help="guard ablation matrix with the scripted agent (packaged scenarios by default)",
    )
    ablate.add_argument(
        "directory", nargs="?", type=Path, help="directory of scenario *.yaml files"
    )
    ablate.add_argument("--out", type=Path, help="write the JSON ablation report here")
    llm = run.add_argument_group("llm agent")
    llm.add_argument("--model", help="model id (required for --agent llm)")
    llm.add_argument("--effort", default="medium", help="output_config.effort (default medium)")
    llm.add_argument(
        "--prompt-variants",
        default="baseline,data_not_instructions",
        help="comma-separated prompt variants",
    )
    llm.add_argument("--cassettes", type=Path, help="cassette directory (replay by default)")
    llm.add_argument("--record", action="store_true", help="make live calls and record them")
    llm.add_argument("--max-cost-usd", type=float, help="whole-run cost cap")

    schema = sub.add_parser("schema", help="print the report JSON Schema")
    schema.add_argument("--out", type=Path, help="write the schema here instead")
    return parser


def _error(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def _ablate(directory: Path | None, out: Path | None) -> int:
    from mulebench.reports.ablation import (
        render_ablation_markdown,
        run_ablation,
        write_ablation,
    )
    from mulebench.workloads import load_workloads

    if directory is not None and not directory.is_dir():
        return _error(f"not a directory: {directory}")
    try:
        scenarios = load_builtin() if directory is None else load_all(directory)
    except ScenarioError as exc:
        return _error(str(exc))
    if not scenarios:
        return _error(f"no scenarios found in {directory or '<builtin>'}")
    try:
        report = run_ablation(scenarios, ScriptedAgent(), load_workloads())
    except UnsupportedInvariant as exc:
        return _error(str(exc))
    if out:
        write_ablation(report, out)
    print(render_ablation_markdown(report))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "schema":
        text = schema_to_json()
        if args.out:
            args.out.write_bytes(text.encode("utf-8"))
        else:
            sys.stdout.write(text)
        return 0

    if args.command == "ablate":
        return _ablate(args.directory, args.out)

    directory: Path | None = args.directory
    if directory is not None and not directory.is_dir():
        return _error(f"not a directory: {directory}")
    try:
        scenarios = load_builtin() if directory is None else load_all(directory)
    except ScenarioError as exc:
        return _error(str(exc))
    if not scenarios:
        return _error(f"no scenarios found in {directory or '<builtin>'}")

    presets: list[str] = args.presets or list(DEFAULT_PRESETS)
    try:
        for p in presets:
            preset_guard_names(p)
    except UnknownPreset as exc:
        return _error(str(exc))

    llm_config: LLMConfig | None = None
    pricing: PricingInfo | None = None
    agent: Agent
    if args.agent == "scripted":
        prompts: list[str] = [NO_PROMPT]
        trials = args.trials or 1
        agent = ScriptedAgent(max_steps=args.max_steps)
    else:
        built = _build_llm(args)
        if isinstance(built, int):
            return built
        agent, llm_config, pricing, prompts = built
        trials = args.trials or DEFAULT_LLM_TRIALS

    from mulebench.agents.llm.model import ModelRequestInvalid
    from mulebench.agents.llm.transport import CassetteMissing

    try:
        outcome = run_all(scenarios, agent, prompt_variants=prompts, trials=trials, presets=presets)
    except UnsupportedInvariant as exc:
        return _error(str(exc))
    except (CassetteMissing, ModelRequestInvalid) as exc:
        return _error(str(exc))

    report = build_report(
        outcome,
        agent,
        prompt_variants=prompts,
        trials=trials,
        llm=llm_config,
        pricing=pricing,
        presets=presets,
    )
    if args.out:
        write_report(report, args.out)
    print(render_table(report))
    if outcome.status != "complete":
        print(f"aborted: {outcome.abort_reason}", file=sys.stderr)
        return 3
    return 1 if report.summary.totals.not_exposed else 0


def _build_llm(
    args: argparse.Namespace,
) -> tuple[Agent, LLMConfig, PricingInfo, list[str]] | int:
    if not args.model:
        return _error("--agent llm requires --model")
    try:
        from mulebench.agents.llm import CostMeter, LLMAgent
        from mulebench.agents.llm.anthropic_model import AnthropicChatModel
        from mulebench.agents.llm.pricing import PRICING_AS_OF, price_for
        from mulebench.agents.llm.prompts import PROMPTS, prompt_sha256
        from mulebench.agents.llm.transport import (
            CassetteTransport,
            LiveCallsDisabled,
            LiveTransport,
        )
    except ImportError:
        return _error("the llm agent needs the llm extra: pip install mulebench[llm]")

    prompts = [p.strip() for p in args.prompt_variants.split(",") if p.strip()]
    unknown = [p for p in prompts if p not in PROMPTS]
    if unknown or not prompts:
        return _error(f"unknown prompt variants {unknown}; known: {sorted(PROMPTS)}")
    if args.cassettes is None:
        return _error("--agent llm needs --cassettes DIR (replay, or --record into it)")
    price = price_for(args.model)
    if args.record:
        if args.max_cost_usd is None:
            return _error("--record requires --max-cost-usd")
        if price is None:
            return _error(f"no known price for {args.model}; cannot enforce the cost cap")
        try:
            upstream = LiveTransport()
        except LiveCallsDisabled as exc:
            return _error(str(exc))
        transport = CassetteTransport(args.cassettes, "record", upstream)
    else:
        transport = CassetteTransport(args.cassettes, "replay")

    agent = LLMAgent(
        AnthropicChatModel(transport),
        model=args.model,
        effort=args.effort,
        max_steps=args.max_steps,
        meter=CostMeter(args.max_cost_usd),
    )
    llm_config = LLMConfig(
        provider="anthropic",
        model=args.model,
        effort=args.effort,
        max_tokens=agent.max_tokens,
        refusal_fallbacks="off",
        prompt_sha256={p: prompt_sha256(p) for p in prompts},
    )
    pricing = PricingInfo(
        as_of=PRICING_AS_OF,
        note="estimates from a dated price table; verify before relying on them",
        per_mtok={}
        if price is None
        else {
            args.model: {
                "input": price.input_per_mtok,
                "output": price.output_per_mtok,
                "cache_write": price.cache_write_per_mtok,
                "cache_read": price.cache_read_per_mtok,
                "cache_read_estimated": price.cache_read_estimated,
            }
        },
    )
    return agent, llm_config, pricing, prompts


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
