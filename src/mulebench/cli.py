"""Command-line interface (argparse only).

    mulebench run [<dir> | --builtin] [--scenario ID ...] [--out report.json]
                  [--agent scripted|llm | --agent-module MOD:FACTORY [--agent-path DIR]]
                  [--trials N] [--max-steps N]
                  [--provider anthropic|openai-compatible]
                  [--model M] [--effort E] [--prompt-variants a,b]
                  [--cassettes DIR] [--record] [--max-cost-usd X]
                  [--base-url URL] [--allow-remote] [--seed S] [--temperature T]
                  [--max-tokens N] [--arg-coercion digit_strings|off]
                  [--checkpoint FILE] [--resume]
                  [--skip-conformance] [--conformance-trials N] [--min-benign-pass R]
    mulebench check-agent [<dir>] --agent-module MOD:FACTORY [--agent-path DIR]
                  [--scenario ID ...] [--trials N] [--min-benign-pass R]
    mulebench doctor --model TAG [--base-url URL] [--allow-remote]
    mulebench schema [--out report.schema.json]
    mulebench view REPORT.json [REPORT.json ...] --out DIR [--force]
    mulebench monitor run|adapt|schema ...   (see mulebench.monitor.cli)
    mulebench monitor eval REPORT.json [...] [--out eval.json] [--markdown eval.md] [--doc DOC.md]

Long runs write a per-trial checkpoint (JSON Lines): --checkpoint FILE, or by
default `<out>.checkpoint.jsonl` for --agent llm or --agent-module with --out. --resume skips the
trials already in it. Ctrl+C keeps the finished trials and writes a valid
partial report. The checkpoint is deleted once a run completes.

LLM runs replay recorded cassettes by default. `--record` makes live calls and
stores them. Anthropic: requires MB_LIVE=1, ANTHROPIC_API_KEY and
--max-cost-usd. openai-compatible (Ollama, local): requires MB_LIVE=1 only; the
base URL must be a loopback host unless --allow-remote. See docs/local-models.md.

Exit codes for `run`: 0 = completed and every attack trial exposed the payload;
1 = at least one attack trial was not_exposed (invalid scenario); 2 = usage,
load/validation error, unsupported invariant, missing cassette or invalid model
request; 3 = run aborted by the cost cap (partial report still written);
130 = interrupted with Ctrl+C (partial report still written); 4 = an
--agent-module agent failed the conformance check (no attack trial was run).

`check-agent` exits 0 when the agent is conformant and 1 when it is not.
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
from mulebench.attacks.schema import Scenario
from mulebench.harness import NO_PROMPT, UnsupportedInvariant, run_all
from mulebench.harness.conformance import DEFAULT_MIN_BENIGN_PASS
from mulebench.harness.conformance import DEFAULT_TRIALS as DEFAULT_CHECK_TRIALS
from mulebench.harness.models import Conformance, Generator, LLMConfig, PricingInfo
from mulebench.harness.presets import DEFAULT_PRESETS, UnknownPreset, preset_guard_names
from mulebench.reports import build_report, render_table, schema_to_json, write_report
from mulebench.tools.client import tool_schema_sha256

DEFAULT_LLM_TRIALS = 10
DEFAULT_EXTERNAL_TRIALS = 5
LOCAL_URL = "http://localhost:11434/v1"  # Ollama; same as http_transport.DEFAULT_BASE_URL
LOCAL_MAX_TOKENS = 2048  # output tokens also count toward a small local num_ctx
SERVER_META_FILE = "_server_meta.json"  # in the cassette directory


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
    which = run.add_mutually_exclusive_group()
    which.add_argument("--agent", choices=("scripted", "llm"), default=None)
    which.add_argument(
        "--agent-module",
        metavar="MODULE:FACTORY",
        help="your own agent: a zero-argument factory, e.g. my_pkg.agent:factory "
        "(see docs/bring-your-own-agent.md)",
    )
    run.add_argument(
        "--agent-path",
        type=Path,
        metavar="DIR",
        help="directory added to the import path for --agent-module, --reader-module "
        "and --payer-module",
    )
    run.add_argument(
        "--reader-module",
        metavar="MODULE:FACTORY",
        help="delegation scenarios: your own agent for the Reader role (default: the run's agent)",
    )
    run.add_argument(
        "--payer-module",
        metavar="MODULE:FACTORY",
        help="delegation scenarios: your own agent for the Payer role (default: the run's agent)",
    )
    run.add_argument(
        "--trials",
        type=int,
        help=f"trials per cell (scripted: 1, llm: {DEFAULT_LLM_TRIALS}, "
        f"--agent-module: {DEFAULT_EXTERNAL_TRIALS})",
    )
    run.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS, help="agent step cap")
    run.add_argument(
        "--scenario",
        action="append",
        dest="scenario_ids",
        metavar="ID",
        help="run only this scenario id (repeatable); default: all loaded scenarios",
    )
    run.add_argument(
        "--checkpoint",
        type=Path,
        help="per-trial checkpoint file (default for --agent llm with --out: "
        "<out>.checkpoint.jsonl)",
    )
    run.add_argument("--resume", action="store_true", help="skip trials already in the checkpoint")
    _add_expect_harness(run)
    run.add_argument(
        "--preset",
        action="append",
        dest="presets",
        metavar="NAME",
        help="guard preset to run (repeatable; default: vulnerable and hardened). Names: "
        "vulnerable, hardened, strict, none, all, only:<guard>, all-minus:<guard>",
    )
    run.add_argument(
        "--skip-conformance",
        action="store_true",
        help="with --agent-module: run attacks without the benign-control check "
        "(recorded in the report)",
    )
    run.add_argument(
        "--conformance-trials",
        type=int,
        default=DEFAULT_CHECK_TRIALS,
        metavar="N",
        help=f"with --agent-module: trials per benign control (default {DEFAULT_CHECK_TRIALS})",
    )
    run.add_argument(
        "--min-benign-pass",
        type=float,
        default=DEFAULT_MIN_BENIGN_PASS,
        metavar="RATE",
        help=f"conformance threshold, 0..1 (default {DEFAULT_MIN_BENIGN_PASS})",
    )

    check = sub.add_parser(
        "check-agent",
        help="run the benign controls with your agent and report whether it completes them",
    )
    check.add_argument("directory", nargs="?", type=Path, help="directory of scenario *.yaml files")
    check.add_argument(
        "--agent-module", required=True, metavar="MODULE:FACTORY", help="zero-argument factory"
    )
    check.add_argument("--agent-path", type=Path, metavar="DIR", help="added to the import path")
    check.add_argument(
        "--scenario", action="append", dest="scenario_ids", metavar="ID", help="repeatable"
    )
    check.add_argument(
        "--trials",
        type=int,
        default=DEFAULT_CHECK_TRIALS,
        help=f"trials per benign control (default {DEFAULT_CHECK_TRIALS}; a deterministic "
        "agent can use 1)",
    )
    check.add_argument(
        "--min-benign-pass",
        type=float,
        default=DEFAULT_MIN_BENIGN_PASS,
        metavar="RATE",
        help=f"pooled benign pass needed, 0..1 (default {DEFAULT_MIN_BENIGN_PASS})",
    )

    ablate = sub.add_parser(
        "ablate",
        help="guard ablation matrix with the scripted agent (packaged scenarios by default)",
    )
    ablate.add_argument(
        "directory", nargs="?", type=Path, help="directory of scenario *.yaml files"
    )
    ablate.add_argument("--out", type=Path, help="write the JSON ablation report here")
    _add_llm_args(run)

    wl = sub.add_parser(
        "workloads",
        help="run benign workloads N times per preset and prompt (scripted or llm agent)",
    )
    wl.add_argument(
        "--workload",
        action="append",
        dest="workload_ids",
        metavar="ID",
        help="run only this packaged workload (repeatable; default: all)",
    )
    wl.add_argument("--agent", choices=("scripted", "llm"), default="scripted")
    wl.add_argument("--trials", type=int, default=1, help="trials per cell (default 1)")
    wl.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS, help="agent step cap")
    wl.add_argument(
        "--preset",
        action="append",
        dest="presets",
        metavar="NAME",
        help="guard preset (repeatable; default: vulnerable and hardened)",
    )
    wl.add_argument("--out", type=Path, required=True, help="write the JSON report here")
    wl.add_argument(
        "--checkpoint", type=Path, help="per-trial checkpoint (default <out>.checkpoint.jsonl)"
    )
    wl.add_argument("--resume", action="store_true", help="skip trials in the checkpoint")
    _add_expect_harness(wl)
    _add_llm_args(wl)

    doctor = sub.add_parser(
        "doctor", help="check a local OpenAI-compatible server (Ollama) before a run"
    )
    doctor.add_argument("--model", required=True, help="model tag, e.g. qwen3:8b")
    _add_server_args(doctor)

    schema = sub.add_parser("schema", help="print the report JSON Schema")
    schema.add_argument("--out", type=Path, help="write the schema here instead")

    view = sub.add_parser(
        "view", help="write a static, offline HTML site from run and ablation reports"
    )
    view.add_argument("reports", nargs="+", type=Path, help="JSON reports (run or ablation)")
    view.add_argument("--out", type=Path, required=True, help="output directory")
    view.add_argument(
        "--force", action="store_true", help="write into a non-empty output directory"
    )

    from mulebench.monitor.cli import add_parser as add_monitor_parser

    msub = add_monitor_parser(sub)
    mon_eval = msub.add_parser(
        "eval", help="replay stored reports through the monitor and score it against attribution"
    )
    mon_eval.add_argument("reports", nargs="+", type=Path, help="mulebench JSON reports")
    mon_eval.add_argument("--out", type=Path, help="write the JSON result here (default stdout)")
    mon_eval.add_argument("--markdown", type=Path, help="also write markdown tables here")
    mon_eval.add_argument(
        "--doc", type=Path, help="replace the generated block of this markdown document"
    )
    return parser


def _add_llm_args(parser: argparse.ArgumentParser) -> None:
    llm = parser.add_argument_group("llm agent")
    llm.add_argument("--model", help="model id (required for --agent llm)")
    llm.add_argument("--effort", default="medium", help="output_config.effort (default medium)")
    llm.add_argument(
        "--prompt-variants",
        default="baseline,data_not_instructions",
        help="comma-separated prompt variants",
    )
    llm.add_argument(
        "--role-prompt",
        action="append",
        dest="role_prompts",
        metavar="ROLE=VARIANT",
        help="delegation role prompt variant (repeatable), e.g. reader=cites_tx; default: default",
    )
    llm.add_argument("--cassettes", type=Path, help="cassette directory (replay by default)")
    llm.add_argument("--record", action="store_true", help="make live calls and record them")
    llm.add_argument("--max-cost-usd", type=float, help="whole-run cost cap")
    llm.add_argument("--provider", choices=("anthropic", "openai-compatible"), default="anthropic")
    _add_server_args(llm)
    llm.add_argument(
        "--seed",
        type=int,
        help="openai-compatible: base seed (per-trial seed: base + sha256(trial_key))",
    )
    llm.add_argument(
        "--temperature", type=float, help="openai-compatible: sampling temperature (default 0)"
    )
    llm.add_argument(
        "--arg-coercion",
        choices=("digit_strings", "off"),
        default="digit_strings",
        help="coerce integers sent as digit-only strings (default); off: strict",
    )
    llm.add_argument(
        "--max-tokens",
        type=int,
        help=f"openai-compatible: output tokens per call (default {LOCAL_MAX_TOKENS})",
    )


def _view(reports: Sequence[Path], out: Path, force: bool) -> int:
    from mulebench.viewer.site import ViewerInputError, build_site, load_any, write_site

    try:
        inputs = [(p.stem, load_any(p)) for p in reports]
        files = build_site(inputs)
        write_site(files, out, force=force)
    except ViewerInputError as exc:
        return _error(str(exc))
    print(f"wrote {len(files)} pages to {out} (open {out / 'index.html'})")
    return 0


def _add_expect_harness(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--expect-harness",
        metavar="SHA",
        help="refuse to start unless src/ on disk equals src/ of this commit (git tree "
        "hash); for frozen pilots, see CONTRIBUTING.md",
    )


def _harness_tree(expect: str | None) -> str | int | None:
    """The src/ tree hash for the report; an exit code when --expect-harness fails."""
    from mulebench.harness.source_tree import HarnessMismatch, check_harness, src_tree

    if expect is None:
        return src_tree()
    try:
        return check_harness(expect)
    except HarnessMismatch as exc:
        return _error(f"--expect-harness: {exc}")


def _stamp(generator: Generator, tree: str | None) -> Generator:
    return generator.model_copy(update={"src_tree": tree})


def _add_server_args(group: argparse._ActionsContainer) -> None:
    group.add_argument("--base-url", help=f"openai-compatible base URL (default {LOCAL_URL})")
    group.add_argument(
        "--allow-remote", action="store_true", help="allow a base URL that is not loopback"
    )


def _doctor(args: argparse.Namespace) -> int:
    try:
        from mulebench.agents.llm.http_transport import RemoteHostRefused
        from mulebench.doctor import print_checks, run_doctor
    except ImportError:
        return _error("doctor needs the local extra: pip install mulebench[local]")
    try:
        checks = run_doctor(args.model, args.base_url or LOCAL_URL, allow_remote=args.allow_remote)
    except (RemoteHostRefused, ValueError) as exc:
        return _error(str(exc))
    return print_checks(checks)


def _error(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def _team(agent: Agent, reader: str | None, payer: str | None, path: Path | None) -> Agent | int:
    """The run's agent with external agents in the delegation roles given."""
    from mulebench.agents import DelegationTeam
    from mulebench.byoa import AgentLoadError, load_agent

    try:
        return DelegationTeam(
            agent if reader is None else load_agent(reader, path),
            agent if payer is None else load_agent(payer, path),
        )
    except AgentLoadError as exc:
        return _error(str(exc))


def _workloads(args: argparse.Namespace) -> int:
    """`mulebench workloads`: benign workloads, N trials per cell, resumable."""
    from mulebench.harness.workload_run import (
        WorkloadCheckpoint,
        fingerprint,
        run_workload_matrix,
        summary_lines,
    )
    from mulebench.workloads import load_workloads

    workloads = load_workloads()
    if args.workload_ids:
        known = {w.id for w in workloads}
        missing = [w for w in args.workload_ids if w not in known]
        if missing:
            return _error(f"unknown workload(s): {', '.join(missing)}")
        workloads = [w for w in workloads if w.id in args.workload_ids]
    presets: list[str] = args.presets or list(DEFAULT_PRESETS)
    try:
        for p in presets:
            preset_guard_names(p)
    except UnknownPreset as exc:
        return _error(str(exc))
    if args.trials < 1:
        return _error("--trials must be >= 1")
    tree = _harness_tree(args.expect_harness)
    if isinstance(tree, int):
        return tree
    llm_config: LLMConfig | None = None
    agent: Agent
    if args.agent == "scripted":
        agent, prompts = ScriptedAgent(max_steps=args.max_steps), [NO_PROMPT]
    else:
        built = _build_llm(args)
        if isinstance(built, int):
            return built
        agent, llm_config, _, prompts = built
    from mulebench.harness.runner import describe_agent

    config = {
        "agent": dict(getattr(agent, "params", {})),
        "llm": None if llm_config is None else llm_config.model_dump(mode="json"),
        "prompts": prompts,
        "presets": presets,
        "trials": args.trials,
    }
    path: Path = args.checkpoint or args.out.with_name(args.out.name + ".checkpoint.jsonl")
    try:
        checkpoint = WorkloadCheckpoint.open(
            path, fingerprint(config, workloads), resume=args.resume
        )
    except ValueError as exc:
        return _error(str(exc))
    try:
        report = run_workload_matrix(
            workloads,
            agent,
            describe_agent(agent, {}),
            prompt_variants=prompts,
            presets=presets,
            trials=args.trials,
            llm=llm_config,
            completed=checkpoint.completed,
            on_trial=checkpoint.write,
        )
    finally:
        checkpoint.close()
    report = report.model_copy(update={"generator": _stamp(report.generator, tree)})
    args.out.write_bytes(report.model_dump_json(indent=2).encode("utf-8") + b"\n")
    print("\n".join(summary_lines(report)))
    if report.run_status != "complete":
        print(f"aborted: {report.abort_reason}; resume with --resume", file=sys.stderr)
        return 130 if report.run_status == "aborted_interrupt" else 3
    checkpoint.path.unlink()
    return 0


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


def _load_scenarios(directory: Path | None, ids: Sequence[str] | None) -> list[Scenario] | int:
    if directory is not None and not directory.is_dir():
        return _error(f"not a directory: {directory}")
    try:
        scenarios = load_builtin() if directory is None else load_all(directory)
    except ScenarioError as exc:
        return _error(str(exc))
    if not scenarios:
        return _error(f"no scenarios found in {directory or '<builtin>'}")
    if ids:
        known = {s.id for s in scenarios}
        unknown = sorted(set(ids) - known)
        if unknown:
            return _error(f"unknown scenario id(s) {unknown}; known: {sorted(known)}")
        scenarios = [s for s in scenarios if s.id in set(ids)]
    return list(scenarios)


def _conformance(
    scenarios: Sequence[Scenario], agent: Agent, trials: int, min_benign_pass: float
) -> Conformance | int:
    from mulebench.harness.conformance import check_agent

    if trials < 1:
        return _error("conformance trials must be >= 1")
    if not 0.0 <= min_benign_pass <= 1.0:
        return _error("--min-benign-pass must be between 0 and 1")
    try:
        return check_agent(scenarios, agent, trials=trials, min_benign_pass=min_benign_pass)
    except UnsupportedInvariant as exc:
        return _error(str(exc))


def _check_agent(args: argparse.Namespace, scenarios: Sequence[Scenario]) -> int:
    from mulebench.byoa import AgentLoadError, load_agent
    from mulebench.harness.conformance import render_conformance

    try:
        agent = load_agent(args.agent_module, args.agent_path)
    except AgentLoadError as exc:
        return _error(str(exc))
    result = _conformance(scenarios, agent, args.trials, args.min_benign_pass)
    if isinstance(result, int):
        return result
    print(render_conformance(result))
    return 0 if result.status == "passed" else 1


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

    if args.command == "doctor":
        return _doctor(args)

    if args.command == "workloads":
        return _workloads(args)

    if args.command == "view":
        return _view(args.reports, args.out, args.force)

    if args.command == "monitor" and args.monitor_command == "eval":
        from mulebench.harness.monitor_eval import main as eval_main

        return eval_main(args.reports, args.out, args.markdown, args.doc)

    if args.command == "monitor":
        from mulebench.monitor.cli import main as monitor_main

        return monitor_main(args)

    loaded = _load_scenarios(args.directory, args.scenario_ids)
    if isinstance(loaded, int):
        return loaded
    scenarios = loaded

    if args.command == "check-agent":
        return _check_agent(args, scenarios)

    presets: list[str] = args.presets or list(DEFAULT_PRESETS)
    try:
        for p in presets:
            preset_guard_names(p)
    except UnknownPreset as exc:
        return _error(str(exc))
    tree = _harness_tree(args.expect_harness)
    if isinstance(tree, int):
        return tree

    conformance: Conformance | None = None
    llm_config: LLMConfig | None = None
    pricing: PricingInfo | None = None
    agent: Agent
    role_modules = args.reader_module is not None or args.payer_module is not None
    if args.agent_path is not None and args.agent_module is None and not role_modules:
        return _error("--agent-path needs --agent-module")
    if args.agent_module is not None:
        from mulebench.byoa import AgentLoadError, load_agent

        try:
            agent = load_agent(args.agent_module, args.agent_path)
        except AgentLoadError as exc:
            return _error(str(exc))
        prompts: list[str] = [NO_PROMPT]
        trials = args.trials or DEFAULT_EXTERNAL_TRIALS
        from mulebench.harness.conformance import render_conformance, skipped

        if args.skip_conformance:
            conformance = skipped(args.min_benign_pass)
            print(
                "warning: conformance check skipped; attack numbers may not be meaningful",
                file=sys.stderr,
            )
        else:
            checked = _conformance(scenarios, agent, args.conformance_trials, args.min_benign_pass)
            if isinstance(checked, int):
                return checked
            conformance = checked
            print(render_conformance(conformance), file=sys.stderr)
            if conformance.status != "passed":
                print(
                    "error: the agent does not complete the benign controls; no attack trials "
                    "were run (resistance is not meaningful without utility). Fix the "
                    "adapter, or pass --skip-conformance to run anyway.",
                    file=sys.stderr,
                )
                return 4
    elif args.agent in (None, "scripted"):
        prompts = [NO_PROMPT]
        trials = args.trials or 1
        agent = ScriptedAgent(max_steps=args.max_steps)
    else:
        built = _build_llm(args)
        if isinstance(built, int):
            return built
        agent, llm_config, pricing, prompts = built
        trials = args.trials or DEFAULT_LLM_TRIALS
    if role_modules:
        team = _team(agent, args.reader_module, args.payer_module, args.agent_path)
        if isinstance(team, int):
            return team
        agent = team

    from mulebench.agents.llm.model import ModelRequestInvalid
    from mulebench.agents.llm.transport import CassetteMissing
    from mulebench.harness.checkpoint import Checkpoint, CheckpointError, fingerprint

    checkpoint_path: Path | None = args.checkpoint
    long_run = args.agent == "llm" or args.agent_module is not None
    if checkpoint_path is None and long_run and args.out:
        checkpoint_path = args.out.with_name(args.out.name + ".checkpoint.jsonl")
    if args.resume and checkpoint_path is None:
        return _error(
            "--resume needs --checkpoint FILE (or --agent llm / --agent-module with --out)"
        )
    checkpoint: Checkpoint | None = None
    if checkpoint_path is not None:
        config = {
            "agent": dict(getattr(agent, "params", {})),
            "llm": None if llm_config is None else llm_config.model_dump(mode="json"),
            "prompts": prompts,
            "presets": presets,
            "trials": trials,
        }
        try:
            checkpoint = Checkpoint.open(
                checkpoint_path, fingerprint(config, scenarios), resume=args.resume
            )
        except CheckpointError as exc:
            return _error(str(exc))

    try:
        outcome = run_all(
            scenarios,
            agent,
            prompt_variants=prompts,
            trials=trials,
            presets=presets,
            completed=None if checkpoint is None else checkpoint.completed,
            on_trial=None if checkpoint is None else checkpoint.write,
        )
    except UnsupportedInvariant as exc:
        return _error(str(exc))
    except (CassetteMissing, ModelRequestInvalid) as exc:
        return _error(str(exc))
    finally:
        if checkpoint is not None:
            checkpoint.close()

    report = build_report(
        outcome,
        agent,
        prompt_variants=prompts,
        trials=trials,
        llm=llm_config,
        pricing=pricing,
        presets=presets,
        conformance=conformance,
    )
    report = report.model_copy(update={"generator": _stamp(report.generator, tree)})
    if args.out:
        write_report(report, args.out)
    print(render_table(report))
    if outcome.status != "complete":
        print(f"aborted: {outcome.abort_reason}", file=sys.stderr)
        if checkpoint is not None:
            print(f"resume with --resume (checkpoint: {checkpoint.path})", file=sys.stderr)
        return 130 if outcome.status == "aborted_interrupt" else 3
    if checkpoint is not None:
        checkpoint.path.unlink()
    return 1 if report.summary.totals.not_exposed else 0


def _build_llm(
    args: argparse.Namespace,
) -> tuple[Agent, LLMConfig, PricingInfo, list[str]] | int:
    if not args.model:
        return _error("--agent llm requires --model")
    if args.provider == "openai-compatible":
        return _build_local(args)
    local_only = {
        "--base-url": args.base_url,
        "--allow-remote": args.allow_remote or None,
        "--seed": args.seed,
        "--temperature": args.temperature,
        "--max-tokens": args.max_tokens,
    }
    used = [flag for flag, value in local_only.items() if value is not None]
    if used:
        return _error(f"{', '.join(used)} only apply to --provider openai-compatible")
    try:
        from mulebench.agents.llm import CostMeter, LLMAgent
        from mulebench.agents.llm.anthropic_model import AnthropicChatModel
        from mulebench.agents.llm.pricing import PRICING_AS_OF, price_for
        from mulebench.agents.llm.prompts import (
            PROMPTS,
            parse_role_prompts,
            prompt_sha256,
            role_prompt_hashes,
        )
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
    try:
        role_prompts = parse_role_prompts(args.role_prompts)
    except ValueError as exc:
        return _error(str(exc))
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
        arg_coercion=args.arg_coercion,
        role_prompts=role_prompts,
    )
    llm_config = LLMConfig(
        provider="anthropic",
        model=args.model,
        effort=args.effort,
        max_tokens=agent.max_tokens,
        refusal_fallbacks="off",
        prompt_sha256={p: prompt_sha256(p) for p in prompts},
        arg_coercion=args.arg_coercion,
        tool_schema_sha256=tool_schema_sha256(),
        role_prompts=role_prompts or None,
        role_prompt_sha256=role_prompt_hashes(prompts, role_prompts),
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


def _build_local(
    args: argparse.Namespace,
) -> tuple[Agent, LLMConfig, PricingInfo, list[str]] | int:
    try:
        from mulebench.agents.base import ServerMeta
        from mulebench.agents.llm import CostMeter, LLMAgent
        from mulebench.agents.llm.http_transport import (
            LocalServerClient,
            OpenAICompatTransport,
            RemoteHostRefused,
            ServerUnreachable,
            check_base_url,
        )
        from mulebench.agents.llm.openai_compat import PROVIDER, OpenAICompatChatModel
        from mulebench.agents.llm.prompts import (
            PROMPTS,
            parse_role_prompts,
            prompt_sha256,
            role_prompt_hashes,
        )
        from mulebench.agents.llm.seeds import SEED_DERIVATION
        from mulebench.agents.llm.transport import CassetteTransport, LiveCallsDisabled, Transport
    except ImportError:
        return _error(
            "--provider openai-compatible needs the local extra: pip install mulebench[local]"
        )

    prompts = [p.strip() for p in args.prompt_variants.split(",") if p.strip()]
    unknown = [p for p in prompts if p not in PROMPTS]
    if unknown or not prompts:
        return _error(f"unknown prompt variants {unknown}; known: {sorted(PROMPTS)}")
    try:
        role_prompts = parse_role_prompts(args.role_prompts)
    except ValueError as exc:
        return _error(str(exc))
    if args.cassettes is None:
        return _error("--agent llm needs --cassettes DIR (replay, or --record into it)")
    try:
        base_url = check_base_url(args.base_url or LOCAL_URL, allow_remote=args.allow_remote)
    except (RemoteHostRefused, ValueError) as exc:
        return _error(str(exc))
    meta_path: Path = args.cassettes / SERVER_META_FILE
    transport: Transport
    meta: ServerMeta | None
    if args.record:
        try:
            upstream = OpenAICompatTransport(base_url, allow_remote=args.allow_remote)
            client = LocalServerClient(base_url, allow_remote=args.allow_remote)
            meta = client.server_meta(args.model)
        except LiveCallsDisabled as exc:
            return _error(str(exc))
        except ServerUnreachable as exc:
            return _error(f"server not reachable ({exc}); try `mulebench doctor`")
        args.cassettes.mkdir(parents=True, exist_ok=True)
        meta_path.write_bytes(meta.model_dump_json(indent=2).encode("utf-8") + b"\n")
        transport = CassetteTransport(args.cassettes, "record", upstream)
    else:
        meta = (
            ServerMeta.model_validate_json(meta_path.read_text(encoding="utf-8"))
            if meta_path.exists()
            else None
        )
        transport = CassetteTransport(args.cassettes, "replay")

    temperature = 0.0 if args.temperature is None else args.temperature
    seed = 0 if args.seed is None else args.seed
    agent = LLMAgent(
        OpenAICompatChatModel(transport, meta),
        model=args.model,
        effort="none",
        max_tokens=args.max_tokens or LOCAL_MAX_TOKENS,
        max_steps=args.max_steps,
        meter=CostMeter(args.max_cost_usd),
        temperature=temperature,
        seed=seed,
        arg_coercion=args.arg_coercion,
        role_prompts=role_prompts,
    )
    llm_config = LLMConfig(
        provider=PROVIDER,
        model=args.model,
        effort="none",
        max_tokens=agent.max_tokens,
        refusal_fallbacks="off",
        prompt_sha256={p: prompt_sha256(p) for p in prompts},
        base_url=base_url,
        temperature=temperature,
        seed=seed,
        seed_derivation=SEED_DERIVATION,
        arg_coercion=args.arg_coercion,
        tool_schema_sha256=tool_schema_sha256(),
        role_prompts=role_prompts or None,
        role_prompt_sha256=role_prompt_hashes(prompts, role_prompts),
    )
    pricing = PricingInfo(as_of="n/a", note="local model: not priced", per_mtok={})
    return agent, llm_config, pricing, prompts


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
