"""Benign workloads as a run of their own: N trials per (workload, prompt,
preset), any agent (scripted, LLM, external), with checkpoint and resume.

The guard ablation runs every workload once with the scripted agent
(mulebench.harness.workloads). An LLM pilot needs more: repeated trials with
distinct seeds, prompt variants, cassettes and a resumable checkpoint. The
trial key `workload/<id>/<prompt>/<preset>/t<NNN>` seeds the LLM and keys
its cassettes, as for scenario trials.

Output: a `WorkloadRunReport` JSON (kind `workload-run`). Trials store no
model output text.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import IO, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, ValidationError

import mulebench
from mulebench.agents import Agent
from mulebench.agents.base import RunAborted
from mulebench.harness.models import AgentDescriptor, Generator, LLMConfig, RunStatus
from mulebench.harness.presets import preset_guard_names
from mulebench.harness.runner import abort_status
from mulebench.harness.workloads import WorkloadTrial, run_workload, workload_key
from mulebench.workloads import Workload

KIND = "mulebench-workload-checkpoint"


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class WorkloadRunAxes(_Model):
    workloads: list[str]
    prompt_variants: list[str]
    presets: list[str]
    trials_per_cell: int


class WorkloadRunReport(_Model):
    kind: Literal["workload-run"] = "workload-run"
    schema_version: Literal[1] = 1
    generator: Generator
    agent: AgentDescriptor
    llm: LLMConfig | None = None
    axes: WorkloadRunAxes
    run_status: RunStatus
    abort_reason: str | None = None
    trials: list[WorkloadTrial]


def fingerprint(config: Mapping[str, Any], workloads: Sequence[Workload]) -> str:
    data = {
        "config": config,
        "workloads": [w.model_dump(mode="json") for w in sorted(workloads, key=lambda w: w.id)],
    }
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class WorkloadCheckpoint:
    """JSON Lines: a header with the fingerprint, then one WorkloadTrial per
    line, fsynced. Same rules as the scenario checkpoint: never overwrites,
    refuses a different configuration, drops a torn last line."""

    def __init__(self, path: Path, handle: IO[bytes], done: dict[str, WorkloadTrial]) -> None:
        self.path = path
        self._handle = handle
        self.completed = done

    @classmethod
    def open(cls, path: Path, fp: str, *, resume: bool) -> Self:
        if not resume:
            if path.exists():
                raise ValueError(f"checkpoint {path} exists; pass --resume or delete it")
            handle: IO[bytes] = path.open("xb")
            _line(handle, json.dumps({"kind": KIND, "fingerprint": fp}).encode("utf-8"))
            return cls(path, handle, {})
        if not path.exists():
            raise ValueError(f"nothing to resume: {path} does not exist")
        lines = path.read_bytes().split(b"\n")
        try:
            header = json.loads(lines[0])
        except json.JSONDecodeError:
            raise ValueError(f"{path}: not a workload checkpoint") from None
        if not isinstance(header, dict) or header.get("kind") != KIND:
            raise ValueError(f"{path}: not a workload checkpoint")
        if header.get("fingerprint") != fp:
            raise ValueError(f"{path} was written by a different configuration; not resuming")
        done: dict[str, WorkloadTrial] = {}
        good = len(lines[0]) + 1
        for raw in lines[1:-1]:
            try:
                t = WorkloadTrial.model_validate_json(raw)
            except ValidationError:
                break
            done[t.trial_key] = t
            good += len(raw) + 1
        handle = path.open("r+b")
        handle.truncate(good)
        handle.seek(good)
        return cls(path, handle, done)

    def write(self, trial: WorkloadTrial) -> None:
        _line(self._handle, trial.model_dump_json().encode("utf-8"))
        self.completed[trial.trial_key] = trial

    def close(self) -> None:
        self._handle.close()


def _line(handle: IO[bytes], data: bytes) -> None:
    handle.write(data + b"\n")
    handle.flush()
    os.fsync(handle.fileno())


def run_workload_matrix(
    workloads: Sequence[Workload],
    agent: Agent,
    descriptor: AgentDescriptor,
    *,
    prompt_variants: Sequence[str],
    presets: Sequence[str],
    trials: int,
    llm: LLMConfig | None = None,
    completed: Mapping[str, WorkloadTrial] | None = None,
    on_trial: Callable[[WorkloadTrial], None] | None = None,
) -> WorkloadRunReport:
    """Every (workload, prompt, preset, trial) once, in a fixed order. A
    RunAborted (cost cap) or Ctrl+C stops the run; finished trials are kept."""
    if trials < 1:
        raise ValueError("trials must be >= 1")
    for p in presets:
        preset_guard_names(p)
    done = dict(completed or {})
    out: list[WorkloadTrial] = []
    status: RunStatus = "complete"
    reason: str | None = None
    ordered = sorted(workloads, key=lambda w: w.id)
    try:
        for w in ordered:
            for prompt in prompt_variants:
                for preset in presets:
                    for t in range(trials):
                        key = workload_key(w.id, preset, t, prompt)
                        if key in done:
                            out.append(done[key])
                            continue
                        result = run_workload(w, preset, agent, trial=t, prompt_variant=prompt)
                        if on_trial is not None:
                            on_trial(result)
                        out.append(result)
    except RunAborted as exc:
        status, reason = abort_status(exc), str(exc)
    except KeyboardInterrupt:
        status, reason = "aborted_interrupt", "interrupted (Ctrl+C)"
    return WorkloadRunReport(
        generator=Generator(name="mulebench", version=mulebench.__version__),
        agent=descriptor,
        llm=llm,
        axes=WorkloadRunAxes(
            workloads=[w.id for w in ordered],
            prompt_variants=list(prompt_variants),
            presets=list(presets),
            trials_per_cell=trials,
        ),
        run_status=status,
        abort_reason=reason,
        trials=out,
    )


def summary_lines(report: WorkloadRunReport) -> list[str]:
    """One line per (workload, prompt, preset): completed k/n, blocked, errored."""
    lines = []
    for w in report.axes.workloads:
        for prompt in report.axes.prompt_variants:
            for preset in report.axes.presets:
                ts = [
                    t
                    for t in report.trials
                    if (t.workload_id, t.prompt_variant, t.guard_set) == (w, prompt, preset)
                ]
                ok = [t for t in ts if not t.errored]
                done = sum(t.completed for t in ok)
                lines.append(
                    f"{w}  {prompt}  {preset}  completed {done}/{len(ok)}  "
                    f"errored {len(ts) - len(ok)}"
                )
    return lines
