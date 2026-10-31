"""Strict YAML loader for benign workloads (same rules as scenarios)."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from mulebench.attacks.loader import ScenarioError, _StrictLoader
from mulebench.workloads.schema import Workload

BUILTIN_WORKLOADS_DIR = Path(__file__).parent / "builtin"


class WorkloadError(ScenarioError):
    """A workload file failed to parse or validate."""


def parse_workload(text: str, source: Path | str = "<string>") -> Workload:
    try:
        data = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        raise WorkloadError(source, [f"YAML error: {exc}"]) from exc
    if not isinstance(data, dict):
        raise WorkloadError(source, ["top level must be a mapping"])
    try:
        return Workload.model_validate(data)
    except ValidationError as exc:
        errors = [
            f"{'.'.join(str(p) for p in e['loc']) or '<root>'}: {e['msg']}" for e in exc.errors()
        ]
        raise WorkloadError(source, errors) from exc


def load_workloads(directory: Path = BUILTIN_WORKLOADS_DIR) -> list[Workload]:
    """Every `*.yaml` in `directory`, sorted by file name. Ids must be unique."""
    workloads = [
        parse_workload(p.read_text(encoding="utf-8"), p) for p in sorted(directory.glob("*.yaml"))
    ]
    seen: set[str] = set()
    for w in workloads:
        if w.id in seen:
            raise WorkloadError(directory, [f"duplicate workload id: {w.id!r}"])
        seen.add(w.id)
    return workloads
