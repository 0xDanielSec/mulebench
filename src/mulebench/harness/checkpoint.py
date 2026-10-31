"""Per-trial checkpoint for long runs (JSON Lines).

Line 1 is a header with a fingerprint of everything that defines the run
(agent params, LLM config, prompts, presets, trials, scenarios). Every other
line is one finished TrialResult, flushed and fsynced as soon as it is written.
`--resume` reads the finished trials and skips their trial_keys; a fingerprint
mismatch refuses to resume. A torn last line (crash mid-write) is dropped.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import IO, Any, Self

from pydantic import ValidationError

from mulebench.attacks import Scenario
from mulebench.harness.models import TrialResult

KIND = "mulebench-checkpoint"
VERSION = 1


class CheckpointError(ValueError):
    pass


def fingerprint(config: Mapping[str, Any], scenarios: Sequence[Scenario]) -> str:
    data = {
        "config": config,
        "scenarios": [s.model_dump(mode="json") for s in sorted(scenarios, key=lambda s: s.id)],
    }
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class Checkpoint:
    def __init__(self, path: Path, handle: IO[bytes], completed: dict[str, TrialResult]) -> None:
        self.path = path
        self._handle = handle
        self.completed = completed

    @classmethod
    def open(cls, path: Path, fp: str, *, resume: bool) -> Self:
        """Start a new checkpoint, or resume one. Never overwrites existing work."""
        if not resume:
            if path.exists():
                raise CheckpointError(
                    f"checkpoint {path} exists; pass --resume to continue it or delete it"
                )
            new: IO[bytes] = path.open("xb")
            _write_line(new, {"kind": KIND, "version": VERSION, "fingerprint": fp})
            return cls(path, new, {})
        if not path.exists():
            raise CheckpointError(f"nothing to resume: {path} does not exist")
        completed, good_bytes = _read(path, fp)
        handle: IO[bytes] = path.open("r+b")
        handle.truncate(good_bytes)  # drop a torn last line
        handle.seek(good_bytes)
        return cls(path, handle, completed)

    def write(self, trial: TrialResult) -> None:
        # As the model serializes it: key order is kept, so a resumed report is
        # byte-identical to an uninterrupted one.
        _write_bytes(self._handle, trial.model_dump_json().encode("utf-8"))
        self.completed[trial.trial_key] = trial

    def close(self) -> None:
        self._handle.close()


def _write_line(handle: IO[bytes], data: object) -> None:
    _write_bytes(handle, json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8"))


def _write_bytes(handle: IO[bytes], line: bytes) -> None:
    handle.write(line + b"\n")
    handle.flush()
    os.fsync(handle.fileno())


def _read(path: Path, fp: str) -> tuple[dict[str, TrialResult], int]:
    # Only newline-terminated lines count; the last split element is "" or a torn tail.
    lines = path.read_bytes().split(b"\n")
    if len(lines) < 2:
        raise CheckpointError(f"{path}: not a mulebench checkpoint")
    try:
        header = json.loads(lines[0])
    except json.JSONDecodeError:
        raise CheckpointError(f"{path}: not a mulebench checkpoint") from None
    if not isinstance(header, dict) or header.get("kind") != KIND:
        raise CheckpointError(f"{path}: not a mulebench checkpoint")
    if header.get("version") != VERSION:
        raise CheckpointError(f"{path}: unsupported checkpoint version {header.get('version')!r}")
    if header.get("fingerprint") != fp:
        raise CheckpointError(
            f"{path} was written by a different run configuration (model, presets, prompts, "
            "trials, sampling or scenarios changed); refusing to resume"
        )
    completed: dict[str, TrialResult] = {}
    good = len(lines[0]) + 1
    for line in lines[1:-1]:
        try:
            trial = TrialResult.model_validate_json(line)
        except ValidationError:
            break  # torn or corrupt tail: everything after it is dropped
        completed[trial.trial_key] = trial
        good += len(line) + 1
    return completed, good
