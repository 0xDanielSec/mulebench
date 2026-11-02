"""Builtin scenarios, loaded once, for reconstruction and post-hoc attribution."""

from __future__ import annotations

from functools import cache

from mulebench.attacks import Scenario, load_builtin


@cache
def builtin_scenarios() -> dict[str, Scenario]:
    return {s.id: s for s in load_builtin()}
