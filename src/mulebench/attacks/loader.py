"""Strict YAML loader for attack scenarios."""

from __future__ import annotations

from collections.abc import Iterable
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from mulebench.attacks.schema import Scenario

BUILTIN_SCENARIOS_DIR = Path(__file__).parent / "scenarios"


class ScenarioError(Exception):
    """A scenario file failed to parse or validate."""

    def __init__(self, path: Path | str, errors: list[str]) -> None:
        super().__init__(f"{path}: " + "; ".join(errors))
        self.path = str(path)
        self.errors = errors


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys (plain YAML keeps the last)."""


def _construct_mapping(loader: _StrictLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark
            )
        seen.add(key)
    return loader.construct_mapping(node)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def parse_scenario(text: str, source: Path | str = "<string>") -> Scenario:
    try:
        data = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        raise ScenarioError(source, [f"YAML error: {exc}"]) from exc
    if not isinstance(data, dict):
        raise ScenarioError(source, ["top level must be a mapping"])
    try:
        return Scenario.model_validate(data)
    except ValidationError as exc:
        errors = [
            f"{'.'.join(str(p) for p in e['loc']) or '<root>'}: {e['msg']}" for e in exc.errors()
        ]
        raise ScenarioError(source, errors) from exc


def load_scenario(path: Path) -> Scenario:
    return parse_scenario(path.read_text(encoding="utf-8"), path)


def load_all(directory: Path = BUILTIN_SCENARIOS_DIR) -> list[Scenario]:
    """Load every `*.yaml` in `directory`, sorted by file name. Ids must be unique."""
    return _collect(
        (str(path), path.read_text(encoding="utf-8")) for path in sorted(directory.glob("*.yaml"))
    )


def load_builtin() -> list[Scenario]:
    """Load the scenarios packaged with mulebench, via importlib.resources.

    Works from a wheel or zip install, where the package has no real directory.
    """
    root = files("mulebench.attacks").joinpath("scenarios")
    entries = sorted(
        (e for e in root.iterdir() if e.is_file() and e.name.endswith(".yaml")),
        key=lambda e: e.name,
    )
    return _collect((f"<builtin>/{e.name}", e.read_text(encoding="utf-8")) for e in entries)


def _collect(sources: Iterable[tuple[str, str]]) -> list[Scenario]:
    scenarios: list[Scenario] = []
    seen: dict[str, str] = {}
    for source, text in sources:
        scenario = parse_scenario(text, source)
        if scenario.id in seen:
            raise ScenarioError(
                source, [f"duplicate scenario id {scenario.id!r} (also in {seen[scenario.id]})"]
            )
        seen[scenario.id] = source
        scenarios.append(scenario)
    return scenarios
