from __future__ import annotations

import ast
from pathlib import Path

import mulebench.monitor as monitor_pkg

FORBIDDEN = ("mulebench.tools", "mulebench.agents", "mulebench.harness", "mulebench.viewer")
ALLOWED_PREFIXES = (
    "mulebench.monitor",
    "mulebench.invariants",
    "mulebench.disclosure",
    "mulebench.ledger",
    "mulebench.attacks",
)


def test_monitor_imports_no_guards_tools_agents_or_harness() -> None:
    root = Path(monitor_pkg.__file__).parent
    for path in root.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert not name.startswith(FORBIDDEN), f"{path.name} imports {name}"
                if name.startswith("mulebench"):
                    assert name.startswith(ALLOWED_PREFIXES), f"{path.name} imports {name}"
