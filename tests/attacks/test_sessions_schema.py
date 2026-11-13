"""Multi-session and memory fields of the scenario schema."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from mulebench.attacks import load_builtin, parse_scenario, scenario_sha256
from mulebench.attacks.loader import BUILTIN_SCENARIOS_DIR

PILOT_03 = Path(__file__).resolve().parents[2] / "docs/experiments/data/pilot-03-qwen3-14b-8k.json"
BASE = BUILTIN_SCENARIOS_DIR / "pix-description-injection-001.yaml"


def _base() -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(BASE.read_text(encoding="utf-8"))
    return data


def _parse(data: dict[str, Any]) -> Any:
    return parse_scenario(yaml.safe_dump(data, sort_keys=False))


def test_pilot_scenarios_keep_their_recorded_hash() -> None:
    recorded = {
        s["scenario_id"]: s["scenario_sha256"]
        for s in json.loads(PILOT_03.read_text(encoding="utf-8"))["scenarios"]
    }
    current = {s.id: scenario_sha256(s) for s in load_builtin() if s.id in recorded}
    assert len(recorded) == 12
    assert current == recorded


def test_single_session_scenario_normalizes_to_one_session() -> None:
    s = _parse(_base())
    sessions = s.sessions()
    assert [x.index for x in sessions] == [0]
    assert sessions[0].request == s.user_task.request
    assert sessions[0].gap_hours == 0
    assert not s.memory


def test_followup_sessions_are_ordered_after_user_task() -> None:
    data = _base()
    data["followup_sessions"] = [
        {"request": "second", "gap_hours": 24},
        {
            "request": "third",
            "gap_hours": 2,
            "authorizations": [
                {
                    "ref": "auth_later",
                    "from_account": "acc_alice",
                    "payee_pix_key": "x@example.test",
                    "max_amount_cents": 100,
                }
            ],
        },
    ]
    s = _parse(data)
    plan = s.sessions()
    assert [(p.index, p.request, p.gap_hours) for p in plan] == [
        (0, s.user_task.request, 0),
        (1, "second", 24),
        (2, "third", 2),
    ]
    assert [a.ref for a in plan[2].authorizations] == ["auth_later"]
    assert scenario_sha256(s) != scenario_sha256(_parse(_base()))


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        ({"followup_sessions": [{"request": "x", "gap_hours": 0}]}, "gap_hours"),
        ({"followup_sessions": [{"request": "x"}]}, "gap_hours"),
        (
            {
                "followup_sessions": [
                    {
                        "request": "x",
                        "gap_hours": 1,
                        "authorizations": [
                            {
                                "ref": "auth_rent",
                                "from_account": "acc_alice",
                                "payee_pix_key": "x@example.test",
                                "max_amount_cents": 1,
                            }
                        ],
                    }
                ]
            },
            "duplicate id: 'auth_rent'",
        ),
        (
            {
                "followup_sessions": [
                    {
                        "request": "x",
                        "gap_hours": 1,
                        "authorizations": [
                            {
                                "ref": "auth_x",
                                "from_account": "acc_nobody",
                                "payee_pix_key": "x@example.test",
                                "max_amount_cents": 1,
                            }
                        ],
                    }
                ]
            },
            "unknown account 'acc_nobody'",
        ),
        (
            {"followup_sessions": [{"request": "say MB-CANARY-7F3A", "gap_hours": 1}]},
            "canary must appear only in injection.payload",
        ),
    ],
)
def test_invalid_followup_sessions_are_rejected(patch: dict[str, Any], message: str) -> None:
    data = _base() | patch
    with pytest.raises(Exception, match=message):
        _parse(data)


def test_memory_tools_in_expected_outcome_need_memory_flag() -> None:
    data = _base()
    data["benign_control"]["expected_outcome"]["tool_calls"] = ["save_note"]
    with pytest.raises(Exception, match="needs memory: true"):
        _parse(data)
    data["memory"] = True
    assert _parse(data).memory is True
