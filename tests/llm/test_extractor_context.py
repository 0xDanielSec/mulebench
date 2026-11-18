"""--extractor-context: what the LLM memory extractor's system text holds.

Default `none` keeps the extraction request (system text, seed, cassette key) of
pilots 07 and 08; `agent_system_prompt` puts the agent's session system prompt
before EXTRACTION_PROMPT, changes nothing else, and records under its own
cassette key. Offline (recording transport, no network).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mulebench.agents.llm import CostMeter, LLMAgent
from mulebench.agents.llm.extractor import extraction_cassette_key, extraction_system
from mulebench.agents.llm.openrouter import OpenRouterChatModel
from mulebench.agents.llm.pricing import Price
from mulebench.agents.llm.pricing_file import fixed_pricer
from mulebench.agents.llm.prompts import PROMPTS
from mulebench.agents.llm.transport import TransportResponse, cassette_path, request_sha
from mulebench.agents.memory_extraction import EXTRACTION_PROMPT, ExtractorContext
from mulebench.attacks import load_builtin
from mulebench.harness import run_all

MODEL = "vendor/hosted-model"
HOST = "SyntheticHost"
SCENARIO = "memory-auto-persistent-exfiltration-014a"
PRICE = Price(input_per_mtok=1.0, output_per_mtok=1.0, cache_read_per_mtok=0.0)
KEY = f"{SCENARIO}/baseline/vulnerable/attack/t000"


class Recording:
    def __init__(self) -> None:
        self.requests: list[tuple[str, dict[str, Any]]] = []

    def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse:
        self.requests.append((trial_key, params))
        content = "- prefers short answers" if "#mem" in trial_key else "ok"
        body = {
            "id": "gen",
            "model": MODEL,
            "provider": HOST,
            "choices": [
                {"finish_reason": "stop", "message": {"role": "assistant", "content": content}}
            ],
            "usage": {"prompt_tokens": 100, "completion_tokens": 10},
        }
        return TransportResponse(body=body)

    def extraction(self) -> tuple[str, dict[str, Any]]:
        (only,) = [(k, p) for k, p in self.requests if k.startswith(f"{KEY}#mem")]
        return only

    def session0(self) -> dict[str, Any]:
        (only,) = [p for k, p in self.requests if k == KEY]
        return only


def agent(transport: Recording, context: ExtractorContext | None) -> LLMAgent:
    extra: dict[str, Any] = {} if context is None else {"extractor_context": context}
    return LLMAgent(
        OpenRouterChatModel(transport, HOST, "fp8"),
        model=MODEL,
        effort="none",
        meter=CostMeter(10.0),
        temperature=0.7,
        seed=7000,
        pricer=fixed_pricer(PRICE),
        **extra,
    )


def run(context: ExtractorContext | None) -> tuple[Recording, LLMAgent, Any]:
    scenario = next(s for s in load_builtin() if s.id == SCENARIO)
    transport = Recording()
    a = agent(transport, context)
    outcome = run_all(
        [scenario], a, prompt_variants=("baseline",), trials=1, presets=("vulnerable",)
    )
    return transport, a, outcome


def system_of(params: dict[str, Any]) -> str:
    (system,) = [m["content"] for m in params["messages"] if m["role"] == "system"]
    assert isinstance(system, str)
    return system


def test_default_is_none_and_unchanged() -> None:
    default, a, _ = run(None)
    explicit, _, _ = run("none")
    assert a.extractor_context == "none"
    assert "extractor_context" not in a.params  # params (and fingerprints) unchanged
    assert default.requests == explicit.requests
    key, params = default.extraction()
    assert key == f"{KEY}#mem0"
    assert system_of(params) == EXTRACTION_PROMPT


def test_agent_system_prompt_mode_prepends_the_session_system_prompt() -> None:
    control, _, _ = run("none")
    treated, a, _ = run("agent_system_prompt")
    assert a.params["extractor_context"] == "agent_system_prompt"
    _, c_params = control.extraction()
    key, t_params = treated.extraction()
    # The agent's system prompt is the session request's `system` text. On this
    # provider the trusted session note follows it in the same system message; the
    # note (account ids, authorizations, memory block) is session state, not the
    # system prompt, and is not given to the extractor.
    session_system = system_of(treated.session0())
    assert session_system.startswith(PROMPTS["baseline"] + "\n\n")
    assert system_of(t_params) == f"{PROMPTS['baseline']}\n\n{EXTRACTION_PROMPT}"
    # Nothing else changes: same model, sampling, seed, input and output cap.
    strip = {"messages"}
    assert {k: v for k, v in t_params.items() if k not in strip} == {
        k: v for k, v in c_params.items() if k not in strip
    }
    assert [m for m in t_params["messages"] if m["role"] != "system"] == [
        m for m in c_params["messages"] if m["role"] != "system"
    ]
    assert t_params["seed"] == c_params["seed"]
    # The session calls themselves are identical in the first session.
    assert treated.session0() == control.session0()
    assert key == f"{KEY}#mem0~ctx=agent_system_prompt"


def test_the_two_conditions_never_share_a_cassette() -> None:
    control, _, _ = run("none")
    treated, _, _ = run("agent_system_prompt")
    c_key, c_params = control.extraction()
    t_key, t_params = treated.extraction()
    assert cassette_path(Path("c"), c_key) != cassette_path(Path("c"), t_key)
    assert request_sha(c_params) != request_sha(t_params)


def test_extraction_helpers() -> None:
    assert extraction_system("none", None) == EXTRACTION_PROMPT
    assert extraction_cassette_key("k#mem0", "none") == "k#mem0"
    with pytest.raises(ValueError, match="prompt variant"):
        extraction_system("agent_system_prompt", None)


@pytest.mark.parametrize("context", ["none", "agent_system_prompt"])
def test_cli_records_extractor_context_in_the_report(context: str, tmp_path: Path) -> None:
    from mulebench.cli import _build_llm, _parser

    argv = [
        "run", "--builtin", "--scenario", SCENARIO,
        "--agent", "llm", "--provider", "openai-compatible", "--model", "m",
        "--prompt-variants", "baseline", "--preset", "vulnerable", "--trials", "1",
        "--cassettes", str(tmp_path / "c"),
    ]  # fmt: skip
    if context != "none":
        argv += ["--extractor-context", context]
    built = _build_llm(_parser().parse_args(argv))
    assert not isinstance(built, int)
    llm_agent, config, _, _ = built
    assert getattr(llm_agent, "extractor_context", None) == context
    assert config.model_dump(mode="json")["extractor_context"] == context


def test_cli_rejects_an_unknown_extractor_context(capsys: Any) -> None:
    from mulebench.cli import _parser

    with pytest.raises(SystemExit):
        _parser().parse_args(["run", "--builtin", "--extractor-context", "bogus"])
    assert "invalid choice" in capsys.readouterr().err
