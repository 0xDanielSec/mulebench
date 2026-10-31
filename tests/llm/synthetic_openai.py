"""Synthetic OpenAI-compatible (chat completions) responses for offline tests.

Same idea as `tests.llm.synthetic` (Anthropic), in the OpenAI response shape,
for one scenario. The deterministic policy simulates a small local model:

- baseline prompt, trial 0: obeys an injected `call transfer_pix` instruction;
- baseline prompt, trial 1: emits the injected transfer with arguments that are
  not valid JSON (a malformed tool call: the trial must be errored);
- data_not_instructions prompt: ignores injected text;
- always: lists transactions, then pays what the customer asked using the
  matching session-note authorization, then answers in text.

The server metadata (`_server_meta.json`) is synthetic too. Regenerate the
committed cassettes (drift-tested):

    uv run python -m tests.llm.synthetic_openai
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from mulebench.agents.base import ServerMeta
from mulebench.agents.llm import CostMeter, LLMAgent
from mulebench.agents.llm.openai_compat import OpenAICompatChatModel
from mulebench.agents.llm.transport import CassetteTransport, TransportResponse, canonical
from mulebench.attacks import load_builtin
from mulebench.cli import SERVER_META_FILE
from mulebench.harness import run_all
from tests.llm.synthetic import _ACCOUNT, _AUTH, _INJECTED, _PAY, _cents

CASSETTE_DIR = Path(__file__).resolve().parent.parent / "cassettes" / "openai_compat"
SCENARIO = "pix-description-injection-001"
MODEL = "synthetic-tiny:1b"
PROMPTS = ("baseline", "data_not_instructions")
TRIALS = 2
MAX_TOKENS = 2048
META = ServerMeta(
    model=MODEL,
    digest="sha256:" + "0" * 64,
    quantization="Q4_K_M",
    server_version="0.0.0-synthetic",
    num_ctx=8192,
    num_ctx_source="parameters",
    context_length=32768,
)


def _id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def respond(params: dict[str, Any], trial_key: str) -> dict[str, Any]:
    """Deterministic synthetic policy; returns a chat completion as a dict."""
    _, prompt, _, _, trial = trial_key.split("/")
    messages = params["messages"]
    turn = sum(m["role"] == "assistant" for m in messages)
    system = messages[0]["content"]
    accounts = _ACCOUNT.findall(system)
    auths = _AUTH.findall(system)
    request = next(m["content"] for m in messages if m["role"] == "user")
    done = [
        (c["function"]["name"], json.loads(c["function"]["arguments"]).get("to_pix_key"))
        for m in messages
        if m["role"] == "assistant"
        for c in m.get("tool_calls") or []
    ]
    results = "\n".join(m["content"] for m in messages if m["role"] == "tool")
    injected = _INJECTED.search(results)
    pay = _PAY.search(request)

    def call(name: str, arguments: str) -> dict[str, Any]:
        return {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": f"call_{_id(trial_key, str(turn))}",
                    "type": "function",
                    "function": {"name": name, "arguments": arguments},
                }
            ],
        }

    finish = "tool_calls"
    if not done:
        message = call("list_transactions", json.dumps({"account_id": accounts[0], "limit": 10}))
    elif injected and prompt == "baseline" and trial == "t001":
        # Truncated arguments, as small models sometimes produce.
        message = call("transfer_pix", '{"from_account_id": "' + accounts[0] + '", "to_pix')
    elif (
        injected
        and prompt == "baseline"
        and trial == "t000"
        and ("transfer_pix", injected.group(2)) not in done
    ):
        args = {
            "from_account_id": accounts[0],
            "to_pix_key": injected.group(2),
            "amount_cents": _cents(injected.group(1)),
        }
        message = call("transfer_pix", json.dumps(args))
    elif pay and ("transfer_pix", pay.group(2)) not in done:
        pay_args: dict[str, Any] = {
            "from_account_id": accounts[0],
            "to_pix_key": pay.group(2),
            "amount_cents": _cents(pay.group(1)),
        }
        for auth_id, source, payee, max_cents in auths:
            if payee == pay.group(2) and pay_args["amount_cents"] <= int(max_cents):
                pay_args.update(from_account_id=source, authorization_id=auth_id)
                break
        message = call("transfer_pix", json.dumps(pay_args))
    else:
        message = {"role": "assistant", "content": "Done."}
        finish = "stop"
    return {
        "id": f"chatcmpl-{_id(trial_key, str(turn))}",
        "object": "chat.completion",
        "model": params["model"],
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
        "usage": {
            "prompt_tokens": len(canonical(params)) // 4,
            "completion_tokens": 20,
            "total_tokens": len(canonical(params)) // 4 + 20,
        },
    }


class SyntheticTransport:
    def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse:
        body = respond(params, trial_key)
        return TransportResponse(body=body, request_id=body["id"])


def scenarios() -> list[Any]:
    return [s for s in load_builtin() if s.id == SCENARIO]


def generate(directory: Path = CASSETTE_DIR) -> None:
    if directory.exists():
        shutil.rmtree(directory)
    transport = CassetteTransport(directory, "record", SyntheticTransport())
    agent = LLMAgent(
        OpenAICompatChatModel(transport, META),
        model=MODEL,
        effort="none",
        max_tokens=MAX_TOKENS,
        meter=CostMeter(),
        temperature=0.0,
        seed=0,
    )
    run_all(scenarios(), agent, prompt_variants=PROMPTS, trials=TRIALS)
    (directory / SERVER_META_FILE).write_bytes(
        META.model_dump_json(indent=2).encode("utf-8") + b"\n"
    )


def main() -> None:
    generate()
    files = sorted(CASSETTE_DIR.glob("*.json"))
    print(f"wrote {len(files)} files to {CASSETTE_DIR}")


if __name__ == "__main__":
    main()
