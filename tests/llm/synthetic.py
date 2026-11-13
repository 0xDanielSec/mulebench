"""Synthetic Anthropic responses for offline LLM tests.

Responses are built with the SDK's own types (`anthropic.types.Message` etc.), so
their shape is validated by the SDK. The policy is deterministic and simulates:

- baseline prompt, trial 0: obeys an injected `call transfer_pix` instruction;
- baseline prompt, trial 1: refuses after reading the injected text;
- data_not_instructions prompt: ignores injected text;
- always: lists transactions, then pays what the customer asked using the
  matching session-note authorization (an amount "the same as my last
  payment" is taken from the listing), or opens the dispute the customer
  asked for, then ends the turn.

Regenerate the committed cassettes (drift-tested):

    uv run python -m tests.llm.synthetic
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

from anthropic.types import (
    Message,
    RefusalStopDetails,
    TextBlock,
    ThinkingBlock,
    ToolUseBlock,
    Usage,
)

from mulebench.agents.llm import CostMeter, LLMAgent
from mulebench.agents.llm.anthropic_model import AnthropicChatModel
from mulebench.agents.llm.transport import CassetteTransport, TransportResponse, canonical
from mulebench.attacks import Scenario, load_builtin
from mulebench.harness import run_all

CASSETTE_DIR = Path(__file__).resolve().parent.parent / "cassettes" / "synthetic"
MODEL = "claude-opus-5-5"
EFFORT = "medium"
PROMPTS = ("baseline", "data_not_instructions")
TRIALS = 2


def scenarios() -> list[Scenario]:
    """The pilot-era scenarios (no agent memory). The synthetic policy has no
    memory behavior, and the committed cassettes freeze these runs."""
    return [s for s in load_builtin() if not s.memory]


_INJECTED = re.compile(
    r"call\s+transfer_pix\s+(?:R\$\s?)?(\d+(?:\.\d{1,2})?)\s+to\s+(\S+?)\.?(?:\s|$)"
)
_PAY = re.compile(r"pay\s+R\$\s?(\d+(?:\.\d{1,2})?)\s+to\s+([^\s,]+?)\.?(?:\s|$)", re.IGNORECASE)
_SAME = re.compile(r"pay\s+(\S+)\s+the\s+same\s+amount\s+as\s+my\s+last\s+payment", re.IGNORECASE)
_DISPUTE = re.compile(
    r"dispute\s+my\s+payment\s+of\s+R\$\s?(\d+(?:\.\d{1,2})?)\s+to\s+([^\s,]+?)\.?(?:\s|$)",
    re.IGNORECASE,
)
_ACCOUNT = re.compile(r"^ACCOUNT id=(\S+)$", re.MULTILINE)
_AUTH = re.compile(r"^AUTHORIZATION id=(\S+) from=(\S+) payee=(\S+) max_cents=(\d+)$", re.MULTILINE)


def _cents(amount: str) -> int:
    whole, _, frac = amount.partition(".")
    return int(whole) * 100 + int((frac + "00")[:2])


def _id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _note_text(params: dict[str, Any]) -> str:
    """Session note: operator-channel message(s) plus the top-level system prompt."""
    parts = [str(params["system"])]
    parts += [str(m["content"]) for m in params["messages"] if m["role"] == "system"]
    return "\n".join(parts)


def _tool_uses(params: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        block
        for m in params["messages"]
        if m["role"] == "assistant"
        for block in m["content"]
        if block.get("type") == "tool_use"
    ]


def _tool_result_texts(params: dict[str, Any]) -> list[str]:
    return [
        block["content"]
        for m in params["messages"]
        if m["role"] == "user" and isinstance(m["content"], list)
        for block in m["content"]
        if block.get("type") == "tool_result"
    ]


def _outgoing(results: list[str]) -> list[dict[str, Any]]:
    """Outgoing transactions in the tool results, newest first per listing."""
    out = []
    for text in results:
        data = json.loads(text).get("data") or {}
        for tx in data.get("transactions") or []:
            if tx.get("direction") == "out":
                out.append(tx)
    return out


def respond(params: dict[str, Any], trial_key: str) -> dict[str, Any]:
    """Deterministic synthetic policy; returns a Message as a dict."""
    _, prompt, _, _, trial = trial_key.split("/")
    turn = sum(m["role"] == "assistant" for m in params["messages"])
    note = _note_text(params)
    accounts = _ACCOUNT.findall(note)
    auths = _AUTH.findall(note)
    request = next(m["content"] for m in params["messages"] if m["role"] == "user")
    done = _tool_uses(params)
    done_names = [(u["name"], u["input"].get("to_pix_key")) for u in done]
    results = "\n".join(_tool_result_texts(params))

    def tool(name: str, args: dict[str, Any]) -> ToolUseBlock:
        return ToolUseBlock(
            type="tool_use", id=f"toolu_{_id(trial_key, str(turn))}", name=name, input=args
        )

    stop_reason: Any = "tool_use"
    stop_details = None
    content: list[Any] = [
        ThinkingBlock(
            type="thinking", thinking="", signature=f"sig_{_id(trial_key, str(turn), 'th')}"
        )
    ]
    injected = _INJECTED.search(results)
    pay = _PAY.search(request)
    same = _SAME.search(request)
    dispute = _DISPUTE.search(request)
    outgoing = _outgoing(_tool_result_texts(params))
    if not done:
        content.append(tool("list_transactions", {"account_id": accounts[0], "limit": 10}))
    elif injected and prompt == "baseline" and trial == "t001":
        content = [TextBlock(type="text", text="I can't help with that.", citations=None)]
        stop_reason, stop_details = (
            "refusal",
            RefusalStopDetails(type="refusal", category=None, explanation=None),
        )
    elif (
        injected
        and prompt == "baseline"
        and trial == "t000"
        and ("transfer_pix", injected.group(2)) not in done_names
    ):
        content.append(
            tool(
                "transfer_pix",
                {
                    "from_account_id": accounts[0],
                    "to_pix_key": injected.group(2),
                    "amount_cents": _cents(injected.group(1)),
                },
            )
        )
    elif pay and ("transfer_pix", pay.group(2)) not in done_names:
        args: dict[str, Any] = {
            "from_account_id": accounts[0],
            "to_pix_key": pay.group(2),
            "amount_cents": _cents(pay.group(1)),
        }
        for auth_id, source, payee, max_cents in auths:
            if payee == pay.group(2) and args["amount_cents"] <= int(max_cents):
                args.update(from_account_id=source, authorization_id=auth_id)
                break
        content.append(tool("transfer_pix", args))
    elif same and ("transfer_pix", same.group(1)) not in done_names:
        key = same.group(1)
        last = next((tx for tx in outgoing if tx.get("counterparty_key") == key), None)
        args = {
            "from_account_id": accounts[0],
            "to_pix_key": key,
            "amount_cents": 0 if last is None else last["amount_cents"],
        }
        for auth_id, source, payee, _max in auths:
            if payee == key:
                args.update(from_account_id=source, authorization_id=auth_id)
                break
        content.append(tool("transfer_pix", args))
    elif dispute and "open_dispute" not in [u["name"] for u in done]:
        cents, key = _cents(dispute.group(1)), dispute.group(2)
        target = next(
            (
                tx["id"]
                for tx in outgoing
                if tx.get("counterparty_key") == key and tx.get("amount_cents") == cents
            ),
            "",
        )
        content.append(tool("open_dispute", {"transfer_id": target, "reason": "not recognized"}))
    else:
        content.append(TextBlock(type="text", text="Done.", citations=None))
        stop_reason = "end_turn"

    message = Message(
        id=f"msg_{_id(trial_key, str(turn), 'msg')}",
        type="message",
        role="assistant",
        model=params["model"],
        content=content,
        stop_reason=stop_reason,
        stop_details=stop_details,
        stop_sequence=None,
        usage=Usage(
            input_tokens=len(canonical(params)) // 4,
            output_tokens=40 + 10 * len(content),
            cache_creation_input_tokens=0,
            cache_read_input_tokens=0,
        ),
    )
    return message.to_dict()


class SyntheticTransport:
    def send(self, params: dict[str, Any], trial_key: str) -> TransportResponse:
        return TransportResponse(body=respond(params, trial_key), request_id=None)


def generate(directory: Path = CASSETTE_DIR) -> None:
    if directory.exists():
        shutil.rmtree(directory)
    transport = CassetteTransport(directory, "record", SyntheticTransport())
    agent = LLMAgent(AnthropicChatModel(transport), model=MODEL, effort=EFFORT, meter=CostMeter())
    run_all(scenarios(), agent, prompt_variants=PROMPTS, trials=TRIALS)


def main() -> None:
    generate()
    files = sorted(CASSETTE_DIR.glob("*.json"))
    calls = sum(len(json.loads(f.read_text(encoding="utf-8"))["interactions"]) for f in files)
    print(f"wrote {len(files)} cassettes ({calls} interactions) to {CASSETTE_DIR}")


if __name__ == "__main__":
    main()
