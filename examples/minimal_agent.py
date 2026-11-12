"""A minimal external agent in plain Python (no model, no dependencies).

Run it:
    mulebench check-agent --agent-module minimal_agent:factory --agent-path examples --trials 1
    mulebench run --agent-module minimal_agent:factory --agent-path examples --trials 1

If Windows Application Control blocks mulebench.exe, use `uv run python -m mulebench`.

It trusts only the session note and the customer's request, never tool output,
so the packaged attacks should fail against it. Real agents are not this simple:
use it to see the shape of the adapter, not as a baseline.
"""

from __future__ import annotations

import re
from typing import Any, cast

from mulebench.byoa import ExternalTask, Tools

_ACCOUNT = re.compile(r"^ACCOUNT id=(\S+)$", re.MULTILINE)
_AUTH = re.compile(r"^AUTHORIZATION id=(\S+) from=(\S+) payee=(\S+) max_cents=(\d+)$", re.M)
_AMOUNT = re.compile(r"R\$ ?(\d+)\.(\d{2})")


class MinimalAgent:
    name = "minimal-example"

    def run(self, task: ExternalTask, tools: Tools) -> str:
        account = _ACCOUNT.findall(task.session_note)[0]
        listed = tools.call("list_transactions", {"account_id": account})
        txs = cast(list[dict[str, Any]], (listed.data or {}).get("transactions", []))
        m = _AMOUNT.search(task.request)
        amount = int(m[1]) * 100 + int(m[2]) if m else None
        if "dispute" in task.request.lower():
            for tx in txs:
                if tx["direction"] == "out" and tx["amount_cents"] == amount:
                    tools.call("open_dispute", {"transfer_id": tx["id"], "reason": "Not received."})
                    return f"Dispute opened for transaction {tx['id']}."
            return "I could not find that payment."
        for auth_id, source, payee, max_cents in _AUTH.findall(task.session_note):
            last = next((t["amount_cents"] for t in txs if t["counterparty_key"] == payee), None)
            cents = amount if amount is not None else last
            if cents and cents <= int(max_cents):
                args = {"from_account_id": source, "to_pix_key": payee, "amount_cents": cents}
                tools.call("transfer_pix", {**args, "authorization_id": auth_id})
        return "Done."


def factory() -> MinimalAgent:
    return MinimalAgent()
