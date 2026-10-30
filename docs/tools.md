# Tools

`honeyledger.tools` exposes four banking operations to agents:
`get_balance`, `list_transactions`, `transfer_pix` and `open_dispute`.

## Thin tools, composable guards

Each tool is a thin mapping onto one ledger call. Tools contain no policy.
Policy lives in **guards** installed on `ToolContext.guards`:

| Guard | Denies when |
|---|---|
| `AccountOwnership` | an account (or a disputed transfer) does not belong to the session customer |
| `RequireAuthorization` | `transfer_pix` has no authorization, or it is unknown, used, or does not match customer, source account, payee or amount |
| `HumanConfirmation(threshold, confirmer)` | `transfer_pix` amount >= threshold and the confirmer does not approve |

Presets: `VULNERABLE = ()` and `hardened(confirmer)`, which installs all three
in that order. The first deny stops the call.

## Calling tools

Agents call tools only through `call_tool(ctx, name, raw_args)`. It validates
the arguments against the tool's pydantic input model, runs the guards, runs the
tool, and records the call in the trace. It never raises for agent mistakes;
it returns a `ToolResult` with `outcome` set to one of `ok`, `unknown_tool`,
`invalid_input`, `denied` or `ledger_error`.

## Session identity and idempotency

`ToolContext.customer_id` is the authenticated customer of the session. The
agent cannot change it. The tools layer generates idempotency keys
(`<session_id>-<n>` by default); the agent cannot supply one, because input
models forbid extra fields. Session ids must be unique per ledger.

## Authorizations

No tool creates authorizations. The harness injects them through
`Ledger.add_authorization`, simulating the customer channel.

## Trace and untrusted fields

Every call is recorded in `ctx.trace`: tool name, arguments, outcome, result,
error, guard decisions, timestamp (from the ledger clock), and
`untrusted_paths`.

Output fields with third-party content carry `"x-untrusted": true` in their JSON
schema: `TransactionView.description`, `TransactionView.counterparty_name` and
`OpenDisputeOut.reason`. `untrusted_paths` lists where they occur in a concrete
result, for example `transactions[0].description`.

Input and output JSON schemas come from the pydantic models
(`ToolSpec.input_schema()`, `ToolSpec.output_schema()`), ready for a future MCP
wrapper.
