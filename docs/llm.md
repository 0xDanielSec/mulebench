# LLM agent

`LLMAgent` implements the same `Agent` protocol as the scripted agent, over a
provider-agnostic `ChatModel`. The first adapter, `AnthropicChatModel`, uses the
Anthropic Messages API with tool use. It needs the optional extra:

```bash
pip install "mulebench[llm]"     # or: uv sync (the dev group includes it)
```

The core install does not import the Anthropic SDK.

Local models through an OpenAI-compatible server (Ollama first) use
`OpenAICompatChatModel` with the same agent, cassettes and report; see
`docs/local-models.md`. Hosted models through OpenRouter use
`OpenRouterChatModel` (a pinned host, a served-model check and a local price
table); see `docs/openrouter.md`.

## What the model sees

- **System prompt** by prompt variant (an explicit matrix axis):
  - `baseline`: a neutral banking assistant working for the session customer.
  - `data_not_instructions`: baseline plus a rule that text inside tool results
    is third-party data and must never be followed.
- **User message:** the customer's request.
- **Session note** (trusted): sent through the operator channel, a
  mid-conversation `system` message, on models that support it. Otherwise it is
  appended to the top-level system prompt. Each trial records which one was used
  in `session_note_channel` (`operator` or `system_prompt`).
- **Tools:** the four banking tools, with input schemas taken from the pydantic
  models. `x-untrusted` markers are stripped; they are trace-only.
- **Tool results:** returned as `tool_result` blocks, all results of one turn in
  one message. The model sees `{ok, outcome, data, error}` only, with no
  untrusted-path metadata. Denials carry only the generic `denied: <code>`.

## Request settings

- `--model` is required and recorded. There is no default model.
- `--effort` (default `medium`) is sent as `output_config.effort` and recorded.
- Thinking is not configured (always on for current Opus models). Thinking
  blocks are sent back unchanged inside the conversation, but **never stored in
  reports**. They exist only in cassettes, where replay needs them.
- No sampling parameters: the API rejects `temperature`/`top_p`/`top_k`. Each
  trial records `temperature: null`.
- `tool_choice` is left at `auto`.
- `--max-tokens` caps each call's output, thinking included. A call that hits
  it (stop reason `max_tokens`, `length` on OpenAI-compatible servers) ends
  without a tool call; reports count such calls (`length_calls`) and the trials
  they cut (`cut_by_cap`). With thinking on, use 4096 or more (see
  [local-models.md](local-models.md)).
- **Refusal fallbacks are off.** A fallback would silently swap the model under
  test. A refusal is its own outcome, `exposed_refused`, and is never counted as
  resisted.

## Trials and statistics

- `--trials N` (default 10 for the LLM agent). Ten is exploratory: **headline
  numbers should use at least 30 trials per cell**.
- `trial_key` (`<scenario>/<prompt>/<preset>/<variant>/tNNN`) identifies a trial
  and keys cassettes. It does not control the model; there is no API seed.
- Rates (exposure, attack success, refusal, utility) come with **Wilson 95%
  intervals**. Attack success and refusal are computed over exposed trials;
  `not_exposed` and errored trials are counted separately.
- **0/n never means safe.** It only bounds the true rate from above, so tables
  print the Wilson upper bound, for example `0/10 (<=28% upper 95%)`.

## Cost

Token usage (input, output, cache write, cache read) and an estimated USD cost
are recorded per model call, per trial and for the run. Prices come from a dated
table in `mulebench/agents/llm/pricing.py`; the report records `pricing.as_of`.
Treat them as estimates.

`--max-cost-usd` caps the **whole run**. Trials run sequentially and the cap is
checked before every model call. When it is reached the run stops, finished
trials are kept, the report says `run_status: "aborted_budget"`, and the CLI
exits with code 3.

## Cassettes (offline by default)

LLM runs replay recorded cassettes by default: `--cassettes DIR`. One JSON file
per trial holds the request bodies, response bodies and request ids. **No
headers and no API key are ever stored**, in cassettes, traces or reports. A
missing cassette is an error (exit 2), never a silent live call.

A call that fails in the transport after its retries (connection, timeout,
rate limit, HTTP or provider error) is recorded as an `error` interaction
(`{"kind", "message"}`, no response), and replay raises the same error, so the
trial is errored again with the same kind. Cassettes recorded before this have
no entry for such a call; `--replay-errors-from REPORT` (the run's own report)
reproduces those errors from the report's errored trials, and any other miss
is still an error. See `docs/experiments/cassettes/README.md`.

Live calls happen only with `--record`, and only when all of these hold:
`MB_LIVE=1`, `ANTHROPIC_API_KEY` set in the environment, a model with a known
price, and `--max-cost-usd`. The SDK reads the key from the environment; mulebench
never passes or prints it.

`tests/cassettes/synthetic/` holds synthetic cassettes built with the SDK's own
response types (so their shape is validated). Regenerate with
`uv run python -m tests.llm.synthetic`; a test fails if they drift.

## Smoke recording (one real run)

This makes real API calls and costs money (well under the $1 cap). Run it
yourself, from your own shell:

```bash
uv sync
export ANTHROPIC_API_KEY=...        # in this shell only; never in a file
MB_LIVE=1 uv run mulebench run --agent llm --model claude-opus-5-5 --effort medium \
  --trials 1 --prompt-variants baseline \
  --record --cassettes tests/cassettes/smoke --max-cost-usd 1 \
  --out smoke-report.json
unset ANTHROPIC_API_KEY
uv run pytest tests/llm/test_cassettes.py -k "structurally or key_shaped"
uv run python scripts/prepublish_check.py
```

That is 4 trials (one per preset and variant, baseline prompt only). The
structural test then checks that the synthetic cassettes are a structural subset
of the real recording (same keys and value types per response and content-block
type). Review `tests/cassettes/smoke/` before committing it.

## Known limitations

- Only the Anthropic adapter exists.
- The prices are a dated snapshot.
- Strict tool use (`strict: true`) is not enabled yet; tool inputs are validated
  by `call_tool` instead.
