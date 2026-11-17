# Hosted models through OpenRouter

`--provider openrouter` runs the LLM agent against hosted models through
OpenRouter's OpenAI-compatible API. It uses the same adapter, agent,
cassettes and report as local models ([local-models.md](local-models.md)),
with four extra safeguards: a pinned host provider, a check that every
response came from the requested model and host, a local price table, and
a cost cap that is always required.

Nothing here runs without `MB_LIVE=1`. Tests are offline.

## Safeguards

**Remote host and key.** The base URL is fixed to
`https://openrouter.ai/api/v1`; `--base-url` is refused. A live run needs
`MB_LIVE=1`, `--allow-remote` and the key in `MB_OPENROUTER_API_KEY`. The
key is sent only in the `Authorization` header. Headers are never logged,
stored or put into error messages, and cassettes hold request and response
bodies only. `scripts/prepublish_check.py` flags OpenRouter key strings
(`secret:openrouter`).

**Pinned routing.** Every request carries

```json
"provider": {"order": ["<host>"], "allow_fallbacks": false,
             "require_parameters": true, "data_collection": "deny"}
```

and no `models` list, so OpenRouter can neither switch to another host nor
to another model, and only uses an endpoint that accepts every parameter
sent (tools, seed, temperature). The host is `--openrouter-host NAME`, the
`provider_name` that `doctor` lists.

One host can list several endpoints of the same model, with different
quantization, price, service tier and capabilities.
`--openrouter-quantization Q` (for example `fp8`) adds
`"quantizations": ["Q"]` to the block. Of the host's endpoints in that
quantization, only those that support tools, seed and temperature are
**eligible** (what `require_parameters` enforces), and any eligible
endpoint may serve a call. `doctor` lists how many are eligible, and fails
if any of them has a context below 8,192 tokens or a price above the
table's; it requires `--openrouter-quantization` only when the eligible
endpoints differ in quantization.

**No silent fallback.** Each response, live or replayed from a cassette,
must name the requested model (exactly, or its dated slug
`<id>-YYYYMMDD`) and the pinned host, and must not report a quantization
other than the pinned one. A response that reports no quantization is
accepted and recorded as `null`: the request pin is then the only guarantee
(`doctor` shows whether the probe responses report it). Anything else stops the whole run
with run status `aborted_routing` (exit code 3; the partial report is
written). An error body returned with HTTP 200 is a provider error of that
trial, as for other providers.

**Rate limits and outages.** HTTP 429 and 5xx answers (also an error body
with such a code sent with HTTP 200) are retried with the same request body
(same seed and messages): up to 6 attempts, waits of about 15, 30, 60, 120
and 240 s with equal jitter, each capped at 300 s, so about 10 minutes at
most; `Retry-After` is honoured when present (also capped). If the
attempts are exhausted, the trial is errored with error kind
`provider_rate_limited` (429) or `provider_unavailable` (5xx), never counted
as resisted, and the run continues. If more than 10% of an attack or benign
cell errored this way, the row is marked not meaningful
(`provider_rate_limited`). `doctor` retries its probes the same way before
failing. Other 4xx answers are not retried.

**What is recorded.** Every model call record keeps `requested_model`,
`served_model`, `served_provider`, `served_quantization` and
`provider_cost_usd`. The report's `routing` block counts the calls by
served provider and by served quantization (`"null"`: the response reported
none), sums `provider_cost_usd`, and counts `retries`, `calls_retried` and
`transient_errored_trials` by kind (each call record also keeps its own
`retries`, stored in the cassette when non-zero) (OpenRouter's
own `usage.cost`, as a cross-check only). The report's `llm` block keeps
`openrouter_host`, `openrouter_quantization` and `pricing_file_sha256`.

**Prices and the cost cap.** Prices come from a local, dated TOML file you
edit, `pricing/openrouter.toml` by default (`--pricing FILE`): USD per
million input and output tokens per (model, host). A host of `TBD` never
matches, so a run cannot start before its host is pinned and priced.
`--max-cost-usd` is required for every openrouter run; the cap is checked
before each model call with the table price. To make sure the cap never
underestimates, enter the highest price among the eligible endpoints;
`doctor` fails if the table price is below any of them. The report stores the
table's `as_of`, its sha256 and the price used.

## Before a run

1. List hosts, prices and quantization (no key needed, no inference):

   ```
   mulebench doctor --provider openrouter --model openai/gpt-oss-20b --allow-remote
   ```

2. Pick a host that supports tools, seed and temperature, and put its
   endpoint price into `pricing/openrouter.toml` (replace `TBD` with the
   host's `provider_name`).
3. Check the pinned host, the price entry and tool calling (two probe chat
   calls, about a cent's fraction):

   ```
   MB_LIVE=1 mulebench doctor --provider openrouter --model openai/gpt-oss-20b \
       --allow-remote --openrouter-host <host> --openrouter-quantization <q>
   ```

4. Estimate the cost (no network call). Tokens per trial come from the
   committed pilot 03, 06 and 07 reports (`--tokens-from` to change), with a
   safety factor of 2 by default:

   ```
   mulebench estimate --model openai/gpt-oss-20b --host openai/gpt-oss-20b=<host> \
       --scenario dispute-flow-foreign-read-009 --trials 30
   ```

## Run

```
MB_LIVE=1 mulebench run --builtin --scenario ... --agent llm --provider openrouter \
    --model openai/gpt-oss-20b --openrouter-host <host> --openrouter-quantization <q> \
    --allow-remote \
    --max-cost-usd 1.50 --cassettes runs/cassettes/<name> --record --out runs/<name>.json
```

Without `--record` the same command replays the cassettes offline (still
with the routing check, the price table and `--max-cost-usd`).

## Setting the key in PowerShell without echoing it

Windows PowerShell 5.1 has no `Read-Host -MaskInput` (PowerShell 7 does).
In 5.1, read a secure string and convert it for this process only:

```powershell
$sec = Read-Host -AsSecureString "OpenRouter key"
$env:MB_OPENROUTER_API_KEY = (New-Object PSCredential "key", $sec).GetNetworkCredential().Password
Remove-Variable sec
```

In PowerShell 7: `$env:MB_OPENROUTER_API_KEY = Read-Host -MaskInput "OpenRouter key"`.
Never pass the key on the command line (it lands in the shell history).
Remove it when done: `Remove-Item Env:MB_OPENROUTER_API_KEY`.

## Limits

- Hosted weights and quantization are the host's and may change without
  notice; `doctor` prints the quantization the endpoint lists at that time.
- Some hosts do not report the served quantization in their responses. Such
  calls are recorded with `served_quantization: null` and counted under
  `"null"` in the report's `routing` block; for them the quantization pin of
  the request is the only guarantee, not checked per call.
- Several eligible endpoints of one host (for example service tiers) may
  serve the calls of one run; responses do not say which.
- Seeds are passed, but hosts do not promise deterministic sampling.
- Prices in the table are what you entered; `provider_cost_usd` lets you
  compare them with what OpenRouter charged.
