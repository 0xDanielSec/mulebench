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

**No silent fallback.** Each response, live or replayed from a cassette,
must name the requested model (exactly, or its dated slug
`<id>-YYYYMMDD`) and the pinned host. Anything else stops the whole run
with run status `aborted_routing` (exit code 3; the partial report is
written). An error body returned with HTTP 200 is a provider error of that
trial, as for other providers.

**What is recorded.** Every model call record keeps `requested_model`,
`served_model`, `served_provider` and `provider_cost_usd` (OpenRouter's
own `usage.cost`, as a cross-check only). The report's `llm` block keeps
`openrouter_host` and `pricing_file_sha256`.

**Prices and the cost cap.** Prices come from a local, dated TOML file you
edit, `pricing/openrouter.toml` by default (`--pricing FILE`): USD per
million input and output tokens per (model, host). A host of `TBD` never
matches, so a run cannot start before its host is pinned and priced.
`--max-cost-usd` is required for every openrouter run; the cap is checked
before each model call with the table price. The report stores the
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
       --allow-remote --openrouter-host <host>
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
    --model openai/gpt-oss-20b --openrouter-host <host> --allow-remote \
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
- Seeds are passed, but hosts do not promise deterministic sampling.
- Prices in the table are what you entered; `provider_cost_usd` lets you
  compare them with what OpenRouter charged.
