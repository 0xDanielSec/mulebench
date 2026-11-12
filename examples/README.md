# Examples: bring your own agent

Two external agents that use the public API in `mulebench.byoa`. Neither one
adds a dependency. See [docs/bring-your-own-agent.md](../docs/bring-your-own-agent.md)
for the API and the trust model.

| File | What it shows |
| --- | --- |
| `minimal_agent.py` | A plain-Python agent with no model. It reads the session note, calls tools and returns a string. |
| `openai_compatible_agent.py` | A function-calling loop written by hand against any OpenAI-compatible `/chat/completions` endpoint, using only `urllib`. |

## Minimal agent

```sh
uv run mulebench check-agent --agent-module minimal_agent:factory --agent-path examples --trials 1
uv run mulebench run --agent-module minimal_agent:factory --agent-path examples --trials 1
```

This agent is deterministic, so `--trials 1` is enough. `check-agent` still
warns that 12 benign trials are too few for a reliable verdict. That warning
matters for model-backed agents.

## OpenAI-compatible loop

```sh
MODEL=llama3.1:8b uv run mulebench check-agent \
    --agent-module openai_compatible_agent:factory --agent-path examples
MODEL=llama3.1:8b uv run mulebench run \
    --agent-module openai_compatible_agent:factory --agent-path examples --trials 10
```

- `OPENAI_BASE_URL` defaults to `http://localhost:11434/v1` (a local Ollama).
- `OPENAI_API_KEY` is optional. It is sent only as a bearer token and is never
  printed, logged or stored in the report.
- If the host is not loopback, the factory prints a warning. In that case every
  scenario (synthetic customer data and injected payloads) leaves your machine,
  and the calls may cost money.
- Token usage is recorded when the server reports it. Cost is always
  unpriced. If the server reports no usage, the report shows the LLM metrics
  as "not recorded".
