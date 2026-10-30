# ADR 0002: Cassettes for offline, reproducible LLM tests

Status: accepted

## Context

Tests must run offline with no API keys. Live model calls cost money, are not
deterministic, and the provider API accepts no sampling parameters, so
temperature cannot pin outputs.

## Decision

The LLM agent talks to a transport. Tests use a cassette transport that
replays recorded response bodies, keyed by trial and request. Replay is the
default. Recording is opt-in and requires `MB_LIVE=1`, an API key and
`--max-cost-usd`. Cassettes store bodies only: no headers, keys or thinking
text. The committed cassettes are synthetic, generated from the SDK's own
types by `tests/llm/synthetic.py`, and a drift test regenerates them.

## Consequences

- CI is offline, free and byte-for-byte reproducible.
- Synthetic cassettes test the harness and the agent loop, not real model
  behavior; a structural-match test compares them with a real smoke recording
  once one exists.
- Any change to scenarios, prompts or tool schemas requires regenerating the
  cassettes.
