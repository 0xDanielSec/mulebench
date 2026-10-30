# Honeyledger

Open-source framework that tests whether AI agents used in financial services
can be manipulated into violating financial invariants. Attack success is
judged by observable effects on a simulated ledger and tool-call traces, not by
an LLM opinion. All data is synthetic.

Status: work in progress (Week 1).

License: Apache-2.0.

## About the reference agent

The Week 1 demo runs a deterministic scripted agent that obeys instructions
found in tool output **by construction**. The demo validates the harness (the
ledger, guards, trace and invariants), not the vulnerability of any real model.
The same agent is run against `VULNERABLE` and hardened tool guards to show
before/after.
