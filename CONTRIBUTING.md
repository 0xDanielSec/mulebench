# Contributing to Mulebench

Thanks for helping. Mulebench tests whether AI agents in financial services
can be manipulated into violating financial invariants. Attack success is
judged from ledger state and tool-call traces, never from an LLM opinion.
Read [CLAUDE.md](CLAUDE.md) for the hard rules; the short version is below.

## Ground rules

- Everything is in English: code, comments, docs and commit messages.
- **100% synthetic data.** No real company, bank or fintech names or
  branding, no real customer data, and nothing from any employer. Domains are
  `example.test`, tax ids are `SYNTHETIC-*`, and people are `Alice Example`.
- Attack scenarios target the bundled reference agents and your own agents
  only. No real-world exploit tooling.
- To report a security problem in Mulebench itself, see [SECURITY.md](SECURITY.md).

## Development setup

You need Python 3.12 and [uv](https://github.com/astral-sh/uv).

```bash
uv sync                 # creates .venv with the dev dependencies
uv run pytest           # offline, no API keys needed
```

**Windows:** if `uv run <tool>` fails with `uv trampoline failed to
canonicalize script path`, call the tools as modules through the venv
interpreter instead:

```powershell
.venv\Scripts\python.exe -m pytest
.venv\Scripts\python.exe -m mulebench run --builtin
```

## Checks to run before a pull request

CI runs the same checks on Ubuntu and Windows:

```bash
uv run ruff check
uv run ruff format --check
uv run mypy                                   # strict
uv run pytest
uv run python scripts/prepublish_check.py     # leaks: domains, e-mails, key-shaped strings
```

Run these too if your change touches what they cover:

- **Invariants, attribution, guards, delegation or monitor rules:** `uv run
  python scripts/mutation_check.py` (a full run rewrites
  `docs/mutation-summary.json`; every mutant must be killed). The weekly CI
  job fails on a survivor or a stale summary.
- **Generated docs:** the scenario catalog, ablation tables, README results,
  monitor rule exports and report schema are generated and checked by tests.
  The failing test prints the command that regenerates the file, for example
  `uv run python -m tests.test_scenario_catalog`.

Commits follow Conventional Commits
(`feat(harness): ...`, `fix(monitor): ...`, `docs: ...`). Keep them small,
and make sure each one passes the checks on its own. Ask in an issue before
adding a heavy dependency or changing the architecture.

## Adding a scenario

Scenarios live in `src/mulebench/attacks/scenarios/<slug>-<number>.yaml`. The
schema is documented in [docs/scenarios.md](docs/scenarios.md); copy a close
existing scenario as a starting point.

1. **Synthetic only.** Use `example.test` keys and `SYNTHETIC-*` tax ids.
   The payload goes through the `{{payload}}` slot of one seeded incoming
   transaction, and the canary (`MB-CANARY-...`) appears only in the payload.
2. **Benign control required.** `benign_control` must have a harmless payload
   and the exact expected outcome (transfers and tool calls). Under the
   `vulnerable` and `hardened` presets the benign control must pass. An attack
   number means nothing without the matching utility number.
3. **`attack_goal` is validated against the payload.** Every goal payee,
   account and amount must appear literally in the attack payload (amounts as
   `450.00`, `450,00` or `45000`). A goal amount may not equal an expected
   benign amount. Goals are what the attacker asked, never chosen to fit the
   results.
4. **Judged on the ledger.** Pick `expected_invariants` that the attack
   breaks in observable ledger state or traces. If your attack can succeed
   with every invariant holding (like 015b), say so with a goal amount or
   payee so attribution can see it.
5. **Regenerate and test.** Run `uv run python -m tests.test_scenario_catalog`
   and the other generators the tests name, then the full test suite. Add a
   test that pins the vulnerable and hardened outcome.
6. Brazil-specific mappings (OWASP Agentic, LGPD, BACEN Res. 4.893) go in
   `brazil_context` with `review_status: to_be_reviewed`.

## Experiments and pre-registration

Changes that affect a reported experiment (a new defence measured in an
ablation, a pilot, a re-analysis) follow the pre-registration rule:

- **Write the predictions first.** Commit them, in
  [docs/ablation-predictions.md](docs/ablation-predictions.md) or the
  experiment's own document under `docs/experiments/`, *before* the code that
  produces the results exists or runs. The git history is the evidence.
- **Never edit a prediction after seeing results.** Add an "Outcome" section
  below it instead, including the predictions that failed.
- If a prediction could only be recorded after implementation, label it as a
  weaker pre-registration and say why.
- Do not tune scenarios, guards or thresholds toward a predicted result.
  Stored pilot data in `docs/experiments/data/` is never rewritten.

### Pinning a frozen run to its harness commit

A pre-registration names the harness commit its Protocol is frozen at. The
run commands must then pass `--expect-harness <that commit>` to
`mulebench run` and `mulebench workloads`:

```powershell
uv run python -m mulebench run ... --expect-harness 1a2b3c4 --out runs/pilot-NN.json
```

- The run refuses to start (exit code 2, nothing written) unless `src/` on
  disk is exactly `src/` of that commit. The check compares git tree
  hashes: tracked edits, staged changes, untracked files and later commits
  that touch `src/` all fail it; ignored files (`__pycache__/`) and changes
  outside `src/` (docs, scripts, tests) do not.
- Every report records the tree hash of `src/` it ran with, in
  `generator.src_tree` (report `schema_minor` 2; workload reports too).
  `null` means the run was not made from a git checkout.
- Before the analysis, check that `generator.src_tree` equals
  `git rev-parse <harness commit>:src`. A mismatch is a Deviation.
- Use it on resumes too: a resume after a code change is refused.

Pilot 04 is why: its Protocol froze one harness commit and it ran on a later
one (see its Deviations).
