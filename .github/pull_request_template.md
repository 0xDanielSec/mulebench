## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `uv run ruff check` and `uv run ruff format --check` pass
- [ ] `uv run mypy` (strict) passes
- [ ] `uv run pytest` passes (offline, no API keys)
- [ ] `uv run python scripts/prepublish_check.py` is clean
- [ ] Generated docs regenerated where a test asked for it (catalog, ablation tables, monitor exports, report schema)
- [ ] Touches invariants, attribution, guards, delegation or monitor rules: `uv run python scripts/mutation_check.py` kills every mutant and `docs/mutation-summary.json` is updated
- [ ] New or changed scenario: synthetic data only, benign control passes, `attack_goal` validated against the payload
- [ ] Experiment change: predictions committed before the run (or labelled as a weaker pre-registration)
- [ ] Conventional Commits, each commit green on its own
