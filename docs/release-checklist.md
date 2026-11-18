# Release checklist (before going public)

Status as of 2026-11-13. Nothing has been published or uploaded. Tick items
in the commit that resolves them.

## Done

- [x] `SECURITY.md` (private advisory reporting, scope, coordinated
  disclosure for vendor findings).
- [x] `CONTRIBUTING.md`, issue templates (bug, new scenario), PR template.
- [x] Weekly CI mutation check (fails on a survivor or a stale
  `docs/mutation-summary.json`); actions pinned by SHA, Dependabot bumps them.
- [x] Package metadata for 0.1.0 (`pyproject.toml`). `uv build` and
  `twine check` pass locally; the sdist no longer ships `.hypothesis/`.
- [x] Name check: `mulebench` is not registered on PyPI (the JSON API
  returned 404 on 2026-11-13; so did `mule-bench` and `mule_bench`). A 404
  does not guarantee PyPI will accept the name. Check again right before the
  upload:

  ```bash
  curl -s -o /dev/null -w "%{http_code}\n" https://pypi.org/pypi/mulebench/json   # 404 = free
  ```

## Decisions needed

- [ ] **Commit e-mail.** Every commit so far (175) is authored with a
  personal e-mail address. Pushing a public repository publishes it in
  every commit. Choose one:
  1. keep it as is;
  2. before the repository becomes public, rewrite the author e-mail of the
     whole history to the GitHub noreply address (`git filter-repo
     --mailmap`), then force-push. This rewrites every commit SHA, which
     breaks existing clones and SHA references in docs (pinned action SHAs
     are not affected). It cannot be undone once others have cloned.
  3. use the noreply address from now on only (old commits keep the
     personal address).

  Then set `git config user.email` to match, so `scripts/prepublish_check.py`
  (which allows only the configured author e-mail) stays meaningful.
- [ ] **Package authors.** `[project]` has no `authors`/`maintainers`. Add a
  name (and an e-mail only if you want it on PyPI), or leave it out.
- [ ] **What the sdist ships.** It currently includes tests, docs,
  `CLAUDE.md`, `demo/demo.tape`, `tools/` and `.github/`. Fine for reproducibility;
  exclude any of them in `[tool.hatch.build.targets.sdist]` if you prefer a
  smaller archive.

## Remaining work

- [ ] **Frontier-model run.** At least one pilot with a hosted frontier model
  (`--agent llm`), pre-registered in `docs/experiments/` before the run, with
  `--max-cost-usd` set. Include the delegation scenarios (015, 015b, 016) and
  the delegation benign workload. The current pilots use local models only.
- [ ] **Write-up.** A short public report: question, method (ledger-judged
  invariants, attribution, pre-registration), results (local pilots,
  frontier run, delegation finding: typed handoff fields stop injected
  instructions, not poisoned values), limitations (scripted agent, author-
  written scenarios), and regulatory mappings marked "to be reviewed".
- [ ] **Demo GIF.** Record `demo/demo.tape` (VHS) against the current version and
  add it to the README. Check that the run shown matches the current
  catalog.
- [ ] **README refresh.** The quickstart comment still says "12 scenarios";
  there are now 17 (14 single-agent, 3 delegation). Mention delegation, the
  monitor, `SECURITY.md` and `CONTRIBUTING.md`.
- [ ] **Final leak check.** `uv run python scripts/prepublish_check.py`
  (working tree and full history), with your private forbidden-terms list in
  `.prepublish-terms`. It must report `clean`.
- [ ] **Visibility.** Make the GitHub repository public. Then turn on private
  vulnerability reporting (Settings, Code security), which `SECURITY.md`
  relies on. Also check branch protection on `main` (required CI checks).
- [ ] **Release.** Tag `v0.1.0`, upload to PyPI (trusted publishing from a
  release workflow is preferable to an API token), and add the PyPI badge.
