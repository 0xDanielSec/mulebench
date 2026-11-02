# Report viewer

`mulebench view` turns run and ablation reports into a static site that works
offline: open `index.html` from disk or publish the directory on GitHub Pages.

```bash
uv run mulebench view report.json [ablation.json ...] --out site
```

The output directory must be empty or missing; `--force` writes into a
non-empty one. Each input becomes `r<k>/` (run) or `a<k>/` (ablation) under the
site, in the order given; `index.html` lists them.

## Pages

- **Overview** (`r<k>/index.html`): run metadata, totals, and a scenario x
  prompt x preset matrix. Each cell shows its headline rates as k/n with a
  Wilson 95% interval, the flags (`not meaningful` with reasons, `cut by cap`,
  `context near limit`, `errored`) and links to the attack and benign cells.
- **Cell** (`r<k>/cell/...html`): every rate of the cell, including
  attributed success, task error/omission and disclosure per sink (exact and
  approximate), then one row per trial with outcome badges. Badges always
  carry text, so color is never the only signal. The table can be filtered.
- **Trial** (`r<k>/trial/...html`):
  - model calls with **metadata only** (stop reason, tokens, whether
    reasoning was present). Model reasoning is never stored and never shown;
  - the final answer when the report stored it. Older reports show "Not
    stored";
  - a timeline of tool calls: arguments, guard decisions, untrusted fields in
    the result, the field where the payload (the scenario canary) entered,
    steps the agent took on instructions from tool output, and the violations
    pinned to the call or transfer where the invariant broke;
  - invariants, confirmations, attribution and disclosure per sink;
  - a ledger diff: balances before and after, and the transfers made.
- **Ablation** (`a<k>/index.html`): guard-set matrix, scenario flags,
  security vs usability, workloads, guard friction and cap sensitivity.

## Ledger diff for older reports

Reports written since the viewer release store `ledger_before` and
`ledger_after` (balance per account) in each trial. For older reports the diff
is **reconstructed**: the current scenario file seeds a fresh ledger ("before"),
and the stored agent transfers are applied to it ("after"). The page labels it
as reconstructed. It also shows a warning when the report records no scenario
hash (`scenario_sha256`, also new) or when the recorded hash differs from the
current scenario, because a changed scenario can make the reconstruction
wrong.

## Security

Report text is attacker-controlled: payloads travel through tool results,
arguments, error messages and final answers. The viewer treats all of it as
data:

- every page is rendered in Python by one builder
  (`mulebench.viewer.html.h`) that escapes every text node and attribute;
  event-handler and `style` attributes are rejected, and links must be relative
  slugs (no scheme, no leading slash);
- each page carries a Content-Security-Policy meta tag:
  `default-src 'none'`, plus the sha256 of the one inline stylesheet and the
  one inline script. No other script or style runs, there is no `eval`, and
  nothing is fetched from the network;
- the inline script only toggles the theme and filters the trial table, via
  `textContent`, attributes and `hidden`. It never writes HTML.

Tests render a report whose payload, final answer, error, scenario name and
limitations contain `<script>`, `onerror=` and `javascript:` markup, and check
that none of it survives unescaped.

## Accessibility and themes

The pages use semantic tables (captions, `scope`), breadcrumbs, a skip link,
visible focus rings and a full keyboard path. Light and dark themes follow
`prefers-color-scheme`, and a button switches between them. A test checks the
palette in both themes: 4.5:1 for text, 3:1 for focus rings and borders.

## Output

The output is deterministic: the same reports give byte-identical files, with
no timestamps. A test keeps the pilot 02 site within 1.5 times the size of its
JSON report, with no page above 300 KB.
