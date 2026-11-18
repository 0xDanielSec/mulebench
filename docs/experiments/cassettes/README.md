# Pilot cassettes

`pilots-01-08.tar.xz` holds every recorded model call of pilots 01 to 08
(8,425 JSON files; 167.6 MB uncompressed; 3,944,652 bytes compressed). With it,
every pilot replays offline: no API key, no model server, no network.

sha256: `7bcad996b2f0805c943d116a6839c4f0a18b09b7c28609cf296417165c3b8482` (also in `pilots-01-08.tar.xz.sha256`).

`pilot-09.tar.xz` holds pilot 09 (720 JSON files, four runs; 157,972 bytes
compressed), sha256
`f8b749d7198e09cb2df148337705781c3edee2254d2d1119bbee882d59b9a668` (also in
`pilot-09.tar.xz.sha256`). It is a separate archive so that the frozen
`pilots-01-08` hash, cited by the pilot 08 document, never changes. Every
command below takes `--archive pilot-09` to act on it instead (default
`pilots-01-08`); verify with
`sha256sum -c pilot-09.tar.xz.sha256` or `Get-FileHash` as below.

`pilot-10.tar.xz` holds pilot 10 (540 JSON files, three phase-1 runs; 660,888
bytes compressed), sha256
`695bd26254390ba71afc83fdc37bd24a64708ece54bef9e5a802cca54faf9ab7` (also in
`pilot-10.tar.xz.sha256`). Use `--archive pilot-10` the same way.

Cassettes hold request and response bodies only, never HTTP headers or keys
(`src/mulebench/agents/llm/transport.py`). `scripts/prepublish_check.py`
scans every member of the archive, in the working tree and in every
committed version.

## Verify and extract

Bash:

```bash
unset MB_LIVE                                   # replay only: no live calls
uv sync --all-extras
(cd docs/experiments/cassettes && sha256sum -c pilots-01-08.tar.xz.sha256)
uv run python scripts/cassette_archive.py extract   # checks the sha256 again, then extracts
```

PowerShell:

```powershell
Remove-Item Env:MB_LIVE -ErrorAction SilentlyContinue   # replay only: no live calls
uv sync --all-extras
(Get-FileHash docs\experiments\cassettes\pilots-01-08.tar.xz -Algorithm SHA256).Hash.ToLower()
# must print 7bcad996b2f0805c943d116a6839c4f0a18b09b7c28609cf296417165c3b8482
uv run python scripts/cassette_archive.py extract   # checks the sha256 again, then extracts
```

`extract` treats the archive as untrusted. It checks the sha256 before
opening it; accepts only regular files named `pilot-<name>/<16 hex>.json` or
`pilot-<name>/_server_meta.json`; rejects absolute paths, `..`, links,
devices and directories; caps the archive size, file count, file size and
total uncompressed size; rejects the whole archive before writing anything
if any member fails; and extracts with tarfile's `data` filter into
`runs/cassettes/`. An existing file that differs is not overwritten unless
`--force` is given. `--only pilot-08-` extracts a single pilot.

## Exit codes of `mulebench run`

| Code | Meaning |
|---|---|
| 0 | Run complete; every attack trial was exposed to its payload |
| 1 | Run complete, but at least one attack trial was `not_exposed` (the agent never read the payload). The report is written and valid |
| 2 | Usage or setup error, nothing run: bad arguments, missing price, a cassette with no recorded response, `--expect-harness` mismatch |
| 3 | Run aborted (cost cap, routing check, ...); report and checkpoint written; continue with `--resume` |
| 4 | `--agent-module`: the agent failed the benign conformance check; no attack trials were run |
| 130 | Interrupted (Ctrl+C); report and checkpoint written; continue with `--resume` |

Errored trials and rows that are not meaningful do not change the exit code.
A successful full replay of pilot 08 returns 0 for qwen3-14b and gemma-4-26b,
and 1 for gpt-oss-20b (1 `not_exposed` trial, 009) and mistral-small-3.2 (3:
009 2, 012 1), exactly as their recorded runs.

## Calls that errored live

A call that failed in the transport (connection, timeout, rate limit, HTTP or
provider error, after retries) has no response to record. Since this commit,
recording writes such a call into the cassette as an `error` interaction, and
replay raises the same error, so the trial is errored again with the same
kind. The cassettes in this archive predate that; for them, pass the run's own
report with `--replay-errors-from REPORT`: on a cassette miss, if the report
says that trial errored with a transport error on that kind of call
(`memory_extraction:<kind>` for the memory extraction call, `<kind>` for any
other), replay raises that error. Every other miss still fails with "no
recorded response". Among the committed reports only pilot 08 qwen3-14b has
such trials (2).

## Rebuild

The archive is deterministic: entries sorted by name, USTAR format, mtime 0,
mode 0644, uid/gid 0, empty user and group names, xz preset 9. From a full
`runs/cassettes/`:

```
uv run python scripts/cassette_archive.py verify   # rebuild in memory, compare with the committed sha256
uv run python scripts/cassette_archive.py build    # rewrite the archive and its .sha256
```

## Replay

Replay commands omit `--expect-harness`: it pins the commit that recorded the run and would refuse the current one, while replay correctness is checked instead by matching the cassette request hashes and the committed reports.

Pilots 01 and 02 have frozen documents (their sha256 is checked by
`tests/test_reanalysis.py`), so their replay commands are here. Pilots 03 to
08 have them in the "Offline replay" section of their documents:
[03](../local-pilot-03.md#offline-replay), [04](../local-pilot-04.md#offline-replay),
[05](../local-pilot-05.md#offline-replay), [06](../local-pilot-06.md#offline-replay),
[07](../local-pilot-07.md#offline-replay), [08](../pilot-08-openrouter.md#offline-replay).
Pilots 02 to 08 replay at the current commit; pilot 01 needs its harness
commit `2fe1dc7`. Run "Verify and extract" above first.

### Pilot 01

Pilot 01 predates the per-trial seed scheme and replays only at its harness commit `2fe1dc7`. Run from a worktree next to the main checkout (here `../Mulebench`; adjust the path), in Bash or PowerShell (each command is one line):

```
git worktree add ../mulebench-2fe1dc7 2fe1dc7
cd ../mulebench-2fe1dc7
uv sync --all-extras
uv run python -m mulebench run --builtin --agent llm --provider openai-compatible --model qwen3-14b-8k --preset vulnerable --prompt-variants baseline,data_not_instructions --trials 10 --temperature 0.7 --max-tokens 2048 --arg-coercion digit_strings --cassettes ../Mulebench/runs/cassettes/pilot-01-qwen3-14b-8k --out ../replay-pilot-01-qwen3-14b-8k.json
uv run python -m mulebench run --builtin --agent llm --provider openai-compatible --model llama31-8b-8k --preset vulnerable --prompt-variants baseline,data_not_instructions --trials 10 --temperature 0.7 --max-tokens 2048 --arg-coercion digit_strings --cassettes ../Mulebench/runs/cassettes/pilot-01-llama31-8b-8k --out ../replay-pilot-01-llama31-8b-8k.json
```

Verified on 2026-11-17: a replay of the first trials of 004 for both models matched the committed reports trial by trial (status, tool calls, final answer, ledger).

### Pilot 02

At the current commit, in Bash or PowerShell (each command is one line). These are the frozen commands without `MB_LIVE`, `--record`, `--resume` and `--expect-harness` (which would refuse a newer commit); the cassettes still match because the request bodies did not change:

```
uv run python -m mulebench run --builtin --scenario pix-description-cross-customer-read-004 --scenario pix-description-foreign-history-008 --scenario dispute-flow-foreign-read-009 --scenario payee-name-cross-customer-read-010 --scenario pix-description-read-before-pay-011 --scenario pix-description-read-before-pay-key-swap-012 --agent llm --provider openai-compatible --model qwen3-14b-8k --preset vulnerable --prompt-variants baseline,data_not_instructions --trials 30 --temperature 0.7 --seed 1000 --max-tokens 2048 --arg-coercion digit_strings --cassettes runs/cassettes/pilot-02-qwen3-14b-8k --out runs/replay-pilot-02.json
```

Verified on 2026-11-17: a replay of the first trials of one scenario matched the committed report trial by trial (status, tool calls, final answer, ledger).
