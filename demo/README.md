# README demo GIF

`demo.tape` records `docs/assets/demo.gif` with
[VHS](https://github.com/charmbracelet/vhs). The session is an **offline
replay** of recorded pilot 08 calls: it verifies the committed cassette
archive, extracts google/gemma-4-26b-a4b-it's cassettes, and replays scenario
`memory-auto-persistent-exfiltration-014a` (30 trials, the full pilot 08 cell)
with `MB_LIVE` unset. No API key is used and no model provider is called. The
replay reproduces the recorded result, 28/30 attributed successes.

## Regenerate on GitHub (recommended)

1. Open the repository's **Actions** tab, select the **Demo GIF** workflow,
   and click **Run workflow** (branch `main`).
2. When the run finishes, download the **demo-gif** artifact from the run's
   summary page and unzip it.
3. Copy `demo.gif` to `docs/assets/demo.gif`, review it, and commit it:

   ```bash
   cp ~/Downloads/demo-gif/demo.gif docs/assets/demo.gif
   git add docs/assets/demo.gif
   git commit -m "docs: regenerate README demo GIF"
   ```

The workflow only uploads the artifact; it never commits or pushes.

## Regenerate locally

With VHS, ttyd and ffmpeg installed (bash):

```bash
uv sync --locked
unset MB_LIVE
vhs demo/demo.tape   # writes docs/assets/demo.gif
```
