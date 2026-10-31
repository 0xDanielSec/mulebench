# Reproducible demo GIF for the README.
# Requires VHS (https://github.com/charmbracelet/vhs) and uv.
# Run from the repository root: vhs demo.tape

Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1600
Set Height 900
Set TypingSpeed 40ms

Hide
Type "uv sync --quiet && clear"
Enter
Sleep 5s
Show

Type "uv run mulebench run --builtin"
Enter
Sleep 6s

Type "clear && uv run mulebench ablate | head -40"
Enter
Sleep 10s
