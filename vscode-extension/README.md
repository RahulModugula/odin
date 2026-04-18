# Odin — VS Code Extension

[![GitHub](https://img.shields.io/badge/GitHub-RahulModugula%2Fodin-black)](https://github.com/RahulModugula/odin)

Fast AI code review inside your editor. Rules run instantly on save — no backend, no API key required. Full review (LLM + taint analysis) on demand.

## What you get

- **On save**: rules-only review → inline squiggles in ~100 ms (no LLM calls)
- **Cmd+Shift+P → "Odin: Full Review"**: full pipeline (security + quality + docs + taint analysis)
- **Hover**: see the finding description, the suggested fix, and — for security findings — the attack scenario
- **Clean-up**: "Odin: Clear All Diagnostics" removes squiggles if you want a neutral editor

## Languages supported

Python, JavaScript, TypeScript, Go, Rust, Java.

## Requirements

The extension shells out to the Odin CLI. Pick one:

```bash
# Zero-install, always latest:
uvx odin-review review --help

# Or pin a version:
pip install odin-review
```

If you run `odin` from a global install, set `odin.cliPath` to `"odin"`.

## Configuration

| Setting | Default | What it does |
|---|---|---|
| `odin.enable` | `true` | Master switch for all Odin checks in the workspace. |
| `odin.reviewOnSave` | `true` | Run a rules-only review on every save. No LLM calls. |
| `odin.cliPath` | `"uvx"` | The CLI to shell out to. `uvx` runs `uvx odin-review review`; `odin` runs a pinned global install. |
| `odin.extraArgs` | `[]` | Extra flags for every invocation, e.g. `["--min-severity", "high"]`. |
| `odin.minSeverity` | `"low"` | Hide findings below this severity from the Problems view. |
| `odin.apiUrl` | `""` | Point the "Full Review" command at a running Odin backend. Leave blank to run locally via `--local`. |

The extension picks up workspace `.odin.yml` automatically via the CLI — you don't need to duplicate config here.

## Development

```bash
cd vscode-extension
npm install
npm run compile
code --install-extension $(npm pack 2>/dev/null | tail -1)
```

Press `F5` inside this folder to launch an Extension Development Host.

## License

MIT — see the [repo root](https://github.com/RahulModugula/odin/blob/main/LICENSE).
