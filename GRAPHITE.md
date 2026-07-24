# Graphite Development Context

Graphite is the shared local code graph for this project. Codex, Claude Code, Gemini CLI, Antigravity, Visual Studio, and other coding agents should use the same graph instead of rebuilding separate mental maps.

All commands below use `python -m graphite`, which works in every shell and for every agent as long as the Python environment has Graphite installed. A bare `graphite` command is equivalent where the console script is on PATH.

## Required Workflow

Before non-trivial code changes:

1. Run `python -m graphite check .`
2. Run `python -m graphite context <target-file>` before editing important files.
3. Run `python -m graphite impact <target-file>` before changing shared logic, APIs, data flow, auth, persistence, deployment behavior, or other high-risk paths.
4. Use `python -m graphite query "stats"` when project structure is unclear.

After edits:

1. Run `python -m graphite build .` (skip if a Graphite daemon/watcher keeps this repo fresh; verify with `python -m graphite check .`)
2. Run relevant tests, typechecks, or validation commands.
3. Do not edit `graph-out/` manually.

## LLM Enrichment

Graphite in this repo is zero-LLM. Canonical graph commands (`scan`/`build`/`report`/`check`/`validate`) do not accept `--llm*` flags. LLM enrichment moved to the operator-governed `graphite overlay build`, which runs after the canonical graph is built and requires verified provider/model identity digests; it is not part of routine agent workflow.

## Operating Rules

- Treat Graphite as a project map, not as proof of correctness.
- Always read the source files and tests that Graphite identifies before changing behavior.
- If `python -m graphite check .` reports stale output, rebuild before relying on context or impact data.
- Graphite runs locally and should not use LLM or network calls unless explicitly configured.
- For TypeScript resolver issues, use `python -m graphite --typescript-resolver disabled build .` only as a fallback.
