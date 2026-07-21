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

## Optional LLM Enrichment

Graphite is zero-LLM by default. Use LLM enrichment only when a human explicitly wants AI-generated graph summaries in `graph-out/GRAPH_REPORT.md`.

Local examples:

```bash
python -m graphite --llm local --llm-provider ollama --llm-model qwen2.5-coder report .
python -m graphite --llm local --llm-provider lmstudio --llm-model local-model report .
```

Cloud or remote OpenAI-compatible example:

```bash
set GRAPHITE_LLM_API_KEY=<provider-key>
python -m graphite --llm cloud --llm-provider openai-compatible --llm-base-url https://example.com/v1 --llm-model my-model report .
```

Intelligent auto mode:

```bash
python -m graphite --llm auto --llm-provider openrouter report .
```

Auto mode keeps builds zero-LLM for small/simple graphs, skips cloud calls when credentials are missing, and uses LLM enrichment only when graph complexity/risk signals justify the extra cost. For OpenRouter, it defaults to `moonshotai/kimi-k2.7-code` when `--llm-model` is omitted.
OpenRouter examples:

```bash
set GRAPHITE_LLM_API_KEY=<openrouter-api-key>
python -m graphite --llm cloud --llm-provider openrouter report .
python -m graphite --llm cloud --llm-provider openrouter --llm-model "moonshotai/kimi-k2.7-code" report .
python -m graphite --llm cloud --llm-provider openrouter --llm-model "~openai/gpt-latest" report .
```

Graphite automatically uses OpenRouter's OpenAI-compatible base URL. To use a specific OpenRouter model, replace `--llm-model` with a model slug from the OpenRouter model catalog.
Rules:

- Prefer local LLMs for sensitive or private codebases.
- Do not put API keys in committed files or shell history; prefer `GRAPHITE_LLM_API_KEY`.
- Keep daemon/watch builds zero-LLM unless explicitly requested.
- LLM enrichment sends bounded graph metadata and analysis summaries, not raw source code, but still treat external providers as third-party data processors.

## Operating Rules

- Treat Graphite as a project map, not as proof of correctness.
- Always read the source files and tests that Graphite identifies before changing behavior.
- If `python -m graphite check .` reports stale output, rebuild before relying on context or impact data.
- Graphite runs locally and should not use LLM or network calls unless explicitly configured.
- For TypeScript resolver issues, use `python -m graphite --typescript-resolver disabled build .` only as a fallback.
