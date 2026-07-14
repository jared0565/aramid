# aramid

A deterministic security & quality gate engine. Phase 1 of a larger red/blue-team
oversight platform for application development: git-hook enforcement that runs
industry-standard tools — gitleaks (secrets), semgrep (SAST), ruff/eslint (lint),
pip-audit (dependency CVEs), and the project's own test suite — at `pre-commit` and
`pre-push`. Findings are severity-tiered: **security blocks, quality warns.** Zero LLM
calls, zero tokens, fully offline-capable.

## Install

```bash
pip install -e .
```

This pulls in `ruff`, `semgrep`, and `pip-audit` as aramid's own dependencies. Secret
scanning additionally requires a `gitleaks` binary on `PATH` (see `aramid doctor`).

## Quickstart

```bash
aramid init <repo>       # onboard a repo: writes aramid.toml, installs git hooks, baselines
aramid doctor             # probe the toolchain (gitleaks/semgrep/ruff/eslint/pip-audit) and offer repair
aramid check --all        # run the full gate on demand (also: --staged, --range, --gate pre-push)
aramid status              # report ledger and config state
```

Once installed, `git commit` and `git push` trigger the gate automatically via the
installed hooks. Local hooks are convenience, not enforcement — `--no-verify` exists.
The authoritative backstop is re-running `aramid check --all --strict --json` in CI.

## Exit-code contract

| Code | Meaning |
|---|---|
| 0 | pass |
| 1 | blocking verdict — real findings, or (pre-push only) degraded BLOCK-tier tooling |
| 2 | pass-but-degraded — a WARN-tier tool was skipped or timed out |
| 3 | engine or config error |

`--strict` (CI mode) remaps 2 and 3 onto 1, so a run that "couldn't tell" fails the
build the same as a run that found something. The engine never exits 0 silently on
its own failure.

## Scope

Phase 1 covers the deterministic slice of OWASP: secrets, SAST, dependency CVEs, and
lint. It does **not** cover access control, security misconfiguration, or
authentication logic — that's adversarial, judgment-based review, out of scope for a
deterministic tool. This is Phase 1 of 4:

1. **Phase 1 (this):** deterministic blue-team gate engine.
2. **Phase 2:** LLM red-team gate — adversarial review at PR/pre-deploy time.
3. **Phase 3:** harness advisory layer — non-blocking, mid-development early warning.
4. **Phase 4:** metering & governance — token budgets, ledger-derived regression tests.

Full design spec and implementation plan: `docs/superpowers/specs/` and
`docs/superpowers/plans/`.

## Phase 2a: watcher chassis

Phase 2 starts with a zero-token chassis — the code has landed and is dogfooded
here, though it is not yet wired into this repo's own hooks or drain schedule.
Once installed, every commit is scored at zero cost by a post-commit hook
(security-surface paths, risky content, novelty, graphite blast radius). Commits
scoring >= 40 join a review queue drained on a schedule (`aramid drain`, Task
Scheduler task `aramid-drain`).
The regression attack pack (`.aramid-rules/regression.yml`, committed) replays
rules compiled from resolved findings — reintroducing a rotated secret or banned
dependency blocks at pre-push. `aramid status` shows queue depth and drain
history; `aramid pack list|add|compile` manages rules.

```bash
aramid triage HEAD                # score a commit (or range) and enqueue if risky
aramid drain --repo . --dry-run   # preview what a drain would consume
aramid schedule install           # register the Task Scheduler drain job (Windows)
aramid pack list                  # show compiled regression rules
```

Still deterministic, still zero LLM calls — 2a is the chassis (triage → queue →
drain) that Phase 2b (LLM adversarial review) and Phase 2c (mutation/fuzz/DAST)
will ride as new drain-time consumers.

### Phase 2b: the LLM reviewer

The `llm-review` drain-time consumer covers exactly the OWASP slice 2a's
deterministic tools can't: broken access control (A01), security
misconfiguration (A05), authentication failures (A07), and business-logic
flaws — adversarial, judgment-based review that a regex or an AST rule
cannot do. Every queued item's diff and touched files are assembled into a
redacted, byte-capped packet and sent down a provider chain
(`claude-cli` → `codex-cli` → `openrouter`, first available wins); every
finding must cite a verbatim evidence quote that is mechanically verified
against the packet and the file's HEAD content before it's trusted, and
every fresh CRITICAL gets one cross-provider refute call before it can be
marked `confirmed`. Findings land in the ledger as WARN — same bake
discipline as semgrep's: they surface at `pre-push` without blocking until
the operator explicitly ends the bake with `aramid arm --llm`, after which
`confirmed`-and-`critical` LLM findings BLOCK. A finding whose evidence quote
no longer appears in the file is auto-resolved before the block check runs,
so a fix is never held hostage by a stale finding.

Setup: install the `claude` and/or `codex` CLI on `PATH` (`aramid doctor`
reports what it sees, informationally — LLM tooling never gates BLOCK-tier
status). `openrouter` is the fallback provider; set `OPENROUTER_API_KEY` in
the environment and optionally cap spend via `aramid.toml`'s
`[llm].openrouter_monthly_cap_usd` (default `$5.00`/month, checked against a
local spend log before every call). All 2b knobs — provider order, per-model
overrides, timeouts, packet size cap, items-per-drain budget, and the
`llm_block_armed` bake flag itself — live under `[llm]` in `aramid.toml`.
