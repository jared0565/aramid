# aramid

A red/blue-team security & quality oversight engine for application development. The
foundation is a **deterministic gate**: git-hook enforcement that runs industry-standard
tools — gitleaks (secrets), semgrep (SAST), ruff/eslint (lint), pip-audit (dependency
CVEs), and the project's own test suite — at `pre-commit` and `pre-push`. Findings are
severity-tiered: **security blocks, quality warns.** The gate itself makes **zero LLM
calls and burns zero tokens** — fully offline-capable. Riding on top of it is a
token-economical **red team**: a scheduled, budgeted drain that spends LLM quota only on
the small, novel, high-risk slice of commits, never on every push (see the roadmap below).

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

## Scope & roadmap

The **deterministic gate** covers the mechanical slice of OWASP: secrets, SAST,
dependency CVEs, and lint. It deliberately does **not** try to reason about access
control, security misconfiguration, or authentication logic in a regex — that
adversarial, judgment-based slice is the red team's job (Phase 2b), run at drain time
under a budget rather than on every commit. Four phases:

1. **Phase 1 — done:** deterministic blue-team gate engine.
2. **Phase 2 — red team**, staged into three:
   - **2a — done:** zero-token watcher chassis — commit triage → risk-scored review
     queue → budgeted scheduled drain → pluggable consumers, plus the regression attack pack.
   - **2b — done:** the LLM reviewer — evidence-bound adversarial review over a provider
     chain, cross-provider refute, bake-then-arm blocking (detailed below).
   - **2c — next:** the heavy adversarial tier — mutation testing, fuzz/property harness,
     DAST — each a new drain consumer.
3. **Phase 3:** harness advisory layer — non-blocking, mid-development early warning.
4. **Phase 4:** metering & governance — token budgets, ledger-derived regression tests.

Full design specs and implementation plans: `docs/superpowers/specs/` and
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
(selected by risk tier — low to high: `ollama-cloud` → `codex-cli` → `claude-cli`, degrading to nearest available); every
finding must cite a verbatim evidence quote that is mechanically verified
against the packet and the file's HEAD content before it's trusted, and
every fresh CRITICAL gets one cross-provider refute call before it can be
marked `confirmed`. Findings land in the ledger as WARN — same bake
discipline as semgrep's: they surface at `pre-push` without blocking until
the operator explicitly ends the bake with `aramid arm --llm`, after which
`confirmed`-and-`critical` LLM findings BLOCK. A finding whose evidence quote
no longer appears in the file is auto-resolved before the block check runs,
so a fix is never held hostage by a stale finding.

The reviewer arm is selected deterministically by a risk-tiered ladder based
on the item's triage score: low-risk items (score 40–59) use ollama-cloud
(cheap tier), mid-risk (60–79) use codex-cli, and high-risk (80+) use
claude-cli (frontier tier). OpenRouter is available for opt-in use only —
not part of the default provider chain per the model-source policy; to enable
it, add `"openrouter"` to `[llm].provider_order` in `aramid.toml` and define an
`openrouter` arm in `[[llm.ladder]]` (with a model and min_score band).

Setup: install the `claude` and/or `codex` CLI on `PATH` (`aramid doctor`
reports what it sees, informationally — LLM tooling never gates BLOCK-tier
status). Set `OLLAMA_API_KEY` in the environment to enable ollama-cloud.
OpenRouter is opt-in: set `OPENROUTER_API_KEY` and optionally cap spend via
`aramid.toml`'s `[llm].openrouter_monthly_cap_usd` (default `$5.00`/month,
checked against a local spend log before every call). All 2b knobs — provider
order, per-model overrides, timeouts, packet size cap, items-per-drain budget,
and the `llm_block_armed` bake flag itself — live under `[llm]` in `aramid.toml`.
