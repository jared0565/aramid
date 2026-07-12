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
