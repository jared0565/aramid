# Aramid — Phase 1 Design: Deterministic Security & Quality Gate Engine

**Date:** 2026-07-12
**Status:** Approved (user-approved section by section; this document is the written record)
**Repo:** `F:\Projects\aramid`

---

## 1. Purpose and context

Aramid is the foundation of a red/blue-team oversight platform for all application
development under `F:\Projects`. The platform's goals: faster development, secure and
OWASP-compliant code, minimized hallucination in LLM-assisted work, robust production,
and token-economics awareness.

The platform ships in four phases, each useful alone:

1. **Phase 1 (this spec):** deterministic blue-team backbone — git-hook gates running
   industry-standard tools (secrets, SAST, lint, dependency audit, tests). Zero LLM,
   zero tokens.
2. **Phase 2:** LLM red-team gate — pluggable Provider (CLI adapters + API/OpenRouter),
   evidence-bound adversarial review at PR/pre-deploy, refute-panel verification.
3. **Phase 3:** harness advisory layer — Claude Code / Codex hooks for mid-development
   early warning (fail-open, non-blocking).
4. **Phase 4:** metering & governance — token dashboards, per-gate budgets, regression
   tests auto-generated from the findings ledger.

Phase 1 is 100% deterministic. Its findings model, ledger, and exit-code contract are
the shared currency Phases 2–4 build on. **Everything in this spec is Phase 1 scope
unless explicitly marked as a forward hook-point.**

### Decisions fixed during brainstorming

| Decision | Choice |
|---|---|
| Enforcement anchor | Layered: git hooks + CI backbone (blocking) now; harness hooks (advisory) in Phase 3 |
| LLM invocation (Phase 2+) | Pluggable Provider abstraction: subscription CLIs by default, API/OpenRouter for metering/cross-family review |
| Compliance target | OWASP security baseline only (ASVS / Top 10 orientation) |
| Blocking posture | Severity-tiered: security blocks, quality warns |
| Architecture | Custom engine (graphite pattern), not the `pre-commit` framework |
| Name | `aramid` (verified free on PyPI 2026-07-12; pairs with `graphite` — materials theme) |

### Non-goals for Phase 1

- No LLM calls of any kind.
- No UK-GDPR / PCI / house-style policy packs (deferred; config leaves room).
- No server-side enforcement (CI re-run is supported and documented, not built here
  beyond `--strict --json` being CI-ready).
- **Honesty note:** SAST + SCA + secret scanning covers roughly the injection, crypto,
  vulnerable-components, and secrets slices of OWASP. Access control (A01), security
  misconfiguration (A05), and authentication (A07) are largely NOT covered by
  deterministic tools; they are Phase 2 red-team territory. `ARAMID.md` states this so
  the gate is not mistaken for full coverage.

---

## 2. Architecture

Standalone Python CLI in its own git repo at `F:\Projects\aramid`, pip-installed
**editable into exactly one blessed interpreter** (unlike graphite's three), invoked as
`python -m aramid` from any repo. Same activation pattern as graphite: central engine,
per-repo onboarding via `init`, per-repo config and state.

### Six internal layers (each independently testable)

1. **detectors** — resolve true repo root (`git rev-parse --show-toplevel`); detect
   stack (Python / JS-TS), package manager (by lockfile: `package-lock.json` → npm,
   `pnpm-lock.yaml` → pnpm, `yarn.lock` → yarn), test setup (pytest / npm test),
   nested `.git` directories to exclude from scope.
2. **runners** — one adapter per external tool: build argv, invoke with timeout,
   capture structured output (JSON where the tool supports it), kill on timeout as a
   **process tree** (`CREATE_NEW_PROCESS_GROUP` + `taskkill /T /F` on Windows), never
   bare `Popen.kill()`.
3. **normalizer** — map every tool's output into the single `Finding` schema (§4).
4. **policy** — map raw severities to `block | warn | info` per gate (§3), apply
   overrides/suppressions, produce the run verdict.
5. **ledger** — SQLite event store at `.aramid/ledger.db` (§5).
6. **reporter** — human console summary + `--json` machine output; truthful exit codes.

### CLI surface (v1)

| Command | Behavior |
|---|---|
| `aramid init <path>` | Onboard a repo: resolve root, detect stack, run doctor, **refuse to arm hooks until BLOCK-tier tools pass doctor**, chain existing hooks, write `aramid.toml` stub + `ARAMID.md` + gitignore entries, full-history secret scan, validate the hook fires through git's real dispatch. Idempotent (contract in §7). |
| `aramid check [--gate pre-commit\|pre-push] [--staged\|--range\|--all] [--strict] [--json] [--accept-degraded --reason "…"]` | Run the pipeline. `--strict` treats degraded/error as failure (CI mode). |
| `aramid doctor` | Verify/repair toolchain and shim interpreter; install pinned gitleaks into the managed tools dir. |
| `aramid status` | Last run, open findings, NEW-since-baseline, aging ("12 medium findings open >30 days"), skip-visibility ("semgrep: skipped last N runs"), unrotated historical secrets. |
| `aramid ledger [list\|show\|filter\|mark-rotated <id>]` | Query findings; `mark-rotated` transitions a `historical` secret finding to `rotated` (writes a `finding_rotated` event, requires `--reason`). |
| `aramid override <id> --reason "…"` | Suppress a WARN finding (ledger-logged). BLOCK findings require the committed allowlist instead (§6). Re-running it re-affirms a stale override (§4). |
| `aramid arm` | End the per-repo WARN-only bake: sets `semgrep_block_armed = true` in `aramid.toml` (§8). Arming is always manual — no timer state. |
| `aramid update-rules` | Refresh the vendored semgrep ruleset explicitly. Never happens at commit time. |
| `aramid uninstall <path>` | Reverse exactly what init installed (hooks, ARAMID.md, gitignore entries); ledger kept by default. |
| `aramid init --discover <base>` | Marker-based walk (skips `node_modules`, `_tools`, `.venv`) listing initable repos 1–3 levels deep; inits repo-by-repo. |

---

## 3. Gates, tool matrix, failure policy

### Pre-commit gate — wall-clock budget 5s, staged content only, FAIL-OPEN

| Check | Tool | Verdict |
|---|---|---|
| Secrets in staged diff | gitleaks | **BLOCK** |
| Python lint + security (`S`/bandit rules) on changed `.py` | ruff | WARN; S-rules on the curated block-list **BLOCK** |

Only sub-second-startup tools live here. Tool crash/timeout → skip with a visible
notice; the commit proceeds. Speed wins locally.

### Pre-push gate — wall-clock budget 5min, commit RANGE, FAIL-CLOSED for BLOCK-tier

**Range resolution chain:** `@{u}..HEAD` if an upstream is set; else
`merge-base(origin/<default>, HEAD)..HEAD` (default branch from `origin/HEAD`); else
(no remote refs at all — first push of a new repo) scan every commit reachable from
`HEAD`. Never exit 3 merely because a branch is new.

| Check | Tool | Verdict |
|---|---|---|
| Secrets, per-commit across the range (catches add-then-remove) | gitleaks | **BLOCK** |
| SAST — curated OWASP set, vendored offline, `--metrics=off` | semgrep | **BLOCK** rules on the curated block-list; WARN rest |
| JS/TS lint | repo-local `node_modules/.bin/eslint` (`.cmd`-aware; skip+doctor-note if absent, never global fallback) | WARN |
| Types | `tsc --noEmit` (if tsconfig) / mypy (if configured) | WARN |
| Dependency CVEs | pip-audit `-r requirements*.txt` (or repo venv; skip+note if neither) / npm/pnpm/yarn audit by lockfile; results cached in `.aramid/` keyed by lockfile hash, 24h TTL | **BLOCK** critical; WARN below threshold |
| Tests | pytest (if tests present) / `npm test` (if script defined) | **BLOCK** on fail |
| No-new-warnings ratchet | ledger fingerprint set-difference | **BLOCK** new WARN-tier findings in the pushed range |

The ratchet makes WARN real: legacy findings collapse into a one-line baseline count;
new ones are shown first and block the push unless overridden.

**Block-list definition ("high-confidence"):** the BLOCK tier for ruff-S and semgrep is
a curated rule-ID list shipped in the built-in defaults as
`aramid/policy/block_rules.toml` — never read from per-finding tool metadata (ruff
emits no confidence field). Selection criteria: ruff S-rules whose bandit equivalents
are HIGH-confidence/HIGH-severity (e.g. exec/eval use, hardcoded credentials,
`shell=True` injection); semgrep rules with registry metadata `confidence: HIGH` +
`severity: ERROR` in the injection/deserialization/crypto classes. The initial list is
an implementation-owned artifact reviewed against those criteria; repos demote noisy
entries via `aramid.toml`.

**Dependency-severity source:** the critical/BLOCK split applies natively to the
npm-family audits (they report severity). For pip-audit, use OSV severity data where
the advisory carries it; advisories with **no severity data default to WARN** — they
never block. Stated so the Python path is decidable offline.

**Ratchet baseline:** the baseline fingerprint set is written as a `baseline_snapshot`
ledger event by `init`'s validation scan (or the first `check --all`). "New" = not in
baseline ∪ previously-seen fingerprints. **Fresh clone / empty ledger:** the first
pre-push run auto-baselines (records, warns, does not block) and says so — legacy
findings never block a first push on a new machine.

### Failure policy (tiered — the answer to "silent no-op" and "uninstall-to-bypass")

- **Pre-commit:** fail-open, always — including engine/config errors (shim mapping
  below makes this concrete).
- **Pre-push:** BLOCK-tier tool missing/crashed/timed-out → the engine **escalates the
  degradation itself to a blocking verdict** (exit 1, reason "gitleaks did not run"),
  with doctor hint. WARN-tier tool degradation (eslint absent, mypy timeout) → exit 2,
  push proceeds.
- **Escape hatch transport** (git passes no flags to hooks): set an environment
  variable — `ARAMID_ACCEPT_DEGRADED="<reason>" git push`. Hooks inherit the
  environment; the shim forwards it untouched; the engine honors it only at pre-push,
  only for infrastructure degradation (never for real findings), and writes the
  auditable `infrastructure_bypass` event with the reason. The `--accept-degraded
  --reason "…"` flag is the equivalent for direct CLI/CI invocations.
- **Owned toolchain:** ruff, semgrep, pip-audit are pip dependencies *of aramid itself*
  (all ship Windows wheels — deterministic install into the blessed interpreter).
  `doctor` installs a pinned gitleaks release binary into a managed tools dir.
  `init` refuses to arm hooks until doctor passes for BLOCK-tier tools.
- **Timeouts:** per-gate wall-clock ceiling enforced across the pipeline; independent
  tools run concurrently (budget is max(), not sum()); timeout kills the whole process
  tree.
- Tool skips are loudly visible in `status`, not throttled to once per day.

### Exit-code contract (engine is CI-ready, not hook-only)

| Code | Meaning |
|---|---|
| 0 | pass |
| 1 | blocking verdict — real findings **or** (pre-push only) degraded BLOCK-tier tooling |
| 2 | pass-but-degraded — WARN-tier tools skipped/timed out |
| 3 | engine or config error |

The engine always reports truthfully; the tiered failure policy is expressed *inside*
the engine (degraded BLOCK-tier at pre-push ⇒ exit 1, so exit 2 always means "safe to
proceed, something advisory was skipped").

**Shim mappings (exhaustive):**
- pre-commit shim: `{2,3} → 0` — fail-open, always, including engine errors.
- pre-push shim: `2 → 0`; `1` and `3` pass through and block (an engine that can't run
  didn't run gitleaks — fail-closed).

`--strict` (CI mode) treats 2 and 3 as failure. If the engine crashes and cannot even
write its ledger event, it exits 3 — never a silent 0.

Local hooks are convenience, not enforcement (`--no-verify` exists). The authoritative
backstop for repos with remotes is re-running `aramid check --all --strict --json` in
CI. `ARAMID.md` states this plainly.

---

## 4. Finding schema and fingerprint

### Finding

```
id            stable fingerprint (below)
tool, rule    e.g. "gitleaks"/"aws-access-key-id", "semgrep"/"sqli-format-string"
severity_raw  tool's own severity, preserved
severity      aramid verdict: block | warn | info
file, line    location; line is DISPLAY-ONLY, never part of id
message       human explanation
evidence      redacted excerpt (§6)
gate, run_id  provenance
source        "deterministic" (Phase 2 adds "llm")
status        open | fixed | overridden | historical | rotated  (materialized from ledger events)
```

### Fingerprint (the most load-bearing algorithm in the platform)

```
id = sha256( tool
           + rule
           + normalized_repo_relative_path      (forward slashes, case-normalized)
           + sha256(whitespace_normalized_flagged_line_content)
           + occurrence_index_among_identical_matches_in_that_file )
```

- **Line number excluded** → findings survive vertical drift; overrides stay attached.
- **Line content read from the git object being scanned, never the raw working-tree
  file** → `core.autocrlf` cannot churn ids. Per mode: **pre-commit** reads the index
  blob (`git show :path`); **pre-push** reads the commit blob (`git show <sha>:path`,
  newest commit in the range containing the finding); **`--all`** reads the HEAD blob,
  falling back to the LF-normalized worktree file only for untracked files.
- **Occurrence index** → identical violations on identical lines are distinct findings.
- **Stale-override rule:** an override whose fingerprint no longer matches but has a
  near-miss (same tool+rule+path, changed line content) is **not honored** — the
  finding re-fires at its normal tier (hooks are non-interactive; "never silently
  honored" wins). The report flags it: *"stale override — re-affirm with `aramid
  override <id> --reason` (WARN) or update `.aramid-suppressions.toml` (BLOCK)"*.
- Pinned by fixture tests: shift-a-violation-50-lines → same id; edit-the-violating-line
  → stale-override re-fire; CRLF flip → same id; two identical lines → two ids;
  **same violation scanned via pre-commit, pre-push, and `--all` → same id**.

---

## 5. Ledger

SQLite at `.aramid/ledger.db`, **gitignored**, event-sourced:

- Events: `run_started`, `run_finished`, `finding_detected` (carries
  `historical: true` when produced by init's full-history scan), `finding_resolved`,
  `finding_overridden`, `finding_rotated`, `infrastructure_bypass`,
  `baseline_snapshot`. Each carries `run_id` and the run's **scan scope** (files ×
  tools actually evaluated).
- Current finding state is a materialized view over events.
- **Scope-aware resolution:** `open → fixed` only when a run whose scope covered that
  finding's file with that finding's tool no longer reports it. A scoped pre-commit run
  can never "fix" findings in files it didn't scan.
- SQLite over JSONL: atomic writes on Windows, safe concurrent hook+manual runs,
  crash-safety, free querying for `ledger`/`status`.

Why gitignored + a committed allowlist (§6) instead of a committed ledger: the ledger
contains operational noise and (even redacted) security telemetry; the only thing that
must survive review is suppression of blocks, which lives in the committed file.

---

## 6. Secret hygiene and suppression

### The scanner must never become the leak

- gitleaks findings store only a `first2…last2` preview plus a **salted hash** of the
  match — enough to dedupe and recognize, useless to an attacker. Salt: generated once
  per repo at `init`, stored at `.aramid/salt` (gitignored), stable thereafter (a
  per-run salt would break dedup). Threat model, stated honestly: this protects
  against ledger exfiltration; a local attacker with repo access could brute-force
  short/low-entropy secrets against the hash — which is why raw material is never
  stored at all, not the salt's job alone. Raw secret material never touches ledger,
  logs, or console.
- Tool stderr captured to `.aramid/logs/` passes through the same redaction filter.
- Every secret finding prints: **deleting the line does not fix the leak — rotate the
  credential** (with file:line, and commit hash for history hits).
- `init` runs a one-time full-history gitleaks scan; hits are recorded via
  `finding_detected` events flagged `historical: true` — non-blocking, but listed in
  `status` with rotation guidance until retired with
  `aramid ledger mark-rotated <id> --reason "rotated in <system>"` (writes a
  `finding_rotated` event; status becomes `rotated`).

### Suppression — two tiers

- **WARN:** `aramid override <id> --reason "…"` — local, ledger-logged.
- **BLOCK:** local override is insufficient. Requires an entry in the **committed**
  `.aramid-suppressions.toml` — visible in diff review, permanently attributed, with a
  reason. A suppression without a reason is itself a WARN finding.

---

## 7. Configuration

Three layers, overrides-only:

1. **Built-in defaults** in the aramid package — the full policy matrix, versioned with
   code.
2. **User-level** `~/.aramid/config.toml` — fleet-wide posture.
3. **Per-repo** `aramid.toml` — near-empty stub from init: only deviations (demoted
   rules, test command override, scan-scope subpath, ignore paths) + `schema_version`.

**Re-init contract:** aramid-owned artifacts (hook shims, `ARAMID.md`, gitignore
entries — marker-tagged) are always regenerated; user-authored `aramid.toml` keys are
never touched; a `schema_version` bump prints an explicit migration message.

---

## 8. `init` mechanics (hardened against the actual `F:\Projects` topology)

- **True repo root** via `git rev-parse --show-toplevel`. Initing a subfolder of a repo
  (verified case: `f:\Claude\Bytes Web\bytes-website` inside the repo rooted at
  `f:\Claude\Bytes Web`) installs hooks at the real root and records the subfolder as
  scan scope in `aramid.toml`.
- **Nested repos** (verified case: `BytesAI Learning` contains `app/.git`) are excluded
  from the parent's scan scope.
- **Non-repos** (verified case: `Atlas` has a lockfile, no `.git`) are refused with a
  clear message — no half-initialization.
- **Chain, never clobber:** honor `core.hooksPath` (husky et al.) by installing there or
  chaining; wrap an existing foreign `pre-commit` hook (rename to
  `pre-commit.aramid-chained`, exec it from the shim) with a marker comment so re-init
  recognizes its own work.
- **Shim contract:** shims pass the process environment through untouched (so
  `ARAMID_ACCEPT_DEGRADED` reaches the engine, §3) and apply exactly the exit-code
  mappings of §3 — nothing else.
- **Shim correctness on Windows:** written in binary mode with `\n` endings
  (`core.autocrlf=true` is set system-wide here and CR in the exec line kills
  Git-for-Windows sh); the blessed interpreter's absolute path is baked in,
  double-quoted, `/c/…` form, with `command -v py && py -3` fallback — never bare
  `python` (five interpreters are visible to hook sh on this machine, including the
  WindowsApps store stub).
- **Validation:** a scratch commit through git's **real hook dispatch** proves the gate
  fires — not just that the pipeline runs when invoked directly.
- **Fleet rollout:** `aramid init --discover F:\Projects` (marker-based walk, 1–3
  levels, skips `node_modules`/`_tools`).
- **Two-week WARN-only bake per repo — manual arming, no timer state:** `init` writes
  `semgrep_block_armed = false` and `bake_started = <date>` into `aramid.toml`. While
  unarmed, semgrep BLOCK-tier findings report as WARN and `status` shows *"bake in
  progress, day N — per-rule hit counts: …"*. The operator demotes noisy rules in
  `aramid.toml`, then ends the bake explicitly with `aramid arm` (sets
  `semgrep_block_armed = true`). There is no auto-promotion — arming is always a
  deliberate act. Prevents the false-positive → `--no-verify` muscle-memory spiral.

---

## 8b. Coexistence with graphite (hard requirement)

Aramid runs side-by-side with graphite in the same repos. Neither may interfere with
the other:

- **Aramid never scans graphite artifacts.** `graph-out/`, `.graphite*`, and
  `.cache/graphite/` are in aramid's built-in default ignore paths (not just
  per-repo config) — no SAST/secret/lint findings, no fingerprints, no ledger noise
  from generated graph JSON. Verified need: the graphite daemon auto-builds graphs
  into new repos under `F:\Projects` **by design**, including this one, within
  minutes of `git init`.
- **Aramid's `init` gitignores both toolchains' artifacts** (`.aramid/`,
  `graph-out/`, `.graphite*`, `.cache/`) so daemon-generated files can never sweep
  into commits — the exact incident that occurred while writing this spec.
- **Hook coexistence:** graphite integrates via Claude Code Stop hooks (per-turn
  graph rebuild, e.g. demo-store2); aramid's gates live in git hooks — different
  dispatch mechanisms, no contention. If a repo ever carries graphite git hooks,
  aramid's chain-never-clobber rule (§8) applies to them like any foreign hook.
- **Interpreter sharing is fine:** aramid's blessed interpreter may be the same one
  graphite uses; they are separate packages with separate state directories.
- **Deliberate synergy (Phase 2 forward-hook):** graphite's code graph is the
  planned blast-radius scoper for LLM red-team review — coexistence is a
  prerequisite, not merely tolerance.

## 9. Testing aramid itself

- **Unit:** captured real output fixtures per tool → normalizer tests; policy-matrix
  decision tests; fingerprint stability tests (§4).
- **Integration:** fixture repo with seeded violations — fake AWS key, SQLi pattern,
  vulnerable pinned dependency, failing test — asserting exact block/warn/exit-code
  behavior at both gates.
- **E2E (Windows):** `init` into a temp repo; real `git commit` / `git push` attempts;
  assert the hook fires through git dispatch, chains a pre-existing hook, and
  `uninstall` reverses everything.
- **Dogfood:** aramid is init'd on its own repo from day one.

## 10. Rollout order

1. aramid repo itself (dogfood)
2. graphite (friendly Python repo, already instrumented with graphite)
3. The two active project repos (Shopify demo-store2, pawscout-worker)
4. `--discover` sweep of the remaining `F:\Projects` repos, WARN-bake each

---

## Appendix A — Design provenance

This design was produced through a question-driven brainstorm and then hardened by an
adversarial three-lens critique panel (Windows/operability, security-engineering,
architecture/YAGNI) before approval — 18 critiques, all high-severity ones incorporated.
Notable machine-verified findings that changed the design: all gate tools initially
absent from PATH (→ owned toolchain + tiered fail-open/closed); five python
interpreters visible to hook sh (→ baked absolute interpreter path); semgrep cold-start
and registry fetch (→ pre-push only + vendored rules); nested/subfolder repo topology
(→ repo-root resolution + scan scopes); append-only-JSONL vs mutable status
contradiction (→ event-sourced SQLite).

A second fresh-eyes review pass (consistency + ambiguity lenses) then found 15 spec
defects — an exit-code contract that could not express the tiered failure policy, an
escape hatch with no transport into git hooks, an unrotatable "historical" status, an
undefined ratchet baseline, and undefined behavior for new branches, among others —
all fixed in this revision before user sign-off.
