# Aramid User Guide

Aramid is a git-hook-driven security and quality gate for a repo, backed by a persistent findings ledger. A deterministic gate runs at commit/push time (gitleaks, semgrep, ruff, tests, dependency audit, etc.), classifying each finding as a hard `BLOCK` or a soft `WARN` and enforcing a no-new-warnings ratchet so a repo can only get cleaner over time. On top of that, a Phase 2 "red-team drain" triages risky commits in the background and runs deeper, slower analysis against them on a schedule — an LLM code reviewer, mutation testing, fuzzing, and passive DAST — without ever slowing down a commit or push.

This guide walks the journey of adopting aramid on a repo you own: install, onboard, understand the gate, handle findings day to day, turn on the background drain, wire up its consumers, graduate out of bake periods, and integrate with CI.

## Table of Contents

1. [Install](#1-install)
2. [Onboarding a Repo — `aramid init`](#2-onboarding-a-repo--aramid-init)
3. [The Deterministic Gate on Commit/Push](#3-the-deterministic-gate-on-commitpush)
4. [Running Checks On Demand — `aramid check`](#4-running-checks-on-demand--aramid-check)
5. [Understanding & Handling Findings](#5-understanding--handling-findings)
6. [Diagnostics — `aramid doctor` and `aramid update-rules`](#6-diagnostics--aramid-doctor-and-aramid-update-rules)
7. [The Phase 2 Red-Team Drain](#7-the-phase-2-red-team-drain)
8. [Drain Consumers](#8-drain-consumers)
9. [The Bake-Then-Arm Model](#9-the-bake-then-arm-model)
10. [CI Integration](#10-ci-integration)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Install

Aramid ships a console script, `aramid` (from the package's `[project.scripts]` entry point), and an identical module form, `python -m aramid`, which behaves the same way — this is in fact what aramid's own installed git hooks call internally, not the console script.

Once the package is available on your interpreter, confirm it:

```powershell
aramid --version
```

```
aramid 0.1.0
```

The real prerequisite isn't the Python package so much as the external scanning toolchain aramid drives (gitleaks, semgrep, ruff, pip-audit). Check and provision that next:

```powershell
aramid doctor
```

If gitleaks or semgrep (the two BLOCK-tier tools) are missing, `doctor` exits `2`. Let it fix what it can:

```powershell
aramid doctor --fix
```

`--fix` runs `pip install --upgrade` for the tools aramid owns (`ruff`, `semgrep`, `pip-audit`) into the current interpreter, and downloads a pinned gitleaks `v8.21.2` release binary into `~/.aramid/tools/` (sha256-verified against a hardcoded checksum table before it's ever trusted/executed), then re-probes. See [section 6](#6-diagnostics--aramid-doctor-and-aramid-update-rules) for the full doctor picture.

`aramid init` (next section) itself gates on `doctor`: if a BLOCK-tier tool is still missing, `init` refuses outright (exit `3`) rather than arming hooks against a toolchain that can't actually run.

---

## 2. Onboarding a Repo — `aramid init`

From inside (or pointing at) the repo you want to protect:

```powershell
aramid init
```

or, targeting a path explicitly:

```powershell
aramid init path\to\repo
```

`init` resolves the given path to its git repo root and refuses (exit `3`) if it isn't inside a git repo at all.

To onboard every nested repo under a directory in one pass:

```powershell
aramid init path\to\workspace --discover
```

`--discover` walks up to 3 levels deep looking for directories containing `.git`, skipping `node_modules`, `_tools`, `.venv`, `.git`, `__pycache__`, `.aramid`, `.cache`, `graph-out`, and anything matching `.graphite*`, and runs the full single-repo flow on each one it finds, returning the worst exit code seen across all of them.

### What a single-repo `init` does

1. Gates on `aramid doctor` — refuses (exit `3`, no partial state written) if gitleaks or semgrep is missing.
2. Writes `aramid.toml` **only if it doesn't already exist** — an existing config is never touched. The fresh stub sets `semgrep_block_armed = false` and `bake_started = <today's date>`.
3. Always regenerates `ARAMID.md`.
4. Appends any missing `.gitignore` entries: `.aramid/`, `graph-out/`, `.graphite*`, `.cache/`.
5. Installs idempotent git hook shims for `pre-commit`, `pre-push`, and `post-commit`. If a foreign hook already exists at one of those paths, it's chained to `<hook>.aramid-chained` rather than clobbered.
6. Registers the repo in the machine-global registry (this is what makes it a candidate for `aramid drain --all` later).
7. Runs a one-time full-history gitleaks scan (`git log --all`), recording any hits as **historical, non-blocking** findings — a secret that's already in history doesn't suddenly block your next commit, but it is now tracked (see `ledger mark-rotated` in [section 5](#5-understanding--handling-findings)).
8. Writes the ratchet baseline once, guarded so a re-run of `init` never resets it.
9. Validates that the installed hook shim files exist and carry aramid's marker.
10. Prints a summary: repo root, scan scope, any nested-repo exclusions, detected stack, whether hooks are armed, baseline finding count, and historical secret count.

### The hooks it installs

| Hook | Command it runs | Exit-code behavior |
|---|---|---|
| `pre-commit` | `"$INTERP" -m aramid check --gate pre-commit` (falls back to `py -3 -m aramid check --gate pre-commit`) | Remaps `{2,3} → 0` — **fail-open**, always |
| `pre-push` | `"$INTERP" -m aramid check --gate pre-push` | Remaps `2 → 0`; `1` and `3` pass through and block — **fail-closed** (an engine that couldn't run didn't run gitleaks, so it must not silently let the push through) |
| `post-commit` | `"$INTERP" -m aramid triage HEAD --budget 15 >/dev/null 2>&1 \|\| true` | Always exits `0` from the shim's perspective — fully fail-open, a commit is never blocked or made noisy by triage |

To reverse onboarding later, `aramid uninstall [path]` removes the installed hook shims, deletes `ARAMID.md`, removes the `.gitignore` entries `init` added, and deregisters the repo — but **deliberately keeps the ledger** (`.aramid/`) so security/audit history survives; delete that by hand if you genuinely don't want it.

---

## 3. The Deterministic Gate on Commit/Push

Once hooks are installed, every commit and push runs a fixed set of runners per gate:

| Gate | Runners |
|---|---|
| `pre-commit` | gitleaks, ruff |
| `pre-push` | gitleaks, semgrep, eslint, typecheck, deps, tests |
| `all` (`aramid check --all`) | same set as pre-push |

Each runner also has to be *applicable* to actually run: ruff only if the repo has a Python stack, eslint only if it has a JS stack, typecheck only if a `tsconfig`/mypy config is present, deps only if a package manager or `requirements*.txt` exists, tests only if a test suite is detected. gitleaks and semgrep are always applicable. A runner that isn't applicable is simply never selected — it never counts as "degraded."

Runners execute concurrently, budgeted by `[timeouts]` (`pre_commit = 5` seconds, `pre_push = 300` seconds by default); a runner still running past its budget is abandoned and recorded as `TIMEOUT` rather than joined.

### Security blocks, quality warns — but not uniformly

The classifier (`policy.classify`) is the single source of truth, and the split isn't one rule per tool:

- **gitleaks** → always `BLOCK`.
- **ruff** → `BLOCK` only for the curated rule set `S102, S105, S106, S107, S608, S301, S302`; everything else is `WARN`.
- **semgrep** → two independent gates:
  - pack-compiled rules (`aramid-regression.block.*`) follow `[pack].pack_block_armed` (default **true**).
  - OWASP block-list matches (`owasp-top-ten.*`, `*sqli*`, `*deserialization*`, `*command-injection*`) follow the top-level `semgrep_block_armed` (default **false**, i.e. baking).
  - Anything else from semgrep → `WARN`.
- **tests-failed** → always `BLOCK`.
- **dependency tools** (`pip-audit`, `npm`, `pnpm`, `yarn`) → `BLOCK` only if severity is at or above `[deps].block_severity` (default `"critical"`); otherwise `WARN`.
- **llm-review** → the classifier itself always returns `WARN` structurally; a confirmed-critical LLM finding can only become `BLOCK` later, at the pre-push gate, once `[llm].llm_block_armed` is set (see [section 9](#9-the-bake-then-arm-model)).
- Everything else → `WARN`.

So only OWASP-semgrep and LLM findings are gated by an arming flag — gitleaks, the curated ruff rules, failing tests, and ≥critical CVEs block unconditionally, bake state or not.

### The pre-push no-new-warnings ratchet

At `pre-push` only, any `WARN` finding that is **new** (never seen before in the ledger) is escalated to `BLOCK`. The one exemption is the `deps.DEPS_SHAPE_DRIFT_RULE` rule, which is never ratcheted. `pre-commit` has no ratchet at all.

On the very first `pre-push` run against a fresh ledger (no baseline yet), aramid writes a baseline from the current findings, and if the *only* reason the exit code came back `1` was the ratchet's own WARN→BLOCK escalation — no genuine BLOCK finding, no degraded BLOCK-tier tool — the exit code is downgraded to `0` (or `2` if something degraded). A real BLOCK is never downgraded.

### The exit-code contract

| Code | Meaning |
|---|---|
| `0` | pass / clean |
| `1` | BLOCK — a genuine gate finding (or a `--strict` remap) |
| `2` | degraded / WARN — a tool skipped or timed out, nothing genuinely BLOCK-tier fired |
| `3` | engine or config error (crash, bad args, missing prerequisite, refusal) |

Layered on top of that base contract:

- `check --strict` remaps `2`/`3` → `1` (CI mode — no soft states).
- The **pre-commit hook shim** remaps `{2,3} → 0` (always fail-open).
- The **pre-push hook shim** remaps `2 → 0`; `1` and `3` pass through and block (fail-closed).
- Any malformed CLI invocation (`aramid` with no command, an unknown subcommand, a bad flag) is remapped to exit `3` at the top level, so a broken invocation reads the same as a genuinely crashed engine, never a bare argparse `2`.

---

## 4. Running Checks On Demand — `aramid check`

The installed hooks call `check` for you, but you can run it manually at any time:

```powershell
aramid check
aramid check --gate pre-commit
aramid check --gate pre-push
```

`--gate` defaults to `pre-commit`.

### Scan mode

```powershell
aramid check --staged
aramid check --range
aramid check --all
```

These three are mutually exclusive. If none is given, the mode defaults per gate: `staged` for `--gate pre-commit`, `range` for `--gate pre-push`. `--all` runs the full pre-push runner set regardless of gate.

### CI / automation flags

```powershell
aramid check --strict --json
```

- `--strict` — remaps exit codes `2`/`3` to `1` (treat degraded/error as failure; no soft-pass in CI).
- `--json` — renders the machine-readable report instead of the console report.
- `--accept-degraded --reason "why"` — accept a degraded run instead of blocking on it; `--reason` defaults to `"no reason given"` if `--accept-degraded` is passed without one. The same signal can be supplied via the `ARAMID_ACCEPT_DEGRADED` environment variable, which hooks inherit from the parent git process automatically.

---

## 5. Understanding & Handling Findings

### `aramid status`

A read-only snapshot — never mutates anything:

```powershell
aramid status
```

Reports: last run summary; open/historical/overridden finding counts; count of findings new since the baseline; count of findings aging past 30 days open; per-tool skip streaks; unrotated historical secrets (with a hint to use `ledger mark-rotated`); while `semgrep_block_armed` is still `false`, the bake day-count and per-rule semgrep hit counts (so you can spot noisy rules before arming); an LLM review status line (open/confirmed-critical counts, armed/baking state, OpenRouter monthly spend vs. cap, ladder tiers) plus an autolearn line; queue status (queued count/score/age, drained/expired counts); last drain timestamp; whether the repo is registered; whether scheduled drain is installed.

### The ledger

```powershell
aramid ledger list
aramid ledger show <id>
aramid ledger filter --tool ruff --rule S608 --status open --severity high
```

- `ledger list` — one line per finding: `[status] id tool:rule file:line — message`.
- `ledger show <id>` — full record (`tool, rule, file, line, severity, verdict, message, evidence, historical, status`) plus every ledger event tied to that id. Exits `3` for an unknown id.
- `ledger filter` — all four filters are optional and AND-combined.

If `init`'s one-time full-history secret scan found something, rotate the credential and then mark it:

```powershell
aramid ledger mark-rotated <id> --reason "rotated in vault, 2026-07-20"
```

`--reason` is required. This only works when the finding's status is exactly `historical` — it refuses (exit `3`) otherwise rather than silently no-op'ing.

### Overriding a WARN finding

```powershell
aramid override <id> --reason "false positive, confirmed by security team"
```

`--reason` is required (non-empty). This refuses (exit `3`) for any BLOCK-tier finding — including a confirmed-critical LLM finding, even before `[llm].llm_block_armed` is set, since arming applies retroactively — and directs you to `.aramid-suppressions.toml` for a reviewed, committed suppression instead.

### `aramid rebaseline` — recovering from a fingerprint change

Finding identity is a fingerprint over tool, rule, normalized path, and normalized line content. An aramid upgrade that changes rule ids or path normalization changes that fingerprint, so previously-accepted findings look brand new to the ratchet and suddenly BLOCK.

```powershell
aramid rebaseline
```

Without `--yes`, this only reports what would be discarded (the old grandfathered-finding count) and refuses with exit `3` — no interactive prompt, so it's always safe to call from a hook or CI without hanging.

```powershell
aramid rebaseline --yes
```

With `--yes`, it runs a full scan, writes a new baseline from the current finding ids, and prints `old -> new` counts. Because it's a full scan, it also appends normal run events — so a finding that merely re-fingerprinted (old id gone, new id present) will show up as "fixed" in `status`/`ledger list` afterward. That's expected, not a bug.

`aramid rebaseline [path] [--yes]` — `path` defaults to `.`.

---

## 6. Diagnostics — `aramid doctor` and `aramid update-rules`

### `aramid doctor [--fix]`

```powershell
aramid doctor
```

Probes `gitleaks`, `semgrep`, `ruff`, `pip-audit` (each via `<exe> --version`, never raising), plus the interpreter path baked into the installed pre-commit shim. Also prints LLM-provider probe lines (`claude`/`codex` CLIs on PATH, `OPENROUTER_API_KEY`/`OLLAMA_API_KEY` env presence, this-month OpenRouter spend) and an autolearn state-health line — all informational, none of it affects the exit code.

Exit is `0` if both BLOCK-tier tools (gitleaks, semgrep) are present, `2` if either is missing. WARN-tier tool absence (ruff, pip-audit) never changes the exit code.

```powershell
aramid doctor --fix
```

Upgrades the owned toolchain (`ruff`, `semgrep`, `pip-audit`) via `pip install --upgrade` into the current interpreter, downloads a pinned gitleaks `v8.21.2` release (sha256-verified before extraction) into `~/.aramid/tools/` if missing, then re-probes.

### `aramid update-rules`

```powershell
aramid update-rules
```

This is **offline by design — it performs no network fetch.** It prints the pinned upstream source (`https://semgrep.dev/p/owasp-top-ten`, with a reminder to pin a specific release tag rather than "latest"), the target vendored path on disk, and whether a ruleset is currently installed there (warning to stderr if not, since semgrep will then crash/degrade rather than silently pass clean). Always exits `0`.

---

## 7. The Phase 2 Red-Team Drain

Alongside the fast deterministic gate, aramid runs a background pipeline: **triage** scores each commit for risk and enqueues the risky ones, a **queue** holds at most one item per repo, and a **scheduled drain** periodically pops the highest-scored item and runs the slower consumers (LLM review, mutation testing, fuzzing, DAST) against it.

### Triage

The `post-commit` hook installed by `init` already runs this for you (`aramid triage HEAD --budget 15`, fully fail-open). You can also run it manually:

```powershell
aramid triage
aramid triage HEAD --budget 15
aramid triage base..head
```

`rev` (positional, default `HEAD`) is a single revision, or `base..head` split on `..` for a range. `--budget SECONDS` arms a wall-clock watchdog that hard-kills the process on expiry; manual invocation without `--budget` is unbounded.

Score signals (capped at 100 total):

| Signal | Weight | Trigger |
|---|---|---|
| path | 30 | a changed path contains a security token (auth, session, login, crypto, token, secret, permission, middleware, config) or matches an `[triage].extra_security_paths` pattern |
| content | 25 | added-line hits for exec/eval/subprocess, SQL-string-building, or an HTTP handler; or a touched dependency manifest |
| novelty | 20 | a touched path never seen in a prior triage run |
| blast radius | 0/10/18/25 | graph-dependent count of touched files |

An item is enqueued only if its score is at or above `[triage].min_score` (default **40**). A second risky commit while one item is already queued **coalesces** into it rather than creating a second item (base kept, head advances, score takes the max, reasons union).

### The scheduled drain

```powershell
aramid drain
aramid drain --all
aramid drain --repo path\to\repo
aramid drain --dry-run
aramid drain --max-items 5
```

`--all` (every registered repo) and `--repo PATH` (one repo) are mutually exclusive; with neither given, it defaults to the current directory. `--dry-run` previews what would be swept/popped per repo with no lock and no mutation. `--max-items N` caps items drained this run; otherwise the max across candidate repos' `[drain].max_items_per_drain` is used.

A singleton lock at `~/.aramid/drain.lock` prevents overlapping drains; it's considered stale (and breakable) if the recorded PID is dead or the lock is older than `2 × [drain].wall_clock_budget_s`. Any exception probing one repo degrades only that repo — the rest still drain. Exit: `0` ok, `2` degraded (some repo/consumer failed, rest completed), `3` if the lock is already held or the registry is unusable (`0` is still returned if no repos are registered at all).

`[drain]` config:

```toml
[drain]
interval_hours = 4
max_items_per_drain = 10
item_expiry_days = 30
wall_clock_budget_s = 600
```

### Installing the schedule

```powershell
aramid schedule install
aramid schedule status
aramid schedule remove
```

This is Windows-only (any other platform exits `3`). `install` reads `[drain].interval_hours` (default 4) and registers a Task Scheduler job named `aramid-drain` that runs `<interpreter> -m aramid drain --all` on that interval (`StartWhenAvailable=true` so a missed window self-heals, a 1-hour execution time limit, and `IgnoreNew` for overlapping runs). `status` queries it via `schtasks /Query` (prints "aramid-drain: not installed" if absent); `remove` deletes it. Both mirror the underlying `schtasks` exit code.

---

## 8. Drain Consumers

Every registered consumer runs against every popped queue item, unconditionally, in this order: `regression_pack`, `llm_review`, `mutation`, `fuzz`, `js_mutation`, `dast`. An item is only marked `drained` if every consumer finishes without an `error` or `degraded` state — otherwise it stays queued and the drain reports degraded.

Important: drain-time findings are always recorded as `WARN` except regression-pack's (BLOCK by default via `[pack].pack_block_armed = true`). An LLM finding can only escalate to BLOCK later, at the pre-push gate — see [section 9](#9-the-bake-then-arm-model). Mutation, JS mutation, fuzz, and DAST are structurally WARN-only; there is no arming flag for any of them.

### llm-review

The only consumer that spends tokens/dollars. It assembles a redacted evidence packet, sends it to a provider, mechanically verifies every finding's evidence against HEAD, and spends one cross-provider "refute" call per fresh CRITICAL before recording anything.

```toml
[llm]
enabled = true
max_items_per_drain = 3
call_timeout_s = 240
packet_max_bytes = 120000
llm_block_armed = false
provider_order = ["claude-cli", "codex-cli", "ollama-cloud"]
max_refutes_per_drain = 6

[[llm.ladder]]
tier = "cheap"
provider = "ollama-cloud"
model = "deepseek-v4-flash"
effort = ""
min_score = 40

[[llm.ladder]]
tier = "mid"
provider = "codex-cli"
model = "gpt-5.5"
effort = "medium"
min_score = 60

[[llm.ladder]]
tier = "frontier"
provider = "claude-cli"
model = "opus"
effort = "high"
min_score = 80

[llm.autolearn]
enabled = true
armed = false
uplift_threshold = 0.15
audit_every = 8
max_audits_per_drain = 1
cascade_hallucination_min = 3
```

Requirement: at least one provider CLI in `provider_order` must be installed and reachable, or the consumer OK-skips (`"llm skipped: no providers installed"`) or degrades (`"all providers unavailable"`). `openrouter` is opt-in only — add it to `provider_order` and give it its own `[[llm.ladder]]` entry; it's capped by `openrouter_monthly_cap_usd` (default `5.0`, read from `[llm]`).

### mutation (Python)

Mutation-tests the Python functions a queue item's commits touched, in a throwaway git worktree, reporting WARN findings for mutants your own test suite fails to kill.

```toml
[mutation]
enabled = true
max_mutants = 20
wall_budget_s = 600
mutant_timeout_s = 120
confirm_cap = 3
```

Requirement: a pytest test stack must be detected (a `tests/` dir or any `test_*.py`) — otherwise it OK-skips permanently and harmlessly (`"no python test stack (mutation skipped)"`) rather than pinning the queue item forever.

### js_mutation (JS/TS)

The JS/TS analog of `mutation` — single-stage (a full-suite pass on a mutant *is* the confirmed survivor).

```toml
[js_mutation]
enabled = true
max_mutants = 20
wall_budget_s = 600
mutant_timeout_s = 120
```

Note the finding `tool` string is `js-mutation` (hyphenated), distinct from the `[js_mutation]` config section name (underscored). Requirements, each checked in order with its own OK-skip: `package.json` must declare a `"test"` script; a resolvable package manager binary (npm/pnpm/yarn) must be on PATH; `node_modules/` must already exist in the repo root.

### fuzz

Calls the top-level, type-hinted Python functions a queue item's commits touched with deterministic seeded inputs, in a throwaway worktree, reporting crashes as WARN findings.

```toml
[fuzz]
enabled = true
max_functions = 10
cases_per_function = 50
wall_budget_s = 300
batch_timeout_s = 120
skip_name_patterns = ["*deploy*", "*delete*", "*remove*", "*drop*", "*push*", "*send*", "*upload*", "*kill*", "*wipe*", "*publish*", "*destroy*", "*truncate*"]
```

`skip_name_patterns` keeps it from ever calling dangerous-sounding, side-effecting function names. This consumer is unusually conservative about its own failure modes — a driver timeout, crash, or bad output is all treated as OK-skip, never degraded.

### dast

A passive web-hygiene prober against a URL you declare — headers, cookies, transport, exposed paths, and banner leaks. Evidence is always synthetic metadata (header names, status codes), never raw response bodies or secret values.

```toml
[dast]
enabled = true
base_url = "https://staging.example.com"
paths = []
timeout_s = 10
```

An empty `base_url` (the default, `""`) means this consumer OK-skips — it never pins a queue item just because a repo doesn't happen to be a web app. There is a `block_armed` key in this section, but it is explicitly **RESERVED and inert** — not wired to anything today. Don't rely on it to block.

---

## 9. The Bake-Then-Arm Model

New rule classes and the LLM reviewer start in a WARN-only "bake" period so you can see what they find before they can block a push. There are exactly four independent arming flags — none gates any other:

| Flag | Location | Default | What it BLOCKs once armed |
|---|---|---|---|
| `semgrep_block_armed` | root of `aramid.toml` | `false` | OWASP-semgrep block-list matches |
| `[pack].pack_block_armed` | `aramid.toml` | `true` | regression-pack compiled block rules |
| `[llm].llm_block_armed` | `aramid.toml` | `false` | confirmed-and-CRITICAL `llm-review` findings |
| `[llm.autolearn].armed` | `aramid.toml` | `false` | not a BLOCK gate — controls whether learned uplift/cascade actually change reviewer *selection* (vs. shadow-only telemetry) |

While a bake is in progress, `aramid status` surfaces the bake day-count (from `bake_started`) and per-rule semgrep hit counts, so you can spot and demote a noisy rule before arming rather than after it starts blocking pushes.

Arming is always a manual, deliberate act — there is no timer or auto-promotion.

```powershell
aramid arm
aramid arm --llm
aramid arm --autolearn
```

- `aramid arm` (no flag) — sets `semgrep_block_armed = true`. "WARN-only bake ended -- semgrep BLOCK-tier findings now block."
- `aramid arm --llm` — sets `[llm].llm_block_armed = true`. "LLM bake ended -- confirmed-CRITICAL llm-review findings now BLOCK at pre-push."
- `aramid arm --autolearn` — sets `[llm.autolearn].armed = true`. "auto-learn armed -- uplift and cascade now change reviewer selection (escalate-only; the ladder tier stays the floor)." Also prints the current shadow record (would-uplift/decisions, audits, missed criticals).

`--llm` and `--autolearn` are mutually exclusive. All three refuse (exit `3`) if `aramid.toml` doesn't exist yet — run `aramid init` first. Each is a targeted, comment-preserving edit of `aramid.toml`, never a full rewrite.

There's no `aramid arm` variant for `[pack].pack_block_armed` — it defaults to `true` (armed immediately) and is meant to be hand-edited down to `false` if a regression-pack rule turns out to be noisy, not bake-then-armed like the others.

### `aramid autolearn [--rebuild]`

```powershell
aramid autolearn
```

Prints the current autolearn mode, state file location and last-updated timestamp, shadow decision counts, audit counts, and per-arm posterior counts — or "none yet (cold start)" if empty.

```powershell
aramid autolearn --rebuild
```

Replays every registered repo's ledger events from scratch into a fresh state file, since the state is fully derived and thus always safe to rebuild. Always exits `0`.

### `aramid pack` — the regression attack pack

```powershell
aramid pack list
aramid pack add <finding_id>
aramid pack compile
```

`pack add` promotes any ledger finding to a compiled semgrep rule (a rotated secret → a redacted reintroduction rule; a fixed CVE/GHSA/PySec/OSV finding → a manifest ban rule; anything else → a draft sentinel you're expected to edit before committing). `pack compile` does this for every eligible finding in one pass. This compiled ruleset is exactly what the `regression_pack` drain consumer replays against each queue item, and what `[pack].pack_block_armed` gates.

---

## 10. CI Integration

In CI there's no git hook context, so invoke the gate directly. Use `--all` for the full pre-push runner set, and `--strict --json` so the pipeline gets a hard pass/fail with a machine-readable report:

```powershell
aramid check --gate pre-push --all --strict --json
```

`--strict` remaps exit codes `2` (degraded) and `3` (engine error) to `1`, so CI never soft-passes on a tool that merely failed to run — a missing tool is treated the same as a real finding. `--json` renders the report as JSON instead of the console format for your CI system to parse.

---

## 11. Troubleshooting

**`aramid doctor` exits 2 / init refuses with exit 3** — a BLOCK-tier tool (gitleaks or semgrep) is missing. Run `aramid doctor --fix` to provision both, then retry.

**A push suddenly blocks after upgrading aramid, on findings you'd already accepted** — a rule-id or path-normalization change altered fingerprints, so the ratchet sees "new" findings. Run `aramid rebaseline --yes` to re-snapshot the current state as accepted (a re-fingerprinted finding will show as "fixed" afterward — expected).

**A push is blocked and you're not sure why** — run `aramid check --gate pre-push --all --json` manually to see the full report, then `aramid ledger list` or `aramid status` to see what's open.

**You need to get past a degraded run without waiting** — `aramid check --accept-degraded --reason "why"`, or set `ARAMID_ACCEPT_DEGRADED` in the environment (hooks inherit it automatically from the parent git process).

**You want to suppress a finding you've reviewed** — `aramid override <id> --reason "..."` for WARN-tier findings. For BLOCK-tier findings, `override` refuses on purpose; use a reviewed, committed entry in `.aramid-suppressions.toml` instead.

**`aramid drain` exits 3 with a lock error** — another drain is running, or the lock at `~/.aramid/drain.lock` is stale. A stale lock (dead PID, or older than `2 × [drain].wall_clock_budget_s`) is broken automatically on the next attempt.

**A drain consumer keeps leaving an item queued instead of draining it** — check the ledger for that item's `CONSUMER_RUN_FINISHED` notes; several consumers (llm-review, mutation, js_mutation, dast) have a "give up" valve after repeated failures at the same head, after which they OK-skip instead of blocking the item forever. `fuzz` and `regression_pack` have no such valve: `fuzz` swallows nearly every failure short of worktree creation as OK-skip, and `regression_pack` has no repeated-failure counter at all — it simply degrades if semgrep itself can't run.

**A bad flag or unknown subcommand** — any argparse failure (bad flags, unknown subcommand, no subcommand at all) is remapped to exit `3`, matching a genuine engine error, so scripts checking for `3` catch both cases.

**Historical secrets flagged by the one-time `init` scan** — rotate the credential, then `aramid ledger mark-rotated <id> --reason "..."` (only valid while the finding's status is `historical`).
