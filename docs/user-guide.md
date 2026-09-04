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
4. Writes a marker-fenced, aramid-managed instruction block into `CLAUDE.md` and `AGENTS.md` (creating them when absent) so agent coders meet the gate before their first commit, not at their first blocked push. Content outside the `<!-- aramid:begin -->`/`<!-- aramid:end -->` fence is never touched; a damaged fence (no closing marker) refuses the write with a notice. Both files are tracked, so teammates' agents inherit the block on pull.
5. Registers aramid's `SessionStart` and `PreToolUse` hooks in `.claude/settings.json` (merging, per event: entries belonging to other tools are preserved intact; aramid's own entries -- identified by `aramid agent-hook` in their command -- are rewritten to the current template; an unparseable file is reported and never written). Claude Code adds the `SessionStart` hook's stdout to each session's context, so agent sessions in the repo open with live gate posture: open findings, skip streaks, bake states, and the commands to use. `PreToolUse` screens every Bash/PowerShell tool call for a git hook-bypass invocation (`--no-verify`/`-n` on commit, `--no-verify` on push, or a `-c core.hooksPath=...` wrapper) -- advisory while baking, rejected once `aramid arm --agent` runs (see [section 9](#9-the-bake-then-arm-model)). Both hooks are fail-open everywhere -- outside an onboarded repo, or on any internal error, they print nothing and exit 0.
6. Appends any missing `.gitignore` entries: `.aramid/`, `graph-out/`, `.graphite*`, `.cache/`.
7. Installs idempotent git hook shims for `pre-commit`, `pre-push`, and `post-commit`. If a foreign hook already exists at one of those paths, it's chained to `<hook>.aramid-chained` rather than clobbered.
8. Registers the repo in the machine-global registry (this is what makes it a candidate for `aramid drain --all` later).
9. Runs a one-time full-history gitleaks scan (`git log --all`), recording any hits as **historical, non-blocking** findings — a secret that's already in history doesn't suddenly block your next commit, but it is now tracked until retired — `ledger mark-rotated` for a real leak, `ledger mark-not-a-secret` for a false positive (see [section 5](#5-understanding--handling-findings)).
10. Writes the ratchet baseline once, guarded so a re-run of `init` never resets it.
11. Validates that the installed hook shim files exist and carry aramid's marker.
12. Prints a summary: repo root, scan scope, any nested-repo exclusions, detected stack, whether hooks are armed, baseline finding count, and historical secret count.

### The hooks it installs

| Hook | Command it runs | Exit-code behavior |
|---|---|---|
| `pre-commit` | `"$INTERP" -m aramid check --gate pre-commit` (falls back to `py -3 -m aramid check --gate pre-commit`) | Remaps `{2,3} → 0` — **fail-open**, always |
| `pre-push` | `"$INTERP" -m aramid check --gate pre-push` | Remaps `2 → 0`; `1` and `3` pass through and block — **fail-closed** (an engine that couldn't run didn't run gitleaks, so it must not silently let the push through) |
| `post-commit` | `"$INTERP" -m aramid triage HEAD --budget 15 >/dev/null 2>&1 \|\| true` | Always exits `0` from the shim's perspective — fully fail-open, a commit is never blocked or made noisy by triage |

These three are git hooks -- they run outside of, and are invisible to, an agent coding session. `init` separately registers a second, unrelated kind of hook: Claude Code `SessionStart` and `PreToolUse` hooks (`aramid agent-hook session-start` / `pre-tool-use`) in `.claude/settings.json`. `SessionStart` gives an agent opening a session in the repo live gate posture -- open findings, skip streaks, bake states -- in its own context, before it ever touches a commit; `PreToolUse` screens each Bash/PowerShell tool call for a git hook-bypass invocation. `aramid doctor` grades both entries (`ok`/`absent`/`stale`/`tampered`/`unparseable`) and `aramid status` reports them on an `agent surfaces:` line; see [section 6](#6-diagnostics--aramid-doctor-and-aramid-update-rules).

To reverse onboarding later, `aramid uninstall [path]` removes the installed hook shims, deletes `ARAMID.md`, removes the `.gitignore` entries `init` added, removes the managed agent blocks from `CLAUDE.md`/`AGENTS.md` (deleting a file that held nothing but the block), removes aramid's hook entries from `.claude/settings.json` (deleting the file if nothing else remains in it), and deregisters the repo — but **deliberately keeps the ledger** (`.aramid/`) so security/audit history survives; delete that by hand if you genuinely don't want it.

---

## 3. The Deterministic Gate on Commit/Push

Once hooks are installed, every commit and push runs a fixed set of runners per gate:

| Gate | Runners |
|---|---|
| `pre-commit` | gitleaks, ruff |
| `pre-push` | gitleaks, semgrep, eslint, typecheck, deps, tests |
| `all` (`aramid check --all`) | same set as pre-push |

Each runner also has to be *applicable* to actually run: ruff only if the repo has a Python stack, eslint only if it has a JS stack, typecheck only if a `tsconfig`/mypy config is present (and mypy is handed only the in-range Python files inside the repo's own `[tool.mypy] files`/`exclude`, when set -- what the gate types is what the repo types), deps only if a package manager, a `requirements*.txt`, or a `pyproject.toml` with a `[project]` table exists (pip-audit audits the requirements files when there are any, else the pyproject's declared dependencies in project-path mode -- about 40 s at pre-push; a tool-only pyproject is not a dependency source, and `doctor` says so when a Python repo has nothing to audit), tests only if a test suite is detected (or `[tests].command` is set). gitleaks and semgrep are always applicable. A runner that isn't applicable is simply never selected — it never counts as "degraded."

Runners execute concurrently, budgeted by `[timeouts]` (`pre_commit = 5` seconds, `pre_push = 300` seconds by default); a runner still running past its budget is abandoned and recorded as `TIMEOUT` rather than joined.

#### Pointing the test gate at a fast subset

`tests` is BLOCK-tier, so a suite that overruns the budget degrades the block tier and **blocks the push**. Most mature repos have a suite too slow for a push gate — aramid's own takes ~15 minutes. Point it at a fast subset rather than living on `--no-verify`, which disables every other check too:

```toml
[tests]
command = ["pytest", "-q", "tests/unit"]   # argv form: no quoting rules
timeout_s = 300                            # capped by [timeouts].pre_push
```

A string (`command = "pytest -q tests/unit"`) works too and is split POSIX-style; prefer the argv form on Windows, where POSIX splitting eats backslashes. The command is never run through a shell, and setting one also makes the gate work in repos whose layout `detect_tests` doesn't recognize (a `make test` wrapper, a suite under a subpath).

`timeout_s` cannot exceed the gate's wall-clock budget — the gate abandons the runner at `[timeouts].pre_push` regardless — so raise both if you need a longer run. aramid warns when they're set incoherently.

`enabled = false` removes the gate entirely (it then never counts as degraded either). aramid prints a notice on every run where that suppresses a real suite: a silently disabled block-tier check is worse than no check at all. Note that subsetting the push gate narrows what it covers — keep the full suite running in CI.

#### When aramid doesn't recognize your suite

Detection is literal, not semantic: it looks for a real `test_*.py`, `*_test.py`, or `conftest.py` file (or a `package.json` `scripts.test` entry), nothing more. A custom pytest `python_files` pattern, unittest-style `testfoo.py` naming, or a doctest-only suite are all invisible to it. If that's this repo's suite and nothing else tells the gate what to run, the tests runner is simply never *selected* — not degraded, not a visible failure, just absent — so the gate can exit clean at pre-push without ever having run your real tests. That is exactly the "reports nothing for a reason indistinguishable from clean" failure class this whole gate exists to prevent.

aramid does print a stderr notice for exactly this case — a plausible `tests/`, `test/`, `pytest.ini`, `tox.ini`, or `[tool.pytest.ini_options]` setup found, but nothing recognized inside it. If you see it, set `[tests].command` to point aramid at your suite explicitly (same escape hatch as above); don't rely on renaming files to match the detector instead.

#### Dual-stack repos: pytest AND npm

If aramid detects both a real Python test file (`test_*.py`, `*_test.py`, or `conftest.py`) and a `package.json` `scripts.test` entry, it runs **both** suites at pre-push rather than picking one — a gate that silently ran only half a dual-stack repo's tests would be exactly the kind of gap this tool exists to close. The combined result blocks unless **both** suites pass; a failing suite reports the ordinary `tests-failed` finding either way, not some separate dual-stack-specific rule.

The npm side only joins the run when a JS package-manager lockfile is present (`package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock`). A `package.json` with a `scripts.test` entry but nothing installed behind it is common — linters, formatters, and git hook managers (prettier, husky) often ship one as boilerplate — so promoting every such repo to a second BLOCK-tier suite would manufacture false blocks on repos that never meant to run JS tests at all. Without a lockfile, aramid runs pytest only and prints a notice explaining that npm was skipped rather than silently dropping it; `npm install` (or pnpm/yarn) is enough to have it join on the next run. This requirement affects only the *dual-stack promotion* — a JS-only repo (no pytest detected) still runs `npm test` with no lockfile required at all.

If either suite's own tool binary can't be found (not installed, not on PATH) **within a dual-stack run**, the push blocks with an explicit `tests-tool-missing` finding rather than an unexplained degraded exit — see below. A single-suite repo (only pytest, or only npm, detected) whose one tool is missing still degrades the BLOCK tier the same way it always has (see [section 6](#6-diagnostics--aramid-doctor-and-aramid-update-rules)); `aramid doctor` does not yet probe for pytest or npm specifically.

### Security blocks, quality warns — but not uniformly

The classifier (`policy.classify`) is the single source of truth, and the split isn't one rule per tool:

- **gitleaks** → always `BLOCK`.
- **ruff** → `BLOCK` only for the curated rule set `S102, S105, S106, S107, S608, S301, S302`; everything else is `WARN`.
- **semgrep** → two independent gates:
  - pack-compiled rules (`aramid-regression.block.*`) follow `[pack].pack_block_armed` (default **true**).
  - OWASP block-list matches (`owasp-top-ten.*`, `*sqli*`, `*deserialization*`, `*command-injection*`) follow the top-level `semgrep_block_armed` (default **false**, i.e. baking).
  - Anything else from semgrep → `WARN`.
- **tests-failed** → always `BLOCK`.
- **tests-tool-missing** → always `BLOCK`. Fires only inside a dual-stack (pytest AND npm detected) run, when one suite's own tool binary can't be resolved at all. A single-suite repo (only pytest, or only npm, detected) whose one tool is missing does **not** get this finding — it still just degrades the BLOCK tier with no finding to explain it: exit `2` normally, or exit `1` at pre-push specifically via `policy.escalate_degraded` (a pure tool-state check — unrelated to the new-findings ratchet), the same unchanged behavior as before this rule existed.
- **dependency tools** (`pip-audit`, `npm`, `pnpm`, `yarn`) → `BLOCK` only if severity is at or above `[deps].block_severity` (default `"critical"`); otherwise `WARN`.
- **llm-review** → the classifier itself always returns `WARN` structurally; a confirmed-critical LLM finding can only become `BLOCK` later, at the pre-push gate, once `[llm].llm_block_armed` is set (see [section 9](#9-the-bake-then-arm-model)).
- Everything else → `WARN`.

So only OWASP-semgrep and LLM findings are gated by an arming flag — gitleaks, the curated ruff rules, failing tests, and ≥critical CVEs block unconditionally, bake state or not.

### The pre-push no-new-warnings ratchet

At `pre-push` only, any `WARN` finding that is **new** (never seen before in the ledger) is escalated to `BLOCK`. The one exemption is the `deps.DEPS_SHAPE_DRIFT_RULE` rule, which is never ratcheted. `pre-commit` has no ratchet at all.

On the very first `pre-push` run against a fresh ledger (no baseline yet), aramid writes a baseline from the current findings, and if the *only* reason the exit code came back `1` was the ratchet's own WARN→BLOCK escalation — no genuine BLOCK finding, no degraded BLOCK-tier tool — the exit code is downgraded to `0` (or `2` if something degraded). A real BLOCK is never downgraded.

**In CI this happens on every run.** `.aramid/` is normally gitignored, so every CI checkout is a fresh ledger and every CI pre-push run is "the first" — the ratchet's new-warning escalation can never fail a CI step by exit code alone. The `--json` report says so: `fresh_ledger_baseline` is `true` and `grandfathered` lists the escalated ids the downgrade waved through (both keys are always present; `false`/`[]` on an ordinary run). A CI step that wants the ratchet to bite must read those keys — or persist `.aramid/` between runs so the baseline survives. Intrinsic BLOCKs (secrets, semgrep BLOCK rules, a failed test suite) still exit `1` regardless.

### What the pre-push gate certifies -- and a branch that moves while it runs

git hands every pre-push hook one line per ref on stdin (`<local ref> <local sha> <remote ref> <remote sha>`). Over a native transport (`ssh://`, `file://`, `git://`) it ships exactly those shas. Over **smart HTTP it does not**: the parent runs the hook first, then `git-remote-http` has `send-pack` resolve the refspec by *name*, at hook exit. So a commit made on the branch while a long gate runs ships, ungated, while `git push` prints the pre-hook range. (Measured on git 2.53; a consumer saw it in production with an 18-minute gate.)

The gate therefore pins what it certifies before anything runs -- the refs on the hook's stdin, plus `HEAD` -- and re-resolves them after the last runner returns. If any moved, the push fails with

```
aramid: pre-push: main moved during the gate: 12a1d68 -> 673c804; re-run the push
```

and the run row records both sides: `refs`, `head_at_start` and `hook` on `run_started`, `refs_moved` and `head_at_exit` on `run_finished` (`aramid check --json` carries `refs_moved` too). The fix is the message: re-run the push, so the gate certifies what actually ships. Do not commit on a branch while its push is inside the hook.

Two details of the mechanism:

- The gate reads the hook's stdin only when the managed shim tells it git is on the other end (`ARAMID_HOOK=pre-push`, exported by the shim `aramid init` writes). Run by hand, or in CI, there are no ref lines and the gate certifies `HEAD` at start against `HEAD` at exit, under the name `HEAD`. Re-run `aramid init` after upgrading to get the marker into an existing shim.
- Under the marker, an empty ref list -- git's `Everything up-to-date`, or a push that only deletes a branch -- ships nothing, so the gate prints `nothing to push` and returns `0` without running the tools and without writing a run row (a row with no tools would read as a skip and start a skip streak for a push that shipped nothing).

### The exit-code contract

| Code | Meaning |
|---|---|
| `0` | pass / clean |
| `1` | BLOCK — a genuine gate finding (or a `--strict` remap) |
| `2` | degraded / WARN — a tool skipped or timed out, nothing genuinely BLOCK-tier fired |
| `3` | engine or config error (crash, bad args, missing prerequisite, refusal) |

A degraded tool is listed with its reason -- `skipped (degraded tools):` then `  - gitleaks (timeout after 120 s)`, `  - semgrep (not found)`, or `  - ruff (crashed (exit 2))` -- and the same `{tool: reason}` map is written to the run's `run_finished` row as `degraded` (empty when every selected tool ran) and to `check --json` as `degraded_reasons`. A tool that timed out also says so in its own log under `.aramid/logs/`, which used to be empty for exactly that case.

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

`--gate` defaults to `pre-commit`. `--gate all` runs every runner either tier runs -- the one invocation that sees both halves of an edit, since `ruff` runs only at pre-commit and `semgrep`/`tests` only at pre-push (an edit that annotates a line for one tool re-keys the other tool's committed suppression id on that same line, and neither hook gate can show you both). It defaults to scanning the whole tree, never ratchets, and no hook invokes it; exit codes are as for any gate.

### Scan mode

```powershell
aramid check --staged
aramid check --range
aramid check --all
```

These three are mutually exclusive. If none is given, the mode defaults per gate: `staged` for `--gate pre-commit`, `range` for `--gate pre-push`, `all` for `--gate all`. `--all` widens the FILE set to the whole tracked tree (and takes the pre-push time budget); it does not change which runners run -- that is `--gate`'s job, so `--gate pre-commit --all` is still a gitleaks+ruff scan. For both tiers at once, use `--gate all`. Under `--all`, gitleaks scans a temporary copy of exactly the tracked files rather than walking the checkout: `gitleaks dir` has no exclude option, and pointed at the repo root it walks every gitignored cache too -- on aramid's own checkout a 418 MB `.cache/` cost 63 s of a 68 s scan against gitleaks' 120 s budget, and under load the tool timed out and `--strict` refused a push whose gate had nothing blocking. The 381 tracked files scan in about 2 s.

### Looking without recording

```powershell
aramid check --gate all --no-record --json
```

`--no-record` runs the gate against a snapshot of the ledger and writes nothing to `.aramid/ledger.db` (the runner logs under `.aramid/logs/` are still written). The report is the real report -- the ratchet, `new_ids` and the fresh-ledger rule read the snapshot's history exactly as a recording run would -- so it is the way to take a whole-tree measurement without leaving it behind: one consumer's `--all` look wrote 683 rows into their ledger before this existed.

### CI / automation flags

```powershell
aramid check --strict --json
```

- `--strict` — remaps exit codes `2`/`3` to `1` (treat degraded/error as failure; no soft-pass in CI).
- `--json` — renders the machine-readable report instead of the console report. Beyond `findings`, it carries `exit_code` (the final one, after `--strict` and the fresh-ledger rule), `degraded` and `degraded_reasons` (the `{tool: reason}` map behind it), `new_ids`, `stale_overrides`, `tools` (which binary backed each probed key), `tools_ran` (what actually ran), `scope_widened`, and — since 0.7.1 — `fresh_ledger_baseline` / `grandfathered` (see the fresh-ledger rule above), and `run_id` / `recorded` (`recorded: false` means the run was `--no-record`: a real report against a snapshot, with no ledger row to match it against). Every finding carries `escalated_by_ratchet` and `verdict_before_ratchet`.
- `--accept-degraded --reason "why"` — accept a degraded run instead of blocking on it: the gate exits `0`, writes an `infrastructure_bypass` ledger row carrying the reason, prints `degraded, ACCEPTED: <reason>` and carries `accepted_reason` in `--json`, so the pass is never mistaken for a clean one. `--strict` does not remap an accepted run, and the CI-parity shim needs no exit-code arm for it (until 0.12.0 the accepted run exited `2`, which `--strict` turned into `1` -- under `[hooks].pre_push_match_ci` the hatch refused the push with its acceptance on record). A genuine BLOCK finding still exits `1`; `--reason` defaults to `"no reason given"` if `--accept-degraded` is passed without one. The same signal can be supplied via the `ARAMID_ACCEPT_DEGRADED` environment variable, which hooks inherit from the parent git process automatically.

---

## 5. Understanding & Handling Findings

### `aramid status`

A read-only report of this repo; the only thing it writes is a machine-level `shown` marker for any fleet notice it displays:

```powershell
aramid status
```

Reports: last run summary; open/historical/not-a-secret/overridden/unreachable/fixed/superseded/out-of-scope/pending-retest/rotated finding counts; count of findings new since the baseline; count of findings aging past 30 days open; per-tool skip streaks; **resolver defects** (see [`aramid resolvers`](#aramid-resolvers--is-auto-resolution-actually-working)); **consumers stuck in `degraded`**, as a streak of consecutive failed drain runs with the note explaining what broke — this matters because the drain re-queues an item while any consumer is degraded, so a stuck consumer means the same work is being retried every drain; unrotated historical secrets (with a hint naming both retirement exits: `ledger mark-rotated` for a real leak, `ledger mark-not-a-secret` for a false positive); unreachable candidates (open findings whose tool no longer runs in this repo, with the exact `ledger mark-unreachable` command to retire each); while `semgrep_block_armed` is still `false`, the bake day-count and per-rule semgrep hit counts (so you can spot noisy rules before arming); an LLM review status line (open/confirmed-critical counts, armed/baking state, OpenRouter monthly spend vs. cap, ladder tiers) plus an autolearn line; queue status (queued count/score/age, drained/expired counts); last drain timestamp; whether the repo is registered; whether scheduled drain is installed; the fleet 1.0-readiness verdict and any fleet notice due in this repo (see [Fleet health](#fleet-health-10-readiness-and-notices)).

### The ledger

```powershell
aramid ledger list
aramid ledger show <id>
aramid ledger filter --tool ruff --rule S608 --status open --severity high
```

- `ledger list` — one line per finding: `[status] id tool:rule file:line — message`.
- `ledger show <id>` — full record (`tool, rule, file, line, severity, verdict, message, evidence, historical, status, reason`) plus every ledger event tied to that id. Exits `3` for an unknown id. `reason` is populated once a finding has been overridden or marked not-a-secret; a rotated finding's reason is recorded in the ledger event but not currently surfaced here.
- `ledger filter` — all four filters are optional and AND-combined. `--status` and `--severity` take the spelling `aramid status` prints (`pending-retest` and `pending_retest` are the same value; case is ignored), and a value outside the vocabulary exits 3 with the vocabulary listed instead of reporting an empty match.

If `init`'s one-time full-history secret scan found something, it has two possible exits: rotate the credential and mark it rotated, or confirm it was never a secret in the first place and mark it as such.

Rotate a real leak, then record it:

```powershell
aramid ledger mark-rotated <id> --reason "rotated in vault, 2026-07-20"
```

Some hits are not leaks at all. gitleaks' `generic-api-key` rule flags any sufficiently long, high-entropy string, so it routinely catches values that are secret-*shaped* but not secret — for example, a Shopify app's public client ID embedded in a `wrangler.toml`, already published in the storefront's HTML by design. Confirm that, then mark it not-a-secret instead of rotating it:

```powershell
aramid ledger mark-not-a-secret <id> --reason "public Shopify client ID, published in the storefront meta tag"
```

`--reason` is required for both commands. `mark-not-a-secret` refuses (exit `3`) for any status other than exactly `historical`, rather than silently no-op'ing — for a live `open` finding it points you at a committed `.aramid-suppressions.toml` entry for a BLOCK, or `aramid override` for a WARN, since those are that finding's real suppression paths; for a finding that's already `rotated`, already `not_a_secret`, or otherwise resolved (e.g. `fixed`), it just refuses. That restriction matters because `not_a_secret`, like `historical`, is inert at gate time — a finding re-fires at its normal severity if it's ever re-detected in the working tree, regardless of ledger status. So loosening the guard would not open a gate bypass; it would open a **reporting** bypass — an uncommitted way to drop an open BLOCK finding out of `status`'s counts, sidestepping the committed, reviewable `.aramid-suppressions.toml` that BLOCK-tier suppression deliberately requires. `mark-rotated`, by contrast, accepts a `historical` finding OR one already marked `not_a_secret`: discovering that a supposed false positive is in fact a real credential, and rotating it, only adds caution, so that direction is never blocked. Neither mark can ever be undone — the ledger is append-only, and there is no path back from `rotated` to `not_a_secret`.

### Retiring a finding whose tool no longer runs

A repo's stack can change: a test file gets removed, `[tests].enabled` gets set to `false`, a `tsconfig.json` disappears. When that happens, any OPEN finding that tool produced is stranded — no future run can ever resolve it the normal way, because resolution requires the tool to run, and it never will again. `aramid status` auto-detects these under an "unreachable candidates" section and names the exact command:

```powershell
aramid ledger mark-unreachable <id> --reason "no python stack in this repo anymore"
```

`--reason` is required. The command refuses (exit `3`) for: an unknown id; a finding whose tool is a producer/consumer (`tdd`, `red-proof`, `mutation`, `mutation-score`, `llm-review`, `js-mutation`, `fuzz`, `dast`) — those resolve through their own producer's mechanism, never by hand; a finding whose status isn't exactly `open` (a historical secret is redirected to `mark-rotated`/`mark-not-a-secret` instead); or a finding whose tool still runs here — that is a broken-toolchain problem (`aramid doctor`), not a ghost, and retiring it would hide a real gap rather than an obsolete one. Unlike `mark-not-a-secret`, this transition **does** resurrect: if the tool ever comes back and re-detects the same finding, it automatically re-opens — a repo that flips detection off and back on cannot permanently launder an open finding this way.

### Findings on a path the runner no longer examines

The other stranded shape: the tool still runs here, so `mark-unreachable` refuses -- but its runner will never examine that path again, so no run can resolve the finding. It happened when the typecheck runner was scoped to `.py`/`.pyi` in 0.6.1: `mypy:syntax` rows recorded against `ci.yml` and `README.md` could neither re-report nor resolve. `aramid status` lists these under an "out-of-scope candidates" section and names the command:

```powershell
aramid ledger resolve <id> [<id> ...] --out-of-scope --reason "typecheck scoped to .py/.pyi in 0.6.1"
```

Several ids per launch are accepted: every id is attempted, a refusal on one does not stop the rest, and the exit is the worst of them. It records `finding_out_of_scope` -- its own event kind, so the ledger can later tell "the tool left the repo" (`unreachable`) from "the path left the tool's scope" (`out_of_scope`) without reading payloads. The guard that keeps it from becoming a silencer: it refuses (exit `3`) while the runner **can still examine the path**, decided by that runner's own file-suffix rule (`ruff`/`mypy`: `.py`/`.pyi`; `eslint`: JS/TS suffixes; `clippy`: `.rs`) and, for mypy, by the repo's own `[tool.mypy] files`/`exclude` -- a `.py` that scope leaves untyped is one mypy will never examine here; it refuses outright for a tool with no suffix scope (`gitleaks`, `semgrep`, `tests`, dependency audits -- "cannot say" is not "no"); and it redirects to `mark-unreachable` when the tool is not selected at all. `--out-of-scope` is the only kind it accepts: a finding that is simply gone resolves on the next run that examines its file. Like `fixed` and `unreachable`, the row re-opens if a runner ever reports it again, and `aramid override` refuses it.

### Findings on a file you deleted

Deleting a file closes its findings automatically — nothing can re-report on a path that is gone, so the next gate run marks them fixed. If the file comes back, they re-open on the next scan.

That has always held for findings from a **runner** (ruff, semgrep, gitleaks, …). Since 2026-08-09 it also holds for `red-proof`, `tdd` and `mutation`, whose findings previously stayed open forever: their own resolvers need the file to be present (red-proof re-runs pytest against it; tdd and mutation wait for the push to touch it), and git file discovery excludes deletions, so a deleted path never entered scope for any of them.

Two producers are still **not** covered — close their findings by hand with `aramid override`:

- `js-mutation` and `fuzz` have **no resolver at all**, which is a bigger problem than deletions. Nothing in the gate matches those tool names, `record_run` cannot reach them (it keys on runner labels, and these are consumers), and the drain deliberately records detections without resolving anything. Their findings stay open permanently — not just after a deletion, but *even once you fix the crash or kill the surviving mutant*. Giving them deletion-resolution alone would paper over that, so they need a resolver of their own instead.
- `dast` is excluded by design, not oversight: its findings are anchored to an endpoint (`GET /login`) rather than a file, so "was this file deleted?" has no answer for them — and because that string does not exist as a path, treating it as one would silently clear live security findings.

### Overriding a WARN finding

```powershell
aramid override <id> --reason "false positive, confirmed by security team"
```

`--reason` is required (non-empty). This refuses (exit `3`) for any BLOCK-tier finding — including a confirmed-critical LLM finding, even before `[llm].llm_block_armed` is set, since arming applies retroactively — and prints the exact `.aramid-suppressions.toml` entry to add instead, ready to paste.

### `DRIFT` in `aramid doctor` — you are running a different analyzer than aramid shipped

aramid declares `ruff`, `semgrep` and `pip-audit` as dependencies, so `pip install aramid` puts specific versions of them next to it. But tool resolution is **PATH-first, by design** — your own toolchain wins, and aramid's copy is a fallback, never an override.

That means an older copy earlier on your `PATH` is what actually runs. It is not an error, and nothing is broken. What matters is that it changes what gets reported:

```
  DRIFT    ruff         running ruff 0.15.18
                        C:\...\Roaming\Python314\Scripts\ruff.EXE
           aramid's own dependency is ruff 0.16.2
                        C:\...\venv\Scripts\ruff.exe
```

Measured on exactly that pair, same file: `0.15.18` reported one finding, `0.16.2` reported three. Two consequences, both quiet:

- **The ratchet.** A finding that exists under one version and not the other is *new* to whichever side sees it first — so CI can block a push for something your own gate never showed you. That is the local-vs-CI gap `[hooks].pre_push_match_ci` exists to close, defeated underneath it.
- **Fingerprints.** A different rule id is a different finding id, so baseline entries and `.aramid-suppressions.toml` stop matching.

`doctor` stays silent when both copies are the same version, and when you have no second copy at all. To make it agree, either remove the older copy from `PATH` or install the same version there. Every gate run also records which binary it used under `tools` in `aramid check --json` — that is what to compare when CI and local disagree.

### An LLM finding you fixed that stays open anyway

LLM findings resolve deterministically and for free: each one stores the verbatim line it was raised against, and when that line is gone from `HEAD`, the next gate closes the finding. No tokens, no re-review.

That is a proxy, and it has one honest failure mode. **A fix that guards the path *leading to* the quoted line leaves the quote byte-identical** — an early return, a new precondition, a call site that stops being reached — so the finding stays open even though it is genuinely fixed.

The match is deliberately not loosened, because resolving too eagerly is how a confirmed-critical finding disappears from the block gate. Close it by hand instead, and say what fixed it:

```powershell
aramid override <id> --reason "fixed in e3270a3; the guard is in run(), so the quoted line in _examined never changed"
```

Use `override` rather than `.aramid-suppressions.toml` here. A suppression asserts something is *acceptable*; this one is *fixed*. A tracked entry would also never go stale — the quote never moves, so it never near-misses — leaving a permanent record of a transient fact. Machine-local is right: the next drain re-reviews the file and re-raises the finding if the fix was incomplete.

### Suppressing a finding for the whole team — `.aramid-suppressions.toml`

`aramid override` writes to the ledger in `.aramid/`, which is gitignored. That is deliberate — it is the "quiet this for me, on this machine" channel, and because nobody else can review it, it is limited to WARN-tier findings.

The decision a *team* makes goes in `.aramid-suppressions.toml` at the repo root. **Commit it.** It is a plain TOML list, and it accepts any tier:

```toml
[[suppress]]
id = "a1b2c3d4e5f60718"
tool = "gitleaks"
rule = "aws-access-key-id"
path = "tests/fixtures/creds.env"
reason = "test fixture, never live; rotated out of the org 2026-08-01"
```

- **`id`** is the finding's content fingerprint. Copy it — don't retype it — from `aramid ledger list`, from `aramid check --json`, or from the snippet `aramid override` prints when it refuses a BLOCK. (`aramid status` prints ids too, but only for secret findings and unreachable candidates.) It is salt-free, so it is the same id in every clone.
- **`reason`** is mandatory. An entry without one is **dropped** — it suppresses nothing — and aramid raises a WARN finding against the file itself, so a reasonless entry is loud rather than silent.
- `tool`, `rule` and `path` are what **stale detection** matches on. If the finding moves (the code changed, so the fingerprint changed) but the same tool still fires the same rule on the same file, the finding **re-fires at its normal tier** and the entry is reported stale. A suppression cannot outlive the thing it was written about.

The two channels differ in reach, not in strength:

| | where | reviewable | tiers |
|---|---|---|---|
| `aramid override <id>` | `.aramid/ledger.db`, gitignored | no | WARN only |
| `.aramid-suppressions.toml` | repo root, committed | yes, in the diff | **any** |

Before 0.2.0 the file quietly ignored WARN entries. If you have one that never seemed to take effect, it works now — no change to the entry is needed.

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

Exit is `0` if both BLOCK-tier tools (gitleaks, semgrep) are present, `2` if either is missing. WARN-tier tool absence (ruff, pip-audit) never changes the exit code. Exit is also `2` when the repo is configured but its hooks are not installed ("configured but NOT enforced"), when another managing tool's trampoline occupies a hook slot and aramid's relocated shim beside it is STALE against the current template or missing altogether (the read-only counterpart of what `aramid init` regenerates; `doctor` never rewrites a hook), when a detected test suite's own tool cannot be resolved, when an aramid-named hook entry in `.claude/settings.json` carries a command that matches no known template ("tampered" -- the `-P`-stripping class of edit; treat as a security signal and re-run `aramid init` to rewrite it), and when **aramid itself is installed editable while any repo is registered** — every registered repo's hooks then run that working tree, uncommitted edits included; the `EDITABLE` notice alone (nothing registered) stays advisory. The remedy for the last is to promote a built wheel (`scripts/promote_live.py`, see RELEASING.md).

**In CI, expect `2`.** Git hooks are not cloned, so every CI checkout is "configured but NOT enforced" and `doctor` exits `2` by construction — even with every BLOCK-tier tool present. Run it informationally there and read the report for a `MISSING` BLOCK-tier tool, and capture the status explicitly: GitHub's default Windows `pwsh` step wrapper reports any non-zero native exit as `1` unless the script ends with `exit $LASTEXITCODE`, which is how a `2` was once read as a crash.

Two more sections print on every non-init `doctor` run (suppressed during `aramid init` itself, per [section 2, item 5](#2-onboarding-a-repo--aramid-init) — their remedy is the very init run that is printing the report): `agent files:` grades the managed instruction block in `CLAUDE.md`/`AGENTS.md` against `ok`/`stale`/`absent`/`damaged`/`unreadable`, and `agent hooks:` grades aramid's `SessionStart` entry in `.claude/settings.json` against `ok`/`absent`/`stale`/`tampered`/`unparseable`, plus an advisory line if PATH's `python` -- the interpreter the generated hook command names -- cannot import aramid. Both sections are advisory: WARN never fails doctor, with one exception. `tampered` is the one state in either vocabulary that moves the exit code, to `2` (see above); every other state -- `stale`, `absent`, `damaged`, `unreadable`, `unparseable`, and the PATH-python probe's own WARN -- means only "re-run `aramid init`" (or fix PATH) and leaves the exit code untouched.

`agent hooks:` covers a second entry beyond `SessionStart`: a `PreToolUse` hook that screens every agent tool call for a `git commit` carrying `--no-verify` or `-n`, a `git push` carrying `--no-verify` (`git push -n` is `--dry-run`, a harmless read-only flag, and is deliberately exempt), or either subcommand carrying a `-c core.hooksPath=...` wrapper. While the agent bake is in progress this is advisory only -- the call goes through, with a warning in the agent's own context; once the repo runs `aramid arm --agent` (see [section 9](#9-the-bake-then-arm-model)) the same call is rejected outright. Humans running `git` from a real terminal are never touched -- the hook only ever sees tool calls an agent issues.

`aramid init` also registers an MCP server entry in `.mcp.json` (`python -P -m aramid.mcp`), so MCP-capable agents -- Claude Code and every non-Claude agent that speaks MCP -- reach the same loop as tools: `aramid_check` (a read-only ledger snapshot; it never records), `aramid_status`, `aramid_ledger_filter`, `aramid_resolvers`, and the suppression tools `aramid_override`, `aramid_mark_not_a_secret`, and `aramid_mark_rotated` (each requires a reason and is ledger-logged with the CLI's own authority and audit trail). `aramid doctor` grades the entry (`ok`/`stale`/`absent`/`tampered`/`unparseable`) alongside the other two agent surfaces, and a `tampered` entry moves the exit code to `2` just as a tampered hook does -- it is the most serious of the three, because a hijacked MCP launch means the agent talks to whatever the repo planted, over the one channel every non-Claude agent uses to reach aramid at all. `aramid status`'s `agent surfaces:` line folds all three gradings together, e.g. `agent surfaces: blocks 2/2, hooks ok, mcp ok | baking`. One thing that grading does not say: an MCP server process lives for the agent session that started it, so a wheel promoted mid-session reaches MCP clients at their next session, not at once -- the CLI answers from the new wheel immediately while the session's `aramid_status` tool still answers from the old one (measured by graphite-agent across the 0.8.0 to 0.9.0 promotion: fresh ledger, no `fleet:` line). `mcp ok` grades the `.mcp.json` entry, not the running server's version; restart the session after a promotion before measuring with its tools.

```powershell
aramid doctor --fix
```

Upgrades the owned toolchain (`ruff`, `semgrep`, `pip-audit`) via `pip install --upgrade` into the current interpreter, downloads a pinned gitleaks `v8.21.2` release (sha256-verified before extraction) into `~/.aramid/tools/` if missing, then re-probes.

### `aramid resolvers` — is auto-resolution actually working?

```powershell
aramid resolvers          # or --json
```

Findings are supposed to clear themselves: fix the bug, push, and the finding resolves. Several **auto-resolvers** do that — one per producer, each with its own proof (a test was added, a mutant was killed, the evidence quote is gone from the file, the suite ran clean). When one of them stops working, nothing tells you. Findings just quietly stop clearing, and the pile grows.

That is not hypothetical. In aramid's own repo, `[hooks].pre_push_match_ci = true` runs the gate with `--all`, and every push-delta-scoped resolver used to sit behind a check for `--range`. Auto-resolution was **completely off** for weeks. Every test passed. Nothing in any report said a word, because **a resolver that resolves nothing writes nothing to the ledger** — its silence looks exactly like a repo with nothing to fix.

This command closes that hole by recording what each resolver **looked at**, not just what it cleared, and grading the two against each other:

| Grade | Meaning | Defect? |
| --- | --- | --- |
| `live` | cleared something | no |
| `no data` | never ran, and this producer has never filed a finding | no |
| `no opportunity` | ran, saw nothing, nothing open for it | no |
| `no clears yet` | saw candidates, cleared none — usually just means nothing has been fixed | no |
| `not instrumented` | no yield data recorded yet — run a gate first | no |
| `NEVER RAN` | no yield events at all, but its producer **has** findings | **yes** |
| `BLIND` | ran, but matched zero candidates while findings are open | **yes** |

The split is the whole point, and it is narrower than you might expect. "Zero" is normal for a JavaScript mutation resolver in a Python-only repo, and a five-alarm fire for a resolver whose producer has eleven findings open.

**Only the two mechanism faults are defects.** `NEVER RAN` and `BLIND` both mean the resolver *could not* have worked — it was not called, or its filter matches nothing. "Saw candidates and cleared none" is an outcome, and outcomes are confounded: it overwhelmingly means the findings have not been fixed, which is no fault of the gate's.

The clearest case is `file_departed`, which clears a finding only when its file has left the repository. In a healthy repo it walks the open set on every run and correctly resolves nothing, indefinitely — so treating "cleared none" as a defect would brand a resolver broken for doing a rare job right.

`BLIND` deserves a note: it catches a resolver whose **filter** never matches — for example one keyed on a tool name that has since been renamed. Counting clears structurally cannot catch that, because a filter matching nothing never produces a candidate to decline.

`aramid status` prints a one-line pointer whenever any resolver is graded a defect, so you do not have to remember to run this. Neither command can block a push — a dead resolver is a fault in the gate's own machinery, not a verdict on your code.

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

### Fleet health, 1.0 readiness and notices

aramid has no telemetry and never phones home, so the question "is aramid ready to be called 1.0?" is answered on your machine, from the repos it gates. Every recording gate run appends one row for its own repo to `~/.aramid/fleet_health.jsonl` -- which tools ran, whether a consumer is degraded or stood down, whether a resolver is graded `NEVER RAN`/`BLIND`, whether a BLOCK-tier tool failed, whether pip-audit ran on a Python repo, and every `*_armed` flag. The drain then judges every registered repo's rows (`~/.aramid/fleet_verdict.json`) and posts notices to aramid's own channel (`~/.aramid/notices.jsonl`). Nothing is written into any repo; no process reads another repo's ledger; `aramid uninstall` leaves the store alone.

```powershell
aramid fleet             # repo x criteria matrix, streak, verdict with reasons
aramid fleet --json      # the verdict file verbatim
aramid notices           # pending notices, one per line
aramid notices show <id>
aramid notices ack <id>  # acking anywhere silences it everywhere
```

The verdict is `ready` only when every registered repo's latest row is green on every criterion, that has held for at least 14 days and across at least 2 aramid versions, and at least one repo has an armed consumer. Disarming a consumer inside the streak restarts the streak at the disarming row (the verdict names the repo, flag and time), so a disarm costs the full waiting period rather than pinning the verdict forever. A registered repo with no rows makes it `insufficient-data`, and so does a registered repo whose latest row is older than the freshness window (7 days by default): a streak is held by rows, not by silence, so every registered repo has to record a gate run at least weekly for the whole 14 days or the clock restarts. Anything else is `not-ready` with the red repos and criteria named. `pip-audit` on a pyproject-only Python repo reads red on purpose: the gate does not audit those dependencies yet, and 1.0 waits for that.

Where you see it: the Claude Code session-start hook prints the verdict and any notice due in this repo (`aramid: fleet: ...`, `aramid: NOTICE <id> ...`); `aramid status` prints the same lines. That `fleet:` line is the last drain's verdict, not this gate's: a gate run only appends its row, and the next `aramid drain` (scheduled, or run by hand) reads the rows and rewrites the verdict, so a row that turns a criterion green or red moves the line at the next drain, not at the gate. A gate run ends with `aramid: N fleet notice(s) pending -- see `aramid notices`` and `check --json` carries `fleet_notices_pending`. A notice is repeated in a given repo at most once a day until acked; `readiness-reached` and `readiness-broken` mark transitions, and a `fleet-defect` notice fires when the same defect sits on three consecutive rows of one repo and clears itself when it goes. Each surface prints at most three notices per visit; `aramid notices` lists them all.

Policy lives in `~/.aramid/fleet.toml` (optional; defaults shown):

```toml
schema_version = 1
[readiness]
min_days = 14
min_versions = 2
max_row_age_days = 7   # 0 disables the freshness window
[notices]
repeat_hours = 24
defect_rows = 3
gate_trailer = true
```

Everything is fail-open: a missing, corrupt or unwritable store costs one stderr line and never changes a gate's, the drain's, or the hook's exit code. The push is budgeted at 2 s and the judgement at 30 s; over budget, the row or verdict is skipped and said so. The store directory can be redirected with the `ARAMID_FLEET_DIR` environment variable (the test suite does this so it never touches yours). A verdict older than 12 hours is marked stale -- the scheduled drain is not running.

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
retest_open_survivors = true   # when a TEST file changes, re-test recorded open survivors
retest_cap = 3                 # ...at most this many per item, after the range's own mutants
```

A survivor the pre-push gate resolved on intent (the push touched its module, or a test named for it) is recorded as `pending_retest`, not `fixed`: it no longer blocks, but nothing has proved it dead. The re-test is what closes it (`mutant_killed` → `fixed`), a later run that regenerates the same mutant re-opens it, and triage scores a push that changes a test named for a recorded survivor's module high enough to be queued (`survivor-retest`), so the push carrying the evidence is the one that reaches the consumer. A survivor bound by `.aramid-suppressions.toml` (an equivalent mutant) is never resolved by the gate at all.

Requirement: a pytest test stack must be detected — a real `test_*.py`, `*_test.py`, or `conftest.py` file; a bare `tests/` directory by itself no longer counts — otherwise it OK-skips permanently and harmlessly (`"no python test stack (mutation skipped)"`) rather than pinning the queue item forever.

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

New rule classes and the LLM reviewer start in a WARN-only "bake" period so you can see what they find before they can block a push. There are several independent arming flags — none gates any other; a representative subset (run `aramid arm --help` for the full list):

| Flag | Location | Default | What it BLOCKs once armed |
|---|---|---|---|
| `semgrep_block_armed` | root of `aramid.toml` | `false` | OWASP-semgrep block-list matches |
| `[pack].pack_block_armed` | `aramid.toml` | `true` | regression-pack compiled block rules |
| `[llm].llm_block_armed` | `aramid.toml` | `false` | confirmed-and-CRITICAL `llm-review` findings |
| `[llm.autolearn].armed` | `aramid.toml` | `false` | not a BLOCK gate — controls whether learned uplift/cascade actually change reviewer *selection* (vs. shadow-only telemetry) |
| `agent_block_armed` | root of `aramid.toml` | `false` | not a BLOCK gate — controls whether the `pre-tool-use` hook REJECTS a bypass-carrying agent tool call outright rather than only warning about it |

While a bake is in progress, `aramid status` surfaces the bake day-count (from `bake_started`) and per-rule semgrep hit counts, so you can spot and demote a noisy rule before arming rather than after it starts blocking pushes.

Arming is always a manual, deliberate act — there is no timer or auto-promotion.

```powershell
aramid arm
aramid arm --llm
aramid arm --autolearn
aramid arm --agent
```

- `aramid arm` (no flag) — sets `semgrep_block_armed = true`. "WARN-only bake ended -- semgrep BLOCK-tier findings now block."
- `aramid arm --llm` — sets `[llm].llm_block_armed = true`. "LLM bake ended -- confirmed-CRITICAL llm-review findings now BLOCK at pre-push."
- `aramid arm --autolearn` — sets `[llm.autolearn].armed = true`. "auto-learn armed -- uplift and cascade now change reviewer selection (escalate-only; the ladder tier stays the floor)." Also prints the current shadow record (would-uplift/decisions, audits, missed criticals).
- `aramid arm --agent` — sets `agent_block_armed = true`. Ends the agent-surface bake; the `pre-tool-use` hook then rejects bypass-carrying tool calls instead of only warning about them.

`--llm` and `--autolearn` are mutually exclusive. Every `arm` variant refuses (exit `3`) if `aramid.toml` doesn't exist yet — run `aramid init` first. Each is a targeted, comment-preserving edit of `aramid.toml`, never a full rewrite.

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

`pack add` promotes any ledger finding to a compiled semgrep rule: a rotated secret becomes a redacted reintroduction rule, a fixed CVE/GHSA/PySec/OSV finding becomes a manifest ban rule, and anything else — including a not-a-secret finding, which has no specialized compiler — becomes a draft sentinel rule you're expected to edit before committing. `pack compile` is narrower: it auto-promotes only the eligible findings (rotated secrets, fixed vuln findings) in one pass, silently skipping everything else — a not-a-secret finding is never auto-promoted into a rule this way, correctly, since a confirmed false positive must never become a permanent gate rule. This compiled ruleset is exactly what the `regression_pack` drain consumer replays against each queue item, what `[pack].pack_block_armed` gates, and what rides along as an extra semgrep config at every pre-commit/pre-push gate — so the rotated/not-a-secret split here is the actual, operator-visible difference between the two retirement exits: rotating a secret eventually compiles a standing gate rule against its reintroduction, while marking it not-a-secret never does.

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

**You need to get past a degraded run without waiting** — the run then exits `0` with the reason on an `infrastructure_bypass` ledger row and `degraded, ACCEPTED: <reason>` on the console, under `--strict` and the CI-parity shim too: `aramid check --accept-degraded --reason "why"`, or set `ARAMID_ACCEPT_DEGRADED` in the environment (hooks inherit it automatically from the parent git process).

**You want to suppress a finding you've reviewed** — `aramid override <id> --reason "..."` for a WARN-tier finding you only need quiet on your own machine. For a BLOCK-tier finding, `override` refuses on purpose and prints the entry to paste into `.aramid-suppressions.toml`. Use that committed file for anything the team should see — it takes **any** tier, not just BLOCK.

**You added a WARN entry to `.aramid-suppressions.toml` and the finding still fires** — before 0.2.0 the file applied only to BLOCK-tier findings, and a WARN entry was a silent no-op: no effect, and no stale report either. Upgrade; the entry starts working as written. If it still fires on 0.2.0+, the finding has moved — check `aramid check --json` for a stale-suppression report and refresh the `id`.

**`aramid drain` exits 3 with a lock error** — another drain is running, or the lock at `~/.aramid/drain.lock` is stale. A stale lock (dead PID, or older than `2 × [drain].wall_clock_budget_s`) is broken automatically on the next attempt.

**A drain consumer keeps leaving an item queued instead of draining it** — check the ledger for that item's `CONSUMER_RUN_FINISHED` notes; several consumers (llm-review, mutation, js_mutation, dast) have a "give up" valve after repeated failures at the same head, after which they OK-skip instead of blocking the item forever. `fuzz` and `regression_pack` have no such valve: `fuzz` swallows nearly every failure short of worktree creation as OK-skip, and `regression_pack` has no repeated-failure counter at all — it simply degrades if semgrep itself can't run.

**A bad flag or unknown subcommand** — any argparse failure (bad flags, unknown subcommand, no subcommand at all) is remapped to exit `3`, matching a genuine engine error, so scripts checking for `3` catch both cases.

**Historical secrets flagged by the one-time `init` scan** — if it's a real leak, rotate the credential, then `aramid ledger mark-rotated <id> --reason "..."`. If it's a false positive instead (gitleaks' `generic-api-key` rule in particular flags plenty of secret-shaped, non-secret values), retire it with `aramid ledger mark-not-a-secret <id> --reason "..."` instead. `mark-not-a-secret` only works while the finding's status is exactly `historical`; `mark-rotated` also accepts a finding already marked not-a-secret, since discovering a supposed false positive was real after all and rotating it only adds caution. Neither mark can be undone.
