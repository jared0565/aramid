# Aramid Knowledge Base

Reference material for looking up aramid concepts, configuration, consumers, CLI commands, exit codes, and troubleshooting steps. Grounded strictly in the aramid source tree (`src/aramid/`) as of this document's writing — nothing here is invented.

## Table of Contents

1. [Concepts Glossary](#1-concepts-glossary)
2. [Configuration Reference](#2-configuration-reference)
3. [Consumer Reference](#3-consumer-reference)
4. [CLI Command Reference](#4-cli-command-reference)
5. [Exit-Code Reference](#5-exit-code-reference)
6. [FAQ / Troubleshooting](#6-faq--troubleshooting)

---

## 1. Concepts Glossary

### Deterministic gate
The rule-based (non-LLM) check pipeline invoked by `aramid check`, and by the installed `pre-commit`/`pre-push` git hooks. Runner set per gate (`pipeline.py` `GATE_RUNNER_KEYS`):

| Gate | Runners |
|---|---|
| `pre-commit` | gitleaks, ruff, shadow |
| `pre-push` | gitleaks, ruff, semgrep, eslint, clippy, typecheck, deps, tests, shadow (every `pre-commit` runner is here too, FN-32; pinned by `test_every_runner_the_commit_gate_runs_also_runs_at_the_push_gate`) |
| `all` (`aramid check --gate all`) | both tiers: every runner of `pre-commit` and `pre-push` (`--all` alone is a scan mode, not this gate) |

Each runner is additionally filtered by `_is_applicable()`: ruff only if the repo has a Python stack, eslint only if a JS stack, typecheck only if a `tsconfig`/mypy config is present (`run_mypy` then filters the in-range Python files by `typecheck.mypy_scope(root)` -- `[tool.mypy] files`/`exclude` -- and `toolset.examines_path("mypy", path, root=)` consults the same helper), deps only if a package manager or `requirements*.txt` exists, tests only if `detectors.detect_tests()` finds a suite. gitleaks and semgrep are always applicable. A non-applicable runner is never selected and never counts as "degraded." `aramid.pipeline.run_gate` recomputes `detect_stacks()`/`detect_tests()` fresh on every gate run (not just at `init` time) via a pruned walk (`node_modules/`, `venv/`, `build/`, and dot-directories excluded) — so a JS/TS repo whose only `.py` files are vendored under one of those no longer spuriously enables ruff (`ctx.stacks`) or the tests gate.

Runners execute concurrently under a `ThreadPoolExecutor`, budgeted by `[timeouts]` (`pre_commit=5s`, `pre_push=300s`); a runner still running past budget is abandoned and recorded `TIMEOUT` (not joined). Two ignore-path filter passes are always on and unremovable by repo config (`_BUILTIN_IGNORE_PATHS`): before file discovery, and again on parsed findings (needed because gitleaks scans by `git log` range, not `ctx.files`).

Severity tiering ("security blocks, quality warns") is **not uniform** — `policy.classify()` is the single source of truth; see [WARN vs BLOCK tiers](#warn-vs-block-tiers) below.

### Drain
The sweep (`aramid drain`) — scheduled (via `aramid schedule install`) or manual — that catches up triage on registered repos, pops the highest-scored queued item(s) from the [review queue](#review-queue), and runs every registered [consumer](#consumer) against each item. Consumers run in this fixed registration order: `regression_pack`, `llm_review`, `mutation`, `fuzz`, `js_mutation`, `dast`.

- Singleton lock: `~/.aramid/drain.lock` (JSON `{pid, started_at, deadline_s}`); considered stale/breakable if the recorded PID is dead or the lock is older than its own `deadline_s` (the holder's hard deadline, updated once its candidates' configs are read) plus 5 minutes. A lock with no `deadline_s` (written by aramid 0.19.1 or older) reads as the default 90 minutes. A drain removes the lock only if it names the drain's own PID. Taking, releasing and re-dating the lock are each one critical section under an OS lock on `~/.aramid/drain.lock.mutex` (`msvcrt.locking` on Windows, `flock` elsewhere; never deleted), so two drains that start together get one lock between them, and a release cannot delete a lock a newer drain took (FN-19). A mutex not had within 30 s starts no drain and removes no lock.
- Hard deadline (0.19.1): `[drain].hard_deadline_s` (default 5400 s) after the lock is taken, the drain stops itself from inside. It writes a `degraded` `consumer_run_finished` row for the running consumer (note names the deadline), kills the children `run_subprocess` and the LLM provider launcher have alive and closes that registry (neither launcher starts a child afterwards, and a child the close killed returns `TIMEOUT`, never an exit code), releases the lock and exits 2; the item stays queued. Every candidate the drain had not opened gets a `queue_item_deferred` row, reason `drain deadline` (the drain tells the watchdog before each item). The row's note starts `deadline_note_prefix(deadline, head)` -- `stopped at the drain's hard deadline ([drain].hard_deadline_s = N) (last seen @ <sha12>)` -- and a consumer with three such rows on one item at that prefix is not run again: `_consume_item` records `ok`, note `<consumer> giving up: ...` (so `status` shows it stood down), and the item drains (FN-16). Capped at `interval_hours × 3600 − 900` of the shortest interval among the candidates, and on Windows at the installed task's `ExecutionTimeLimit` − 300 s (read with `schtasks /Query /XML` at each drain; PT0S or no task clamps nothing). The Windows task's `ExecutionTimeLimit` is `interval_hours × 60 − 5` minutes, so the order is always deadline < task limit < interval (`aramid.drain_limits`). `gitutil`'s git calls are in the same registry (FN-17), and bounded at `gitutil.GIT_TIMEOUT_S` (600 s): a git that times out, that the kill stops, or that is asked for after the close raises `gitutil.GitTimeout` and never answers, because callers read a failed git as an empty answer. Where a caller would read the timeout as a verdict it goes up: `review`'s evidence-gone resolver (it would resolve the finding), candidate verification (a hallucination) and packet build (a file dropped), so the gate fails and the drain's item stays queued; and the leftover sweep stops rather than judge shells it cannot see as locked (a failed `git worktree list` stops it too). `tdd.scan` and `red_proof.scan_scoped` let it go up too (FN-21), and `run_gate` decides by arming, asking `policy.classify` as the override refusal does: armed (`tdd_block_armed`, `[red_proof].red_proof_block_armed`), the producer is a degraded BLOCK-tier tool -- in `degraded` as `git did not answer: ...`, `degraded_block_tier`, pre-push exit 1 unless `--accept-degraded` -- and disarmed (the bake) it is no finding, as before. Every other error in either producer is still no finding. Kept as documented fail-open readings: `pipeline._changed_since` (the liberal rule), the agent hook and a by-hand `certify`. `js_mutation`'s one-shot `mklink` junction is bounded at 60 s, not registered.
- Candidate items (score ≥ `[triage].min_score`) across all target repos are sorted by score descending, then drained up to `max_items_per_drain` (CLI `--max-items` override, else the max across candidate repos' config, default 10) or until `[drain].wall_clock_budget_s` (default 600s) is exhausted; remaining items stay queued.
- Drain-recorded findings are normalized with `Gate.ALL` and an **empty scope** for `record_run` — detections fire, but nothing is auto-resolved (only a full gate scan may resolve a finding).
- An item is marked `drained` only if **every** consumer finished with state `!= "error"` and `!= "degraded"`. If any consumer returns DEGRADED or ERROR, the item stays queued for a future drain and the whole `cmd_drain` call sets `degraded=True` (exit code 2).
- Per-repo isolation: an exception probing one repo degrades only that repo; the rest still drain.
- After each drain, newly-drained ledger events are folded into the machine-global [auto-learn](#auto-learn) state (rollup failure never fails the drain).

### Consumer
A drain-time analysis module implementing the protocol in `consumers/base.py`: exposes `NAME: str` and `consume(item, ctx: DrainContext) -> ConsumerResult`, and self-registers into `base.CONSUMERS[NAME]` on import (mirrors the `providers/` self-registration pattern).

- `DrainContext`: `root`, `cfg`, `ledger`, `clock`.
- `ConsumerResult`: `consumer`, `state` (one of `OK`, `DEGRADED`, `ERROR`), `findings` (default `[]`), `duration_s` (default `0.0`), `cost` (default `0.0`), `note` (default `""`), `extra` (default `{}`, merged into the `CONSUMER_RUN_FINISHED` event payload via `setdefault` — core keys always win).
- Six consumers exist: `regression_pack`, `llm-review`, `mutation`, `js_mutation`, `fuzz`, `dast`. See [Section 3](#3-consumer-reference) for per-consumer detail.
- Every registered consumer runs unconditionally per queue item (no cross-consumer skip logic); any raised exception is caught into `ConsumerResult(state="error", note=str(exc))`.
- A `CONSUMER_RUN_FINISHED` ledger event is appended per consumer per item: `{consumer, item_id, state, duration_s, cost, finding_count, note, **result.extra}`.

### Triage score
A pure, git-plumbing-only, self-budgeted score (default `budget_s=2.0`, checked between signal computations and measured from the first signal, after the diff fetch -- a slow `git` no longer zeroes the score; a partial score is kept past budget with a `"triage-budget-exceeded"` reason) computed by `triage.py score()`, capped at 100 total, from four weighted signals:

| Signal | Weight | Trigger |
|---|---|---|
| `path_signal` | 30 | any changed path contains a security token (`auth, session, login, crypto, token, secret, permission, middleware, config`) or matches an `extra_security_paths` fnmatch pattern |
| `content_signal` | 25 | added-line regex hits for exec/eval/subprocess, SQL-string-building, or an HTTP handler decorator/call; or a touched dependency-manifest file (`pyproject.toml`, `package.json`, `requirements`, lockfiles) |
| `novelty_signal` | 20 | any touched path never seen in a prior triage run (per `queue.triaged_paths`) |
| `blast_radius_signal` | 0/10/18/25 | number of graphite-graph dependents of touched files: ≥10→25, ≥3→18, ≥1→10, else 0. Fails open (returns 0/`[]`) if `graph-out/graph.json` is absent, corrupt, or unexpectedly shaped |
| `survivor_signal` | 40 | a changed file holds an open or `pending_retest` mutation survivor, or a changed test maps to its module by the `gap_addressed` stem rule; or any changed test while an `open` survivor is not bound by `.aramid-suppressions.toml` (FN-37: the drain's re-test already treats the suite as the mapping). An unreadable suppressions file counts nothing as bound |

`run_triage()` always records a `TRIAGE_RECORDED` event (so the drain sweep can resume from its last-seen head), and enqueues (`QUEUE_ITEM_ADDED`) only at/above `[triage].min_score` (default 40).

### Review queue
The ledger-backed queue of triaged commits/ranges awaiting drain consumption (`queue.py`). Invariant: **at most one `"queued"` item exists per repo ledger at a time** — a second commit while one is queued coalesces into it (base kept, head advances, score = max of the two, reasons unioned) rather than creating a second item. Queue item states: `queued` → `drained` (every consumer finished cleanly) or `expired` (`[drain].item_expiry_days`, default 30, unattended).

Enqueue path: `aramid init` installs a `post-commit` hook shim that runs `aramid triage HEAD --budget 15` and swallows every outcome — a commit is never blocked/noisy-failed by triage.

### WARN vs BLOCK tiers
Verdict is computed by `policy.classify(tool, rule, severity_raw, gate, cfg)` — the single source of truth, dispatching on the finding's `tool` string:

- `gitleaks` → always `BLOCK`.
- `ruff` → `BLOCK` only if `rule` is in the curated list `["S102","S105","S106","S107","S608","S301","S302"]`; everything else `WARN`.
- `semgrep` → pack-block rules (`aramid-regression.block.*`) → `BLOCK`/`WARN` per `[pack].pack_block_armed` (default **true**); OWASP block-list matches (`owasp-top-ten.*`, `*sqli*`, `*deserialization*`, `*command-injection*`) → `BLOCK`/`WARN` per `semgrep_block_armed` (default **false**); anything else → `WARN`.
- `tests-failed` rule → always `BLOCK`.
- Dependency tools (`pip-audit`, `npm`, `pnpm`, `yarn`) → `BLOCK` iff severity ≥ `[deps].block_severity` (default `"critical"`); else `WARN`.
- `llm-review` tool → `classify()` always returns `WARN` structurally; the real BLOCK verdict is computed later, at pre-push, from ledger state + `[llm].llm_block_armed` (never inside `classify`).
- aramid's own producers → `tdd`, `mutation`, `red-proof` and `shadow` are `BLOCK` once their own flag is set (`tdd_block_armed`, `[mutation].mutation_block_armed`, `[red_proof].red_proof_block_armed`, `[shadow].shadow_block_armed`), else `WARN`; `mutation-score` is `BLOCK` only for rule `transition` once `[mutation].score_block_armed` is set, else `WARN`.
- The inline labels (`runners/inline.py`, FN-38) → `ruff-inline`, `gitleaks-inline` and `semgrep-inline` are `WARN`, checked FIRST, ahead of every promotion path, so no `block_rules` addition can reach them. Each carries rule `inline-suppressed-block` and reports a hit the repo's own marker hid from its tool (`# noqa` / ruff `per-file-ignores`, `gitleaks:allow`, `# nosemgrep`). Only a hidden hit that `classify` would BLOCK at that gate is reported (`inline.block_tier_only`, applied in `run_gate` before normalize), so a semgrep hit during the bake reports nothing.
- Everything else → `WARN`.

Net effect: **apart from aramid's own producers, only the semgrep rules (the pack's and the OWASP block-list's) and LLM findings are gated by an arming flag** — gitleaks, the curated ruff rules, failing tests, and ≥critical CVEs BLOCK unconditionally regardless of bake state.

**Pre-push no-new-warnings ratchet**: at `Gate.PRE_PUSH`, any `WARN` finding whose id is "new" (`f.id in new_ids`, never seen before in the ledger) is escalated to `BLOCK` — except five kinds, which are exempt (`pipeline.py`, `_escalates`): rule `deps.DEPS_SHAPE_DRIFT_RULE`; tools `cargo-audit-warnings`, `tdd` and `red-proof`; and the inline labels with rule `inline-suppressed-block` (label AND rule, never rule alone), which ship disarmed and which every repo meets all at once on its first run after upgrading. ruff and clippy are NOT exempt: a lint the push's author wrote and can fix. A ruff WARN recorded at pre-commit is already seen, so only one first seen at the push -- a commit that skipped the pre-commit hook -- escalates (FN-32). The LLM and mutation ledger gates' findings (`llm-review`, `mutation`, `mutation-score`) are added after the ratchet has run, so it never sees them.

### Arming / bake-then-arm
Aramid ships with several checks in a WARN-only "bake" period so an operator can observe noise before committing to enforcement. There are exactly **ten** arming-style flags, independent of one another:

| Flag | Location | Default | Armed by | What it changes when armed |
|---|---|---|---|---|
| `semgrep_block_armed` | root of `aramid.toml` | `false` | `aramid arm` | OWASP-semgrep block-list matches BLOCK |
| `[pack].pack_block_armed` | `aramid.toml` | `true` | hand edit (no `arm` variant) | regression-pack-compiled block rules (`aramid-regression.block.*`) BLOCK — deliberately independent of `semgrep_block_armed` |
| `[llm].llm_block_armed` | `aramid.toml` | `false` | `arm --llm` | confirmed-and-CRITICAL `llm-review` findings BLOCK at pre-push |
| `[llm.autolearn].armed` | `aramid.toml` | `false` | `arm --autolearn` | not a BLOCK gate — learned uplift/cascade actually change reviewer *selection* (vs. shadow-only telemetry) |
| `tdd_block_armed` | root of `aramid.toml` | `false` | `arm --tdd` | code-without-test (`tdd`) findings BLOCK at pre-push |
| `[mutation].mutation_block_armed` | `aramid.toml` | `false` | `arm --mutation` | surviving-mutant findings BLOCK at pre-push |
| `[mutation].score_block_armed` | `aramid.toml` | `false` | `arm --mutation-score` | mutation-score *transition* regressions BLOCK at pre-push (rate deltas stay WARN) |
| `[red_proof].red_proof_block_armed` | `aramid.toml` | `false` | `arm --red-proof` | never-red test findings BLOCK at pre-push |
| `[shadow].shadow_block_armed` | `aramid.toml` | `false` | `arm --shadow` | a repo-root file that hijacks `python -m aramid` or `python -m graphite` BLOCKs at every gate, pre-commit included |
| `agent_block_armed` | root of `aramid.toml` | `false` | `arm --agent` | not a finding tier — the agent `pre-tool-use` hook REJECTS a git hook-bypass (`--no-verify`, `core.hooksPath`) instead of only warning |

The verdict of every armable finding tool is computed from the arming flag at gate time, so arming applies to findings recorded before it. Drain-time mutation survivors are recorded `WARN`; `mutation_block_armed` is what escalates them at the next pre-push. `[dast]`, `[fuzz]` and `[js_mutation]` have **no** arming flag of any kind (until 0.19.0 `defaults.toml` carried a never-read `[dast].block_armed`; setting it now warns).

Arming is always a manual, deliberate act (`aramid arm` and its variants) — never a timer or auto-promotion. Every variant rewrites `aramid.toml` via targeted regex substitution (not a full TOML parse/re-dump) specifically to preserve hand-written comments byte-for-byte. `aramid init` writes a fresh repo's `aramid.toml` stub with `semgrep_block_armed = false` and `bake_started = <today>` always, and never touches an existing `aramid.toml`. `aramid status` surfaces bake day-count and per-rule semgrep hit counts while unarmed, so an operator can spot/demote noisy rules before arming.

The stub's header **comment** (`# aramid repo config -- detected stack: ...; package manager: ...`, and the matching "Detected stack:" line `init` writes into `ARAMID.md`) is informational only — `detect_stacks()`/`detect_package_manager()` are re-detected fresh on every gate run, never persisted as config keys (`render_repo_stub`'s own docstring is explicit about this). Its only observable effect is that comment's text: a JS/TS repo whose only `.py` files are vendored under `node_modules/`, `venv/`, or `build/` (no top-level Python of its own) now gets an accurate `detected stack: js` there instead of a spurious `detected stack: js, python` — the same pruned walk described under the `[tests]` config section above, applied to `detect_stacks()` too.

### Fingerprint / ratchet
**Fingerprint** (`fingerprint.py compute_fingerprint`):
```
sha256(tool + "\x1f" + rule + "\x1f" + normalize_path(path) + "\x1f" + sha256(normalize_line(line_content)) + "\x1f" + str(occurrence_index))
```
`normalize_path` = backslash→forward-slash + casefold; `normalize_line` = collapse all whitespace runs to a single space + strip. `occurrence_index` disambiguates multiple identical (tool, rule, file, normalized-line) hits within one scan; see [PIN_OCCURRENCE](#pin_occurrence) for the alternative mode. A finding about ANOTHER tool's hit (`RawFinding.subject`, set only by the FN-38 inline passes) passes `rule + "\x1f" + hidden_tool + "\x1f" + hidden_rule` as `rule`, so two rules hidden on one line get ids that do not depend on the tool's output order. With `subject` unset the input is unchanged, so no other id moved.

**Ratchet**: driven by "is this id new" (`new_ids` from `Ledger.record_run`, i.e. never previously `seen`), not by baseline membership directly — the baseline only matters for the fresh-clone downgrade path and `Ledger.is_new()`. See [WARN vs BLOCK tiers](#warn-vs-block-tiers) for the escalation rule.

### Rebaseline
`aramid rebaseline --yes` re-snapshots current findings as the accepted ratchet baseline: runs a full `Gate.ALL` scan and calls `ledger.write_baseline()` with the resulting finding-id set, discarding prior grandfathering, and prints `old -> new` count. Without `--yes`, only reports the count that would be discarded and returns exit 3 (no interactive prompt — safe to invoke from hooks/CI).

Needed because an aramid upgrade that changes rule-id or path normalization changes the fingerprint hash, so previously-accepted findings re-fingerprint and the ratchet treats them as brand-new, escalating them to BLOCK. Side effect: because a full gate is run, normal `RUN_STARTED`/`FINDING_DETECTED`/`FINDING_RESOLVED`/`RUN_FINISHED` events are also appended — a re-fingerprinted-but-functionally-unchanged finding shows up as resolved in `status`/`ledger list` afterward -- `superseded` naming the new id when the new row is a same-tool/rule/file sibling within 40 lines, `fixed` otherwise (documented, expected, not a bug).

### Provider ladder / risk tiers
Two different orderings — do not conflate them:

- **`[llm].provider_order`** (default `["claude-cli", "codex-cli", "ollama-cloud"]`) feeds `providers/base.py chain(cfg)`, filtered to `module.available(cfg)` (fail-open on a raising probe). In practice this list is consumed only as a **set** or via an order-irrelevant `any()` check — its job is to declare which providers exist and gate availability, not to set review priority.
- **The risk-tiered ladder** (`[[llm.ladder]]`, `review.py build_arms`/`target_arm`/`reviewer_order`) is what actually drives reviewer selection, cheap→frontier by ascending `min_score`:

| tier | provider | model (default) | effort | min_score |
|---|---|---|---|---|
| `cheap` | `ollama-cloud` | `deepseek-v4-flash` | `""` | `40` |
| `mid` | `codex-cli` | `gpt-5.5` | `medium` | `60` |
| `frontier` | `claude-cli` | `opus` | `high` | `80` |

`target_arm(score)` picks the highest-`min_score` arm whose band contains the item's score (or the cheapest arm below the lowest band). `reviewer_order()` then attempts the target tier first, degrading to nearest-available (prefer at-or-below the target, then climb above), deduped by provider. OpenRouter is opt-in only — added to `provider_order` plus a `[[llm.ladder]]` arm manually — capped by `[llm].openrouter_monthly_cap_usd` (default $5.00/month), checked against a local spend log before every call.

### Auto-learn
Machine-global learned model-selection engine (`~/.aramid/autolearn_state.json`, `STATE_VERSION=1`; unreadable/malformed/foreign-version state degrades silently to an empty cold-start state), config under `[llm.autolearn]`. Three mechanisms:

- **Uplift**: escalate-only Thompson-sampling walk up the ladder from the target tier; each cell samples a miss-probability `q ~ Beta(1+misses, 9+clean)` (no-data prior mean `1/(1+9)=0.10`); serves the lowest arm whose `q ≤ uplift_threshold` (default 0.15). With `armed=false` (shipped default) the pick is computed and recorded (`uplift.mode="shadow"`) but never changes the effective score; only `armed=true` lets a picked higher tier raise it (never lowers below the deterministic floor).
- **Audit sampling**: `should_audit`/`audit_arm` deterministically hash-sample 1-in-`audit_every` (default 8) below-frontier reviews for a frontier double-review, capped at `max_audits_per_drain` (default 1) per drain; active in shadow *and* armed modes; costs a flat-rate quota only (its own separate cap, never counted against the review budget). `audit_diff` compares fingerprints to find findings the served arm missed, feeding `misses` on that arm-cell's posterior.
- **Cascade**: armed-only re-review by the next-higher arm, triggered on any of: a verified CRITICAL in the served review, `rejected ≥ cascade_hallucination_min` (default 3), or a truncated packet. Never fires for a top-tier review; consumes a normal review-budget slot; skipped if the drain's LLM review budget is already exhausted.

Feature bucket is 2-valued only: `"sec"` if any triage reason names a security signal, else `"plain"`. Cost accrues on actual spend, not on parse success. `aramid autolearn --rebuild` replays every registered repo's ledger events from scratch into a fresh empty state (safe because the state file is fully derived).

### Give-up valve
Shared primitive `prior_note_count(ledger, consumer, item_id, prefix)` (`consumers/base.py`) that counts prior `CONSUMER_RUN_FINISHED` events for a (consumer, item_id) pair whose `note` starts with an exact prefix string. Once a per-consumer threshold is reached, the consumer OK-skips permanently (for that head) instead of retrying forever. Known thresholds: `llm_review` malformed-response ×3 (`_MALFORMED_GIVE_UP=3`); `mutation` baseline-fail ×3 (`_BASELINE_GIVE_UP=3`, head-scoped); `js_mutation` baseline-fail ×3 and node_modules-link-fail ×3 (`_BASELINE_GIVE_UP=3`/`_LINK_GIVE_UP=3`, head-scoped, independent valves); `dast` target-unreachable ×3 and probe-error ×3 (`_UNREACHABLE_GIVE_UP=3`, head-scoped, independent valves). `regression_pack` and `fuzz` have **no** give-up valve at all — the exact note-prefix strings are load-bearing (each consumer must emit the identical prefix every time for the counter to work).

### PIN_OCCURRENCE
Optional per-consumer-module attribute, read via `getattr(module, "PIN_OCCURRENCE", False)` in the drain; defaults to `False`. Set `True` by `mutation`, `fuzz`, `js_mutation`, and `dast` — all of which have budget-truncated or membership-variable batches across drains, so positional occurrence-index fingerprints would drift and create ghost never-resolving findings. When set, fingerprinting instead pins one finding per `(tool, rule, file, line-content)` and collapses/drops duplicates. `regression_pack` and `llm_review` do **not** set it (their finding-sets aren't drain-to-drain membership-variable the same way; `llm_review` additionally has its own separate internal fingerprint scheme).

### Store versions
The two files aramid keeps on disk carry the version of their layout (0.19.0, 1.0 blocker API-4). `.aramid/ledger.db` records it in SQLite's `user_version` header (`ledger.LEDGER_SCHEMA_VERSION`, now `1`); `~/.aramid/repos.toml` carries a top-level `schema_version` (`registry.REGISTRY_SCHEMA_VERSION`, now `1`). A file written before 0.19.0 has neither and is read as it is -- the same layout; the first 0.19.0 open of a ledger stamps it. A ledger stamped higher than this aramid knows raises `LedgerTooNew`, so `check` exits `3` with `... was written by a newer aramid (ledger schema N; this one reads up to 1) -- upgrade aramid to use it` (the pre-commit shim lets that through, the pre-push shim blocks). A registry from a newer aramid reads as empty with one stderr line, is never rewritten (`register` refuses, `deregister` raises `RegistryTooNew`, `uninstall` exits `3` having done everything else), and makes `drain` exit `3`. An unreadable one is treated the same way (`RegistryUnusable`): until 0.19.0 `register` wrote over it, so one `aramid init` turned a corrupt fleet into a one-repo fleet. The stamp is the one write a ledger open makes, once per ledger, and a locked database at that moment does not fail the open. A new EVENT KIND is not a layout change: `Ledger.events()` keeps a kind it does not know as an `UnknownEventType` -- in place, since autolearn's rollup cursor counts positions in that list -- and nothing matches it. 0.18.0 was rehearsed reading both stamped files: it ignores the stamps.

---

## 2. Configuration Reference

Config file: `aramid.toml` at the repo root. Three-layer merge: package defaults (`src/aramid/data/defaults.toml`) ← `~/.aramid/config.toml` ← `<root>/aramid.toml`. `CURRENT_SCHEMA_VERSION = 1`. `block_rules` is **not** sourced from `defaults.toml` at all — its base is the separate packaged, curated file `src/aramid/data/block_rules.toml` (`[ruff].block`, `[semgrep].block`, `[deps].block_severity`), and the two layers a person writes merge over it as `[block_rules.<tool>]`. `~/.aramid/config.toml` may demote an entry; a repo's own `aramid.toml` may only add to a list — an entry it drops is restored, with a stderr notice naming it — and may lower `[deps].block_severity`, never raise it above what the layers beneath set (compared as severities: an unrecognised word counts as `medium`), nor drop it by putting a value where the `deps` table was (FN-20).

**Validation (0.19.0).** Each layer a person writes (`~/.aramid/config.toml`, `<root>/aramid.toml`) is checked against the keys aramid reads: every key in `defaults.toml`, with its type, plus `config_keys.OPTIONAL` (`test_command`, `bake_started`, `[tests].command`, `[mutation].test_command`, the two `baseline_timeout_s` keys, `[shadow]`); `block_rules` tool tables are left open. An unknown key or table, a key in the wrong table, a wrong type, and a retired key (`scope_subpath`, `[llm].model_openrouter`, `[dast].block_armed`, `[dast].start_command`) each print `aramid: config: <file>: <problem>` on stderr, once per process, and a `WARN` row under `doctor`'s `config:` section. WARN only (DEC-4): what is loaded, and every exit code, are unchanged.

### Top level

| Key | Type | Default | Meaning |
|---|---|---|---|
| `schema_version` | int | `1` | Config schema tag; `load_config` warns to stderr if a repo's value differs from `CURRENT_SCHEMA_VERSION`. |
| `semgrep_block_armed` | bool | `false` | OWASP-bake arming flag; while false, semgrep BLOCK-tier findings are demoted to WARN. Flipped by `aramid arm`. |
| `ignore_paths` | list[str] | the 8 built-ins below (set in `defaults.toml`) | Exclude patterns. The 8 built-ins — `.aramid/`, `graph-out/`, `.graphite*`, `.cache/`, `node_modules/`, `.venv/`, `__pycache__/`, `.git/` — are the default and are always unioned back in regardless of repo config (never removable); a repo's `ignore_paths` adds to them. |
| `bake_started` | str \| None | `None` (absent from defaults.toml — TOML has no null literal) | ISO date string set by `init`'s repo stub marking when the WARN-only bake period began; reported by `status` as "bake in progress, day N". |
| `test_command` | str \| None | `None` | **Legacy alias for `[tests].command`.** Shipped in schema v1 documented but with no read site at all; now consumed by `pipeline.run_gate` as the fallback when `[tests].command` is unset. `[tests].command` wins if both are set, by presence: `command = ""` in `[tests]` blocks the fallback. Since 0.19.0 the mutation drain consumer honours it too, after `[mutation].test_command`; the gate, `toolset`, `doctor` and the consumer all resolve it through `config.effective_test_command`. Prefer `[tests].command` in new config. |
| `tdd_block_armed` | bool | `false` | Arming flag: code-without-test (`tdd`) findings BLOCK at pre-push. A root-table key, although the rest of the TDD gate's config is under `[tdd]`. Flipped via `aramid arm --tdd`. |
| `agent_block_armed` | bool | `false` | Arms the agent `pre-tool-use` hook: a git commit or push carrying a hook bypass (`--no-verify`, `core.hooksPath`) is REJECTED in an agent session instead of advised against. Changes no finding's tier and nothing a person runs at a terminal. Flipped via `aramid arm --agent`. |

### `[timeouts]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `pre_commit` | int (s) | `5` | Wall-clock budget for the pre-commit gate. |
| `pre_push` | int (s) | `300` | Wall-clock budget for the pre-push gate. |
| `stall_s` | number (s) | `300` | Seconds a child process tree may show no CPU and write no output before aramid kills it as stalled instead of waiting out the wall-clock budget. `0` turns the watchdog off. The tree is sampled every 15 s (`SAMPLE_S`), so the kill comes after between `stall_s` and `stall_s` + 15 s of idleness -- never earlier than about 315 s from launch at the default -- and a run whose budget is at or under that reads as a `timeout` (whose text ends with the trailing idle time), not a stall: at the defaults that is every gate runner, so a stall verdict is for the long-budget callers (the mutation and js_mutation baselines, the drain's consumers) or a lowered `stall_s`. A negative value turns the watchdog off, like `0` (`set_stall_window` clamps it to 0); a non-numeric value, a bool, or a `timeouts` that is not a table falls back to `300`. Set it above the longest quiet wait your suite legitimately has. |

Code's own ultimate fallback if the section were entirely absent: `60.0`.

### `[tests]`

The BLOCK-tier `tests` gate (`--gate pre-push` and `--gate all`). Read by `pipeline.run_gate`, which resolves the section onto `RunContext.test_command` / `.test_timeout_s` / `.tests_enabled` — the Runner protocol is `run(ctx)`, so ctx is the only channel a runner has to config.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | `false` makes the runner **inapplicable**, so it is never selected and therefore never counts as degraded. (Degrading it instead would block every push — the very thing disabling it avoids.) A notice is printed on every gate run where this suppresses a real suite. |
| `command` | str \| list[str] \| None | `None` (absent from defaults.toml — TOML has no null literal) | Overrides detection entirely. A string is split POSIX-style (`shlex.split`); a list is used verbatim — **prefer the list form on Windows**, since POSIX splitting eats backslashes. Never run through a shell. Setting it also makes the gate applicable to repos whose suite `detect_tests` doesn't recognize. Falls back to the legacy top-level `test_command`. |
| `timeout_s` | int (s) | `300` | Per-invocation subprocess timeout. **Capped by `[timeouts].<gate>`**: `run_gate` abandons any runner still going at the gate's wall-clock budget, so a larger `timeout_s` can never be reached — aramid warns to stderr when the two are set incoherently, and does *not* silently override either. Raise both to allow a longer run. |

Why it exists: `tests` is in `BLOCK_TIER_KEYS`, so a suite that overruns the timeout degrades the block tier and `policy.escalate_degraded` returns 1 at pre-push. With no way to point the gate at a fast subset, **every push blocks on any repo whose suite exceeds the budget** — aramid's own (~900 s) included. A gate that must routinely be bypassed with `--no-verify` trains the bypass, which disables every other check too.

Two invariants worth keeping in mind when touching this:

- BLOCK-tier escalation keys on the registry **key** (`results["tests"]`), not on `RunnerResult.tool`. A custom `make test` reports `tool == "make"`, which name-matches nothing in `BLOCK_TIER_KEYS`; if that ever switched to name-matching, configuring a command would silently demote the test gate out of BLOCK tier.
- A configured command that parses to empty argv degrades `MISSING` rather than returning zero findings — a gate cannot fall silent because its own config is malformed. Likewise pytest's rc 5 ("no tests collected") stays blocking: a selector matching nothing is a vacuous gate, not a pass.

**Detection rules**: `detectors.detect_tests(root)` returns `"pytest"` iff a real Python test file exists somewhere in the tree — `test_*.py`, `*_test.py`, or `conftest.py`. A bare `tests/` directory is deliberately **not** a signal on its own: that was the false-positive bug (a TypeScript repo's `tests/` directory of `*.test.ts` files used to read as a pytest suite, ran `pytest -q`, got exit `5` for "no tests collected", and blocked every push). It returns `"npm"` iff `package.json` declares a `scripts.test` entry. Both walks prune dot-directories, `node_modules/`, `venv/`, and `build/`, so vendored/build-tree files never contribute either signal. This detection is bypassed entirely by an explicit `[tests].command` (or the legacy `test_command`), which is checked first and always wins.

**Dual-stack repos** (both a Python test file AND an npm test script): `runners/tests.py` runs **both** suites and aggregates, rather than silently picking one — the exact bug class this module exists to close, a check that reports nothing for a reason indistinguishable from "clean." The shape mirrors `runners/deps.py`'s `_run_mixed` (two sub-results attached via `.sub_results`), but the state rule is inverted: the combined result is `OK` **iff both** sub-suites are `OK` (deps' analogous aggregate uses OR — a degraded/missing suite there is still a useful partial result; here it must still block). A failing sub-suite still reports `ToolState.OK` with a non-zero `returncode`; it blocks through the ordinary `tests-failed` finding, not through the aggregate's `.state` (which is meaningless to read directly on the combined result — consult `.sub_results` for the real per-suite outcomes). The two suites run sequentially, sharing one wall-clock deadline (`ctx.gate_deadline`) rather than each getting a full independent `[tests].timeout_s`.

**The npm side is promoted to a real second suite only when a JS package-manager lockfile is present** (`package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock`, via `detect_package_manager`). A `package.json` `scripts.test` entry with nothing installed behind it is common — e.g. `npm init`'s own default stub, `"... && exit 1"` — and promoting every such stub to a second concurrent BLOCK-tier suite would manufacture false blocks on repos that only ever meant that `package.json` for tooling like prettier/husky. Without a lockfile, only pytest runs and a stderr notice explains that npm was skipped rather than silently dropping it. This lockfile gate applies **only** to the promotion decision: a repo with npm detected but no pytest still runs `npm test` with no lockfile required at all, unchanged.

**A detected suite whose own tool can't run.** Inside a dual-stack run, if one sub-suite's binary can't be resolved at all (not installed, not on PATH), that sub-result comes back `MISSING` and now surfaces a `tool="tests"`, `rule="tests-tool-missing"` finding — unconditionally `BLOCK` per `policy.classify`, same tier as `tests-failed`, so the push fails with a stated reason instead of a bare degraded exit code. **This is narrower than it may sound: it fires only for a sub-result of a dual-stack run.** A single-suite repo (only pytest, or only npm, detected) whose one tool is missing still gets the pre-existing, unchanged behavior — zero findings from `runners/tests.py`, degrading the BLOCK tier via `degraded_block_tier`/`--accept-degraded` exactly as before this dual-suite path existed. Closing that single-suite gap (the more common case in practice — an unactivated venv or a slim CI image missing pytest entirely) is a separately tracked follow-up. `aramid doctor` does probe it (`probe_tests`: pytest/npm, or the binary a configured `[tests].command` names, resolved the way the gate would) and exits `2` when a detected suite's tool cannot be resolved, so the single-suite case is visible before a push.

**Notices.** Six independent stderr notices exist around `[tests]`: the pre-existing `[tests].enabled = false` notice (fires only when a suite or command actually exists to be suppressed); two added by Task 4 for a false-negative/skipped suite, both pointing at `[tests].command` as the fix — `detect_tests()` finds nothing despite a plausible test setup existing anyway (`tests/`, `test/`, `pytest.ini`, `tox.ini`, or `[tool.pytest.ini_options]` — e.g. a custom `python_files` pattern, unittest-style `testfoo.py` naming, or a doctest-only suite that the detector's literal filename match doesn't recognize), and both kinds detected but no lockfile backing the npm side (the case above); two independent budget-vs-timeout notices — one dual-suite-specific (fires only inside the lockfile-present dual-suite branch, comparing the effective per-suite timeout, defaulted via `tests.TIMEOUT_S` when unset, against the shared gate budget) and one general (fires whenever `[tests].timeout_s` is explicitly set above the gate budget, regardless of single- or dual-stack — the same check the `timeout_s` row above already documents); and a sixth, separate, differently-worded notice that `runners/tests.py` itself prints at actual dual-suite execution time for the same no-lockfile case. The last is a deliberate duplication across two independent code paths (pipeline's pre-flight check vs. the runner's own runtime check), not a bug — Task 4 kept both so neither's removal silently reopens the other's gap.

### `[triage]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `min_score` | int | `40` | Zero-token triage score threshold; items scoring ≥ this are queued for drain. |
| `extra_security_paths` | list[str] | `[]` | Additional path globs treated as security-sensitive on top of built-in heuristics. |

### `[drain]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `interval_hours` | int | `4` | Scheduling cadence for the drain job. |
| `max_items_per_drain` | int | `10` | Cap on ledger items processed per drain run. Distinct from `[llm].max_items_per_drain` (=3). |
| `item_expiry_days` | int | `30` | Items older than this are expired out of the queue. |
| `wall_clock_budget_s` | int (s) | `600` | Whole-drain wall-clock budget. |
| `hard_deadline_s` | int (s) | `5400` | Seconds from the drain's start to its hard deadline: the running consumer is stopped and recorded `degraded`, and the item stays queued. Capped 15 min under `interval_hours`; ≤ 0 or non-numeric reads as the default, under 60 reads as 60. |

### `[pack]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Read only by the deterministic **gate** (`pipeline.py`): when true, the compiled regression pack (`.aramid-rules/regression.yml`) rides along as an extra semgrep `--config` at pre-commit/pre-push. It does **not** gate the drain-time `regression_pack` consumer — that consumer is gated solely by whether the pack file exists on disk (see the Consumer reference). |
| `pack_block_armed` | bool | `true` | Arming flag for `aramid-regression.block.*` rules — its own flag, separate from `semgrep_block_armed`. Default `true` (enforces immediately). No `aramid arm --pack` subcommand exists; meant to be hand-edited. |

### `[llm]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Master switch for the LLM reviewer consumer. |
| `max_items_per_drain` | int | `3` | Cap on items reviewed by the LLM per drain. Distinct from `[drain].max_items_per_drain` (=10). |
| `call_timeout_s` | int (s; `float()`'d) | `240` | Per-call timeout for an LLM provider invocation. |
| `packet_max_bytes` | int | `120000` | Max size of the review packet sent to the LLM; oversized packets get sections dropped. |
| `llm_block_armed` | bool | `false` | Bake-then-arm flag: confirmed-CRITICAL LLM findings WARN until armed. Flipped via `aramid arm --llm`. |
| `provider_order` | list[str] | `["claude-cli", "codex-cli", "ollama-cloud"]` | Ordered provider chain (consumed only as a set/availability check). `openrouter` is opt-in only. |
| `openrouter_monthly_cap_usd` | float | `5.0` | Monthly USD spend cap for the openrouter provider. |
| `max_refutes_per_drain` | int | `6` | Hard cap on cross-provider refute calls across a whole drain; once hit, further fresh CRITICALs are treated like a transport-failed refute (demoted to high, `confirmed=False`). |

**`[[llm.ladder]]`** (array of tables):

| tier | provider | model | effort | min_score |
|---|---|---|---|---|
| `"cheap"` | `"ollama-cloud"` | `"deepseek-v4-flash"` | `""` | `40` |
| `"mid"` | `"codex-cli"` | `"gpt-5.5"` | `"medium"` | `60` |
| `"frontier"` | `"claude-cli"` | `"opus"` | `"high"` | `80` |

**`[llm.autolearn]`**:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Master switch for the auto-learn engine (telemetry + shadow decisions + audit double-reviews). |
| `armed` | bool | `false` | Whether shadow-computed uplift decisions actually change which arm serves. Flipped via `aramid arm --autolearn`. |
| `uplift_threshold` | float | `0.15` | Serve the lowest arm whose Thompson-sampled miss probability is ≤ this. |
| `audit_every` | int | `8` | Audit 1-in-N below-frontier reviews with a frontier double-review. |
| `max_audits_per_drain` | int | `1` | Cap on audit double-reviews per drain. |
| `cascade_hallucination_min` | int | `3` | Cascade re-review trigger threshold (armed only). |

### `[mutation]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Master switch. |
| `max_mutants` | int | `20` | Mutants generated-and-tested per queue item. |
| `wall_budget_s` | int (`float()`'d) | `600` | Whole-item wall clock for the mutant loop. |
| `mutant_timeout_s` | int (`float()`'d) | `120` | Per-pytest-invocation timeout (stage 1 and stage 2 alike). |
| `confirm_cap` | int | `3` | Cap on full-suite confirmation runs per item. |
| `retest_open_survivors` | bool | `true` | When the item's range changes any test file, regenerate each open or `pending_retest` mutation survivor from its fingerprint and re-run it through the same stage-1 / full-suite confirmation (and, on the item the drain synthesizes for a repo with an empty queue, the `pending_retest` rows alone); a confirmed kill is claimed as `mutant_killed`. Survivors bound by `.aramid-suppressions.toml` are skipped; the range's mutation scores are untouched. |
| `retest_cap` | int | `3` | Re-tests per item. A survivor whose module a changed test in the range maps to (the `gap_addressed` stem rule) is re-tested first, on its own confirm budget (one per re-test) and outside `max_mutants`; every other survivor runs after the range's own mutants, inside the range's budget. One survivor id names every line with that content, and a claim needs every occurrence killed, so a survivor whose occurrences outnumber the mutant or confirm slots a pass has left is skipped before its first run rather than half-tested (a later pass with room picks it up; the empty-queue re-test item has room for min(`max_mutants`, `confirm_cap`) occurrences, and a survivor with more is never re-tested -- the gate keeps it open and `aramid status` names it, see the user guide). The note reads `re-tested N of M open survivor(s), K killed`, plus `C of D survivor(s) named by a changed test re-tested first` when there were any, plus `S survivor(s) not re-tested: occurrences exceed the remaining re-test budget` when any were skipped. |
| `test_command` | str \| list[str] | unset | The whole-suite command for the baseline and every stage-2 confirmation. Unset: `[tests].command`, else the legacy top-level `test_command`, else `python -m pytest -q`. Separate from `[tests].command` on purpose: the gate should run what CI runs, while mutation's baseline has to fit `baseline_timeout_s`. |
| `baseline_timeout_s` | int (`float()`'d) | `mutant_timeout_s` × 4 (`480`) | Budget for the baseline suite run that establishes green before any mutant. Not in `defaults.toml`, because its default is derived. A timed-out baseline notes `baseline timeout: <suite> did not finish within the <N>s budget`; after repeated timeouts mutation gives up on the repo until this key or `test_command` changes, and the give-up note names both. |
| `mutation_block_armed` | bool | `false` | Arming flag: surviving-mutant findings BLOCK at pre-push. Flipped via `aramid arm --mutation`. |
| `score_block_armed` | bool | `false` | Arming flag: mutation-score *transition* regressions BLOCK at pre-push; rate deltas stay WARN. Flipped via `aramid arm --mutation-score`. |

Drain-time survivors are recorded `WARN` either way; the pre-push gate applies the flag, so arming covers survivors recorded before it.

### `[js_mutation]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Master switch. |
| `max_mutants` | int | `20` | Mutants generated-and-tested per queue item. |
| `wall_budget_s` | int (`float()`'d) | `600` | Whole-item wall clock for the mutant loop. |
| `mutant_timeout_s` | int (`float()`'d) | `120` | Per `<pm> test` invocation (single-stage — no `confirm_cap` key here). |
| `baseline_timeout_s` | int (`float()`'d) | `mutant_timeout_s` × 4 (`480`) | Budget for the baseline `<pm> test` run. Not in `defaults.toml`, because its default is derived. |

No arming flag exists in `[js_mutation]`.

### `[fuzz]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Master switch. |
| `max_functions` | int | `10` | Functions fuzzed per queue item. A candidate the driver cannot call (no usable type hints) is skipped without spending it, and the note says `N skipped (unhinted)`; `truncated` means a callable one was left over. |
| `cases_per_function` | int | `50` | Fuzz cases generated per function. |
| `wall_budget_s` | int (`float()`'d) | `300` | Whole-item wall clock budget. |
| `batch_timeout_s` | int (`float()`'d) | `120` | Timeout for the single driver subprocess. |
| `skip_name_patterns` | list[str] | `["*deploy*","*delete*","*remove*","*drop*","*push*","*send*","*upload*","*kill*","*wipe*","*publish*","*destroy*","*truncate*"]` | fnmatch patterns of function names never to fuzz. |

No arming flag exists in `[fuzz]`.

### `[dast]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Master switch. |
| `base_url` | str | `""` | Target base URL. Empty ⇒ OK-skip. |
| `paths` | list[str] | `[]` | Extra paths to probe on top of the curated exposed-path set. |
| `timeout_s` | int (`float()`'d) | `10` | Per-request timeout. |

### `[tdd]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Master switch for the pre-push code-without-test producer (`tdd`: one finding per changed production `.py` file when the range adds no test line) and for its auto-resolution. Its arming flag is the top-level `tdd_block_armed`. |

### `[red_proof]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Master switch for the pre-push red-first proof: each test file the range changes is run against the range's base tree, and a file whose tests all pass there was never red (`red-proof` / `test-not-red`). |
| `red_proof_block_armed` | bool | `false` | Arming flag: never-red findings BLOCK at pre-push. Flipped via `aramid arm --red-proof`. |
| `wall_budget_s` | int (`float()`'d) | `120` | Wall clock for the whole scan; files left when it runs out are skipped, which means "not scanned", never "clean". |
| `test_timeout_s` | int (`float()`'d) | `60` | Per pytest invocation against the base tree. |

### `[shadow]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `shadow_block_armed` | bool | `false` | Arming flag for the module-shadow detector: an `aramid.py` or `graphite.py`, or an `aramid/` or `graphite/` directory holding an `__init__.py`, at the repo root is imported instead of the installed package by every `python -m` launched there. The detector runs at every gate, pre-commit included, and ships disarmed (WARN). Flipped via `aramid arm --shadow`. Not in `defaults.toml`. |

### `[deps]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `cargo_audit_warnings` | bool | `false` | Surface cargo-audit's RUSTSEC `warnings` (unmaintained, unsound, yanked crates) as `cargo-audit-warnings` findings. WARN-tier by construction: they can never block, armed or not. Off by default because most carry no fix. |

The dependency BLOCK threshold is not here: it is `block_severity` in `block_rules.toml`'s own `[deps]` table (see the section intro).

### `[hooks]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `pre_push_match_ci` | bool | `false` | The generated pre-push shim runs `check --gate pre-push --all --strict`, what CI's pre-push-tier step runs (ruff included, since FN-32; CI's pre-commit-tier step, `check --all --strict`, has no hook equivalent), instead of the changed-files range, and passes every exit code through instead of mapping `2` to `0`. Takes effect when the shim is regenerated (`aramid init`); turn it on together with `aramid rebaseline`, or the first full scan's never-seen findings are new and the ratchet blocks the push on them. An unreadable config yields the default shim. |

### Key naming collisions (same name, different meaning)

- **`max_items_per_drain`**: `[drain]` = `10` (total items per drain run) vs. `[llm]` = `3` (LLM reviews per drain).
- **`min_score`**: `[triage]` = `40` (queueing threshold) vs. each `[[llm.ladder]]` entry's own `min_score` (40/60/80, a reviewer-arm band floor).

### Arming flags — full inventory

1. `semgrep_block_armed` (top level) — default `false` — armed via `aramid arm`.
2. `[pack].pack_block_armed` — default `true` — no arm subcommand; hand-edited.
3. `[llm].llm_block_armed` — default `false` — armed via `aramid arm --llm`.
4. `[llm.autolearn].armed` — default `false` — armed via `aramid arm --autolearn`.
5. `tdd_block_armed` (top level) — default `false` — armed via `aramid arm --tdd`.
6. `[mutation].mutation_block_armed` — default `false` — armed via `aramid arm --mutation`.
7. `[mutation].score_block_armed` — default `false` — armed via `aramid arm --mutation-score`.
8. `[red_proof].red_proof_block_armed` — default `false` — armed via `aramid arm --red-proof`.
9. `[shadow].shadow_block_armed` — default `false` — armed via `aramid arm --shadow`.
10. `agent_block_armed` (top level) — default `false` — armed via `aramid arm --agent`.

`[dast]`, `[fuzz]` and `[js_mutation]` have **no** arming flag of any kind. What each flag changes: see "Arming / bake-then-arm" in section 1.

---

## 3. Consumer Reference

### regression_pack
- **NAME**: `regression_pack`. Findings emit `tool="semgrep"` (not `tool="regression_pack"`).
- **Purpose**: drain-time replay of the compiled attack-pack ruleset (`<repo>/.aramid-rules/regression.yml`, compiled by `aramid pack` from previously-resolved findings) against the queue item's changed files — catches commits/ranges that bypassed hooks.
- **Config keys**: none read by the consumer itself (only whether the pack file exists on disk gates it); `[pack].pack_block_armed` (default `true`) is consulted later, only inside `policy.classify`. Uses the global `ignore_paths` to prune changed files.
- **WARN/BLOCK + arming**: findings are `tool=semgrep`, rule prefix `aramid-regression.block.*` → BLOCK/WARN per `[pack].pack_block_armed` — the only drain consumer that can BLOCK out of the box (default-armed).
- **OK-skip / give-up**: OK-skip (not degraded) when no pack file exists (`"no pack file"`) or no changed files survive the diff+ignore-path filter+existence check (`"no files in range"`). DEGRADED when semgrep's subprocess isn't `ToolState.OK` (`f"semgrep {checked.state}"`). No give-up counter.
- **Stack requirement**: needs a compiled pack file (`.aramid-rules/regression.yml`) to exist; otherwise a total no-op.
- **Token cost**: always `0.0`.

### llm-review
- **NAME**: `llm-review` (consumer module `llm_review`). The only consumer that calls an LLM / spends tokens or dollars.
- **Purpose**: assemble a redacted evidence packet (zero tokens) for the queue item, send it down the provider chain for one review call, mechanically verify each candidate's evidence is a verbatim quote anchored to a real line in HEAD, pre-refute-dedupe against the ledger, then spend one cross-provider refute call per fresh CRITICAL candidate before recording.
- **Config keys**: `[llm]` (`enabled`, `max_items_per_drain=3`, `call_timeout_s=240`, `packet_max_bytes=120000`, `llm_block_armed=false`, `provider_order`, `max_refutes_per_drain=6`), `[[llm.ladder]]` (cheap/mid/frontier), `[llm.autolearn]` (`enabled`, `armed`, `uplift_threshold`, `audit_every`, `max_audits_per_drain`, `cascade_hallucination_min`).
- **WARN/BLOCK + arming**: always recorded WARN at drain time (`policy.classify`'s hard-coded `tool=="llm-review"` branch). Becomes BLOCK only later, at the PRE_PUSH gate, via `review.llm_gate_findings`: requires `[llm].llm_block_armed=true` AND the finding is confirmed (survived cross-provider refute) AND severity is critical. Computed fresh from ledger state every gate run — arming applies retroactively.
- **Auto-resolve** (`review.auto_resolve_llm`, at every pre-push gate, before the LLM block check): an open finding resolves `evidence_gone` when its whitespace-stripped evidence quote is no longer in its file at HEAD. A path absent at HEAD is searched for first (FN-22): `git grep -F` on the quote's longest line across every tracked file at HEAD, then the whole stripped quote on each hit. Found anywhere, the finding stays open (a `git mv` is not a fix); found nowhere, or the search fails, it resolves as before (a deleted file still clears). A quote moved into another file while its own file stays is still resolved. A `GitTimeout` resolves nothing and fails the gate.
- **OK-skip / give-up**: OK-skip when `[llm].enabled=false` (`"llm disabled"`); empty packet (`"empty packet"`); no provider CLIs installed at all (`"llm skipped: no providers installed"`); give-up valve — malformed responses ≥3 (`_MALFORMED_GIVE_UP=3`, note `"llm giving up: repeated malformed output"`). DEGRADED when per-process review budget exhausted (`"llm budget exhausted"`); every configured provider installed but unavailable (`"all providers unavailable"`); or a response parses to `None` (`f"malformed response from {provider}"`).
- **Stack requirement**: at least one of the configured provider CLIs (claude-cli / codex-cli / ollama-cloud, or opt-in openrouter) must be installed and reachable.
- **Token cost**: the only consumer with nonzero cost; accrues on spend, not on parse success (unparseable responses still burn tokens). Cascade re-review consumes a normal review slot; audit double-review has its own separate cap (`max_audits_per_drain`); refute calls have their own cap (`max_refutes_per_drain=6`).

### mutation
- **NAME**: `mutation`, findings `tool="mutation"`.
- **Purpose**: mutation-test the Python functions the queue item's commits touched, inside a throwaway `git worktree --detach` at `item.head`. Two-stage: targeted pytest run per mutant, then a capped full-suite confirmation run — a survivor is only reported once the full suite passes on it. Operators: `cmp-flip`, `bool-swap`, `int-bound`, `not-drop`.
- **Config keys**: `[mutation]` (`enabled=true`, `max_mutants=20`, `wall_budget_s=600`, `mutant_timeout_s=120`, `confirm_cap=3`).
- **WARN/BLOCK + arming**: no arming knob exists; findings are always medium severity → WARN under the catch-all.
- **OK-skip / give-up**: OK-skip when `enabled=false` (`"disabled"`); no non-test Python files changed (`"no python files in range"`); no pytest stack detected — deliberately OK not DEGRADED (`"no python test stack (mutation skipped)"`); give-up valve — baseline failed 3 times at this exact head (`_BASELINE_GIVE_UP=3`, head-scoped note from `mutation.failing_note_prefix(head)` → `f"baseline failing (last seen @ {head12})"`) → `"mutation giving up: baseline persistently failing"`. **ERROR** (not degraded) when `git worktree add` fails. DEGRADED when the full-suite baseline run on the pristine worktree doesn't pass.
- **Runs that certify nothing** stay `ok` (`degraded` would pin the queue item) and carry a note `status` lists under "consumers doing no work", which the fleet row grades as `consumers_healthy: false`: `"no mutants tested: N generated, 0 certified -- ..."` when the wall budget ran out before the first mutant, and `"no mutant reached a verdict: N tested, T timed out, E errored -- the baseline took Bs; [mutation].mutant_timeout_s is Ms"` when mutants ran and none reached a verdict (FN-23). The verdicts are a stage-1 kill, a full-suite kill and a confirmed survivor; a timeout or error at either stage, or a stage-1 survivor the confirm cap cut, is none of them.
- **Stack requirement**: `"pytest" in detectors.detect_tests(root)` — true only if a real pytest-shaped file exists (`test_*.py`, `*_test.py`, or `conftest.py`); a bare `tests/` directory alone is not a signal (see the `[tests]` config section's detection-rules note above).
- **Token cost**: always `0.0`.
- **Latent mutants**: a generator mutant on a line the unit suite never executes cannot be killed by the two-stage confirmation (both stages run `tests/unit` only), so it surfaces as a survivor the first time the drain draws it -- the 2026-09-14 burn-down found and pinned 300 of them (`docs/superpowers/plans/2026-09-14-latent-mutant-burndown.md`). `scripts/latent_mutants.py measure <coverage.json>` counts what is left per file from a unit-suite coverage JSON (`python -m pytest tests/unit --cov=aramid --cov-report=json:cov-unit.json`), attributing a mutant to the innermost statement containing its line; the `ubuntu-latest / 3.12` CI leg runs `check --baseline tests/latent_mutants_baseline.json --verbose` after the full suite: a file above its committed count fails the leg (naming the file and the stage-1 test set to pin it in), a file below it is reported so the baseline can be lowered with `write-baseline` -- never raise it by hand; every latent mutant is named in the log. The same leg then runs `no-rise tests/latent_mutants_baseline.json --previous <the copy at github.event.before>`: a per-file count above the pre-push copy's fails the leg, so a hand raise cannot land in the same push as the code it excuses (lowering never was a bypass -- it fails `check`; a ref-creating push has no before and skips out loud). The baseline was written from that leg's own measurement, not from the Windows machine that runs the drain (an untracked `graph-out/graph.json` and the Windows-only tests make the two counts differ). The generator used is the tree's own (imported from `src/` ahead of any installed aramid), because the drain that draws them runs whatever ships next.

### js_mutation
- **NAME**: `js_mutation` (config section `[js_mutation]`), findings `tool="js-mutation"` (hyphenated — differs from the module name/config key).
- **Purpose**: JS/TS analog of `mutation`, single-stage: mutate changed lines in a throwaway worktree (with the real repo's `node_modules` junctioned/symlinked in), run `<pm> test` once per mutant — a full-suite pass on a mutant is the confirmed survivor. Operators: `cmp-flip` (like-for-like relational/equality swap), `logical-swap` (`&&`↔`||`).
- **Config keys**: `[js_mutation]` (`enabled=true`, `max_mutants=20`, `wall_budget_s=600`, `mutant_timeout_s=120`; no `confirm_cap`).
- **WARN/BLOCK + arming**: no arming knob exists; catch-all WARN.
- **OK-skip / give-up**: requirements checked in order, each OK-skip: no npm test script (`"no js test stack (mutation skipped)"`); no resolvable package-manager binary (`"js package manager not found (mutation skipped)"`); no `node_modules/` in the real repo root (`"node_modules not installed (js mutation skipped)"`); `enabled=false` (`"disabled"`); no JS/TS files changed (`"no js files in range"`); two independent give-up valves, each `=3` with head-scoped prefixes from `mutation.failing_note_prefix(head)` / `js_mutation.link_note_prefix(head)` → `f"baseline failing (last seen @ {head12})"` / `f"node_modules link failing (last seen @ {head12})"` → `"js mutation giving up: baseline persistently failing"` / `"...node_modules link persistently failing"`. **DEGRADED** (not ERROR, unlike `mutation`) when `git worktree add` fails, the node_modules junction/symlink fails, or the pristine-worktree baseline test run doesn't pass.
- **Runs that certify nothing** stay `ok` with the same two no-work notes as `mutation` (FN-23): `"no mutants tested: N generated, 0 certified -- ... Raise [js_mutation].wall_budget_s."` and `"no mutant reached a verdict: N tested, T timed out, E errored -- the baseline took Bs; [js_mutation].mutant_timeout_s is Ms"`. Every mutant runs the whole `<pm> test`, so a suite slower than `mutant_timeout_s` can reach no verdict at all; a kill or a survivor is the only verdict.
- **Stack requirement**: `"npm" in detectors.detect_tests(root)`, a resolvable npm/pnpm/yarn binary, and an existing `node_modules/`.
- **Token cost**: always `0.0`.

### fuzz
- **NAME**: `fuzz`, findings `tool="fuzz"`.
- **Purpose**: call top-level, type-hinted Python functions touched by the queue item's commits with deterministic seeded inputs, inside a throwaway worktree; report DEEP-CRASH exceptions as WARN-tier findings. Candidate selection is AST-only; fuzzing runs in a separate subprocess (`python -m aramid.fuzzdriver <spec.json>`) that re-checks type hints at import time. `PYTHONHASHSEED=0` is forced for stable crash reproduction. The driver runs in a sandbox inside its own `aramid-fuzz-*` temp shell (FN-31, after a fuzzed `handover._load_key(create=True)` created the real `~/.aramid/handover.key` on 2026-10-07): `HOME`, `USERPROFILE`, `TMP`, `TEMP` and `TMPDIR` point into the shell on every OS, `ARAMID_HANDOVER_KEY_FILE`, `ARAMID_FLEET_DIR` and `ARAMID_TOOLS_DIR` are set under the sandbox home, and `PYTHONUSERBASE` keeps the parent's user site. `APPDATA`, `LOCALAPPDATA` and `XDG_*` are not moved. Only the fuzz child is sandboxed: mutation and red-proof run the consumed repo's own suite, which isolates itself.
- **Config keys**: `[fuzz]` (`enabled=true`, `max_functions=10`, `cases_per_function=50`, `wall_budget_s=300`, `batch_timeout_s=120`, `skip_name_patterns=[...]`).
- **WARN/BLOCK + arming**: no arming knob exists; WARN only.
- **OK-skip / give-up**: OK-skip when `enabled=false` (`"disabled"`); no non-test Python files changed (`"no python files in range"`); no fuzzable functions found (`"no fuzzable functions in range"`). A driver that **times out** is recorded OK — `degraded` would pin the queue item — with a note naming the function it hung in and the marker `no cases run`; that marker is what `aramid status`'s no-work line and the fleet row's `no_work` evidence read, so a consumer that keeps timing out turns `consumers_healthy` red instead of passing silently (exclude the blocking target with `skip_name_patterns`). A driver that **exits non-zero / crashes** or prints **no parseable JSON** is **DEGRADED** (`fuzz driver broken @ <head[:12]>: ...`): the item stays queued and the next drain retries. After three such runs at the same head the consumer gives up (`"fuzz giving up: driver persistently broken"`), recorded OK so the item can drain and reported as stood down. **ERROR** when `git worktree add` fails. (Until 2026-08-11 every driver failure was swallowed as OK; `6a97508` made them visible.)
- **Stack requirement**: Python stack with top-level, non-async, type-hinted functions in changed lines.
- **Token cost**: always `0.0`.

### dast
- **NAME**: `dast`, findings `tool="dast"`.
- **Purpose**: passive web-hygiene scan of a user-declared `base_url` via an owned stdlib HTTP prober — five check families: headers (HSTS/CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy missing), cookies (Set-Cookie missing Secure/HttpOnly/SameSite), transport (plaintext HTTP, expired/invalid TLS cert), exposed paths (curated probes for `/.git/config`, `/.git/HEAD`, `/.env`, `/server-status`, plus user-declared `paths`), and banner leaks (`Server`/`X-Powered-By` version strings). Evidence is always synthetic metadata, never raw response body/cookie/secret values.
- **Config keys**: `[dast]` (`enabled=true`, `base_url=""`, `paths=[]`, `timeout_s=10`; no arming flag).
- **WARN/BLOCK + arming**: no arming flag; all dast findings are WARN-tier via the catch-all.
- **OK-skip / give-up**: OK-skip when `enabled=false` (`"disabled"`); `base_url` empty (`"no dast target configured"`); malformed `base_url` (`"invalid dast base_url (need http(s)://host with a valid port)"`); two independent give-up valves, both `=3`, head-scoped prefixes `f"dast target unreachable (last seen @ {head12})"` / `f"dast probe error (last seen @ {head12})"` → `"dast giving up: target persistently unreachable or erroring"`. DEGRADED when the target is unreachable (`DastUnreachable`) or the probe crashes unexpectedly — both explicitly not permanent (app may simply not be up at drain time).
- **Stack requirement**: none structural — purely config-declared (`base_url` must be set by the operator; no auto-discovery of a running app).
- **Token cost**: always `0.0`.

---

## 4. CLI Command Reference

Entry points: console script `aramid` (`pyproject.toml` `[project.scripts]`), or `python -P -m aramid` (what the installed git hooks actually call). `aramid --version` prints `aramid <version>` (e.g. `aramid X.Y.Z`) and exits 0. `-h`/`--help` on any (sub)parser exits 0. No subcommand → `aramid: no command` to stderr, exit 3. Unknown/bad subcommand or malformed flags → remapped to exit 3.

### `aramid init [path] [--discover]`
Onboard a repo: write config, install hooks, seed baseline.
- `path` (positional, optional, default `.`).
- `--discover` — walk under `path` (max depth 3) for every directory containing `.git` (skipping `node_modules`, `_tools`, `.venv`, `.git`, `__pycache__`, `.aramid`, `.cache`, `graph-out`, `.graphite*`); runs the full single-repo init flow on each, returning the worst exit code seen.
- Gates on `aramid doctor`; refuses (exit 3) if a BLOCK-tier tool (gitleaks/semgrep) is missing. Writes `aramid.toml` only if absent; always regenerates `ARAMID.md`; appends missing `.gitignore` entries (`.aramid/`, `graph-out/`, `.graphite*`, `.cache/`); installs idempotent hook shims (chains any pre-existing foreign hook to `<hook>.aramid-chained`); registers the repo in the machine-global registry; runs a one-time full-history gitleaks scan (`git log --all`, non-blocking historical findings); writes the ratchet baseline once.

### `aramid check [--gate pre-commit|pre-push|all] [--staged|--range|--all] [--strict] [--json] [--accept-degraded] [--reason REASON] [--no-record]`
Run the gate pipeline.
- `--gate {pre-commit,pre-push,all}` (default `pre-commit`). `all` runs every tool of both hooks (round 126 s4b, when ruff ran only at pre-commit and so neither hook gate saw both; since FN-32 `pre-push` runs ruff too) in mode `all` unless a mode flag is given. No shim invokes it, it never ratchets (the ratchet runs at `pre-push` only), and it skips everything the pre-push gate adds on top of its runners: the TDD test-gap check, the red-first proof, and the LLM and mutation ledger gates (`pipeline.py`, `gate is Gate.PRE_PUSH`). `--gate all --all --strict --json` is a one-step CI form only for a fresh checkout of a repo that has not armed the TDD gate; otherwise use the two steps (user guide, section 10).
- Mode group (mutually exclusive): `--staged`, `--range`, `--all`; default is `staged` for pre-commit, `range` for pre-push, `all` for `--gate all`.
- `--strict` — remaps exit code 2 to 1; 3 passes through unchanged.
- `--json` — render JSON instead of console report.
- `--accept-degraded` — accept a degraded run; `--reason` (default `None`, falls back to `"no reason given"`) records why. Also settable via `ARAMID_ACCEPT_DEGRADED` env var.
- `--no-record` — runs the gate against a sqlite-backup snapshot of the ledger (`commands/check.py::_ledger_snapshot`, reaped in `finally`) so the report answers as a recording run would while nothing reaches `.aramid/ledger.db`; logs are still written. A repo with no ledger yet ends the run with none.
- Fresh-ledger downgrade at `--gate pre-push` with no baseline yet.
- The run's `run_finished` row is written once the exit code is final (FN-24): `record_run` holds it back on the ledger `cmd_check` sets `defer_finish` on, `finish_run` writes it, and `finish_pending` in `finally` writes it for a gate that died first, counted as recorded. Its `blocking` counts `pipeline.gating_blocks` -- the exit code's own predicate, after the ratchet and the LLM/mutation ledger gates -- minus historical findings, and is 0 when the fresh-ledger rule waved the run through. A refusal no finding caused (`refs_moved`, `--strict` on a degraded run) reads 0 and the row says why. Stored verdicts never change: an overridden row stored as `block` is re-opened at every gate start. `status`'s `last run:` line is the count's reader; the fleet row's `evidence.blocking` is a separate count of every BLOCK verdict in the report. Every other `record_run` caller (drain, init, rebaseline) still finishes at once.

### `aramid doctor [--fix]`
Probe (and optionally repair) the toolchain and the hook shim's baked interpreter.
- No flag: probes `gitleaks`, `semgrep`, `ruff`, `pip-audit` via `<exe> --version`, plus the shim's baked interpreter; prints LLM-provider probe lines, autolearn state health, and a `config:` section (one `WARN` row per config-key problem, or one `OK` row; never an exit code).
- `--fix` — `pip install --upgrade`s `ruff`/`semgrep`/`pip-audit` into the current interpreter if missing; downloads a pinned gitleaks v8.30.1 binary into `~/.aramid/tools/` (sha256-verified) if missing, or over aramid's own copy there when it is off the pin (never a PATH gitleaks; written beside it and moved into place); re-probes.

### `aramid status`
Read-only report of ledger/config state; never mutates anything. No flags.

### `aramid resolvers [--json]`
Grades each auto-resolver on what it SAW, not only on what it cleared, which finds a resolver that silently stopped firing. The grades and what each means: the user guide, *`aramid resolvers`*. `--json` prints the machine-readable form. Exits `0` whether or not a resolver is flagged (section 5).

### `aramid notices [list | show <id> | ack <id>]`
aramid's own notices. `list`, the default, prints the pending ones one per line; `show <id>` prints one; `ack <id>` acknowledges it, and an ack anywhere silences it everywhere. Exit codes: section 5.

### `aramid handover [write | show | done]`
The per-repo session handover: an agent writes one before a restart or a long pause, and a fresh session resumes it without the operator. `write` reads the body from stdin, or from `--file FILE` (`-` is stdin); `--author NAME` records who wrote it; `--replace` archives a pending one and writes this one, where without it a second `write` is refused. `show`, the default, prints the pending handover, or `no pending handover`. `done` archives the file under `.aramid/handovers/` and says where; it never deletes, it archives an unreadable or unverified file too (under the fixed name `unverified.json`, never a name taken from an unverified file) except a symlink, which it refuses (remove the link by hand), and a second `done` is `0`. Every subcommand acts on the root of the git repository it runs in, from any subdirectory, and refuses outside a repository where `aramid init` has run. The file is signed with a machine key, so one that did not come from aramid on this machine, or was written for another repo, is printed by `show` only under a `NOT VERIFIED` header, and anything unparseable is named but never printed; the `aramid_handover_show` MCP tool withholds an unverified file's commit, author and body. A body or author holding a lone surrogate is refused, and one already on disk prints escaped. Exit codes: section 5.

### `aramid mutation-score [--json]`
Advisory per-function mutation-score and regression report. `--json` prints the machine-readable form. Advisory: a regression never changes the exit (section 5).

### `aramid triage [rev] [--budget SECONDS]`
Score one commit (or `A..B` range) and enqueue it if risky.
- `rev` (positional, optional, default `HEAD`).
- `--budget SECONDS` (float, default `None`) — wall-clock watchdog via a daemon `threading.Timer`; on expiry, hard-kills with `os._exit(3)`. Unbounded without `--budget`.

### `aramid drain [--all | --repo PATH] [--dry-run] [--max-items N]`
Sweep registered repos, catch-up-triage, pop the highest-scored queued item(s), run consumers, record results.
- Scope group (mutually exclusive): `--all`, `--repo PATH`; default is the current directory.
- `--dry-run` — read-only preview, no lock, no mutation.
- `--max-items N` (int, default `None`) — caps items drained this run.

### `aramid ledger list|show <id>|filter [--tool] [--rule] [--status] [--severity] [--json]|consumers [--consumer NAME] [--last N] [--json]|mark-rotated <id> --reason REASON|mark-not-a-secret <id> --reason REASON|mark-unreachable <id> --reason REASON|resolve <id>... --out-of-scope --reason REASON`
- `list` — every open/known finding, one line each.
- `show <id>` — full record fields plus every ledger event tied to that id (exit 3 if id unknown).
- `filter [--tool] [--rule] [--status] [--severity] [--json]` — all optional/AND-combined. `--status` takes the underlying status string with underscores (`not_a_secret`), which differs from the hyphenated `not-a-secret` label `aramid status` displays. `--json` prints the machine-readable form (the user guide's *Machine-readable output* table).
- `consumers [--consumer NAME] [--last N] [--json]` — the drain's consumer runs, newest first. `--consumer` keeps one consumer by its exact name: `regression_pack`, `llm-review`, `mutation`, `fuzz`, `js_mutation` or `dast`. `--last N` keeps the newest N rows; `--json` prints the machine-readable form.
- `mark-rotated <id> --reason REASON` — `--reason` required; valid when the finding's status is `historical` OR `not_a_secret`, else refuses with exit 3. Accepting `not_a_secret` too is deliberate: a supposed false positive later found to be a real credential can still be rotated — transitions only ever move toward more caution.
- `mark-not-a-secret <id> --reason REASON` — `--reason` required; valid only when the finding's status is exactly `historical` (never a live `open` finding), else refuses with exit 3. Retires a false-positive historical hit (status becomes `not_a_secret`) without asserting a rotation that never happened. Reporting-only and inert at gate time: a re-detected instance still classifies exactly as before, so this is not a gate-bypass path. Neither mark can be undone.
- `mark-unreachable <id> --reason REASON` — `--reason` required; valid only when the finding's status is exactly `open` AND its tool is in the retireable universe (runner-produced, never a producer/consumer tool like `tdd`/`mutation`/`llm-review`) AND not currently selected for this repo, else refuses with exit 3 (unknown id; a producer-tool finding; a non-open status, each with its own message; or a tool that still runs here — that's `aramid doctor`'s problem, not this command's). Retires a finding whose tool has left this repo's live selection (de-selected, disabled, or genuinely removed) so no future run can ever resolve it the normal way. If the tool later returns and re-detects the same finding, it re-opens automatically — like `fixed` and `superseded`, a resting state a re-detect leaves. `aramid status`'s "unreachable candidates" section names exactly which open findings currently qualify.
- `resolve <id> [<id> ...] --out-of-scope --reason REASON` — the other stranded shape: the finding's tool is still selected (so `mark-unreachable` refuses) but its runner will never examine that path again (its file scope narrowed — typecheck to `.py`/`.pyi` in 0.6.1). Records `finding_out_of_scope`, its own event kind; status becomes `out_of_scope`. Refuses with exit 3 when the runner can still examine the path (per the runner's own suffix rule), when the tool has no suffix scope at all (gitleaks, semgrep, tests, deps — "cannot say" is never permission), when the tool is not selected (that is `mark-unreachable`), without `--out-of-scope`, without `--reason`, or for a non-open status. Re-opens on re-detect. `aramid status` lists candidates under "out-of-scope candidates". Several ids per launch: every id is attempted and the exit is the worst of them.
- Bare `aramid ledger` — usage line, exit 3.

### `aramid override <id> --reason REASON`
Suppress a WARN-tier finding, ledger-logged. `--reason` required (non-empty after stripping). Refuses (exit 3) for any BLOCK-tier finding, including a confirmed+critical LLM finding even if unarmed (arming is retroactive) — and prints the ready-to-paste `[[suppress]]` entry (escaped TOML, `id`/`tool`/`rule`/`path`/`reason` filled from the ledger record) for `.aramid-suppressions.toml` instead. The tier limit is on this CHANNEL, not that file: `.aramid/` is gitignored so a ledger decision is unreviewable, while the committed file is tier-agnostic and takes any verdict (design doc §6 amendment, 2026-08-09).

### `aramid pack list|add <id>|compile`
- `list` — existing pack rule ids.
- `add <finding_id>` — promotes a finding to a pack rule (specialized compiler for rotated gitleaks secrets or fixed CVE/GHSA/PYSEC/OSV vuln findings; otherwise — including a not-a-secret finding, which has no specialized compiler — a DRAFT sentinel rule with a warning to edit its pattern-regex).
- `compile` — auto-promotes only the eligible findings (rotated secrets, fixed vuln findings) in one pass, silently skipping the rest; a not-a-secret finding is never auto-promoted this way, correctly, since a confirmed false positive must not become a standing gate rule (`pack_cmd.py:16` → `pipeline.py:431-433`, the compiled ruleset loads as an extra semgrep config at every gate).
- Bare `aramid pack` — usage line, exit 3.

### `aramid autolearn [--rebuild]`
- No flag — prints mode, state file path/timestamp, shadow decision counts, per-arm/band/bucket posterior counts, or "none yet (cold start)".
- `--rebuild` — replays every registered repo's ledger events from scratch into a fresh state.
- Always exits 0.

### `aramid arm [--llm | --autolearn | --tdd | --mutation | --mutation-score | --red-proof | --shadow | --agent]`
End a WARN-only bake by flipping an armed flag.
- No flag — `semgrep_block_armed = true`.
- `--llm` — `[llm].llm_block_armed = true`.
- `--autolearn` — `[llm.autolearn].armed = true` (also prints the shadow record).
- `--tdd` — `tdd_block_armed = true` (top level).
- `--mutation` — `[mutation].mutation_block_armed = true`.
- `--mutation-score` — `[mutation].score_block_armed = true`.
- `--red-proof` — `[red_proof].red_proof_block_armed = true`.
- `--shadow` — `[shadow].shadow_block_armed = true` (BLOCKs at every gate, pre-commit included).
- `--agent` — `agent_block_armed = true` (top level).
- All eight flags are mutually exclusive: one flag per call. Refuses (exit 3) if `aramid.toml` doesn't exist yet, or if the rewritten file would not read back as armed (e.g. the key sits in the wrong table); nothing is written then.

### `aramid update-rules`
Reports on the vendored, offline OWASP semgrep ruleset — performs no network fetch. Prints the pinned upstream source, the vendored path, and whether a ruleset is installed (warns to stderr if not). Always exits 0.

### `aramid uninstall [path]`
Removes installed hook shims, deletes `ARAMID.md`, removes the `.gitignore` entries `init` appended, deregisters the repo. The ledger (`.aramid/`) is deliberately kept. Needs the repo on disk (exit 3 otherwise) -- use `aramid fleet deregister` for a repo that has gone.

### `aramid fleet [--json]` / `aramid fleet deregister <path|name>`
`aramid fleet` prints the fleet-health matrix and the 1.0 readiness verdict from `~/.aramid/fleet_verdict.json` (`--json`: the verdict file verbatim). A report: always exits 0.
`aramid fleet deregister` removes ONE entry from `~/.aramid/repos.toml`, matched by path or by the directory name `aramid fleet` prints (case-insensitive), including a path that no longer exists. It keeps the old file as `repos.toml.bak-<UTC>-deregister`, touches nothing in the repo (hooks, `aramid.toml`, ledger stay), and re-judges at once. Exit 0 on removal; 3 when the target names no entry or more than one (nothing written) or the registry cannot be rewritten.

### `aramid schedule install|remove|status`
Register/remove/query a recurring `<interpreter> -P -m aramid drain --all`. Cross-platform: Windows Task Scheduler on Windows, cron elsewhere.
- `install` — reads `[drain].interval_hours` (default 4).
  - **Windows** — registers via `schtasks /Create ... /F` under task name `aramid-drain`. The trigger's `StartBoundary` is the installed task's own when one exists, so a re-install changes the time limit and never the cadence; a first install starts at the next local hour divisible by the interval (the next midnight for a day or more), so for an interval that divides 24 it runs at the hours cron's `0 */N` does.
  - **Linux/macOS** — writes one crontab line tagged `# aramid-drain`. Intervals under a day become an hour step (`0 */4 * * *`); a day or more becomes a day step (48h → `0 0 */2 * *`), because `*/N` in the hour field is meaningless for N > 23. Re-installing replaces aramid's line rather than adding a second one, and every unmarked line in your crontab is preserved verbatim.
- `remove` — `schtasks /Delete /TN aramid-drain /F`, or strips only the marked crontab line.
- `status` — exit `0` if installed, `3` if not.
- cron has no equivalent of Task Scheduler's `StartWhenAvailable`; the drain sweep already self-heals a fully missed window. macOS uses cron rather than launchd so one implementation covers both POSIX platforms.

### `aramid hooks install|remove|status`
Manage the machine-wide git hook template (`init.templateDir`), which seeds the hooks into NEW clones and `git init`s; the shims do nothing in a repo without an `aramid.toml`. `install` refuses (exit `3`, nothing written) when `init.templateDir` already points at a directory that is not aramid's. `remove` and `status` exit `0`.

### `aramid rebaseline [path] [--yes]`
- `path` (positional, optional, default `.`).
- `--yes` — required to proceed; without it, reports what would be discarded and refuses with exit 3.
- With `--yes`: full `Gate.ALL` scan, writes new baseline, prints `old -> new` count.

### `aramid agent-hook <event> [...]`
The agent-harness hook endpoint (Claude Code) that `aramid init` registers in `.claude/settings.json`. `session-start` prints a pending handover first (a verified one as an instruction to resume it, anything else as one fixed line that never carries the file's content; it still prints if the rest of the block fails), then the live gate posture into the session's context; `pre-tool-use` screens a git command for hook-bypass flags -- advice while baking, a deny once `agent_block_armed` is true; any other event is a silent no-op. Every token after the event is accepted and ignored, so an older aramid does nothing on a newer template's command line. Its output is UTF-8 on every platform, with anything unencodable backslash-escaped. Always exits `0`: a deny travels in the JSON on stdout (section 5).

---

## 5. Exit-Code Reference

### Global engine contract

| Code | Meaning |
|---|---|
| `0` | success / clean / pass |
| `1` | BLOCK — a genuine gate finding, or a `--strict` remap |
| `2` | degraded/WARN — a tool degraded but nothing genuinely BLOCK-tier fired; also doctor's "BLOCK-tier tool missing" signal |
| `3` | engine/config error — crash, bad args, missing prerequisite, refusal |

### Remap layers

1. **`--strict`** (`aramid check`): remaps `2` → `1`; `3` passes through unchanged (an engine or config error is already a hard failure). Applied after the fresh-clone downgrade.
2. **Git hook shims** (`hooks.py`):
   - `pre-commit` shim: `{2,3} → 0` (always fail-open).
   - `pre-push` shim: `2 → 0`; `1` and `3` pass through and block (fail-closed).
   - `post-commit` shim: always exits `0` regardless of the underlying `triage` exit (fully fail-open).
3. **CLI argv failures** (`cli.py main`): any argparse `SystemExit` other than `0` is remapped to `3`.
4. **`check` fresh-ledger downgrade**: at `--gate pre-push` with no existing baseline, if the only reason `exit_code==1` was the ratchet's own WARN→BLOCK escalation (no genuine BLOCK finding, no degraded BLOCK-tier tool), downgrades to `0` (or `2` if something degraded). In CI every checkout is a fresh ledger (`.aramid/` is gitignored), so this applies to EVERY CI pre-push-tier step and the ratchet cannot fail a step by rc alone (the pre-commit tier and `--gate all` never ratchet); the `--json` report carries `fresh_ledger_baseline: true` and `grandfathered: [ids]` when it applied (both keys always present, `false`/`[]` otherwise) — read them, or persist `.aramid/` between runs (interop rounds 149 s3 / 150). The report also carries `run_id` and `recorded` (both always present); `recorded: false` is a `--no-record` run, whose id matches no ledger row (round 155 s3).

### Per-command exit codes

| Command | Exit codes |
|---|---|
| `aramid check` | the global engine contract above: `0` clean, `1` BLOCK, `2` degraded/WARN, `3` engine or config error, after the remap layers (`--strict`, the fresh-ledger downgrade) |
| `aramid status` | `0` for every state it reports, healthy or not; `3` when the config or the ledger cannot be loaded (engine error), which still prints `aramid status:` and a pending handover's line first |
| `aramid rebaseline` (no `--yes`) | `3` always (reports what would be discarded) |
| `aramid doctor` | Checked in this order (`commands/doctor.py` `cmd_doctor`): `2` if a BLOCK-tier tool (gitleaks, semgrep) is missing or a detected or configured test suite's tool cannot be resolved; else `3` if `aramid.toml` cannot be parsed (the test-toolchain probe is then skipped, so a missing test tool cannot be seen); else `2` if the repo is configured but not enforced, a relocated shim behind another tool's hook is stale or missing, aramid is installed editable while any repo is registered, or `.claude/settings.json` or `.mcp.json` carries a tampered aramid entry; else `0`, including when the only problems are WARN rows (a missing WARN-tier tool such as ruff or pip-audit, a config-key warning, a test gate with nothing to run). |
| `aramid schedule` | `3` on unknown action, a non-zero `schtasks` result, a failed `crontab` write, or `crontab` missing from `PATH`; `status` returns `3` when the job is not installed |
| `aramid drain` | `0` ok; `2` degraded (some repo/consumer failed, rest completed); `3` if the lock is already held (real drain, not dry-run) or the registry is unusable (unreadable, or written by a newer aramid -- before 0.19.0 that case read as an empty registry and exited `0`); `0` also when no repos are registered/given |
| `aramid triage` | `0` on success (queued or not); `3` on engine error |
| `aramid ledger show <id>` | `3` if id unknown |
| `aramid ledger mark-rotated` | `3` if id unknown, or finding's status is neither `historical` nor `not_a_secret` |
| `aramid ledger mark-not-a-secret` | `3` if id unknown, or finding's status is not exactly `historical` |
| `aramid ledger mark-unreachable` | `3` if id unknown, tool is a producer/consumer, status isn't exactly `open`, or the tool is still selected for this repo |
| `aramid ledger resolve --out-of-scope` | `3` if id unknown, tool is a producer/consumer, status isn't exactly `open`, the tool is NOT selected (use `mark-unreachable`), the tool has no suffix scope, the runner still examines the path, or `--out-of-scope`/`--reason` is missing. Several ids per launch: every id is attempted and the exit is the worst of them |
| `aramid override` | `3` if the finding is BLOCK-tier (refused), or the finding is `unreachable` or `out_of_scope` (nothing to override), or `superseded` (its line was rewritten -- the refusal names the finding that replaced it) |
| `aramid hooks` | `0`; `3` when `install` finds `init.templateDir` already pointing at a directory that is not aramid's (refused, nothing written). `remove` and `status` always `0` -- `status` reports "not installed" with `0`, unlike `schedule status`. The refusal was `2` before 0.19.0 |
| `aramid fleet` | always `0`, including when the verdict or policy cannot be read (one stderr line) -- a report has nothing to block |
| `aramid fleet deregister` | `0` once the repo is removed; `3` when the target names no registered repo or more than one, or the registry cannot be rewritten |
| `aramid notices` | `0`; `3` for an id the channel has never seen (`show`, `ack`) or an internal failure. `ack` of an already-acked id is `0` |
| `aramid handover` | `0`; `2` for a refusal (run outside a git repository whose root holds `aramid.toml`, `write` of an empty body, of a body or author holding a lone surrogate, or of a body whose file would exceed 1 MiB, a second `write` without `--replace`, an unsafe or non-directory `.aramid`, a symlinked handover file at `done`, a corrupt key, an unreadable `--file`, or an OS error from `write` or `done`); `3` when `show` finds a pending file that cannot be delivered as verified (the body, if it parsed, prints under a `NOT VERIFIED` header) |
| `aramid resolvers` | `0` whether or not a resolver is flagged -- it follows `status`'s contract, not `check`'s, so a false flag can never block; `3` on an engine error |
| `aramid mutation-score` | `0`, including an empty history; `3` on an engine error. Advisory: a regression never changes the exit |
| `aramid agent-hook <event>` | always `0` -- a deny or an advisory is carried in the JSON on stdout, never in the exit code, and an internal failure fails open. `python -P -m aramid agent-hook` with no event also exits `0`; the `aramid` console script needs the event like any argument and exits `3` without it |
| `aramid pack` (bare) | `3` (usage line) |
| `aramid ledger` (bare) | `3` (usage line) |
| `aramid arm` | `3` if `aramid.toml` doesn't exist yet |
| `aramid init` / `uninstall` | `3` if not inside a git repo; `init` also `3` if a BLOCK-tier tool is missing (doctor gate); `uninstall` also `3`, after every other step, when the registry is unreadable or was written by a newer aramid (it is left as it is) |
| `aramid autolearn` | always `0` |
| `aramid update-rules` | always `0` |
| `aramid --version` / `-h`/`--help` | `0` |
| no subcommand | `3` |
| unknown/malformed subcommand or flags | `3` (remapped from argparse's `2`) |

---

## 6. FAQ / Troubleshooting

**"gitleaks"/"semgrep" not found / doctor reports missing tools.**
Run `aramid doctor` to see which of `gitleaks`, `semgrep`, `ruff`, `pip-audit` are missing (`doctor` exits `2` if either BLOCK-tier tool — gitleaks or semgrep — is missing; WARN-tier absence of ruff/pip-audit never affects the exit code; `2` also for "configured but not enforced", a stale or missing relocated shim behind another tool's managed hook (reported, never rewritten -- `aramid init .` regenerates it), a broken detected test toolchain, and an editable aramid install while any repo is registered — see the user guide's doctor section). On a CI checkout `doctor` exits `2` by construction — hooks are never cloned, so it is "configured but NOT enforced" — and a `pwsh` step wrapper without `exit $LASTEXITCODE` reports that as `1`; run it informationally there. Run `aramid doctor --fix` to `pip install --upgrade` the owned toolchain (`ruff`, `semgrep`, `pip-audit`) into the current interpreter, and to download a pinned, sha256-verified gitleaks v8.30.1 binary into `~/.aramid/tools/` if missing, or over aramid's own copy there when it is off the pin. Note that `aramid init` itself gates on `doctor`: if a BLOCK-tier tool is missing at init time, the whole init aborts (no hooks installed, no partial config written), exit 3.

**The scheduled drain doesn't seem to be running.**
Read `aramid status`'s `last drain:` line first: every drain writes a `drain_visited` row into each repo it looks at, with or without work, so the line moves every interval -- `idle: nothing to drain` means it ran and found nothing, a timestamp older than one interval means it did not run here (not scheduled, or this repo is not registered). Until 2026-09-16 an idle drain wrote nothing and the line kept naming the last consumer run, so a dead scheduler and an empty queue looked alike. Then check `aramid schedule status` (on Windows the Task Scheduler job named `aramid-drain`, printing `schtasks`' own output; on Linux/macOS the marked crontab line; "aramid-drain: not installed" if neither). If not installed, run `aramid schedule install` (reads `[drain].interval_hours`, default 4). If it's installed but drains never seem to complete, check for a stuck singleton lock at `~/.aramid/drain.lock` (JSON `{pid, started_at, deadline_s}`) — it's treated as stale/breakable automatically once its recorded PID is dead or it's older than its own `deadline_s` plus 5 minutes (default deadline 90 minutes, `[drain].hard_deadline_s`). `aramid drain --dry-run` gives a read-only preview of what would be swept/popped without acquiring the lock.

**Findings aren't blocking even though they look like real issues.**
Check which arming flag governs that finding — most WARN/BLOCK behavior is arming-gated: `semgrep_block_armed` (top-level, default `false`) for OWASP-semgrep matches; `[pack].pack_block_armed` (default `true`, so normally already armed) for compiled regression-pack rules; `[llm].llm_block_armed` (default `false`) for confirmed-CRITICAL LLM findings, applied retroactively at the pre-push gate only; `[llm.autolearn].armed` doesn't affect BLOCK at all, only reviewer selection. `[mutation].mutation_block_armed` escalates drain-recorded survivors at the next pre-push (the arming table in section 1 lists every flag). `[dast]`, `[fuzz]` and `[js_mutation]` have no arming flag at all and are structurally WARN-only. Run `aramid status` to see current bake day-count and per-rule semgrep hit counts before deciding to arm. Note: gitleaks, curated ruff rules (`S102,S105,S106,S107,S608,S301,S302`), failing tests, and dependency findings ≥ `[deps].block_severity` (default `"critical"`) BLOCK unconditionally regardless of any arming flag.

**How do I rebaseline after an aramid upgrade re-triggers old findings?**
Run `aramid rebaseline --yes` — an aramid upgrade that changes rule-id or path normalization changes the fingerprint hash, making previously-accepted findings look "new" and triggering the pre-push ratchet. `aramid rebaseline` without `--yes` only reports the count of grandfathered findings that would be discarded and refuses with exit 3 (no interactive prompt, safe for hooks/CI). With `--yes`, it runs a full `Gate.ALL` scan and writes a new baseline, printing `old -> new` counts. Expect re-fingerprinted-but-unchanged findings to subsequently show as resolved in `status`/`ledger list` — `superseded` (naming the new id) when the new row is a nearby sibling, `fixed` otherwise; documented, expected behavior.

**How do I arm a subsystem after its bake period?**
There is no single "arm everything" command — arm each flag deliberately:
- `aramid arm` (no flag) — ends the semgrep OWASP bake (`semgrep_block_armed = true`).
- `aramid arm --llm` — ends the LLM bake (`[llm].llm_block_armed = true`); confirmed-CRITICAL LLM findings now BLOCK at pre-push.
- `aramid arm --autolearn` — arms auto-learn (`[llm.autolearn].armed = true`); uplift/cascade now change reviewer selection (escalate-only; the ladder tier stays the floor). Also prints the shadow record (would-uplift count, audits performed, missed criticals) at arming time.
- `[pack].pack_block_armed` has no `arm` subcommand at all — it's meant to be hand-edited in `aramid.toml` (and defaults to `true` already).
- All three `arm` invocations refuse with exit 3 if `aramid.toml` doesn't exist yet (run `aramid init` first), and all use a comment-preserving regex rewrite rather than a full TOML re-dump.

**A drain consumer keeps skipping my item / says it's "giving up."**
Each consumer with a give-up valve stops retrying after repeated identical failures at the same head (typically 3 times), to avoid burning budget forever on a structurally-broken item: `llm-review` after 3 malformed provider responses; `mutation` after 3 failing baseline runs at that exact head; `js_mutation` after 3 failing baseline runs or 3 failed `node_modules` link attempts at that head; `dast` after 3 unreachable-target or 3 probe-error attempts at that head; `fuzz` after 3 broken-driver runs (a crash, a non-zero exit or unparseable output, each `degraded`) at that head. A new commit (new head) resets these counters. `regression_pack` has no give-up valve. A fuzz driver TIMEOUT is not a broken driver: it is recorded `ok` with a `no cases run` note, which `aramid status` reports under `consumers doing no work`.

**Why does a consumer report "no python/js test stack" instead of failing?**
This is deliberate — `mutation`/`js_mutation` treat a permanently-absent test stack (no pytest/no npm test script) as an OK-skip, not a DEGRADED failure, so that a JS-only repo (for `mutation`) or a Python-only repo (for `js_mutation`) doesn't pin its queue item forever waiting on a stack that will never appear.
