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
| `pre-commit` | gitleaks, ruff |
| `pre-push` | gitleaks, semgrep, eslint, typecheck, deps, tests |
| `all` (`--all` / `aramid check --all`) | same as pre-push |

Each runner is additionally filtered by `_is_applicable()`: ruff only if the repo has a Python stack, eslint only if a JS stack, typecheck only if a `tsconfig`/mypy config is present, deps only if a package manager or `requirements*.txt` exists, tests only if `detectors.detect_tests()` finds a suite. gitleaks and semgrep are always applicable. A non-applicable runner is never selected and never counts as "degraded."

Runners execute concurrently under a `ThreadPoolExecutor`, budgeted by `[timeouts]` (`pre_commit=5s`, `pre_push=300s`); a runner still running past budget is abandoned and recorded `TIMEOUT` (not joined). Two ignore-path filter passes are always on and unremovable by repo config (`_BUILTIN_IGNORE_PATHS`): before file discovery, and again on parsed findings (needed because gitleaks scans by `git log` range, not `ctx.files`).

Severity tiering ("security blocks, quality warns") is **not uniform** — `policy.classify()` is the single source of truth; see [WARN vs BLOCK tiers](#warn-vs-block-tiers) below.

### Drain
The sweep (`aramid drain`) — scheduled (via `aramid schedule install`) or manual — that catches up triage on registered repos, pops the highest-scored queued item(s) from the [review queue](#review-queue), and runs every registered [consumer](#consumer) against each item. Consumers run in this fixed registration order: `regression_pack`, `llm_review`, `mutation`, `fuzz`, `js_mutation`, `dast`.

- Singleton lock: `~/.aramid/drain.lock` (JSON `{pid, started_at}`); considered stale/breakable if the recorded PID is dead or the lock is older than `2 × wall_clock_budget_s`.
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
A pure, git-plumbing-only, self-budgeted score (default `budget_s=2.0`, checked between signal computations; a partial score is kept past budget with a `"triage-budget-exceeded"` reason) computed by `triage.py score()`, capped at 100 total, from four weighted signals:

| Signal | Weight | Trigger |
|---|---|---|
| `path_signal` | 30 | any changed path contains a security token (`auth, session, login, crypto, token, secret, permission, middleware, config`) or matches an `extra_security_paths` fnmatch pattern |
| `content_signal` | 25 | added-line regex hits for exec/eval/subprocess, SQL-string-building, or an HTTP handler decorator/call; or a touched dependency-manifest file (`pyproject.toml`, `package.json`, `requirements`, lockfiles) |
| `novelty_signal` | 20 | any touched path never seen in a prior triage run (per `queue.triaged_paths`) |
| `blast_radius_signal` | 0/10/18/25 | number of graphite-graph dependents of touched files: ≥10→25, ≥3→18, ≥1→10, else 0. Fails open (returns 0/`[]`) if `graph-out/graph.json` is absent, corrupt, or unexpectedly shaped |

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
- Everything else → `WARN`.

Net effect: **only OWASP-semgrep and LLM findings are gated by an arming flag** — gitleaks, the curated ruff rules, failing tests, and ≥critical CVEs BLOCK unconditionally regardless of bake state.

**Pre-push no-new-warnings ratchet**: at `Gate.PRE_PUSH`, any `WARN` finding whose id is "new" (`f.id in new_ids`, never seen before in the ledger) is escalated to `BLOCK` — except findings with rule `deps.DEPS_SHAPE_DRIFT_RULE`, which are exempt.

### Arming / bake-then-arm
Aramid ships with several checks in a WARN-only "bake" period so an operator can observe noise before committing to enforcement. There are exactly **four** arming-style flags:

| Flag | Location | Default | What it BLOCKs when armed |
|---|---|---|---|
| `semgrep_block_armed` | root of `aramid.toml` | `false` | OWASP-semgrep block-list matches |
| `[pack].pack_block_armed` | `aramid.toml` | `true` | regression-pack-compiled block rules (`aramid-regression.block.*`) — deliberately independent of `semgrep_block_armed` |
| `[llm].llm_block_armed` | `aramid.toml` | `false` | confirmed-and-CRITICAL `llm-review` findings |
| `[llm.autolearn].armed` | `aramid.toml` | `false` | not a BLOCK gate — controls whether learned uplift/cascade actually change reviewer *selection* (vs. shadow-only telemetry) |

`[dast].block_armed` exists as a fifth flag-shaped key but is explicitly RESERVED/inert (never read by the dast consumer). `[mutation]`, `[fuzz]`, and `[js_mutation]` have **no** arming flag of any kind.

Arming is always a manual, deliberate act (`aramid arm` / `arm --llm` / `arm --autolearn`) — never a timer or auto-promotion. All three commands rewrite `aramid.toml` via targeted regex substitution (not a full TOML parse/re-dump) specifically to preserve hand-written comments byte-for-byte. `aramid init` writes a fresh repo's `aramid.toml` stub with `semgrep_block_armed = false` and `bake_started = <today>` always, and never touches an existing `aramid.toml`. `aramid status` surfaces bake day-count and per-rule semgrep hit counts while unarmed, so an operator can spot/demote noisy rules before arming.

### Fingerprint / ratchet
**Fingerprint** (`fingerprint.py compute_fingerprint`):
```
sha256(tool + "\x1f" + rule + "\x1f" + normalize_path(path) + "\x1f" + sha256(normalize_line(line_content)) + "\x1f" + str(occurrence_index))
```
`normalize_path` = backslash→forward-slash + casefold; `normalize_line` = collapse all whitespace runs to a single space + strip. `occurrence_index` disambiguates multiple identical (tool, rule, file, normalized-line) hits within one scan; see [PIN_OCCURRENCE](#pin_occurrence) for the alternative mode.

**Ratchet**: driven by "is this id new" (`new_ids` from `Ledger.record_run`, i.e. never previously `seen`), not by baseline membership directly — the baseline only matters for the fresh-clone downgrade path and `Ledger.is_new()`. See [WARN vs BLOCK tiers](#warn-vs-block-tiers) for the escalation rule.

### Rebaseline
`aramid rebaseline --yes` re-snapshots current findings as the accepted ratchet baseline: runs a full `Gate.ALL` scan and calls `ledger.write_baseline()` with the resulting finding-id set, discarding prior grandfathering, and prints `old -> new` count. Without `--yes`, only reports the count that would be discarded and returns exit 3 (no interactive prompt — safe to invoke from hooks/CI).

Needed because an aramid upgrade that changes rule-id or path normalization changes the fingerprint hash, so previously-accepted findings re-fingerprint and the ratchet treats them as brand-new, escalating them to BLOCK. Side effect: because a full gate is run, normal `RUN_STARTED`/`FINDING_DETECTED`/`FINDING_RESOLVED`/`RUN_FINISHED` events are also appended — a re-fingerprinted-but-functionally-unchanged finding shows up as "fixed"/resolved in `status`/`ledger list` afterward (documented, expected, not a bug).

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

---

## 2. Configuration Reference

Config file: `aramid.toml` at the repo root. Three-layer merge: package defaults (`src/aramid/data/defaults.toml`) ← `~/.aramid/config.toml` ← `<root>/aramid.toml`. `CURRENT_SCHEMA_VERSION = 1`. `block_rules` is **not** sourced from `defaults.toml` at all — it is always overwritten from the separate packaged, curated file `src/aramid/data/block_rules.toml` and is not a user-facing tunable.

### Top level

| Key | Type | Default | Meaning |
|---|---|---|---|
| `schema_version` | int | `1` | Config schema tag; `load_config` warns to stderr if a repo's value differs from `CURRENT_SCHEMA_VERSION`. |
| `semgrep_block_armed` | bool | `false` | OWASP-bake arming flag; while false, semgrep BLOCK-tier findings are demoted to WARN. Flipped by `aramid arm`. |
| `ignore_paths` | list[str] | the 8 built-ins below (set in `defaults.toml`) | Exclude patterns. The 8 built-ins — `.aramid/`, `graph-out/`, `.graphite*`, `.cache/`, `node_modules/`, `.venv/`, `__pycache__/`, `.git/` — are the default and are always unioned back in regardless of repo config (never removable); a repo's `ignore_paths` adds to them. |
| `bake_started` | str \| None | `None` (absent from defaults.toml — TOML has no null literal) | ISO date string set by `init`'s repo stub marking when the WARN-only bake period began; reported by `status` as "bake in progress, day N". |
| `test_command` | str \| None | `None` | Loaded into `Config` but has no read site anywhere in `src/aramid` outside `config.py` itself — reserved/currently unconsumed. |
| `scope_subpath` | str \| None | `None` | Set by `init` when the target dir isn't the true repo root; printed as "scan scope: …". |

### `[timeouts]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `pre_commit` | int (s) | `5` | Wall-clock budget for the pre-commit gate. |
| `pre_push` | int (s) | `300` | Wall-clock budget for the pre-push gate. |

Code's own ultimate fallback if the section were entirely absent: `60.0`.

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
| `model_openrouter` | str | `"anthropic/claude-sonnet-4-5"` | Model id for the opt-in openrouter provider. No confirmed read site found in `src/aramid` beyond its own declaration. |
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

No arming flag exists in `[mutation]`.

### `[js_mutation]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Master switch. |
| `max_mutants` | int | `20` | Mutants generated-and-tested per queue item. |
| `wall_budget_s` | int (`float()`'d) | `600` | Whole-item wall clock for the mutant loop. |
| `mutant_timeout_s` | int (`float()`'d) | `120` | Per `<pm> test` invocation (single-stage — no `confirm_cap` key here). |

No arming flag exists in `[js_mutation]`.

### `[fuzz]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Master switch. |
| `max_functions` | int | `10` | Functions fuzzed per queue item. |
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
| `block_armed` | bool | `false` | **RESERVED and inert** — never read by the dast consumer's `consume()`. |
| `start_command` | — | *(commented out, not a live key)* | Not currently a real config key. |

### Key naming collisions (same name, different meaning)

- **`max_items_per_drain`**: `[drain]` = `10` (total items per drain run) vs. `[llm]` = `3` (LLM reviews per drain).
- **`min_score`**: `[triage]` = `40` (queueing threshold) vs. each `[[llm.ladder]]` entry's own `min_score` (40/60/80, a reviewer-arm band floor).

### Arming flags — full inventory

1. `semgrep_block_armed` (top level) — default `false` — armed via `aramid arm`.
2. `[pack].pack_block_armed` — default `true` — no arm subcommand; hand-edited.
3. `[llm].llm_block_armed` — default `false` — armed via `aramid arm --llm`.
4. `[llm.autolearn].armed` — default `false` — armed via `aramid arm --autolearn`.

`[dast].block_armed` is a fifth flag-shaped key but explicitly RESERVED/inert. `[mutation]`, `[fuzz]`, and `[js_mutation]` have **no** arming flag of any kind.

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
- **OK-skip / give-up**: OK-skip when `[llm].enabled=false` (`"llm disabled"`); empty packet (`"empty packet"`); no provider CLIs installed at all (`"llm skipped: no providers installed"`); give-up valve — malformed responses ≥3 (`_MALFORMED_GIVE_UP=3`, note `"llm giving up: repeated malformed output"`). DEGRADED when per-process review budget exhausted (`"llm budget exhausted"`); every configured provider installed but unavailable (`"all providers unavailable"`); or a response parses to `None` (`f"malformed response from {provider}"`).
- **Stack requirement**: at least one of the configured provider CLIs (claude-cli / codex-cli / ollama-cloud, or opt-in openrouter) must be installed and reachable.
- **Token cost**: the only consumer with nonzero cost; accrues on spend, not on parse success (unparseable responses still burn tokens). Cascade re-review consumes a normal review slot; audit double-review has its own separate cap (`max_audits_per_drain`); refute calls have their own cap (`max_refutes_per_drain=6`).

### mutation
- **NAME**: `mutation`, findings `tool="mutation"`.
- **Purpose**: mutation-test the Python functions the queue item's commits touched, inside a throwaway `git worktree --detach` at `item.head`. Two-stage: targeted pytest run per mutant, then a capped full-suite confirmation run — a survivor is only reported once the full suite passes on it. Operators: `cmp-flip`, `bool-swap`, `int-bound`, `not-drop`.
- **Config keys**: `[mutation]` (`enabled=true`, `max_mutants=20`, `wall_budget_s=600`, `mutant_timeout_s=120`, `confirm_cap=3`).
- **WARN/BLOCK + arming**: no arming knob exists; findings are always medium severity → WARN under the catch-all.
- **OK-skip / give-up**: OK-skip when `enabled=false` (`"disabled"`); no non-test Python files changed (`"no python files in range"`); no pytest stack detected — deliberately OK not DEGRADED (`"no python test stack (mutation skipped)"`); give-up valve — baseline failed 3 times at this exact head (`_BASELINE_GIVE_UP=3`, head-scoped note prefix `f"baseline failing @ {head12}"`) → `"mutation giving up: baseline persistently failing"`. **ERROR** (not degraded) when `git worktree add` fails. DEGRADED when the full-suite baseline run on the pristine worktree doesn't pass.
- **Stack requirement**: `"pytest" in detectors.detect_tests(root)` — true only if `tests/` dir exists or any `test_*.py` is found.
- **Token cost**: always `0.0`.

### js_mutation
- **NAME**: `js_mutation` (config section `[js_mutation]`), findings `tool="js-mutation"` (hyphenated — differs from the module name/config key).
- **Purpose**: JS/TS analog of `mutation`, single-stage: mutate changed lines in a throwaway worktree (with the real repo's `node_modules` junctioned/symlinked in), run `<pm> test` once per mutant — a full-suite pass on a mutant is the confirmed survivor. Operators: `cmp-flip` (like-for-like relational/equality swap), `logical-swap` (`&&`↔`||`).
- **Config keys**: `[js_mutation]` (`enabled=true`, `max_mutants=20`, `wall_budget_s=600`, `mutant_timeout_s=120`; no `confirm_cap`).
- **WARN/BLOCK + arming**: no arming knob exists; catch-all WARN.
- **OK-skip / give-up**: requirements checked in order, each OK-skip: no npm test script (`"no js test stack (mutation skipped)"`); no resolvable package-manager binary (`"js package manager not found (mutation skipped)"`); no `node_modules/` in the real repo root (`"node_modules not installed (js mutation skipped)"`); `enabled=false` (`"disabled"`); no JS/TS files changed (`"no js files in range"`); two independent give-up valves, each `=3` with head-scoped prefixes `f"baseline failing @ {head12}"` / `f"node_modules link failing @ {head12}"` → `"js mutation giving up: baseline persistently failing"` / `"...node_modules link persistently failing"`. **DEGRADED** (not ERROR, unlike `mutation`) when `git worktree add` fails, the node_modules junction/symlink fails, or the pristine-worktree baseline test run doesn't pass.
- **Stack requirement**: `"npm" in detectors.detect_tests(root)`, a resolvable npm/pnpm/yarn binary, and an existing `node_modules/`.
- **Token cost**: always `0.0`.

### fuzz
- **NAME**: `fuzz`, findings `tool="fuzz"`.
- **Purpose**: call top-level, type-hinted Python functions touched by the queue item's commits with deterministic seeded inputs, inside a throwaway worktree; report DEEP-CRASH exceptions as WARN-tier findings. Candidate selection is AST-only; fuzzing runs in a separate subprocess (`python -m aramid.fuzzdriver <spec.json>`) that re-checks type hints at import time. `PYTHONHASHSEED=0` is forced for stable crash reproduction.
- **Config keys**: `[fuzz]` (`enabled=true`, `max_functions=10`, `cases_per_function=50`, `wall_budget_s=300`, `batch_timeout_s=120`, `skip_name_patterns=[...]`).
- **WARN/BLOCK + arming**: no arming knob exists; WARN only.
- **OK-skip / give-up**: OK-skip when `enabled=false` (`"disabled"`); no non-test Python files changed (`"no python files in range"`); no fuzzable functions found (`"no fuzzable functions in range"`); driver timed out — treated as OK (`"driver timed out (budget did its job)"`); driver exited non-zero/crashed — still OK (`f"driver error: ..."`); driver produced unparseable JSON — still OK (`"driver produced no parseable output"`). **ERROR** only when `git worktree add` fails. **No give-up valve at all, and can never return DEGRADED** — every failure short of worktree-add is swallowed as OK.
- **Stack requirement**: Python stack with top-level, non-async, type-hinted functions in changed lines.
- **Token cost**: always `0.0`.

### dast
- **NAME**: `dast`, findings `tool="dast"`.
- **Purpose**: passive web-hygiene scan of a user-declared `base_url` via an owned stdlib HTTP prober — five check families: headers (HSTS/CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy missing), cookies (Set-Cookie missing Secure/HttpOnly/SameSite), transport (plaintext HTTP, expired/invalid TLS cert), exposed paths (curated probes for `/.git/config`, `/.git/HEAD`, `/.env`, `/server-status`, plus user-declared `paths`), and banner leaks (`Server`/`X-Powered-By` version strings). Evidence is always synthetic metadata, never raw response body/cookie/secret values.
- **Config keys**: `[dast]` (`enabled=true`, `base_url=""`, `paths=[]`, `timeout_s=10`, `block_armed=false` — reserved/inert).
- **WARN/BLOCK + arming**: no live arming; all dast findings are WARN-tier via the catch-all (`block_armed` is never read).
- **OK-skip / give-up**: OK-skip when `enabled=false` (`"disabled"`); `base_url` empty (`"no dast target configured"`); malformed `base_url` (`"invalid dast base_url (need http(s)://host with a valid port)"`); two independent give-up valves, both `=3`, head-scoped prefixes `f"dast target unreachable @ {head12}"` / `f"dast probe error @ {head12}"` → `"dast giving up: target persistently unreachable or erroring"`. DEGRADED when the target is unreachable (`DastUnreachable`) or the probe crashes unexpectedly — both explicitly not permanent (app may simply not be up at drain time).
- **Stack requirement**: none structural — purely config-declared (`base_url` must be set by the operator; no auto-discovery of a running app).
- **Token cost**: always `0.0`.

---

## 4. CLI Command Reference

Entry points: console script `aramid` (`pyproject.toml` `[project.scripts]`), or `python -m aramid` (what the installed git hooks actually call). `aramid --version` prints `aramid 0.1.0` and exits 0. `-h`/`--help` on any (sub)parser exits 0. No subcommand → `aramid: no command` to stderr, exit 3. Unknown/bad subcommand or malformed flags → remapped to exit 3.

### `aramid init [path] [--discover]`
Onboard a repo: write config, install hooks, seed baseline.
- `path` (positional, optional, default `.`).
- `--discover` — walk under `path` (max depth 3) for every directory containing `.git` (skipping `node_modules`, `_tools`, `.venv`, `.git`, `__pycache__`, `.aramid`, `.cache`, `graph-out`, `.graphite*`); runs the full single-repo init flow on each, returning the worst exit code seen.
- Gates on `aramid doctor`; refuses (exit 3) if a BLOCK-tier tool (gitleaks/semgrep) is missing. Writes `aramid.toml` only if absent; always regenerates `ARAMID.md`; appends missing `.gitignore` entries (`.aramid/`, `graph-out/`, `.graphite*`, `.cache/`); installs idempotent hook shims (chains any pre-existing foreign hook to `<hook>.aramid-chained`); registers the repo in the machine-global registry; runs a one-time full-history gitleaks scan (`git log --all`, non-blocking historical findings); writes the ratchet baseline once.

### `aramid check [--gate pre-commit|pre-push] [--staged|--range|--all] [--strict] [--json] [--accept-degraded] [--reason REASON]`
Run the gate pipeline.
- `--gate {pre-commit,pre-push}` (default `pre-commit`).
- Mode group (mutually exclusive): `--staged`, `--range`, `--all`; default is `staged` for pre-commit, `range` for pre-push.
- `--strict` — remaps exit codes 2/3 to 1.
- `--json` — render JSON instead of console report.
- `--accept-degraded` — accept a degraded run; `--reason` (default `None`, falls back to `"no reason given"`) records why. Also settable via `ARAMID_ACCEPT_DEGRADED` env var.
- Fresh-ledger downgrade at `--gate pre-push` with no baseline yet.

### `aramid doctor [--fix]`
Probe (and optionally repair) the toolchain and the hook shim's baked interpreter.
- No flag: probes `gitleaks`, `semgrep`, `ruff`, `pip-audit` via `<exe> --version`, plus the shim's baked interpreter; prints LLM-provider probe lines and autolearn state health.
- `--fix` — `pip install --upgrade`s `ruff`/`semgrep`/`pip-audit` into the current interpreter if missing; downloads a pinned gitleaks v8.21.2 binary into `~/.aramid/tools/` (sha256-verified) if missing; re-probes.

### `aramid status`
Read-only report of ledger/config state; never mutates anything. No flags.

### `aramid triage [rev] [--budget SECONDS]`
Score one commit (or `A..B` range) and enqueue it if risky.
- `rev` (positional, optional, default `HEAD`).
- `--budget SECONDS` (float, default `None`) — wall-clock watchdog via a daemon `threading.Timer`; on expiry, hard-kills with `os._exit(3)`. Unbounded without `--budget`.

### `aramid drain [--all | --repo PATH] [--dry-run] [--max-items N]`
Sweep registered repos, catch-up-triage, pop the highest-scored queued item(s), run consumers, record results.
- Scope group (mutually exclusive): `--all`, `--repo PATH`; default is the current directory.
- `--dry-run` — read-only preview, no lock, no mutation.
- `--max-items N` (int, default `None`) — caps items drained this run.

### `aramid ledger list|show <id>|filter [--tool] [--rule] [--status] [--severity]|mark-rotated <id> --reason REASON`
- `list` — every open/known finding, one line each.
- `show <id>` — full record fields plus every ledger event tied to that id (exit 3 if id unknown).
- `filter [--tool] [--rule] [--status] [--severity]` — all optional/AND-combined.
- `mark-rotated <id> --reason REASON` — `--reason` required; only valid when the finding's status is exactly `historical`, else refuses with exit 3.
- Bare `aramid ledger` — usage line, exit 3.

### `aramid override <id> --reason REASON`
Suppress a WARN-tier finding, ledger-logged. `--reason` required (non-empty after stripping). Refuses (exit 3) for any BLOCK-tier finding, including a confirmed+critical LLM finding even if unarmed (arming is retroactive) — directs the operator to `.aramid-suppressions.toml` instead.

### `aramid pack list|add <id>|compile`
- `list` — existing pack rule ids.
- `add <finding_id>` — promotes a finding to a pack rule (specialized compiler for rotated gitleaks secrets or fixed CVE/GHSA/PYSEC/OSV vuln findings; otherwise a DRAFT sentinel rule with a warning to edit its pattern-regex).
- `compile` — auto-promotes every eligible finding in one pass.
- Bare `aramid pack` — usage line, exit 3.

### `aramid autolearn [--rebuild]`
- No flag — prints mode, state file path/timestamp, shadow decision counts, per-arm/band/bucket posterior counts, or "none yet (cold start)".
- `--rebuild` — replays every registered repo's ledger events from scratch into a fresh state.
- Always exits 0.

### `aramid arm [--llm | --autolearn]`
End a WARN-only bake by flipping an armed flag.
- No flag — `semgrep_block_armed = true`.
- `--llm` — `[llm].llm_block_armed = true`.
- `--autolearn` — `[llm.autolearn].armed = true` (also prints the shadow record).
- `--llm`/`--autolearn` mutually exclusive; refuses (exit 3) if `aramid.toml` doesn't exist yet.

### `aramid update-rules`
Reports on the vendored, offline OWASP semgrep ruleset — performs no network fetch. Prints the pinned upstream source, the vendored path, and whether a ruleset is installed (warns to stderr if not). Always exits 0.

### `aramid uninstall [path]`
Removes installed hook shims, deletes `ARAMID.md`, removes the `.gitignore` entries `init` appended, deregisters the repo. The ledger (`.aramid/`) is deliberately kept.

### `aramid schedule install|remove|status`
Register/remove/query a Windows Task Scheduler job running `<interpreter> -m aramid drain --all` on a recurring interval.
- Windows-only; any other platform → exit 3.
- `install` — reads `[drain].interval_hours` (default 4), registers via `schtasks /Create ... /F` under task name `aramid-drain`.
- `remove` — `schtasks /Delete /TN aramid-drain /F`.
- `status` — `schtasks /Query /TN aramid-drain`; prints its output or "aramid-drain: not installed".

### `aramid rebaseline [path] [--yes]`
- `path` (positional, optional, default `.`).
- `--yes` — required to proceed; without it, reports what would be discarded and refuses with exit 3.
- With `--yes`: full `Gate.ALL` scan, writes new baseline, prints `old -> new` count.

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

1. **`--strict`** (`aramid check`): remaps `2`/`3` → `1`. Applied after the fresh-clone downgrade.
2. **Git hook shims** (`hooks.py`):
   - `pre-commit` shim: `{2,3} → 0` (always fail-open).
   - `pre-push` shim: `2 → 0`; `1` and `3` pass through and block (fail-closed).
   - `post-commit` shim: always exits `0` regardless of the underlying `triage` exit (fully fail-open).
3. **CLI argv failures** (`cli.py main`): any argparse `SystemExit` other than `0` is remapped to `3`.
4. **`check` fresh-ledger downgrade**: at `--gate pre-push` with no existing baseline, if the only reason `exit_code==1` was the ratchet's own WARN→BLOCK escalation (no genuine BLOCK finding, no degraded BLOCK-tier tool), downgrades to `0` (or `2` if something degraded).

### Per-command exit codes

| Command | Exit codes |
|---|---|
| `aramid rebaseline` (no `--yes`) | `3` always (reports what would be discarded) |
| `aramid doctor` | `2` if either BLOCK-tier tool (gitleaks, semgrep) missing; `0` otherwise. WARN-tier tool absence (ruff, pip-audit) never changes it. |
| `aramid schedule` | `3` on non-Windows, unknown action, or non-zero `schtasks` result; otherwise mirrors `schtasks`' own return code (`status`) |
| `aramid drain` | `0` ok; `2` degraded (some repo/consumer failed, rest completed); `3` if the lock is already held (real drain, not dry-run) or the registry is unusable; `0` also when no repos are registered/given |
| `aramid triage` | `0` on success (queued or not); `3` on engine error |
| `aramid ledger show <id>` / `mark-rotated` | `3` if id unknown / finding not in `historical` status |
| `aramid override` | `3` if the finding is BLOCK-tier (refused) |
| `aramid pack` (bare) | `3` (usage line) |
| `aramid ledger` (bare) | `3` (usage line) |
| `aramid arm` | `3` if `aramid.toml` doesn't exist yet |
| `aramid init` / `uninstall` | `3` if not inside a git repo; `init` also `3` if a BLOCK-tier tool is missing (doctor gate) |
| `aramid autolearn` | always `0` |
| `aramid update-rules` | always `0` |
| `aramid --version` / `-h`/`--help` | `0` |
| no subcommand | `3` |
| unknown/malformed subcommand or flags | `3` (remapped from argparse's `2`) |

---

## 6. FAQ / Troubleshooting

**"gitleaks"/"semgrep" not found / doctor reports missing tools.**
Run `aramid doctor` to see which of `gitleaks`, `semgrep`, `ruff`, `pip-audit` are missing (`doctor` exits `2` if either BLOCK-tier tool — gitleaks or semgrep — is missing; WARN-tier absence of ruff/pip-audit never affects the exit code). Run `aramid doctor --fix` to `pip install --upgrade` the owned toolchain (`ruff`, `semgrep`, `pip-audit`) into the current interpreter, and to download a pinned, sha256-verified gitleaks v8.21.2 binary into `~/.aramid/tools/` if missing. Note that `aramid init` itself gates on `doctor`: if a BLOCK-tier tool is missing at init time, the whole init aborts (no hooks installed, no partial config written), exit 3.

**The scheduled drain doesn't seem to be running.**
Check `aramid schedule status` (Windows Task Scheduler job named `aramid-drain`; prints `schtasks`' own output or "aramid-drain: not installed"). If not installed, run `aramid schedule install` (reads `[drain].interval_hours`, default 4). If it's installed but drains never seem to complete, check for a stuck singleton lock at `~/.aramid/drain.lock` (JSON `{pid, started_at}`) — it's treated as stale/breakable automatically once its recorded PID is dead or it's older than `2 × [drain].wall_clock_budget_s` (default 600s, so 1200s). `aramid drain --dry-run` gives a read-only preview of what would be swept/popped without acquiring the lock.

**Findings aren't blocking even though they look like real issues.**
Check which arming flag governs that finding — most WARN/BLOCK behavior is arming-gated: `semgrep_block_armed` (top-level, default `false`) for OWASP-semgrep matches; `[pack].pack_block_armed` (default `true`, so normally already armed) for compiled regression-pack rules; `[llm].llm_block_armed` (default `false`) for confirmed-CRITICAL LLM findings, applied retroactively at the pre-push gate only; `[llm.autolearn].armed` doesn't affect BLOCK at all, only reviewer selection. `[dast].block_armed` exists but is explicitly reserved/inert — dast findings are always WARN. `[mutation]`, `[fuzz]`, `[js_mutation]` have no arming flag at all and are structurally WARN-only. Run `aramid status` to see current bake day-count and per-rule semgrep hit counts before deciding to arm. Note: gitleaks, curated ruff rules (`S102,S105,S106,S107,S608,S301,S302`), failing tests, and dependency findings ≥ `[deps].block_severity` (default `"critical"`) BLOCK unconditionally regardless of any arming flag.

**How do I rebaseline after an aramid upgrade re-triggers old findings?**
Run `aramid rebaseline --yes` — an aramid upgrade that changes rule-id or path normalization changes the fingerprint hash, making previously-accepted findings look "new" and triggering the pre-push ratchet. `aramid rebaseline` without `--yes` only reports the count of grandfathered findings that would be discarded and refuses with exit 3 (no interactive prompt, safe for hooks/CI). With `--yes`, it runs a full `Gate.ALL` scan and writes a new baseline, printing `old -> new` counts. Expect re-fingerprinted-but-unchanged findings to subsequently show as "fixed"/resolved in `status`/`ledger list` — this is documented, expected behavior.

**How do I arm a subsystem after its bake period?**
There is no single "arm everything" command — arm each flag deliberately:
- `aramid arm` (no flag) — ends the semgrep OWASP bake (`semgrep_block_armed = true`).
- `aramid arm --llm` — ends the LLM bake (`[llm].llm_block_armed = true`); confirmed-CRITICAL LLM findings now BLOCK at pre-push.
- `aramid arm --autolearn` — arms auto-learn (`[llm.autolearn].armed = true`); uplift/cascade now change reviewer selection (escalate-only; the ladder tier stays the floor). Also prints the shadow record (would-uplift count, audits performed, missed criticals) at arming time.
- `[pack].pack_block_armed` has no `arm` subcommand at all — it's meant to be hand-edited in `aramid.toml` (and defaults to `true` already).
- All three `arm` invocations refuse with exit 3 if `aramid.toml` doesn't exist yet (run `aramid init` first), and all use a comment-preserving regex rewrite rather than a full TOML re-dump.

**A drain consumer keeps skipping my item / says it's "giving up."**
Each consumer with a give-up valve stops retrying after repeated identical failures at the same head (typically 3 times), to avoid burning budget forever on a structurally-broken item: `llm-review` after 3 malformed provider responses; `mutation` after 3 failing baseline runs at that exact head; `js_mutation` after 3 failing baseline runs or 3 failed `node_modules` link attempts at that head; `dast` after 3 unreachable-target or 3 probe-error attempts at that head. A new commit (new head) resets these counters. `regression_pack` and `fuzz` have no give-up valve — `fuzz` in particular can never report DEGRADED at all; every failure short of `git worktree add` failing is swallowed as an OK-skip.

**Why does a consumer report "no python/js test stack" instead of failing?**
This is deliberate — `mutation`/`js_mutation` treat a permanently-absent test stack (no pytest/no npm test script) as an OK-skip, not a DEGRADED failure, so that a JS-only repo (for `mutation`) or a Python-only repo (for `js_mutation`) doesn't pin its queue item forever waiting on a stack that will never appear.
