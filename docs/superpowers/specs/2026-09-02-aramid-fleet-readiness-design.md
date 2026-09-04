# Aramid — Fleet health, 1.0 readiness, and aramid's own notice channel

**Date:** 2026-09-02
**Baseline:** `main` @ `392c2d0` (release: v0.8.1, published to PyPI and promoted on this machine), level with `origin/main`, CI green (run 33614105885, seven legs), 3 open ledger findings (all suppressed, 0 blocking).
**Status:** design approved by the user in chat (2026-09-02); ready for writing-plans.
**Scope decisions made by the user:** approach **A — push at gate time, judge at drain time, deliver wherever the operator works** (option 1 of 3); readiness threshold **strict — every criterion green on every registered repo, held across at least 2 consecutive aramid releases and at least 14 days** (option 1 of 3); all six design sections approved as presented, **including the one-line gate trailer** and **fleet-defect notices** in the first version.

---

## 1. Context & motivation

aramid records everything it does inside the repo it gates — the append-only event ledger, per-run logs, `status`, `resolvers` — and rolls two things up machine-wide (autolearn state, LLM spend). It has **no feedback channel to its maintainer**: no telemetry, no phone-home, by design. So the question "is aramid ready to be called 1.0?" has no external answer. The evidence exists, but it lives in five separate ledgers (the registry lists `aramid`, `pawscout-worker`, `graphite`, `operation-firewall`, `Atlas_Data`), nothing judges it over time, and nothing carries the verdict to the operator.

The user asked for exactly that loop: collect across every repo aramid touches, decide when enough evidence has accumulated, and say so **in the repo where the operator is working right now** — the way the Graphite agent channel already reaches them.

Everything this needs already has a seam:

- **Fleet definition:** `~/.aramid/repos.toml` (`registry.load_registry()`), iterated by the 4-hourly scheduled drain.
- **Machine-global state precedent:** `autolearn.load_state/save_state` (versioned JSON, unreadable or foreign-version → empty, fail-open) and the append-only LLM spend log.
- **Per-repo signals:** `commands/status.py` already computes skip streaks, degraded-consumer streaks, stood-down consumers, no-work consumers, resolver defects (via `yield_report.collect`) and bake posture. `config.armed_flags(cfg)` walks every `*_armed` flag.
- **Delivery surfaces in the repo you are in:** the SessionStart agent hook (`agent_hook._session_context`), `aramid status`, and the gate's own console/JSON output. None of them needs a tracked-file change in any consumer.
- **A judged, budgeted, end-of-cycle rollup point:** `cmd_drain` already runs the autolearn rollup after draining, fail-open.

## 2. Approaches considered

- **A — push at gate time, judge at drain time, notices delivered everywhere. CHOSEN.** Each gate run appends its own repo's health row to a machine-level store; the drain judges the fleet and posts notices to an aramid-owned channel; the session-start hook, `status` and a gate trailer surface pending notices in whatever repo the operator is in. No process ever opens another repo's ledger. Data is as fresh as the last gate run.
- **B — pull-only at drain time.** The drain opens every registered ledger and recomputes. Rejected: reads across repos (the very thing the isolation rule and the drain's incident history warn about), stale by up to four hours, and O(fleet × ledger) every cycle.
- **C — report-only `aramid fleet`.** Rejected: answers the question only when asked; the user asked to be told.

## 3. Machine-level data (all under `~/.aramid/`; nothing new is written into any repo)

### 3.1 `fleet_health.jsonl` — one row per gate run per repo, append-only

```json
{"schema_version": 1, "at": "2026-09-02T18:04:11+00:00", "repo": "f:/projects/aramid", "name": "aramid",
 "aramid_version": "0.8.2", "gate": "pre-push", "run_id": "61abba7e…", "exit_code": 0, "engine_error": false,
 "criteria": {"no_skip_streak": true, "consumers_healthy": true, "resolvers_ok": true,
              "no_self_inflicted_block": true, "dep_audit_ran": false},
 "evidence": {"skip_streaks": {}, "degraded_consumers": [], "stood_down": [], "no_work": [],
              "resolver_defects": [], "bad_tools": [], "degraded_block_tier": false,
              "armed": {"semgrep_block_armed": false, "tdd_block_armed": false, "agent_block_armed": false},
              "open": 3, "blocking": 0}}
```

`repo` is `normalize_path(root)` — the same key the registry and autolearn use. `dep_audit_ran` is tri-state (`true`/`false`/`null`, see §4). Every row carries `schema_version`; a reader ignores rows whose version is newer than its own, with one stderr note per read.

### 3.2 `fleet_verdict.json` — the latest judgement, written atomically (tmp + replace) by the drain

```json
{"schema_version": 1, "computed_at": "…", "aramid_version": "…",
 "policy": {"min_days": 14, "min_versions": 2},
 "repos": {"f:/projects/aramid": {"name": "aramid", "rows": 41, "latest_at": "…", "green": false,
                                  "red_criteria": ["dep_audit_ran"]}},
 "fleet": {"all_green_now": false, "streak_started_at": null, "days_held": 0.0,
           "versions_in_streak": [], "armed_anywhere": false, "disarm_in_streak": false},
 "verdict": "not-ready", "reasons": ["aramid: dep_audit_ran", "no repo is armed"]}
```

`verdict` ∈ `ready` | `not-ready` | `insufficient-data`.

### 3.3 `notices.jsonl` — aramid's own channel, append-only events

```json
{"schema_version": 1, "kind": "notice", "id": "9f3c1a7e2b40", "notice_kind": "readiness-reached",
 "key": "streak:2026-09-05T10:00:00+00:00", "at": "…", "title": "…", "body": "…", "evidence": {}}
{"kind": "shown", "id": "9f3c1a7e2b40", "at": "…", "repo": "f:/projects/atlas_data", "surface": "session-start"}
{"kind": "ack",   "id": "9f3c1a7e2b40", "at": "…", "repo": "f:/projects/atlas_data"}
{"kind": "cleared", "id": "…", "at": "…", "reason": "defect absent from latest row"}
```

`id` is the first 12 hex of `sha256(notice_kind + ":" + key)`, so a re-posted condition maps to the same id and is deduplicated by construction. Event-sourced like the ledger: nothing is ever rewritten; "pending" is materialised (§7).

### 3.4 `fleet.toml` — optional operator policy

```toml
schema_version = 1
[readiness]
min_days = 14          # user's choice: strict
min_versions = 2       # distinct aramid versions inside the green streak
max_row_age_days = 7   # a repo whose latest row is older than this is stale; 0 disables (amendment A1)
[notices]
repeat_hours = 24      # a pending notice is re-shown in a given repo at most this often
defect_rows = 3        # a fleet-defect notice needs the same defect on this many consecutive rows
gate_trailer = true    # the one-line console trailer
```

Absent → defaults above. Unreadable → defaults plus one stderr note (the registry precedent).

## 4. The criteria

Five are computed **per row, from that repo's own ledger, at push time**. One is judged **fleet-wide** at drain time from the rows. A seventh is **manual** and stays in `RELEASING.md`.

| # | Key | Green when | Source |
| --- | --- | --- | --- |
| 1 | `no_skip_streak` | every tool expected at this gate ran on this run (all skip streaks 0) | `status._skip_streak_lines` internals |
| 2 | `consumers_healthy` | no consumer in a degraded streak, stood down, or in a no-work streak | `_consumer_health_lines`, `_stood_down_lines`, `_no_work_lines` internals |
| 3 | `resolvers_ok` | no resolver graded `NEVER RAN` or `BLIND` | `yield_report.collect` verdicts |
| 4 | `no_self_inflicted_block` | this run's verdict was not caused by aramid's own machinery: no BLOCK-tier tool in `MISSING`/`CRASHED`/`TIMEOUT`, `degraded_block_tier` false, no engine error. A block on a genuine finding is green — that is the gate working. | `GateResult.tools_ran` states, `degraded_block_tier`, `cmd_check`'s engine-error path |
| 5 | `dep_audit_ran` | `null` when pip-audit is not expected at this gate; `true` when it ran `OK` and examined at least one file; otherwise `false` | `expected` set and `RunnerResult.examined` |
| 6 | `armed_on_evidence` (fleet) | at least one registered repo's latest row has any `*_armed` flag true, and no flag went true→false between consecutive rows of any repo inside the streak | `evidence.armed` across rows |
| 7 | API freeze (manual) | two consecutive releases with no `Changed`/`Removed` entry against the declared compatibility surface | `CHANGELOG.md`, human judgement at release time |

Criterion 5 is the open lead from `aramid doctor` on this repo made visible: a pyproject-only Python repo currently reads `false` at pre-push, and readiness cannot go green until that is fixed. That is the intent.

A row is **green** when criteria 1–4 are `true` and 5 is `true` or `null`. Arming and disarming are `aramid.toml` edits, not ledger events, so criterion 6 is observable only from the sequence of rows — which is why every row carries the full `armed` dict.

## 5. Push at gate time

**Seam:** `cmd_check`, immediately after `print(output)` and before `return exit_code`, and also in the engine-error `except` branch (a row with `engine_error: true`, `exit_code: 3`, criteria all `false` except 5 = `null`).

```python
if record:
    fleet.record_health(root, cfg, ledger, result, aramid_version=__version__, now=_now())
```

- **Fail-open, always.** The call is wrapped inside `fleet.record_health` itself: any exception, a read-only home directory, a full disk, a corrupt store → one stderr line `aramid: fleet: health row not recorded (<reason>)`, and the gate's exit code is untouched. This is the same contract as the session-start hook.
- **Budgeted.** 2 s wall clock for computing the criteria (they walk the ledger's events the way `status` does). Over budget → the row is skipped with a stderr note, never a partial row.
- **`--no-record` writes nothing.** A snapshot run is not evidence.
- **Atomic enough.** One `write()` of one newline-terminated line in `O_APPEND` mode; concurrent gates in different repos interleave whole lines. No lock.
- **Signals are shared, not copied.** The criteria are computed by a new `aramid/health.py` — `snapshot(cfg, ledger, result=None) -> Health` — and `status`'s `_x_lines` functions are refactored to render from the same `Health` object. The two surfaces therefore cannot disagree (the "two computations that must agree" rule), and `agent_hook._session_context` keeps importing the `_x_lines` names it uses today.

## 6. Judge at drain time

**Seam:** `cmd_drain`, after the autolearn rollup and before the final print, under the drain lock already held. Fail-open: any exception → stderr `aramid drain: fleet judgement skipped: <exc>`; the drain's return code is unchanged.

Algorithm, `fleet.judge(rows, registry, policy, now) -> Verdict`:

1. Consider only rows for repos **currently registered**; rows for deregistered repos are ignored. Rows older than 180 days are ignored (and compacted away, §10).
2. Sort rows by `at`. Walk them, maintaining `latest[repo]`. The fleet is **green at time t** iff every registered repo has a row, its latest row is green (§4) and no older than `max_row_age_days` at t (amendment A1), and criterion 6 holds over the current streak.
3. `streak_started_at` = the time of the transition into green that has held continuously through `now`; any transition to red resets it to `null`. A registered repo with **no rows** makes the fleet `insufficient-data`, which also resets the streak — a newly onboarded repo has to earn its rows (strict, per the user's choice). A registered repo whose latest row is **older than `max_row_age_days` at `now`** is stale and makes the fleet `insufficient-data` the same way (amendment A1).
4. `versions_in_streak` = distinct `aramid_version` over rows with `at >= streak_started_at`. `days_held = now - streak_started_at`.
5. `ready` iff a streak exists, `days_held >= min_days`, `len(versions_in_streak) >= min_versions`, `armed_anywhere`, and not `disarm_in_streak`. Otherwise `not-ready` with `reasons` naming every red repo/criterion, or `insufficient-data`.
6. Write `fleet_verdict.json` atomically.

**Transitions post notices** (compared against the previous verdict file):

- `not-ready`/`insufficient-data` → `ready`: **`readiness-reached`**, key `streak:<streak_started_at>`. Body names the streak start, days, versions, and repos.
- `ready` → anything else: **`readiness-broken`**, key `run:<run_id of the breaking row>`. Body names the repo, the row's time, and the red criteria.
- **`fleet-defect`**: a repo whose last `defect_rows` (default 3) consecutive rows carry the same defect — a resolver name graded `NEVER RAN`/`BLIND`, a stood-down or degraded consumer, or a skip streak on the same tool — gets one notice keyed `defect:<repo>:<kind>:<name>`. When the latest row no longer carries it, a `cleared` event is appended. A pending notice with the same key is never re-posted.

## 7. Notices channel semantics

- **Pending** = a `notice` with no `ack` and no `cleared` for its id.
- **Display rule** for the full-body surfaces (session-start, `status`): show a pending notice in repo R only if no `shown` event exists for `(id, R)` within `repeat_hours`; append a `shown` event when displayed. The gate trailer shows only a **count** and prints whenever the count is non-zero (cheap, never a `shown` event).
- **`ack`** appends an `ack` event with the repo it was acked in. Acking is idempotent. An unknown id exits 3 with the pending ids listed.
- Notices are machine-level: acking in one repo silences it everywhere. That is the point — it followed you; you answered it.

## 8. Delivery surfaces (exact line shapes; every one has a full-line test)

**Session-start hook** (appended after the bake lines in `_session_context`):

```
aramid: fleet: 1.0 readiness NOT READY -- 4/5 repos green, streak 0d, versions 0/2; red: aramid (dep_audit_ran)
aramid: NOTICE 9f3c1a7e2b40 readiness-broken: Atlas_Data went red at 2026-09-03T10:11Z (resolvers_ok: file_departed BLIND) -- ack: aramid notices ack 9f3c1a7e2b40
```

**`aramid status`** (new `fleet:` block after `scheduled drain:`): the same two line shapes without the `aramid:` prefix, plus `fleet: no verdict yet -- first drain after promotion computes it` when `fleet_verdict.json` is absent.

Amendment A1 adds one tail to the readiness line, `stale: <name> (<age>d) -- window <W>d`, after `red:` and `no rows:` and before the blockers, and a third clause to the `aramid fleet` header (`..., 7-day row window)`). See A1.4.

**Gate console trailer** (last line, console mode only, when `gate_trailer` is on and pending > 0):

```
aramid: 2 fleet notice(s) pending -- see `aramid notices`
```

**Gate JSON:** additive key `"fleet_notices_pending": 2` (always present, `0` when none; absent only if the store could not be read, and then `"fleet_notices_pending": null`).

**`aramid fleet [--json]`:** a repo × criteria matrix (`ok` / `RED` / `-`), the streak line, and the verdict with reasons; `--json` prints `fleet_verdict.json` verbatim. Exit 0 always; it is a report.

**`aramid notices [list] | show <id> | ack <id>`:** `list` prints pending notices one per line (`<id> <kind> <title>`), `show` prints the body and evidence, `ack` appends the event. Exit 0; unknown id → 3.

## 9. Failure handling and invariants

1. No fleet call ever changes a gate's, the drain's, or the hook's exit code, or raises out of its seam.
2. No fleet call opens a ledger other than the current repo's. The drain reads only `~/.aramid/fleet_health.jsonl`.
3. No network, ever. Nothing leaves the machine.
4. The store lives under `~/.aramid` only; `aramid uninstall` does not touch it (it is fleet state, not repo state). `aramid init` needs no change.
5. A store that is missing, empty, corrupt, or newer-schema reads as empty with one stderr note; a corrupt trailing line (a torn write) is skipped, not fatal.
6. Writes are single-line appends, or tmp + `os.replace` for the two whole-file artefacts.
7. Budgets: push ≤ 2 s; judge ≤ 30 s; both report and skip on overrun.
8. Compaction: the drain rewrites `fleet_health.jsonl` without rows older than 180 days, under its lock, tmp + replace, at most once per day.

## 10. Testing

- **Each criterion, both directions**, from synthetic ledgers built with the existing `Ledger.record_run` and consumer/yield event writers: skip streak present/absent; degraded, stood-down and no-work consumers; resolver `BLIND` and `NEVER RAN`; a crashed BLOCK-tier tool versus a genuine finding block; pip-audit expected-and-ran, expected-and-not, not-expected.
- **Streak and verdict math**, table-driven on fixture rows with explicit timestamps and versions, no sleeps: streak start, reset on red, reset on a registered repo without rows, versions counted inside the streak only, `min_days` and `min_versions` boundaries, disarm inside the streak.
- **Notice state machine:** transitions produce exactly one notice per key; dedupe on re-post; `cleared` on recovery; `shown` respects `repeat_hours` per repo; `ack` is idempotent; unknown id exits 3.
- **Rendering:** full-line assertions for every surface in §8, including the `no verdict yet` line and the JSON key.
- **Fail-open, as subprocesses:** `aramid check --staged` with `HOME` pointed at a directory holding a corrupt `fleet_health.jsonl`, and at a read-only directory, exits exactly as it does with a healthy store; the drain with a corrupt verdict file exits as before.
- **`--no-record` writes no row.**
- **Two computations that must agree:** `status`'s rendered lines and the health row are both derived from one `Health` snapshot; a test perturbs the snapshot (adds a defect) and asserts both surfaces move together.
- **Drain integration:** two temp repos with ledgers, a temp registry and `HOME`; after `cmd_drain`, the verdict file exists, and a seeded red→green→red sequence yields `readiness-reached` then `readiness-broken`.

## 11. Rollout and dogfood

- Ships in the next minor release. **No version floor for consumers:** every delivery surface lives in the wheel; no tracked file changes.
- First rows appear on each registered repo's next gate run after promotion; the first verdict on the next scheduled drain; `insufficient-data` until every registered repo has rows.
- `RELEASING.md` gains a "1.0 gate" section: `aramid fleet` must read `ready`, plus the manual criterion 7. `MAINTAINERS.md` links it.
- Expected first reading on this machine: `not-ready`, with `aramid: dep_audit_ran` red and `no repo is armed` — both true today, both things 1.0 should wait for.

## 12. Out of scope

Network access of any kind; "a newer aramid is available" checks; cross-machine aggregation; reading other repos' ledgers; automating criterion 7; changing what `init` writes; any change to a consumer's tracked files.

## Amendment A1 (2026-09-04): the freshness window

**Decision, operator, 2026-09-04 ~02:10Z.** A registered repo's latest row counts toward the fleet's green streak only while it is no older than `max_row_age_days` (default **7**); a stale row makes the fleet `insufficient-data` and **resets** the streak. Announced to graphite-agent as channel round 171.

### A1.1 Why

Sections 6.2 to 6.3 as written evaluate `green` only when a row arrives, and `days_held` is pure wall clock. `ready` was therefore reachable from two green rows carrying two versions followed by 14 idle days, and `armed_anywhere` could be read off a row up to 180 days old. "Held continuously for 14 days" was meant as continuing positive evidence; the code read it as absence of contrary evidence. On an active fleet the two coincide; on an idle one they do not. Recorded at the final review of the implementation plan (Important 7) and parked until the operator decided.

Options weighed and rejected: a 3-day window (a long weekend restarts the 14-day clock); keeping the spec as written (documenting that readiness measures absence of contrary evidence); a 7-day window that only **pauses** `days_held` (a new "paused" state on every surface). Seven days guarantees at least two rows per repo inside any 14-day streak, tolerates a week idle, and reuses the `insufficient-data` label the judge already has -- strict, matching the deregistration decision of 2026-09-03: a registered repo with no rows blocks any verdict, and a registered repo with only old rows now does too.

### A1.2 Policy (amends §3.4)

`[readiness].max_row_age_days`, integer days, default `7`. `0` **disables** the window and restores the behaviour of §6 as originally written. A negative or non-integer value falls back to the default like every other key (`_int_or`). The verdict's `policy` block carries it: `{"min_days": 14, "min_versions": 2, "max_row_age_days": 7}`.

### A1.3 Judge (amends §6, steps 2, 3 and 5)

Let `W` be the window as a duration; a row is **fresh at time t** when `t - row.at <= W` (exactly `W` old is still fresh). With `W` disabled nothing below applies.

- **Step 2, during the walk.** The fleet is green at a row's time `t` iff every registered repo has a row, its latest row is green **and fresh at `t`**, and criterion 6 holds. In addition, **before** a row is applied, if a streak is open and any repo's latest row -- the same repo's previous row included -- is no longer fresh at `t`, the streak resets (`streak_started_at = null`, versions cleared, disarm forgotten) exactly as a red row resets it. The second rule catches the gap the first cannot see: a single-repo fleet, or every repo silent past the window and then all pushing on the same day, produces no row inside the gap for the walk to evaluate.
- **Step 3, at `now`.** A registered repo whose latest row is not fresh at `now` is **stale**. Any stale repo makes the verdict `insufficient-data`, resets the streak, and `days_held` reads `0`. Label precedence for prediction: no repos registered -> a registered repo with no rows -> **a registered repo with a stale row** -> a red latest row -> the ready checks. A row that is stale **and** red reads `insufficient-data` with both reasons listed: an old row is not evidence of the current state in either direction.
- **Step 5, output (additive; `schema_version` unchanged).** Per repo: `stale: bool` and `age_days: float | null` (days from the latest row to `now`, two decimals; `null` with no rows). Fleet: `stale_repos: [<name>, ...]` sorted case-insensitively. `reasons` gains `stale: <name> (<age>d), <name> (<age>d) -- window <W>d` after the `no rows:` entry and before any blocker; `<age>` has one decimal so a `7.4d` row never reads as `7d` beside a `7d` window.
- **Transitions (§6, unchanged in code).** `ready` -> `insufficient-data` caused by staleness has no breaking row (every latest row is still green), so the existing no-breaking-row branch keys the `readiness-broken` notice on the prior verdict's streak start; its title reads `fleet readiness lost -- stale: ...`. No new notice kind.

### A1.4 Surfaces (amends §8)

- Readiness line (session-start hook, `aramid status`): the tail gains `stale: <name> (<age>d) -- window <W>d`, placed after `red:` and `no rows:` and before the blockers, e.g. `fleet: 1.0 readiness INSUFFICIENT DATA -- 2/2 repos green, streak 0d, versions 0/2; stale: graphite (9.3d) -- window 7d`. The `N/N repos green` count stays a property of the rows (a stale row can still be green); the tail says why the verdict is not. Verdict files written before A1 carry no `stale` keys and render exactly as before.
- `aramid fleet`: the header reads `fleet health -- 1.0 readiness (policy: 14 days, 2 versions, 7-day row window)`, or `..., no row window)` when disabled; the matrix is unchanged and the `stale:` reason prints under `verdict:` like any other.
- `aramid fleet --json`: the verdict file verbatim, with the new keys.

### A1.5 Testing (amends §10)

Streak math, table-driven, no sleeps: two green rows then idle past the window -> `insufficient-data`, `stale` named, streak `null`, `days_held` 0, and the same rows under `max_row_age_days = 0` -> `ready` (the original behaviour, still reachable); an active fleet with rows every 6 days for 20 days under the default policy -> `ready` (the window does not tax the happy path); a cross-repo gap inside the walk restarts the streak at the returning row; a same-repo gap in a single-repo fleet restarts it too; `no rows` beats `stale`, `stale` beats red, both reasons listed; exactly `W` old is fresh. Policy: default `7`, `0` accepted, negative and string fall back. Rendering: full-line assertions for the readiness-line tail and both `aramid fleet` headers. Drain: the transition fixtures place rows at most 6 days apart so they run under the production default rather than a disabled window, and a `ready` verdict left idle past the window posts `readiness-broken` keyed on the prior streak start.

### A1.6 Rollout

Ships in the next MINOR (a new policy key is new surface). No tracked file in any consumer changes. Expected first reading on this machine: no change -- both registered repos' latest rows are hours old. The first observable effect is that a `ready` verdict now needs every registered repo to have pushed within the last 7 days at the moment of the drain, throughout the 14-day streak. Documented in `docs/user-guide.md` (policy block and one paragraph).
