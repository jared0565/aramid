# Aramid Auto-Learn Model Selection — Design

**Date:** 2026-07-18
**Status:** Approved
**Builds on:** `2026-07-14-aramid-reviewer-model-selection-design.md` (the Arm
substrate + deterministic risk-tiered ladder). This spec delivers the engine
that spec's §6.4 and §12 deferred: the real escalation signal, the reward
signal from ledger outcomes, and probabilistic arm selection.

---

## 1. Goal

Replace the reviewer's **provisional** tier signal (raw triage score) with a
learned selection policy that (a) measures what cheaper arms actually miss,
(b) uplifts items to higher tiers when the evidence says the floor arm is not
good enough, and (c) ships observably safe: it runs in **shadow** until
explicitly armed, and its cold-start / no-data / failure behavior is exactly
today's deterministic ladder.

### Terminology

The learned tier-raise is called **uplift** throughout. The word
"escalation" is already taken in this codebase (`policy.escalate_degraded`:
gate-exit escalation on degraded BLOCK-tier tooling) and is never used for
arm selection.

## 2. Scope

**In scope (one spec, one branch):**

1. **Structured selection telemetry** — arm attribution, failed-arm traces,
   refuter identity, per-call latency, cascade/audit attribution, all as
   structured ledger payload fields (today this exists only as a free-text
   `note` string, or not at all).
2. **Reward extraction + machine-global state** — a pure rollup from
   per-repo ledgers into `~/.aramid/autolearn_state.json`.
3. **The uplift policy** — escalate-only Thompson sampling over Beta
   posteriors (counting-Bayes bandit), plus deterministic **cascade**
   re-review rules and **audit sampling** (frontier double-reviews that
   measure miss rate).
4. **Bake-then-arm shipping** — telemetry, shadow decisions, and audits run
   by default; the policy only changes selection after
   `aramid arm --autolearn` flips the per-repo armed flag.
5. Report/ops surface: `aramid autolearn` (+ `--rebuild`), a `status` line,
   a `doctor` probe.

**Explicitly OUT of scope (forward hooks, §13):**

- De-escalation below the ladder floor (serving a cheaper arm than the
  deterministic target). Escalate-only is a hard rule in this version.
- Wiring the secondary reward counters (hallucination rate, refute outcomes,
  human overrides) into the uplift decision — they are recorded and reported
  but do not influence v1 decisions.
- Contextual bandits / learned feature weights; learned cascade triggers;
  learned refuter selection (`select_refuter` stays deterministic).
- Per-repo state overlays; multi-refuter panels.

## 3. Non-negotiable invariants

1. **Block path.** The per-finding contract is unchanged and untouchable:
   `verify_findings` → confirmed-strip (`cand.pop("confirmed")`) →
   fingerprint dedupe → capped cross-provider refute → `apply_refute` →
   `llm_gate_findings` (BLOCK = armed AND confirmed AND critical).
   Uplift, cascade, and audit change only *which and how many model calls
   produce review candidates*. Every candidate — served, cascade, or audit —
   flows through the identical downstream contract. More reviews may surface
   more findings (that is the feature's purpose: an audit catching a missed
   critical files it for real), but each finding individually earns
   `confirmed` through the full unchanged per-finding contract.
   The single permitted edit inside block-path code: `apply_refute` gains
   one marker line (`out["refuted"] = True` on the refuted branch). Its
   `confirmed` logic stays byte-identical.
2. **Cold start ≡ shipped ladder.** No state file, empty posteriors, unknown
   state version, or any exception inside policy code must reproduce today's
   deterministic selection exactly. This falls out of the prior (§8) and the
   fail-open wrapper (§11), and is asserted by regression tests: the
   existing arm-selection tests pass unchanged with autolearn enabled in
   shadow.
3. **Escalate-only.** The deterministic ladder tier is a floor. The policy
   may serve a higher tier, never a lower one.
4. **No live LLM calls in tests.** Fakes / monkeypatched transports only.
5. **Model-source policy.** Arms remain the config ladder (subscription /
   flat-rate providers by default; OpenRouter stays opt-in, in-app only).
6. **Graphite coexistence.** New state lives under `~/.aramid/` and
   per-repo `.aramid/` — both already outside graphite's artifacts and
   inside aramid's built-in ignore paths. No new top-level repo artifacts.

## 4. Decision table

| Decision | Choice |
|---|---|
| Shipping model | Telemetry + shadow policy in one spec; bake-then-arm (`aramid arm --autolearn`) |
| Risk posture | Escalate-only (ladder tier is a floor); de-escalation is a forward hook |
| Signal layers | Predictive (Thompson uplift) + reactive cascade + audit sampling — all three |
| Learning core | Counting-Bayes bandit: Beta posteriors per (arm, band, bucket), Thompson sampling |
| Primary reward | Audit outcomes only (missed-critical vs clean). Secondary counters observed, not wired |
| State locality | Machine-global `~/.aramid/autolearn_state.json`, derived + rebuildable from per-repo ledgers |
| Selection seams | Reuse `reviewer_order` unchanged: uplift = `reviewer_order(arms, max(item.score, uplift_arm.min_score), avail)` |
| Telemetry channel | `ConsumerResult.extra` dict merged into `CONSUMER_RUN_FINISHED` payload; `Finding.refuted` flag |
| Sampling determinism | Hash-based (audit: `hash(item.id) % audit_every == 0`; Thompson RNG seeded from item id + state `updated_at`) |

## 5. Components

### 5.1 New: `src/aramid/autolearn.py`

Pure functions plus two explicit I/O functions (`load_state(path)`,
`save_state(state, path)` — atomic tmp+rename). Owns:

- `bucket_for(item) -> str` — feature bucketing (§8.1).
- `band_for(arms, score) -> str` — the floor band name.
- `uplift_pick(arms, score, bucket, state, cfg, rng) -> Arm | None` — the
  Thompson decision (§8.2). Returns the arm to serve, or `None` meaning "no
  uplift" (serve the deterministic floor).
- `cascade_trigger(served_arm, arms, verified, rejected, truncated, cfg) -> str | None`
  — deterministic trigger name or `None` (§9).
- `should_audit(item_id, served_arm, arms, cfg) -> bool` (§10).
- `audit_diff(served_verified, audit_verified) -> tuple[int, int]` —
  (new_findings, missed_criticals), by fingerprint (§10).
- `rollup(state, events, repo_key) -> state` — fold ledger events past the
  repo cursor into posterior counts (§8.3).
- `empty_state() -> dict`, state-version validation.

### 5.2 Modified (all additive)

| File | Change |
|---|---|
| `consumers/llm_review.py` | Consult policy before selection (shadow records, armed applies); cascade + audit orchestration; build the `selection` telemetry dict; per-call latency in `_call` |
| `consumers/base.py` | `ConsumerResult` gains `extra: dict` (default empty) |
| `commands/drain.py` | Merge `ConsumerResult.extra` into the `CONSUMER_RUN_FINISHED` payload; run the incremental rollup at drain end (fail-open) |
| `models.py` | `RawFinding` and `Finding` gain `refuted: bool = False` |
| `ledger.py` | `_detect_payload` carries `refuted` (materialized state picks it up via payload spread) |
| `review.py` | `apply_refute`: one marker line on the refuted branch. Nothing else |
| `commands/arm_cmd.py` (or wherever `aramid arm` lives) | `--autolearn` flag writes `[llm.autolearn] armed = true` to repo `aramid.toml` (same idiom as `arm --llm`) |
| `commands/status.py` | One autolearn line (§12) |
| `commands/doctor.py` | State-file readability/version probe |
| new `commands/autolearn_cmd.py` | `aramid autolearn` report + `--rebuild` (§12) |
| `data/defaults.toml` | `[llm.autolearn]` section (§7) |

`reviewer_order`, `target_arm`, `select_refuter`, `verify_findings`,
`auto_resolve_llm`, `llm_gate_findings` are **not modified**.

## 6. Telemetry: the `selection` payload

`consume()` returns `ConsumerResult(extra={"selection": {...}})`; drain
merges `extra` into the `CONSUMER_RUN_FINISHED` payload alongside the
existing structured keys and the human-readable `note` (which is unchanged —
existing note-string tests keep passing).

```json
"selection": {
  "target_tier": "cheap",
  "served": {"tier": "mid", "provider": "codex-cli", "model": "gpt-5.5", "effort": "medium"},
  "attempts": [
    {"tier": "cheap", "provider": "ollama-cloud", "model": "deepseek-v4-flash", "error": "unavailable", "latency_s": 0.02},
    {"tier": "mid", "provider": "codex-cli", "model": "gpt-5.5", "error": "", "latency_s": 41.3}
  ],
  "uplift": {"mode": "shadow", "pick": "mid", "applied": false, "sampled_q": 0.21},
  "cascade": {"triggered": true, "trigger": "critical", "applied": false},
  "audit": {"performed": true, "tier": "frontier", "new_findings": 1, "missed_criticals": 1},
  "refutes": [
    {"refuter_provider": "claude-cli", "refuter_tier": "frontier", "outcome": "survived", "latency_s": 55.0}
  ],
  "tokens": {"in": 8123, "out": 942}
}
```

Rules:

- `attempts` records **every** arm tried in the fallthrough loop, including
  the winner (`error: ""`) — failed arms finally leave a trace.
- `uplift.mode` is `"off" | "shadow" | "armed" | "error"`. In shadow,
  `pick` records what the policy would have served; `applied` is false.
- `cascade.applied` / `audit.performed` are false when skipped for budget or
  provider failure; the reason lands in `note` only if it already does today.
- `refutes[*].outcome` ∈ `survived | refuted | unavailable` (unavailable =
  transport-failed/malformed/budget-clipped refute, i.e. today's
  demote-fail-safe path).
- `audit` is `null` when not sampled.
- Per-call latency is measured in `_call()` via `time.monotonic()`.
- Per-finding attribution needs no new finding fields beyond `refuted`:
  the run's findings join to `selection.served` via the existing shared
  `run_id`.

The spend log (`~/.aramid/llm_spend.jsonl`) is **unchanged**.

## 7. Config surface

```toml
[llm.autolearn]
# Telemetry + shadow decisions + audit sampling. Safe default: shadow never
# changes selection; audits cost flat-rate quota only (all default arms are
# subscription / flat-rate).
enabled = true
# Flipped per-repo by `aramid arm --autolearn` (bake-then-arm, same idiom as
# `aramid arm --llm`). Only when true do uplift and cascade change selection.
armed = false
# Serve the lowest arm whose Thompson-sampled miss probability is <= this.
uplift_threshold = 0.15
# Audit 1 in N reviews served below frontier (deterministic hash sampling).
audit_every = 8
max_audits_per_drain = 1
# Cascade trigger: hallucination_rejected >= this.
cascade_hallucination_min = 3
```

Deep-merge semantics: `[llm.autolearn]` is a nested table, so repo overrides
merge key-by-key (dict deep-merge; the ladder's list-replace rule does not
apply here).

## 8. The learning core

### 8.1 Feature buckets

Deliberately coarse for ~18 reviews/day of data. Cells per arm:

- **band** — the deterministic floor band name (`cheap|mid|frontier`), from
  `target_arm(arms, item.score).tier`.
- **bucket** — `"sec"` if any queue-item triage reason contains
  `security-path` or `risky-content`, else `"plain"`.

Posterior key: `"<provider>/<model>|<band>|<bucket>"`.

### 8.2 Uplift decision (Thompson, escalate-only)

For an item whose deterministic floor arm is F:

1. Walk arms from F upward in `min_score` order.
2. For each arm A, sample
   `q ~ Beta(1 + misses(A, band, bucket), PRIOR_CLEAN + clean(A, band, bucket))`
   where `PRIOR_CLEAN = 9`. A cell with zero evidence (`misses + clean == 0`)
   does not sample: it uses the deterministic prior mean
   `1/(1+PRIOR_CLEAN)` = 0.10, so empty posteriors reproduce the ladder
   exactly (§3.2); Thompson sampling begins once audit evidence exists.
3. Serve the lowest arm with `q <= cfg uplift_threshold` (default 0.15).
4. The frontier (highest-`min_score`) arm always qualifies — it is the
   measuring ceiling; if nothing else qualifies, serve it.

Properties:

- No data → every cell on the walk is zero-evidence → deterministic prior
  mean 0.10 ≤ 0.15 → the floor arm qualifies → behavior is *exactly* the
  deterministic ladder, not merely in expectation. This is the load-bearing
  cold-start property (invariant 2).
- The decision RNG is seeded from `sha256(item.id + state["updated_at"])` —
  deterministic in tests, varies across state updates in production.
- Applying an uplift means computing
  `order = reviewer_order(arms, max(item.score, uplift_arm.min_score), avail)`
  — the uplifted arm becomes the target and the existing availability
  degrade-down chain is preserved without modifying `review.py`.
- In shadow mode the decision is computed and recorded
  (`uplift.pick/sampled_q`) but `order` is built from the raw `item.score`.

### 8.3 Reward extraction & state

Machine-global, derived, rebuildable. `~/.aramid/autolearn_state.json`:

```json
{
  "version": 1,
  "updated_at": "2026-07-18T09:00:00+00:00",
  "cursors": {"F:/Projects/demo-store2": 4812},
  "posteriors": {
    "ollama-cloud/deepseek-v4-flash|cheap|sec": {
      "misses": 1, "clean": 13,
      "halluc": 4, "malformed": 0, "refuted": 2, "survived": 1, "overridden": 0
    }
  },
  "shadow": {"decisions": 17, "would_uplift": 3},
  "audits": {"performed": 14, "missed_criticals": 1}
}
```

- **Primary reward (drives uplift):** audit outcomes only.
  `misses` += the audit's `missed_criticals`; `clean` += 1 per audit with
  `missed_criticals == 0`. Attributed to the **served** arm's posterior key.
- **Secondary counters** (recorded, reported, NOT wired into decisions):
  `halluc` (hallucination_rejected), `malformed` (malformed-response
  drains), `refuted`/`survived` (refute outcomes of the arm's CRITICALs),
  `overridden` (human `aramid override` of a finding joined to the arm via
  `run_id`). These are the fuel for a future reward refinement.
- **Rollup:** at the end of `cmd_drain` (when `enabled`), replay the
  **current repo's** ledger events with `seq > cursors[repo]`, fold into
  counts, bump the cursor, atomic-write. Other repos fold in during their
  own drains; `--rebuild` covers all. Wrapped fail-open: a rollup failure
  never fails the drain.
- **Rebuild:** `aramid autolearn --rebuild` starts from `empty_state()` and
  replays every registered repo's ledger (via the existing registry) from
  seq 0.
- **Compaction rule on record:** `Ledger.compact()` remains unwired. If it
  is ever wired to a command, it must run a rollup first (the state file is
  the durable aggregate; compaction keeps only the newest
  `CONSUMER_RUN_FINISHED` event and would destroy unrolled history).

## 9. Cascade (reactive re-review — armed only)

After the served review is parsed and verified:

- **Condition:** served tier < frontier AND at least one of
  - a verified candidate with `severity == "critical"` (`trigger: "critical"`),
  - `hallucination_rejected >= cascade_hallucination_min` (`trigger: "hallucination"`),
  - `packet.truncated` (`trigger: "truncated"`).
- **Action (armed):** one re-review by the next-higher **available** arm
  (via `reviewer_order` at that arm's `min_score`); union the two verified
  candidate lists; the single downstream confirmed-strip → dedupe → refute
  pass runs over the union. Max **1** cascade per item.
- **Budget:** the cascade call consumes a normal review slot
  (`_reviews_used`, capped by `max_items_per_drain`). Budget exhausted →
  skip cascade, keep served findings (fail-safe).
- **Shadow:** `cascade.triggered`/`trigger` recorded; no call made
  (`applied: false`).

## 10. Audit sampling (active in shadow AND armed)

Audits are the data engine — without them, misses (§6.4's exact failure
mode) are invisible. They run whenever `enabled`, including shadow, because
the bake period is precisely when the miss-rate evidence must accumulate.

- **Condition:** served tier < frontier AND
  `int(sha256(item.id).hexdigest(), 16) % audit_every == 0` AND
  `_audits_used < max_audits_per_drain`.
- **Action:** one review by the audit arm = the highest-`min_score`
  available arm. If the audit arm equals the served arm (frontier tiers
  unavailable), the audit is skipped — self-audit measures nothing. Diff by
  fingerprint:
  `new_findings` = audit's verified candidates not in served's;
  `missed_criticals` = the subset with `severity == "critical"`.
- **Findings are real:** the audit's verified candidates are unioned into
  the pipeline exactly like cascade candidates — an audit that catches a
  missed critical files it through the normal refute/confirm contract.
- **Budget:** audits do NOT consume review slots; they have their own cap
  (`max_audits_per_drain`, default 1) and their own drain-reset counter
  `_audits_used` in `begin_drain()`.
- **Reward write:** the audit outcome lands in the `selection.audit`
  payload; the rollup (not the consumer) folds it into posteriors.

## 11. Error handling

- Every policy consultation (`uplift_pick`, `cascade_trigger`,
  `should_audit`, bucket/band mapping) is wrapped fail-open: any exception →
  deterministic ladder behavior, `uplift.mode = "error"` in the payload.
  A drain never crashes because of autolearn.
- State file corrupt / missing / unknown `version` → treated as
  `empty_state()` (i.e., deterministic behavior); `doctor` surfaces it;
  `--rebuild` repairs it.
- Cascade/audit provider failures degrade silently: the served review
  stands; `applied`/`performed` stay false.
- State writes are atomic (tmp file + `os.replace`); a torn write cannot
  corrupt the previous state.
- Rollup failures are logged in the drain summary line but never fail the
  drain.

## 12. Commands & UX

- **`aramid autolearn`** — the report: mode (off/shadow/armed per current
  repo), state age, posterior table (per arm|band|bucket: misses/clean +
  secondary counters), shadow ratio (`would-uplift 3/17`), audit totals,
  cascade trigger counts.
- **`aramid autolearn --rebuild`** — regenerate state from all registered
  repos' ledgers; prints per-repo event counts.
- **`aramid arm --autolearn`** — writes `[llm.autolearn] armed = true` to
  the repo's `aramid.toml` (mirrors `arm --llm`). Prints the shadow stats it
  is arming on top of, so arming is an informed act.
- **`aramid status`** — one line, e.g.
  `autolearn: shadow (would-uplift 3/17, audits 14, misses 1)` or
  `autolearn: armed`.
- **`aramid doctor`** — probes state-file readability + version.

## 13. Forward hooks (deliberately not built)

- **De-escalation unlock:** once audit data proves a cheap arm at a higher
  band (e.g. `misses/clean` bound under a threshold with N ≥ some floor), a
  future `allow_deescalate` knob could serve below the ladder floor. Not in
  v1.
- **Reward refinement:** wire the secondary counters (halluc/malformed/
  refuted/overridden) into the decision as weighted evidence.
- **Contextual features:** replace the 2-value bucket with richer features
  if data volume ever supports it.
- **Learned cascade / refuter selection**; **N-refuter panels** (the 2b
  config-shape hook).
- **Per-repo overlay** on the global posteriors.

## 14. Testing strategy

No live LLM calls anywhere (invariant 4). Coverage:

- **`autolearn.py` unit tests:** posterior math (prior mean, threshold
  boundaries), cold-start-equals-ladder, uplift walk order,
  frontier-always-qualifies, bucket/band mapping, hash-sampling
  determinism (`audit_every` boundaries), cascade trigger matrix,
  `audit_diff` fingerprint logic, state serde round-trip, corrupt/
  unknown-version → empty, rollup cursor advance + idempotence, rebuild.
- **Consumer tests (fake providers):**
  - Shadow regression: with `enabled=true, armed=false` and no state file,
    every existing arm-selection test passes **unchanged** (the proof that
    shadow never changes behavior).
  - Shadow recording: `selection.uplift.pick` populated, `applied=false`.
  - Armed uplift: seeded state with high `misses` → higher tier served,
    `attempts`/`served` reflect it.
  - Cascade: trigger fires → union of candidate sets → downstream
    confirmed-strip applied to cascade candidates (block-path proof);
    budget-exhausted skip.
  - Audit: sampled item double-reviewed, diff counted, audit findings enter
    the normal refute path; `max_audits_per_drain` respected; not counted
    against review budget.
  - `_call` latency lands in `attempts`.
- **Drain integration:** `ConsumerResult.extra` merged into
  `CONSUMER_RUN_FINISHED`; rollup advances cursor and updates posteriors;
  rollup failure does not fail the drain.
- **Command tests:** `aramid autolearn` report rendering; `--rebuild` from
  two fake repo ledgers; `arm --autolearn` writes the toml key; status
  line; doctor probe.
- **Ledger/model tests:** `refuted` flag persists through
  `_detect_payload` → materialize; `apply_refute` marker set on refuted
  branch, absent on survived branch, `confirmed` behavior byte-identical
  (existing refute tests unchanged).
