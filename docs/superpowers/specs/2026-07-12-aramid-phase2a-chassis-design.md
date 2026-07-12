# Aramid Phase 2a — Watcher Chassis + Regression Attack Pack

**Status:** approved 2026-07-12
**Depends on:** Phase 1 (deterministic gate engine, merged to `main`, CI green)

## 1. Overview

Phase 2 of aramid is the red team. During brainstorming it was restaged from one
phase into three sub-phases, each useful alone:

- **Phase 2a (this spec):** the zero-token chassis — commit-event triage, a
  risk-scored review queue in the ledger, a scheduled budgeted drain, and the
  first queue consumer: the deterministic **regression attack pack**.
- **Phase 2b (own spec, later):** the LLM reviewer — provider chain, evidence-bound
  adversarial review, refute panel, bake-then-arm blocking. Rides the 2a chassis.
- **Phase 2c (own spec, later):** the heavy deterministic adversarial tier —
  mutation testing, fuzz/property harness, DAST baseline. Each is a new queue
  consumer slotting into the same chassis.

The core token-economics insight that shaped this design: **the always-running
overseer never needs to burn a token.** Watching, triaging, scoring, and queueing
are pure computation. Spending (LLM quota/dollars in 2b, CPU in 2c) happens only
at the drain, under explicit budgets, on the small novel high-risk slice.

### Decisions fixed during brainstorming

| Decision | Choice |
|---|---|
| Phase 2 staging | Three sub-specs: 2a chassis+pack, 2b LLM reviewer, 2c heavy adversarial tier |
| Watcher mechanism | Hybrid (option C): post-commit hook enqueue + scheduled drain + catch-up sweep |
| Red-team composition | Hybrid: deterministic-adversarial tier auto-runs free; LLM reserved for the semantic residue (A01/A05/A07, logic flaws) |
| Drain trigger | Windows Task Scheduler every 4h (config) + manual `aramid drain` |
| Provider order (binds 2b) | Claude CLI → Codex CLI → OpenRouter under a hard dollar cap → queue holds |
| LLM blocking posture (binds 2b) | Bake period, then refute-panel-confirmed CRITICAL findings arm to BLOCK-tier (mirrors semgrep's Phase 1 arming) |
| Deterministic tier tools | Regression pack (2a); mutation, fuzz, DAST (2c) |
| Coalescing (binds 2b) | Queue items for the same repo merge: range extends, score takes max — an agentic burst is one review, not twenty |

### Non-goals for 2a

- No LLM calls of any kind (2b). No Provider abstraction yet (2b).
- No mutation/fuzz/DAST consumers (2c).
- No cross-machine sync; the registry and scheduler are this-machine-only.
- **Honesty note (circularity):** with only deterministic findings available,
  auto-compiling regression rules from tool findings is circular — those findings
  came from rules that still run. The 2a pack therefore ships the *mechanism*
  plus the two rule classes meaningful today (rotated-secret reintroduction,
  vulnerable-dependency bans) and a manual promotion command. The auto-compiler
  for LLM findings is 2b scope, when LLM findings exist.

## 2. Architecture

New modules in the existing `src/aramid/` layout; no changes to Phase 1's gate
semantics except one addition (the pack file joins semgrep's `--config`).

```
commit ──► post-commit shim ──► aramid triage HEAD        (fail-open, ≤2s, zero tokens)
                                   │
                                   ▼
                       queue events in .aramid/ledger.db   (coalesced per repo)
                                   │
   Task Scheduler (4h) ──► aramid drain --all
                                   │
                    ~/.aramid/repos.toml registry ──► per repo:
                       1. catch-up sweep (commits since last seen head)
                       2. pop items ≥ min_score, priority desc
                       3. run consumers (2a: regression pack)
                                   │
                                   ▼
                 findings ──► existing normalize/classify/ledger pipeline
```

### Components

- **`src/aramid/triage.py`** — deterministic risk scorer. Pure computation:
  `git diff` stats/text, regex over the diff text only, ledger novelty lookups,
  optional graphite graph read. **Never spawns a scan tool.** Self-budgeted
  ≤2s hard / ~200ms typical.
- **`src/aramid/queue.py`** — queue state materialized from ledger events
  (section 4). Coalescing lives here.
- **Post-commit hook** — third shim rendered by the existing `hooks.py`
  machinery (same marker guard, chaining, binary-mode `\n`, baked interpreter
  path, uninstall reversal). Body: `aramid triage HEAD`, exit 0 always.
- **`src/aramid/commands/triage.py`** — `aramid triage <rev>`: score and
  enqueue. A single rev scores its diff against its first parent (a root
  commit scores the full tree it introduces); `A..B` scores the range diff.
  Called by the hook with `HEAD`; usable manually. Every triage appends an
  event recording the head it saw — that record is what the sweep resumes
  from.
- **`src/aramid/commands/drain.py`** — `aramid drain [--all | --repo PATH]
  [--dry-run] [--max-items N]`: registry iteration, sweep, pop, consume,
  record. The sweep triages `<last-triaged-head>..HEAD`, where the last
  triaged head is materialized from the repo's own ledger events. **Bootstrap
  rule:** a repo with no triage history sweeps `HEAD` only — registering a
  repo must never queue its entire past. Exit codes reuse the Phase 1
  contract (0 ok / 2 degraded / 3 engine error).
- **`src/aramid/commands/schedule.py`** — `aramid schedule install|remove|status`:
  manages the Task Scheduler entry via `schtasks.exe` (task name
  `aramid-drain`, `StartWhenAvailable` semantics via `/Z`-equivalent flags,
  action `<blessed-python> -m aramid drain --all`).
- **`src/aramid/consumers/`** — new package, mirroring `runners/`. Protocol:
  `NAME: str`, `consume(item: QueueItem, ctx: DrainContext) -> ConsumerResult`.
  2a ships `consumers/regression_pack.py`. 2b adds `llm_review`; 2c adds
  `mutation`, `fuzz`, `dast`. `ConsumerResult` carries findings (RawFinding
  list routed through the existing normalizer), duration, and a `cost` field
  (always 0.0 in 2a — the slot Phase 4 metering reads).
- **`src/aramid/registry.py`** — `~/.aramid/repos.toml` read/write.
  `aramid init` appends `{path, registered_at}`; `aramid uninstall` removes.
- **Regression pack** — `<repo>/.aramid-rules/regression.yml`, a committed
  semgrep ruleset (like `.aramid-suppressions.toml`, it is repo-visible state).
  Management: `aramid pack list|add <finding-id>|compile`. Integration: the
  existing semgrep runner appends it as an extra `--config` **in the normal
  gates**, so a reintroduction is blocked at pre-push, not merely at the next
  drain. Pack rules inherit block-tier from their source finding and ride
  semgrep's existing arming state.
- **`aramid status`** additions: queue depth + top item with reasons, last
  drain result, next scheduled drain, registry health.

## 3. Triage scoring

Additive weighted signals, each independently testable; all weights and the
threshold are config-tunable:

| Signal | Weight | Detection |
|---|---|---|
| Security-surface path | +30 | changed path matches builtin + `[triage].extra_security_paths` patterns (auth, session, login, crypto, token, secret, permission, middleware, config) |
| Risky content delta | +25 | added diff lines match regex classes: exec/eval/subprocess, SQL string building, new HTTP handlers/routes, dependency-manifest changes |
| Novelty | +20 | changed blobs whose fingerprints the ledger has never recorded |
| Blast radius | 0–25 | if `graph-out/` exists: scaled by count of graphite dependents of changed symbols; absent graph contributes 0 |

Default `min_score = 40`. Sub-threshold commits are logged (one triage event,
visible in `status`) but not queued. Scores clamp to 100.

## 4. Data model

Five new ledger event types, same append-only + replay discipline as Phase 1:

| Event | Payload |
|---|---|
| `queue_item_added` | item id, range `base..head`, score, reasons[] |
| `queue_item_coalesced` | item id, absorbed range, new range, new score |
| `queue_item_drained` | item id, drain run id |
| `queue_item_expired` | item id, age_days |
| `consumer_run_finished` | drain run id, consumer, item id, state, duration_s, cost, finding_count |

`QueueItem` materialized fields: `id`, `range`, `score`, `reasons`,
`state ∈ {queued, drained, expired}`, `created_at`, `updated_at`.

**Coalescing rule:** on `triage` of commit C for a repo with an existing
`queued` item: extend the item's range to include C, set
`score = max(old, new)`, union the reasons, emit `queue_item_coalesced`.
At most one `queued` item exists per repo at any time.

**Central state is exactly one file:** `~/.aramid/repos.toml`. Everything else
stays in the per-repo ledger so each repo remains a self-contained audit unit.

### Config additions (same three-layer TOML merge)

```toml
[triage]
min_score = 40
extra_security_paths = []

[drain]
interval_hours = 4
max_items_per_drain = 10
item_expiry_days = 30
wall_clock_budget_s = 600

[pack]
enabled = true
```

## 5. Regression attack pack

- **Rule sources in 2a:**
  1. *Rotated-secret reintroduction:* when a gitleaks finding is resolved, the
     compiler emits a **redacted structural regex** — anchored prefix/suffix
     plus shape (e.g. `AKIA…[0-9A-Z]{12}` style). The literal rotated secret
     NEVER appears in the rules file (it is committed; embedding the old value
     would re-leak it — same hygiene stance as Phase 1's `redact.py`).
  2. *Vulnerable-dependency bans:* a resolved dep-audit finding compiles to a
     manifest-scoped semgrep rule matching reintroduction of the banned
     package@version-range.
  3. *Manual promotion:* `aramid pack add <finding-id>` renders any ledger
     finding into a draft rule (id `aramid-regression.<n>`, message citing the
     source finding id and date) for the user to tune before committing.
- **Rule ids** are namespaced `aramid-regression.*`; the semgrep runner's
  check-id normalization (Phase 1, commit 56e4022) already strips config-path
  prefixes, so gate and drain produce identical fingerprints.
- **Severity/tier:** each rule records its source finding's severity; block-tier
  sources yield block-tier rules, enforced through the existing
  `block_rules`/arming machinery — no new policy path.
- **Drain-time replay:** the pack consumer replays the ruleset against the
  queue item's changed files (fast). A full-repo replay happens naturally
  whenever `aramid check --all` runs (CI already does).

## 6. Error handling & failure modes

- **Post-commit hook:** fail-open absolutely — any exception, or the 2s
  self-timeout, exits 0 and writes one line to `.aramid/logs/triage-<ts>.log`.
  A commit can never be blocked or noticeably slowed by triage. The drain's
  sweep is the recovery path for anything the hook misses.
- **Drain singleton:** lockfile `~/.aramid/drain.lock` containing PID +
  start time; stale locks (dead PID) are broken with a logged note. A
  scheduled and a manual drain cannot run concurrently.
- **Per-repo isolation:** one repo's failure (corrupt ledger, missing path)
  degrades that repo only; the sweep continues; exit code 2 reports it.
- **Missed schedules:** the task is registered "run as soon as possible after
  a missed start"; even a fully missed window self-heals because the next
  drain sweeps every commit since the last recorded head per repo.
- **Registry rot:** a registered path that no longer exists is skipped and
  surfaced in `status` — never auto-deregistered (unmounted drive ≠ deleted
  repo).
- **Queue hygiene:** items older than `item_expiry_days` emit
  `queue_item_expired` — nothing silently vanishes; `status` counts them.
- **graphite coexistence (§8b upheld):** the graph is read as *input* for
  blast radius; graphite artifacts are never scan targets (already in the
  un-removable builtin ignore paths). Absent/stale graph → signal contributes
  0 + one doctor note.
- **Timestamps:** ISO-8601 UTC via the same injected-clock seam as Phase 1.

## 7. Testing

- **Unit:** table-driven triage scoring (each signal isolated, then combined,
  clamping, threshold edge); coalescing semantics (extend/max/union, single
  queued item invariant); pack compiler golden tests (secret → redacted regex
  that must NOT contain the seeded literal; dep finding → manifest rule);
  registry round-trip incl. missing/corrupt file; `schtasks` argv construction
  (no real scheduler).
- **Integration:** tmp repo → `hooks.install` → real `git commit` → queue item
  materializes with expected score + reasons; hook fail-open when `aramid` is
  broken (commit still lands); `drain --dry-run` mutates nothing; real drain
  emits `queue_item_drained` + `consumer_run_finished`; **reintroduction e2e:**
  seed + resolve a finding → `pack compile` → reintroduce the pattern → the
  pre-push gate blocks via the existing semgrep runner; sweep catches commits
  made with `--no-verify`.
- **e2e (Windows):** post-commit shim chained with a foreign hook (extends the
  Phase 1 `test_windows_hooks.py` module); real Task Scheduler
  register/verify/remove with a uniquely-named disposable task and guaranteed
  cleanup (skipped where `schtasks` is unavailable).
- **CI:** the existing workflow covers all of 2a unchanged — everything is
  zero-token. The dogfood step will exercise triage/queue on aramid's own
  repo once hooks are installed there.

## 8. Forward hooks (NOT 2a scope — listed so interfaces leave room)

- `ConsumerResult.cost` and `consumer_run_finished.cost` are the Phase 4
  metering slots; 2a always writes 0.0.
- The consumer protocol is the 2b LLM reviewer's entry point; coalescing,
  budgets, and queue state need no changes for 2b.
- `Source.LLM` already exists in the Phase 1 findings model (`source` field);
  2a does not use it.
- The provider chain, evidence-bound protocol, refute panel, and bake-then-arm
  posture are FIXED decisions (table §1) whose implementation is entirely 2b.
