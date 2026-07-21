# Aramid TDD-Enforcement Gate — Sub-project 1a: Code-Without-Test Signal + Teeth (Design)

**Date:** 2026-07-21
**Status:** Approved design, pre-plan
**Epic:** TDD-enforcement gate (Graphite ↔ Aramid ↔ SDD/TDD integration #2 — the back-of-loop "robust + safe" lever)

## 0. Epic map and this sub-project's place

The TDD-enforcement gate is a multi-part epic. During design of the original "signal + teeth"
sub-project, review found that arming the *existing* mutation findings is not a small classify
tweak but a whole gate-surfacing seam (see §2.4); it was therefore split out. The epic is now:

- **Sub-project 1a (this spec):** a synchronous, git-fact **code-without-test** signal at the
  pre-push gate, plus `tdd_block_armed` so it can BLOCK. Self-contained; ships enforcement now.
- **Sub-project 1b (own spec, next):** a `mutation_gate_findings` seam that surfaces the drain's
  existing surviving-mutant findings at the pre-push gate, plus `mutation_block_armed` + resolution
  semantics — a parallel to the LLM reviewer gate.
- **Sub-project 2:** mutation-score regression (per-target kill-rate baseline + delta).
- **Sub-project 3:** red-first proof (run new tests against the pre-change tree).

## 1. Goal and scope (sub-project 1a)

Give Aramid a cheap, reliable way to *enforce* that changed code comes with a test — not merely
score it after the fact.

### In scope
- A synchronous **code-without-test** producer at the pre-push gate: production `.py` changed in
  the range **and** no new test lines added → a WARN-tier finding per changed production file.
- **Arming** so those findings can BLOCK: a dedicated `tdd_block_armed` flag (default off).
- `aramid arm --tdd` CLI.
- A **fail-open, advisory-only** graph-annotation seam, shipped as a **no-op stub** (decoupled
  from the in-progress Graphite work; §9).

### Explicitly out of scope
- **Arming the existing mutation findings** → sub-project 1b (needs a gate seam, §2.4).
- **Mutation-score regression** → sub-project 2. **Red-first proof** → sub-project 3.
- **Graph-first test→symbol reachability** as a *decision* input — proven non-viable on today's
  graph (§2.3); revisit once Graphite is decision-grade.
- Pre-commit and `--all` enforcement (the signal runs at **pre-push only** in v1).
- Non-Python stacks (v1 keys on `.py`; stack-awareness is a clean extension point, §3).
- **Per-file test attribution** (whole-range test presence is used; §3, documented limitation).

## 2. Background — the machinery this rides

The north star is **maximum reuse**: emit an ordinary finding and let Aramid's proven gate
machinery do the rest.

### 2.1 Consumers vs. the synchronous gate
`consumers/mutation.py` mutates changed functions in a throwaway worktree and reports surviving
mutants as WARN-tier findings — but it runs **async in the drain**, surfaces at the *next* gate,
and its findings are **always WARN** (no mutation branch in `policy.classify`; falls through to
`Verdict.WARN`). The **synchronous** path is `pipeline.run_gate`, which runs subprocess runners and
then already appends a **non-subprocess, ledger-derived producer**: `review.llm_gate_findings(cfg,
ledger, gate)` (pipeline.py:313). That is the seam the code-without-test producer mirrors — a pure
producer whose output joins the normal finding stream. The code-without-test producer is even
simpler than `llm_gate_findings`: it reads the git diff (not the ledger).

### 2.2 Arming, the ratchet, and `_has_genuine_block`
- `policy.classify(tool, rule, severity_raw, gate, cfg)` is the single, pure verdict authority.
  Existing arming flags (`semgrep_block_armed`, `pack_block_armed`, `llm_block_armed`) are read
  *inside* it and each independently maps a finding to BLOCK vs WARN (policy.py:80-119).
- The pre-push **ratchet** (pipeline.py:300-307) escalates any *new* WARN → BLOCK, except
  `deps.DEPS_SHAPE_DRIFT_RULE`.
- `check.py`'s fresh-clone rule writes a baseline on first pre-push and, if `exit_code==1` was
  *solely* the ratchet's doing, downgrades to 0/2 — **unless** `_has_genuine_block(result, cfg)` is
  true. `_has_genuine_block` (check.py:112-118) treats a still-BLOCK finding as genuine iff
  `policy.classify(...)` returns BLOCK for it (or it is `Source.LLM`, a special case).

**Key consequence:** routing the code-without-test finding's arming through `policy.classify` (like
semgrep/pack) makes arming, the fresh-clone downgrade, `_has_genuine_block`, overrides/suppressions,
the ledger, and the reporter **all work unchanged, with no edit to `check.py`.** The Task-13b masking
bug (an armed source silently downgraded on a fresh clone) is avoided **by construction**: an armed
`tdd` finding returns BLOCK from classify, so `_has_genuine_block` sees it as genuine.

### 2.3 Why the graph is advisory-only here (decoupled)
Measured on the live aramid graph: only ~24% of call edges bind to a real definition, and
`policy.classify`'s 26 in-repo test callers (plus its one internal caller) produce **zero** call
edges to the real definition node — calls resolve to caller-scoped placeholders or are dropped.
Basing a BLOCK on graph-absence-of-an-edge would mass-false-block well-tested code; `graph-out/` is
also gitignored (absent in CI) and daemon-lagged (15–40 s stale). Therefore **the block rests only
on git-diff facts**, and the graph may only ever *annotate* (§9). This keeps 1a fully decoupled from
the concurrent Graphite resolution work.

### 2.4 Why arming mutation is a separate sub-project (1b), not here
Mutation findings are produced only in the drain and stored in the ledger. Nothing in `run_gate`
pulls open *consumer* findings into the blocking `findings` list — **except LLM**, via
`review.llm_gate_findings`, which filters `ledger.open_findings()` to `rec["source"]=="llm"`
(review.py:477-478). (Regression-pack reintroduction likewise blocks via pack YAML riding semgrep
as `extra_semgrep_configs`, *not* via the consumer's ledger findings.) So a bare `tool=="mutation"`
classify branch would arm **nothing** — the findings never reach the gate's exit-code decision.
Giving them teeth requires a `mutation_gate_findings` seam mirroring `llm_gate_findings` (read open
mutation findings → verdict from `mutation_block_armed` → append at pre-push) **plus** resolution
semantics (when a surfaced mutation BLOCK clears). That is sub-project 1b.

## 3. The detection rule (git facts only)

Evaluated at **pre-push**, over the resolved range, after the §8b/ignore-path filter:

1. **Changed production files** = files in the range ending in `.py` that are **not** test files.
   Test classification reuses the existing `consumers/mutation.py::_is_test_file` (under `tests/` or
   `.../tests/`, or basename `test_*.py` / `*_test.py`), promoted to a shared location (e.g. a small
   `_util` or `gitutil`) so producer and consumer share one definition.
2. **"Has a test" = new test lines added in the range.** The change is considered tested iff **some
   test file has ≥1 added line on the new side** within the range, via `gitutil.diff_new_lines(root,
   base, head)` → `{path: {new-side line numbers}}`. Pure test *touches/deletions* with no added
   lines do **not** count.
3. **Flag condition (whole-range):** ≥1 changed production file **and** zero new test lines anywhere
   in the range → flag **every** changed production file.
4. **Granularity:** **one finding per changed production file**. `RawFinding(tool="tdd",
   rule="code-without-test", file=<prod file>, line=0, severity_raw="medium", message="code changed
   with no new test in this range")`.
5. **Stable fingerprint:** `line=0` makes `normalize()` derive `line_content=""` (idx=-1 →
   out-of-range → empty; normalizer.py:50-51), so the id is `compute_fingerprint("tdd",
   "code-without-test", path, "", 0)` — a function of **tool+rule+path only**, stable across pushes
   (no content churn; matches the existing dast `line=0` precedent). One finding per file keeps
   `occurrence_index==0`.
6. **Diff-scoped:** findings exist only for files **changed in this push**. This — not the ratchet —
   is the safety that prevents arming from wall-blocking a repo's pre-existing untested code (§6).

**Documented limitation (whole-range test presence):** a single new test line anywhere in a push
satisfies the whole push, even for unrelated production changes. This is the conservative
(fewest-false-positives) choice and is acceptable because arming is default-off and bake-first.
True per-file test attribution requires coverage/reachability data Aramid does not have here; it is
deferred to sub-project 2 (mutation-based), which measures per-target test strength directly.

Rationale for "new test lines" over "any test file touched" / "module-matched test": it is a pure
git fact, robust to repo test layouts, and catches "added production code, only reformatted a test"
without a `test_<module>.py` naming assumption.

## 4. Architecture and components

New/changed surface, in total:

1. **`src/aramid/tdd.py`** (new) — the producer. Pure git-diff analysis, **no subprocess**, **never
   raises** (§10). `scan(ctx: RunContext) -> list[RawFinding]`: reads `ctx.files` (already
   changed+filtered) and `ctx.rng`, applies the §3 rule, returns zero or more `RawFinding`s. Honors
   `cfg.tdd["enabled"]` (default true) and runs only for `Gate.PRE_PUSH`.
2. **`src/aramid/policy.py`** — one additive branch in `classify`: `tool == "tdd"` →
   `BLOCK if cfg.tdd_block_armed else WARN` (a 3-line mirror of the semgrep/pack branches).
3. **`src/aramid/pipeline.py`** — wire the producer into `run_gate`:
   - Call `tdd.scan(ctx)` and extend `all_raws` with its findings **before** the §8b second filter
     and `normalize()` (so classify/fingerprint/ratchet/overrides all apply). Gate: PRE_PUSH only.
   - Extend the pre-push ratchet's exclusion (pipeline.py:304) so a **WARN** `tdd` finding is not
     auto-escalated (the "pure advisory until armed" decision, §6). Armed `tdd` findings are already
     BLOCK from classify, so the exemption only affects the disarmed WARN case.
4. **`src/aramid/data/defaults.toml`** — `tdd_block_armed = false` (sibling of `semgrep_block_armed`)
   and a `[tdd]` section: `enabled = true` (plus a path-scope hook reserved for later).
5. **`src/aramid/config.py`** — surface `tdd_block_armed` and the `[tdd]` table on `Config` (mirroring
   `semgrep_block_armed` / `pack`), through the layered-merge + defaults path.
6. **`src/aramid/commands/arm.py`** — add `--tdd`, flipping `tdd_block_armed` in the repo's
   `aramid.toml` (mirrors `--semgrep` / `--llm`), printing before/after state.

No new gate, no ledger schema change, no `check.py` change, no consumer change.

## 5. Data flow

```
git push → check.cmd_check(PRE_PUSH) → pipeline.run_gate
  ├─ _discover_files → files (changed), rng
  ├─ runners run (subprocess) → parse → all_raws
  ├─ tdd.scan(ctx) [NEW] ─────────────────────────→ all_raws   (git-fact producer, PRE_PUSH only)
  ├─ §8b second filter → normalize(…, classify=policy.classify(cfg=cfg))
  │        tool=="tdd":  armed? BLOCK : WARN            [NEW classify branch]
  ├─ ledger.record_run → new_ids
  ├─ pre-push ratchet: new WARN→BLOCK, EXCEPT deps-shape-drift AND tool=="tdd"   [NEW exempt]
  ├─ overrides/suppressions
  └─ exit code  →  check.py fresh-clone downgrade unless _has_genuine_block
                    (armed tdd ⇒ classify BLOCK ⇒ genuine ⇒ survives; unchanged check.py)
```

## 6. Enforcement / arming semantics

| State | Verdict | Blocks a push? | Fresh clone |
|---|---|---|---|
| **Disarmed** (`tdd_block_armed=false`, default) | WARN, **ratchet-exempt** | **Never** — advisory only, shows in report | downgraded (not genuine) |
| **Armed** (`tdd_block_armed=true`) | BLOCK (via classify) | **Yes**, for any changed prod file lacking a new test in the range | **survives** (genuine-by-classify) |

- **Bake-then-arm:** default-off; teams run disarmed (advisory) until confident, then `aramid arm
  --tdd`. Same lifecycle as semgrep's OWASP bake.
- **Diff-scoped safety:** armed enforcement only ever sees files changed in the push, so `arm --tdd`
  never wall-blocks a repo's pre-existing untested code (the ratchet plays no grandfathering role
  here — disarmed is ratchet-exempt and armed is genuine-BLOCK, so diff-scoping is the sole safety).
- **Touching legacy untested code (ratified decision):** when armed, changing a pre-existing untested
  file *without* adding a test **blocks** until you add one or run `aramid override` (the standard
  escape hatch). Intentional for an armed TDD gate; bounded to files in the push. (A
  ratchet-respecting-armed variant was considered and deferred.)

## 7. Config schema (defaults.toml)

```toml
semgrep_block_armed = false
tdd_block_armed = false          # NEW (1a) — arms code-without-test findings
# … existing keys …

[tdd]                            # NEW (1a)
enabled = true
# (reserved) exclude / extra_untested_paths globs for later refinement
```

`tdd_block_armed` is additive; absence in a repo's `aramid.toml` defaults to `false`, so existing
repos are unaffected until they opt in. (`mutation_block_armed` is added by 1b, not here.)

## 8. CLI

`aramid arm --tdd` flips `tdd_block_armed` in the repo's `aramid.toml`, printing before/after
(mirroring `arm --semgrep` / `arm --llm`). `aramid status` reflects arming via existing config
rendering (a dedicated status line is optional polish, not required for 1a).

## 9. Graph advisory layer (fail-open, decoupled, no-op stub)

`tdd.scan` may append an **advisory** note to a finding's message when `root/graph-out/graph.json`
is readable — e.g. `graph: N test node(s) reference this file` — read exactly like
`triage.dependents()` (fail-open: absent/corrupt/misshapen → contributes nothing, never raises).
**The note never affects the verdict.** Because the graph is currently unreliable *and* Graphite is
being actively updated, v1 ships this as a **no-op stub** (the seam exists; it returns no note). It
lights up automatically once Graphite's resolution is decision-grade. Zero clash surface with the
Graphite work.

## 10. Error handling

- `tdd.scan` **never raises** into `run_gate`. Any exception (git failure, decode error) is caught
  and yields **zero findings** (fail-open — a broken producer must never block a push or crash the
  gate). Mirrors Aramid's whole-file fail-open discipline.
- Range edge cases: on the `FULL_HISTORY_RNG` first-push case (no upstream yet), `ctx.files` is the
  whole tracked tree, so the producer treats the change as tested iff any tracked file is a test
  file — a diff over all history is not a meaningful "new test lines" notion. A first push of a
  genuinely untested repo surfaces advisory WARNs (never blocks while disarmed).
- No secrets are produced (no `RawFinding.secret`), so nothing is added to the redaction path.

## 11. Testing strategy (TDD, red→green)

1. **Producer rule** (git fixtures): prod-only diff → one `tdd` finding per changed prod file; prod +
   new test lines → **no** finding; test-only diff → no finding; prod change + pure test deletion →
   still flags (no *added* test lines).
2. **§8b:** changed graphite-artifact paths never produce a `tdd` finding.
3. **classify:** `tool="tdd"` armed→BLOCK / disarmed→WARN (discriminating: the opposite flag flips it).
4. **Ratchet exemption:** a new disarmed `tdd` WARN does **not** escalate to BLOCK at pre-push
   (red-proof: without the exemption it would).
5. **Fresh clone:** armed `tdd` BLOCK **survives** the fresh-ledger downgrade (`_has_genuine_block`);
   disarmed `tdd` does **not** block on a fresh ledger.
6. **Fingerprint stability + diff-scoping:** the same untested file across two pushes yields the same
   finding id (stable `line=0` fingerprint); an untested file *not* in the diff produces no finding.
7. **`arm --tdd`:** round-trip flips the flag in `aramid.toml`; gate behavior changes accordingly.
8. **Graph note fail-open:** absent/corrupt `graph-out/graph.json` → producer still returns findings,
   no note, no raise.
9. **End-to-end:** a real pre-push `aramid check` on a fixture repo blocks (armed) / warns (disarmed)
   for an untested change, and passes when a test is added.

## 12. Success criteria / invariants

- Disarmed `tdd` **never** blocks a push; armed `tdd` blocks a changed prod file that lacks a new test
  in the range, and survives fresh-clone downgrade.
- The block rests **only** on git-diff facts; absence/corruption/staleness of the graph **never**
  changes a verdict.
- No edit to `check.py`; no ledger-schema change; no consumer change; existing repos unaffected until
  they set `tdd_block_armed`.
- `python -m pytest` green; `python -m ruff` at or below the baseline (43).

## 13. Follow-on (rest of the epic)

- **Sub-project 1b (next):** `mutation_gate_findings` seam + `mutation_block_armed` + resolution
  semantics — teeth for the existing surviving-mutant findings, parallel to the LLM reviewer gate.
- **Sub-project 2:** mutation-score regression (baseline store + delta); can reuse 1b's arming.
- **Sub-project 3:** red-first proof.
- **Graph promotion:** once Graphite is decision-grade, promote the §9 stub to a real (advisory, then
  possibly exonerating) reachability signal.
