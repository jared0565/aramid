# Aramid TDD-Enforcement Gate — Sub-project 1: Signal + Teeth (Design)

**Date:** 2026-07-21
**Status:** Approved design, pre-plan
**Epic:** TDD-enforcement gate (Graphite ↔ Aramid ↔ SDD/TDD integration #2 — the back-of-loop "robust + safe" lever)

## 1. Goal and scope

Give Aramid a way to *enforce* test-discipline on changed code, not merely score it.
This document specifies **sub-project 1 of a three-part epic**: a cheap, reliable
"code-without-test" signal at the pre-push gate, plus the arming machinery ("teeth")
that lets it — and Aramid's *existing* surviving-mutant findings — actually BLOCK a
push when the repo opts in.

### In scope (this sub-project)
- A synchronous **code-without-test** producer at the pre-push gate: production code
  changed in the range **and** no new test lines added → a WARN-tier finding per
  changed production file.
- **Arming** so those findings can BLOCK: a dedicated `tdd_block_armed` flag.
- **Teeth for the existing mutation gaps**: a `mutation_block_armed` flag that lets the
  *already-emitted* surviving-mutant findings BLOCK — with **no change to the mutation
  consumer itself**.
- `aramid arm --tdd` / `aramid arm --mutation` CLI.
- A **fail-open, advisory-only** graph annotation seam, shipped as a no-op stub
  (decoupled from the in-progress Graphite work; see §9).

### Explicitly out of scope (later sub-projects / future)
- **Sub-project 2 — mutation-score regression:** per-target kill-rate baseline store +
  delta detection ("tests got weaker"). Not here.
- **Sub-project 3 — red-first proof:** run new tests against the pre-change tree. Not here.
- **Graph-first test→symbol reachability** as a *decision* input. Proven non-viable on
  today's graph (see §2.3); revisit once Graphite is decision-grade.
- Pre-commit and `--all` enforcement (the signal runs at **pre-push only** in v1).
- Non-Python stacks (the v1 rule keys on `.py`; the design leaves stack-awareness as a
  clean extension point, see §3).

## 2. Background — the machinery this rides

The design's north star is **maximum reuse**: emit an ordinary finding and let Aramid's
proven gate machinery do the rest. Almost nothing new is invented.

### 2.1 Consumers vs. the synchronous gate
Aramid's existing `consumers/mutation.py` already mutates changed functions in a throwaway
worktree and reports surviving mutants as WARN-tier (`severity_raw="medium"`) findings —
but it runs **async in the drain**, surfaces at the *next* gate, and (per `policy.classify`)
its findings are **always WARN** (there is no mutation branch, so they fall through to
`Verdict.WARN`). There is no `mutation_block_armed`.

The **synchronous** path is `pipeline.run_gate`, which runs subprocess runners, then already
appends a **non-subprocess, ledger-derived producer**: `review.llm_gate_findings(cfg, ledger, gate)`
(pipeline.py:313). That is the exact seam the code-without-test producer uses — a pure
producer whose output joins the normal finding stream.

### 2.2 Arming, the ratchet, and `_has_genuine_block`
- `policy.classify(tool, rule, severity_raw, gate, cfg)` is the single, pure verdict
  authority. Existing arming flags (`semgrep_block_armed`, `pack_block_armed`,
  `llm_block_armed`) are read *inside* it and each independently maps a finding to BLOCK
  vs WARN (policy.py:80-119).
- The pre-push **ratchet** (pipeline.py:300-307) escalates any *new* WARN → BLOCK, except
  `deps.DEPS_SHAPE_DRIFT_RULE`. This is Aramid's "don't add new problems" quality gate.
- `check.py`'s fresh-clone rule writes a baseline on the first pre-push and, if
  `exit_code==1` was *solely* the ratchet's doing, downgrades to 0/2 — **unless**
  `_has_genuine_block(result, cfg)` is true. `_has_genuine_block` (check.py:112-118) treats
  a still-BLOCK finding as genuine iff `policy.classify(...)` returns BLOCK for it (or it is
  a `Source.LLM` finding, a special case because LLM BLOCK is computed outside classify).

**Key consequence:** if the code-without-test finding routes its arming through
`policy.classify` (like semgrep/pack), then arming, the ratchet, the fresh-clone
downgrade, `_has_genuine_block`, overrides/suppressions, the ledger, and the reporter
**all work unchanged, and correctly, with no edit to `check.py`.** In particular the
Task-13b masking bug (an armed source silently downgraded on a fresh clone) is avoided
**by construction**, because an armed `tdd` finding is genuine-by-classify.

### 2.3 Why the graph is advisory-only here (decoupled)
Measured on the live aramid graph: only ~24% of call edges bind to a real definition, and
`policy.classify`'s 26 in-repo test callers (plus its one internal caller) produce **zero**
call edges to the real definition node — the calls resolve to caller-scoped placeholders or
are dropped entirely. Basing a BLOCK on graph-absence-of-an-edge would mass-false-block
well-tested code; `graph-out/` is also
gitignored (absent in CI) and daemon-lagged (15–40 s stale). Therefore **the block rests
only on git-diff facts**, and the graph may only ever *annotate* (§9). This keeps
sub-project 1 fully decoupled from the concurrent Graphite resolution work.

## 3. The detection rule (git facts only)

Evaluated at **pre-push**, over the resolved range, after the §8b/ignore-path filter:

1. **Changed production files** = files in the range that end in `.py` and are **not** test
   files. Test-file classification reuses the existing `consumers/mutation.py::_is_test_file`
   (path under `tests/` or `.../tests/`, or basename `test_*.py` / `*_test.py`). This helper
   is promoted to a shared location (e.g. `gitutil` or a small `_util`) so producer and
   consumer share one definition.
2. **"Has a test" = new test lines added in the range.** A change is considered tested iff
   **some test file has ≥1 added line on the new side** within the range, computed via
   `gitutil.diff_new_lines(root, base, head)` (returns `{path: {new-side line numbers}}`).
   Pure test *touches/deletions* with no added lines do **not** count.
3. **Flag condition:** ≥1 changed production file **and** zero new test lines in the range.
4. **Granularity:** **one finding per changed production file** (not per function — the
   graph is unreliable and this is a git-fact signal). `RawFinding(tool="tdd",
   rule="code-without-test", file=<prod file>, line=0, severity_raw="medium",
   message="code changed with no new test in this range")`.
5. **Diff-scoped:** findings exist only for files **changed in this push**. Arming therefore
   never touches files you are not modifying (the primary safety against wall-blocking a
   repo's pre-existing untested code).

Rationale for the "new test lines" definition (chosen over "any test file touched" and
"module-matched test"): it is a pure git fact, robust to repo test-layout conventions, and
catches "added production code, only reformatted a test" without the brittleness of a
`test_<module>.py` naming assumption. False-positive pressure (e.g. a pure refactor that
legitimately needs no new test) is absorbed by the default-off arming (advisory bake) and
the `override` escape hatch (§6).

### Whole-range semantics (not per-file test matching)
A push that changes several production files but adds tests for only one still does **not**
flag the others individually? — **No.** v1 uses **whole-range** test presence: if the range
adds *any* new test lines, *no* production file in the range flags. This is the conservative
(fewest false positives) choice and matches "did this unit of work come with tests." Per-file
test attribution requires reliable coverage/graph data we do not have; it is a documented
future refinement (belongs with sub-project 2). *(This is the one rule-strength knob to
confirm at spec review — the stricter alternative is "flag every changed prod file that has
no new test lines, regardless of other files' tests.")*

## 4. Architecture and components

New/changed surface, in total:

1. **`src/aramid/tdd.py`** (new) — the producer. Pure git-diff analysis, **no subprocess**.
   - `scan(ctx: RunContext) -> list[RawFinding]`: reads `ctx.files` (already changed+filtered)
     and `ctx.rng`, applies the §3 rule, returns zero or more `RawFinding`s. Never raises
     (fail-open, §10). Honors `cfg.tdd["enabled"]` (default true).
2. **`src/aramid/policy.py`** — two additive branches in `classify`:
   - `tool == "tdd"` → `BLOCK if cfg.tdd_block_armed else WARN` (mirrors the semgrep/pack branches).
   - `tool == "mutation"` → `BLOCK if cfg.mutation_block_armed else WARN` (arms the *existing*
     surviving-mutant findings; the mutation consumer is untouched).
3. **`src/aramid/pipeline.py`** — wire the producer into `run_gate`:
   - Call `tdd.scan(ctx)` and extend `all_raws` with its findings, **before** the §8b second
     filter and `normalize()` (so classify/fingerprint/ratchet/overrides all apply).
   - Add `tdd` findings' ratchet exemption: extend the pre-push ratchet's exclusion
     (pipeline.py:304) so a **WARN** `tdd` finding is not auto-escalated (the "pure advisory
     until armed" decision, §6). Armed `tdd` findings are already BLOCK from classify, so the
     exemption only affects the disarmed WARN case.
   - Guard: the producer runs only for `Gate.PRE_PUSH` (range mode) in v1.
4. **`src/aramid/data/defaults.toml`** — additions:
   - top-level `tdd_block_armed = false`, `mutation_block_armed = false` (siblings of
     `semgrep_block_armed`).
   - a `[tdd]` section: `enabled = true` (and a path-scope hook reserved for later).
5. **`src/aramid/config.py`** — surface `tdd_block_armed`, `mutation_block_armed`, and the
   `[tdd]` table on the `Config` object (mirroring how `semgrep_block_armed` / `pack` are
   exposed), including the layered-merge + defaults path.
6. **`src/aramid/commands/arm.py`** — add `--tdd` and `--mutation` flags that flip the
   respective booleans in the repo's `aramid.toml`, mirroring the existing `--semgrep` /
   `--llm` arming.

No new gate, no ledger schema change, no `check.py` change.

## 5. Data flow

```
git push → check.cmd_check(PRE_PUSH) → pipeline.run_gate
  ├─ _discover_files → files (changed), rng
  ├─ runners run (subprocess) → parse → all_raws
  ├─ tdd.scan(ctx) [NEW] ─────────────────────────→ all_raws  (git-fact producer)
  ├─ §8b second filter → normalize(…, classify=policy.classify(cfg=cfg))
  │        tool=="tdd":      armed? BLOCK : WARN
  │        tool=="mutation": armed? BLOCK : WARN   (existing findings from prior drains)
  ├─ ledger.record_run → new_ids
  ├─ pre-push ratchet: new WARN→BLOCK, EXCEPT deps-shape-drift AND tool=="tdd"  [NEW exempt]
  ├─ overrides/suppressions
  └─ exit code  →  check.py fresh-clone downgrade unless _has_genuine_block
                    (armed tdd/mutation ⇒ classify BLOCK ⇒ genuine ⇒ survives) 
```

## 6. Enforcement / arming semantics

| State | Verdict | Blocks a push? | Fresh clone |
|---|---|---|---|
| **Disarmed** (`tdd_block_armed=false`, default) | WARN, **ratchet-exempt** | **Never** — advisory only, shows in report | downgraded (not genuine) |
| **Armed** (`tdd_block_armed=true`) | BLOCK (via classify) | **Yes**, for any changed prod file lacking a new test | **survives** (genuine-by-classify) |

- **Bake-then-arm:** default-off; teams run disarmed (advisory) until confident, then
  `aramid arm --tdd`. Same lifecycle as semgrep's OWASP bake.
- **Diff-scoped safety:** armed enforcement only ever sees files changed in the push, so
  `arm --tdd` never wall-blocks a repo's pre-existing untested code.
- **Touching legacy untested code (documented):** when armed, changing a pre-existing
  untested file *without* adding a test will block until you add one or run `aramid override`
  (the standard escape hatch). This is intentional for an *armed* TDD gate and is bounded to
  files in the push. A **ratchet-respecting-armed** variant (armed blocks only genuinely
  *new* untested findings, grandfathering touched-but-already-untested files) is a documented
  future option, deferred to keep v1 aligned with the semgrep arming model.
- **`mutation_block_armed`** governs the existing surviving-mutant findings identically and
  independently; default off.

## 7. Config schema (defaults.toml)

```toml
semgrep_block_armed = false
tdd_block_armed = false          # NEW — arms code-without-test findings
mutation_block_armed = false     # NEW — arms existing surviving-mutant findings
# … existing keys …

[tdd]                            # NEW
enabled = true
# (reserved) extra_untested_paths / exclude globs for later refinement
```

`tdd_block_armed` and `mutation_block_armed` are additive; absence in a repo's `aramid.toml`
defaults to `false`, so existing repos are unaffected until they opt in.

## 8. CLI

`aramid arm --tdd` and `aramid arm --mutation` flip the respective flag in the repo's
`aramid.toml`, printing the before/after state (mirroring `arm --semgrep` / `arm --llm`).
`aramid status` continues to reflect arming state via existing config rendering (a dedicated
status line is optional polish, not required for v1).

## 9. Graph advisory layer (fail-open, decoupled, no-op stub)

`tdd.scan` may append an **advisory** note to a finding's message when
`root/graph-out/graph.json` is readable — e.g. `graph: N test node(s) reference this file` —
read exactly like `triage.dependents()` (fail-open: absent/corrupt/misshapen → contributes
nothing, never raises). **The note never affects the verdict.**

Because the graph is currently unreliable *and* Graphite is being actively updated, v1 ships
this as a **no-op stub** (the seam exists; it returns no note). It lights up automatically
once Graphite's resolution is decision-grade — at which point a future sub-project can
promote it from advisory annotation to (optionally) an *exonerating* signal. Shipping the
stub keeps the clash surface with the Graphite update at exactly zero.

## 10. Error handling

- `tdd.scan` **never raises** into `run_gate`. Any exception (git failure, decode error) is
  caught and yields **zero findings** (fail-open — a broken producer must never block a push
  or crash the gate). This mirrors the whole-file fail-open discipline used across Aramid.
- Range edge cases: `FULL_HISTORY_RNG` (new-repo first push) is handled by treating the
  new-repo diff endpoints consistently with `changed_files`/`diff_new_lines`' `base=None`
  path; a first push with no tests surfaces advisory WARNs (never blocks while disarmed).
- No secrets are produced by this tool (no `RawFinding.secret`), so it adds nothing to the
  redaction path.

## 11. Testing strategy (TDD, red→green)

Each behavior gets a failing test first, then implementation:

1. **Producer rule** (git fixtures): prod-only diff → one `tdd` finding per changed prod
   file; prod + new test lines → **no** finding; test-only diff → no finding; prod change +
   pure test deletion → still flags (no *added* test lines).
2. **§8b:** changed graphite-artifact paths never produce a `tdd` finding.
3. **classify:** `tool="tdd"` armed→BLOCK / disarmed→WARN; `tool="mutation"` armed→BLOCK /
   disarmed→WARN. (Discriminating: assert the *opposite* flag state flips the verdict.)
4. **Ratchet exemption:** a new disarmed `tdd` WARN does **not** escalate to BLOCK at
   pre-push (red-proof: without the exemption it would).
5. **Fresh clone:** armed `tdd` BLOCK **survives** the fresh-ledger downgrade
   (`_has_genuine_block`); disarmed `tdd` does **not** block on a fresh ledger.
6. **Ratchet grandfathering:** a pre-existing untested file re-touched keeps a stable
   per-file fingerprint (diff-scoped emission verified).
7. **`arm --tdd` / `--mutation`:** round-trip flips the flag in `aramid.toml`; gate behavior
   changes accordingly.
8. **Graph note fail-open:** absent/corrupt `graph-out/graph.json` → producer still returns
   findings, no note, no raise.
9. **End-to-end:** a real pre-push `aramid check` on a fixture repo blocks (armed) / warns
   (disarmed) for an untested change, and passes when a test is added.

## 12. Success criteria / invariants

- Disarmed `tdd` **never** blocks a push; armed `tdd` blocks a changed prod file that lacks a
  new test in the range, and survives fresh-clone downgrade.
- The block rests **only** on git-diff facts; absence/corruption/staleness of the graph
  **never** changes a verdict.
- Arming the existing mutation findings requires **no change** to `consumers/mutation.py`.
- No edit to `check.py`; no ledger schema change; existing repos are unaffected until they
  set an arming flag.
- `python -m pytest` green; `python -m ruff` at or below the baseline (43).

## 13. Follow-on (the rest of the epic)

- **Sub-project 2:** mutation-score regression (baseline store + delta), which can *also*
  reuse `mutation_block_armed` for its teeth.
- **Sub-project 3:** red-first proof.
- **Graph promotion:** once Graphite is decision-grade, promote the §9 stub to a real
  (advisory, then possibly exonerating) reachability signal.
