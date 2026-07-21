# Aramid TDD-Enforcement Gate — Sub-project 1b: Mutation Gate Teeth + Resolution (Design)

**Date:** 2026-07-21
**Status:** Approved design, pre-plan
**Epic:** TDD-enforcement gate (Graphite ↔ Aramid ↔ SDD/TDD integration #2 — the back-of-loop "robust + safe" lever)

## 0. Epic map and this sub-project's place

The TDD-enforcement gate is a multi-part epic. Sub-project **1a** shipped a synchronous, git-fact
**code-without-test** signal at the pre-push gate plus `tdd_block_armed` (merged to `main`, CI green).
This sub-project **1b** gives *teeth* to the **already-existing** surviving-mutant findings that the
drain's `consumers/mutation.py` produces but which never reach the gate's exit code today.

- **Sub-project 1a (shipped):** synchronous code-without-test signal + `tdd_block_armed`.
- **Sub-project 1b (this spec):** a `mutation_gate_findings` seam that surfaces the drain's existing
  surviving-mutant findings at the pre-push gate, plus `mutation_block_armed` + **gate-side
  resolution** — a parallel to the LLM reviewer gate.
- **Sub-project 2:** mutation-score regression (per-target kill-rate baseline + delta); can reuse 1b's
  arming.
- **Sub-project 3:** red-first proof (run new tests against the pre-change tree).

## 1. Goal and scope (sub-project 1b)

Let a repo *enforce* that changed code is covered well enough that the test suite kills mutations of
it — by arming the drain's existing, full-suite-**confirmed** surviving-mutant findings so they can
BLOCK a push, with the resolution machinery that makes armed teeth safe.

### In scope
- A **`mutation_gate_findings`** seam: at pre-push, materialize still-**open** mutation ledger
  findings as gate findings (they are never in `all_raws` — mutation runs only in the drain). Mirrors
  `review.llm_gate_findings`.
- **Arming**: a dedicated `[mutation].mutation_block_armed` flag (default off) that maps a materialized
  mutation finding to BLOCK vs WARN, via a `policy.classify` branch.
- **Gate-side resolution** (`auto_resolve_mutation`): optimistically resolve an open mutation finding
  when the push addresses the gap, **before** the block check — mirroring `review.auto_resolve_llm`'s
  call site — so a dev who just added a test is not blocked by a stale finding. **Module-mapped**
  predicate (§4). The async re-drain is the authoritative backstop (§6, §10).
- `aramid arm --mutation` CLI.

### Explicitly out of scope
- **Mutation-score regression** (per-target kill-rate baseline + delta) → sub-project 2.
- **Red-first proof** → sub-project 3.
- **Changing how the drain generates or confirms mutants** (`consumers/mutation.py::consume`,
  `mutation.generate_mutants`, the two-stage kill run). 1b only *surfaces* and *resolves* the findings
  the drain already writes.
- **Pre-commit and `--all` enforcement** (the seam runs at **pre-push only**, exactly like
  `llm_gate_findings`).
- Non-Python mutation (JS mutation lives in `consumers/js_mutation.py`; 1b keys on `tool=="mutation"`
  only — the Python consumer. Arming `tool=="js-mutation"` is a clean later extension, not v1).
- A new `Source` enum member and any `check.py` change — avoided by construction (§2.3).

## 2. Background — the machinery this rides

The north star, as in 1a, is **maximum reuse**: surface an ordinary ledger finding and let Aramid's
proven gate machinery (classify → ratchet → overrides → fresh-clone rule → reporter) do the rest.

### 2.1 What the drain already produces (and where it dead-ends)
`consumers/mutation.py::consume` mutates the changed **source** functions in a throwaway worktree at
the item's head and, for each mutant the **full** suite still passes on (a stage-2-confirmed
survivor), appends `RawFinding(tool="mutation", rule=m.op, severity_raw="medium", file=rel,
line=m.line, message="mutant survived: …")`. The drain normalizes these and writes them to the
ledger via `ledger.record_run(run_id, at, "drain", set(), set(), findings)` — **deliberately empty
scope** (drain.py:117-131), because the drain runs a narrow ruleset and must resolve nothing. So a
mutation finding, once **detected**, is stored `open` and:

- **Never blocks** — no `tool=="mutation"` branch in `policy.classify`, so it falls through to
  `Verdict.WARN`; and nothing pulls it back into the gate's `findings` at pre-push.
- **Never resolves** — the empty drain scope means `record_run`'s resolution loop (ledger.py:81-84)
  never matches it, and no gate-side resolver exists for it. It stays `open` forever.

1b fills both gaps.

### 2.2 The LLM gate is the exact precedent
Nothing in `run_gate` pulls open *consumer* findings into the blocking `findings` list **except LLM**:
`review.llm_gate_findings(cfg, ledger, gate)` (called at pipeline.py:320) filters
`ledger.open_findings()` to `rec["source"]=="llm"`, computes each verdict from ledger state +
`[llm].llm_block_armed`, and appends the results **after** the ratchet. Its sibling
`review.auto_resolve_llm(root, ledger, run_id, at)` runs **first** (pipeline.py:319), *before* the
block check, so "a dev who fixed the code is never blocked by a stale finding." 1b adds the mutation
twins of both, keyed on `tool=="mutation"`.

### 2.3 Verdict via `classify`, not a `Source` exception
`check.py`'s fresh-clone rule downgrades an `exit_code==1` that was *solely* the ratchet's doing —
**unless** `_has_genuine_block(result, cfg)` is true. `_has_genuine_block` (check.py:112-118) treats a
still-BLOCK finding as genuine iff `policy.classify(...)` returns BLOCK for it **or** it is
`Source.LLM` (a special case that exists only because an LLM finding's verdict depends on `confirmed`
ledger state that `classify` cannot see, so `classify("llm-review", …)` deliberately returns WARN).

A mutation finding's verdict has **no** per-finding ledger-state dependency — it is a pure
`mutation_block_armed` toggle. Therefore `classify` can **own** it (a `tool=="mutation"` branch,
exactly like the 1a `tdd` branch), and:

**Key consequence:** an armed mutation BLOCK returns BLOCK from `classify`, so `_has_genuine_block`
sees it as genuine **with no `check.py` change and no new `Source` enum member** — it survives the
fresh-clone / CI downgrade by construction. The materialized finding keeps its stored source
(`Source.DETERMINISTIC`, the normalizer default); only the `classify` branch is needed.

**"Seam AND classify branch, not one instead of the other."** The seam
(`mutation_gate_findings`) *materializes* the ledger-resident finding into the gate (it is never in
`all_raws`); the `classify` branch encodes the armed→BLOCK verdict rule so `_has_genuine_block`'s
`classify(...)` call sees an armed mutation BLOCK as genuine. The seam computes the surfaced verdict
**inline** from `mutation_block_armed` — mirroring `llm_gate_findings`, which likewise computes its
verdict inline rather than calling `classify` (this avoids coupling the seam to a full `cfg`, since
`classify` reads `cfg.block_rules` unconditionally at policy.py:82). The seam's one-line rule and the
`classify` branch's one-line rule are identical and must stay in agreement.

## 3. What "still-open mutation finding" means at the gate

`mutation_gate_findings` reads `ledger.open_findings()` and selects records with `rec["tool"] ==
"mutation"` and `rec["status"] == "open"`. Because every mutation ledger finding is a stage-2
full-suite-**confirmed** survivor (the consumer only appends after the full suite passes on the
mutant, consumers/mutation.py:168-176), the surfaced set is high-signal — blocking on it when armed is
defensible. Each record already carries `tool`, `rule` (the mutation op), `severity` ("medium"),
`file`, `line`, `message`, and `source` in its `_detect_payload` (ledger.py:14-19), which is
everything needed to reconstruct a `Finding`.

## 4. The resolution rule (module-mapped, git facts only)

`auto_resolve_mutation` runs at **pre-push**, over the resolved range's changed-file set (the
`scope_files`/`files` `run_gate` already computes at pipeline.py:245,303), **before** the block check.
For each open mutation finding on source path `p` with module stem `m = Path(p).stem`:

**Resolve the finding iff** — over the push's changed files `C` (compared with `fingerprint.normalize_path`):

1. **Source touched:** `normalize_path(p) ∈ {normalize_path(c) for c in C}`, **or**
2. **Mapped test added/modified:** some `c ∈ C` is a **test file** (per the shared `is_test_file`
   promoted in 1a to `gitutil.is_test_file`) whose basename stem is `test_<m>` or `<m>_test` — the
   same `test_<module>.py` ↔ module convention the consumer's own kill-run selection uses
   (`_stage1_argv`, consumers/mutation.py:47-54).

On a match, append `Event(FINDING_RESOLVED, run_id, at, finding_id=fid,
payload={"auto_resolved": "gap_addressed"})` (mirroring `auto_resolve_llm`'s resolved-event shape).

**Why module-mapped and not source-only or any-test.** The fix for a surviving-mutant test-gap is
*adding a test*, which usually does **not** touch the mutated source line — so a source-only /
evidence-gone predicate (the LLM model) would keep blocking a dev who did exactly the right thing.
Keying on the mapped test surface is the minimum that covers "added a test in a separate file."
Resolving on *any* test touch was rejected as too eager (an unrelated test edit would clear a real,
still-surviving gap). The chosen predicate matches the consumer's own kill-run convention, so it is
principled rather than arbitrary.

**Low-stakes, so liberal is safe.** A wrong LLM resolve leaks a confirmed critical; a wrong mutation
resolve only lets a *test-gap* slip until the re-drain re-reports it (§6, §10). This inversion of
stakes is why optimistic gate-side resolution — not authoritative drain-only resolution — is correct
here.

## 5. Architecture and components

New/changed surface, in total:

1. **`src/aramid/mutation_gate.py`** (new) — the gate-time twin of the LLM helpers, holding two pure,
   **never-raises** functions:
   - `mutation_gate_findings(cfg, ledger, gate: Gate) -> list[Finding]`: PRE_PUSH only; materialize
     open `tool=="mutation"` findings; verdict computed **inline** from
     `cfg.mutation.get("mutation_block_armed", False)` (mirroring `llm_gate_findings`; the identical
     rule the `classify` branch encodes for `_has_genuine_block`);
     per-record fail-safe guard (a malformed rec is **skipped**, never crashes the gate — staying
     `open` forces manual triage, the safe outcome for a block gate). Structural mirror of
     `review.llm_gate_findings`.
   - `auto_resolve_mutation(ledger, run_id, at, changed_files: set[str]) -> list[str]`: PRE_PUSH,
     module-mapped §4 predicate; per-record fail-safe guard; returns resolved ids.
   - Named `mutation_gate` to avoid colliding with `aramid.mutation` (the mutant generator) and
     `aramid.consumers.mutation` (the drain consumer).
2. **`src/aramid/policy.py`** — one additive branch in `classify`: `tool == "mutation"` →
   `BLOCK if cfg.mutation.get("mutation_block_armed", False) else WARN` (a 3-line mirror of the `tdd`
   branch; reads the `[mutation]` table, sibling of `[pack].pack_block_armed`).
3. **`src/aramid/pipeline.py`** — in the existing PRE_PUSH block (pipeline.py:318-320), append the two
   mutation calls **beside** their LLM twins, **after** the ratchet so the surfaced findings are
   ratchet-exempt exactly like LLM:
   ```python
   review_mod.auto_resolve_llm(root, ledger, run_id, at)
   mutation_gate.auto_resolve_mutation(ledger, run_id, at, scope_files)              # NEW
   findings = [*findings,
               *review_mod.llm_gate_findings(cfg, ledger, gate),
               *mutation_gate.mutation_gate_findings(cfg, ledger, gate)]             # NEW
   ```
   Both resolves run before both materializes, so a just-resolved finding is never re-surfaced in the
   same run.
4. **`src/aramid/data/defaults.toml`** — add `mutation_block_armed = false` inside the existing
   `[mutation]` table (sibling of `enabled`, `max_mutants`, …).
5. **`src/aramid/commands/arm.py`** + **`cli.py`** — add `--mutation`, flipping
   `[mutation].mutation_block_armed` in the repo's `aramid.toml` (mirrors `--llm`'s table insertion),
   in the mutually-exclusive arm group, printing before/after state.

**No `config.py` change** (unlike 1a's top-level `tdd_block_armed`, which needed a `Config` field):
`mutation_block_armed` lives *inside* the `[mutation]` table that `load_config` already surfaces as
`cfg.mutation` (config.py:44,111), so `cfg.mutation.get("mutation_block_armed", False)` reads it with
no dataclass change — and it defaults `False` even when the key is absent, so a repo that sets other
`[mutation]` keys is never accidentally armed regardless of merge depth.

No new gate, no ledger schema change, **no `check.py` change**, **no `Source` enum change**, no change
to `consumers/mutation.py`.

## 6. Enforcement / arming semantics

| State | Verdict | Blocks a push? | Fresh clone |
|---|---|---|---|
| **Disarmed** (`mutation_block_armed=false`, default) | WARN, surfaced at pre-push, ratchet-exempt (post-ratchet append) | **Never** — advisory only, shows in report | downgraded (not genuine) |
| **Armed** (`mutation_block_armed=true`) | BLOCK (via classify) | **Yes**, for any open confirmed-survivor finding not resolved by §4 | **survives** (genuine-by-classify) |

- **Bake-then-arm:** default-off; teams run disarmed (advisory) until confident, then `aramid arm
  --mutation`. Same lifecycle as semgrep's OWASP bake and 1a's `tdd`.
- **Ratchet-exempt by construction:** the surfaced findings are appended *after* the ratchet
  (pipeline.py:306-314 runs on `findings` before line 320), so a disarmed WARN is never auto-escalated
  — identical to the LLM gate, no explicit exemption needed.
- **Override is the escape:** when armed and blocking, the standard `aramid override <id> --reason …`
  applies (same escape hatch as every other BLOCK). Adding a mapped test also clears it on the next
  gate run (§4).

## 7. Config schema (defaults.toml)

```toml
[mutation]
enabled = true
# … existing budgets: max_mutants, wall_budget_s, mutant_timeout_s, confirm_cap …
mutation_block_armed = false     # NEW (1b) — arms surviving-mutant findings
```

`mutation_block_armed` is additive; absence in a repo's `aramid.toml` defaults to `false`, so existing
repos are unaffected until they opt in.

## 8. CLI

`aramid arm --mutation` flips `[mutation].mutation_block_armed` in the repo's `aramid.toml`, printing
before/after (mirroring `arm --llm`). It joins the existing mutually-exclusive arm group (so
`arm --mutation --llm` exits with the usage error, as the group already enforces).

## 9. Data flow

```
git push → check.cmd_check(PRE_PUSH) → pipeline.run_gate
  ├─ _discover_files → files/scope_files (changed), rng
  ├─ runners + tdd.scan → all_raws → normalize → findings
  ├─ ledger.record_run → new_ids
  ├─ pre-push ratchet: new WARN→BLOCK (does NOT see mutation gate findings — appended later)
  ├─ PRE_PUSH producers:
  │    auto_resolve_llm(…)                                   [existing]
  │    auto_resolve_mutation(ledger, run_id, at, scope_files) [NEW]  ── §4 module-mapped resolve
  │    findings += llm_gate_findings(…)                       [existing]
  │    findings += mutation_gate_findings(cfg, ledger, gate)  [NEW]  ── verdict inline: armed? BLOCK : WARN
  │                                                                     (same rule the classify branch encodes,
  │                                                                      so _has_genuine_block sees armed BLOCK)
  └─ exit code  →  check.py fresh-clone downgrade unless _has_genuine_block
                    (armed mutation ⇒ classify BLOCK ⇒ genuine ⇒ survives; unchanged check.py)
```

## 10. Error handling and the accepted limitation

- **Fail-open:** `mutation_gate_findings` and `auto_resolve_mutation` **never raise** into `run_gate`;
  each has an outer per-record guard and, on any unexpected error, contributes nothing (a broken
  producer/resolver must never block a push or crash the gate). Mirrors `llm_gate_findings` /
  `auto_resolve_llm`.
- **Re-detection backstop:** when the async drain next pops the item, the consumer re-runs mutation on
  the changed source; a still-surviving mutant is re-emitted and `record_run` re-detects it (its
  status was `fixed` → re-`DETECTED` as `open`, ledger.py:76). So a wrongly-resolved-but-still-gappy
  finding comes back.
- **Accepted limitation (documented, not a hidden bug):** the re-detection backstop only fires if the
  finding's **source** file re-enters a drained item's range. If the fix commit touches **only** a
  test file *and* the originating queue item has **already been drained**, the next sweep's range
  excludes the source, so the consumer skips it (`files` empty, consumers/mutation.py:76-83) and does
  not re-report — a wrongly-resolved gap can then slip until the source file is next changed. When the
  item has **not** yet drained (common, since drain auto-start is still roadmap item 2c-3b), the test
  commit coalesces into the same item whose range still includes the source, and re-detection works.
  This is the deliberate low-stakes tradeoff of optimistic resolution (a missed *test-gap*, never a
  security hole). **Noted follow-up (out of 1b scope):** let the mutation consumer also re-mutate
  source files that carry open mutation findings even when not in the current range, closing the gap.

## 11. Testing strategy (TDD, red→green)

1. **`mutation_gate_findings` — surfacing:** an open `tool=="mutation"` ledger record materializes to
   a `Finding` at PRE_PUSH; not at PRE_COMMIT/ALL (returns `[]`); a `fixed`/`resolved` mutation record
   is **not** surfaced; a non-mutation record is ignored.
2. **`mutation_gate_findings` — verdict:** armed → BLOCK, disarmed → WARN (discriminating: flipping
   `[mutation].mutation_block_armed` flips the verdict); malformed rec (e.g. `line=null`) is skipped,
   others still surface (fail-safe).
3. **classify:** `tool="mutation"` armed→BLOCK / disarmed→WARN (asserts `Severity.MEDIUM` too).
4. **Fresh clone:** an armed mutation BLOCK **survives** the fresh-ledger downgrade
   (`_has_genuine_block` returns true via classify); a disarmed mutation finding does **not** block on
   a fresh ledger (red-proof: without the classify branch, `_has_genuine_block` would treat it as
   non-genuine and downgrade).
5. **Ratchet exemption:** a new disarmed mutation WARN does **not** escalate to BLOCK at pre-push
   (guaranteed structurally by the post-ratchet append; a test pins it).
6. **`auto_resolve_mutation` — module-mapped:**
   - open finding on `pkg/x.py`; push changes `pkg/x.py` → **resolved** (source touched).
   - open finding on `pkg/x.py`; push adds `tests/test_x.py` → **resolved** (mapped test).
   - open finding on `pkg/x.py`; push adds `tests/test_y.py` (unrelated) → **not** resolved.
   - open finding on `pkg/x.py`; push touches only unrelated non-test files → **not** resolved.
   - resolution runs before materialize: a resolved finding does **not** surface in the same run.
7. **`arm --mutation`:** round-trip flips `[mutation].mutation_block_armed` in `aramid.toml`; gate
   behavior changes accordingly; `arm --mutation --llm` exits with the mutually-exclusive usage error.
8. **End-to-end:** a real pre-push `aramid check` on a fixture repo whose ledger holds an open mutation
   survivor **blocks** (armed) / **warns** (disarmed), and **passes** once the push adds a mapped test
   (resolution fires before the block check).

## 12. Success criteria / invariants

- Disarmed mutation findings **never** block a push; armed mutation findings block an open
  confirmed-survivor unless the push addresses the gap (§4), and survive fresh-clone downgrade.
- Mutation findings **resolve** at the gate on the module-mapped predicate, so a dev who adds the
  mapped test is not blocked by a stale finding; the async re-drain is the backstop (§10).
- The verdict rests on `policy.classify` + `[mutation].mutation_block_armed`; no `check.py` change, no
  `Source` enum change, no ledger-schema change, no `consumers/mutation.py` change; existing repos
  unaffected until they set `mutation_block_armed`.
- `python -m pytest` green; `python -m ruff` at or below the baseline (43).

## 13. Follow-on (rest of the epic)

- **Sub-project 2:** mutation-score regression (per-target kill-rate baseline + delta); can reuse 1b's
  arming and the `[mutation]` config surface.
- **Sub-project 3:** red-first proof.
- **1b noted follow-up:** mutation consumer re-mutates source files carrying open findings even when
  not in range (§10), tightening the re-detection backstop.
- **Shared with 1a follow-up #1:** 1a's `tdd` findings also never auto-resolve from the ledger;
  `auto_resolve_mutation`'s changed-file/module-mapped shape is a candidate to generalize across both
  producer surfaces.
