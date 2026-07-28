# Aramid — Unreachable Findings (ticket T-8)

**Date:** 2026-07-28
**Ticket:** T-8, filed 2026-07-27 during pawscout onboarding. Found by real use, not by review.
**Baseline:** `main` @ `45d8232`, level with `origin/main`, CI green 7/7, suite 1214 passed / 4 skipped.
**Status:** design approved by the user in three sections (2026-07-28); ready for writing-plans.
**Scope decisions made by the user:** auto-*detect* candidates + retire them *manually* (option 1 of 3);
a retired finding whose tool returns **comes back open** (option 1 of 3); build **A + C** together; and
**fold in the `tsc` label mismatch** (§11) found while writing this spec, rather than filing it as T-12.

---

## 1. Context & motivation

### 1.1 The defect

`ledger.py:85-88` resolves an open finding only when its tool was in the current run's scope:

```python
for fid, rec in state.items():
    if rec["status"] == "open" and fid not in present \
       and rec.get("tool") in scope_tools and rec.get("file") in scope_files:
        self.append(Event(EventType.FINDING_RESOLVED, run_id, at, finding_id=fid))
```

and `pipeline.py:524` builds that scope from the current run's successful runners only:

```python
scope_tools = {r.tool for r in flat_results if r.state is ToolState.OK}
```

**Consequence:** when a repo stops running a tool, every open finding that tool produced is stranded
open *permanently*. No future run can resolve it, because resolution requires the tool to run, and the
tool never runs again. The row is a wrong answer to "what is outstanding" that can never become right.

**This is a live scenario, not a corner case.** The detector-fix branch changed test-stack detection for
every JS repo. Any repo previously mis-detected as a pytest repo carries one. pawscout's ledger holds:

```
pytest:tests-failed  "pytest exited 5"  verdict=block  status=open
```

whose only event is a `finding_detected` from 2026-07-25. `detect_tests` now returns `{'npm'}` there, so
`pytest` can never enter `scope_tools` again.

### 1.2 It is the fourth consequence of one rule, and the first with no producer to fix it

The `tool in scope_tools` guard has now stranded findings four times. The first three were each closed by
writing a bespoke resolver for the producer in question:

| # | Stranded tool | Why it never entered `scope_tools` | Fix |
|---|---|---|---|
| 1 | `llm-review` | async consumer, not a runner | `review.auto_resolve_llm` |
| 2 | `mutation` | async consumer, not a runner | `mutation_gate.auto_resolve_mutation` |
| 3 | `tdd`, `red-proof` | synchronous producers, appended outside the runner dict | `tdd.auto_resolve_tdd`, `red_proof.auto_resolve_red_proof` (see `2026-07-24-aramid-tdd-gate-cleanup-design.md` §2) |
| 4 | **any de-selected runner tool** | **the tool is gone from the repo** | **this spec, §3–§9** |
| 5 | **`tsc`, on Windows only** | **the tool runs fine — its `RunnerResult.tool` is labelled `tsc.cmd` while its findings are stamped `tsc`** | **this spec, §11** |

Case 5 was found while writing this spec and is folded in at the user's direction. It is the first
instance where the tool is *running perfectly* and the finding is stranded anyway, by a pure name-space
mismatch. It is detailed in §11.

Case 4 is structurally different from 1–3. Those tools still exist and still have evidence to consult —
a resolver can ask "did the push add the mapped test?", "does the evidence quote still exist at HEAD?".
Case 4 has no producer left to write a resolver for and no evidence source to consult. The tool cannot
run, so nothing can ever say whether the finding is fixed. The only honest disposition is to record that
the finding became **unreachable**, and to say so in those words.

### 1.3 Why the existing exits are all wrong

Each was checked against current code, not inherited from the ticket text:

* **`aramid override`** — `commands/override.py:60` refuses BLOCK-verdict findings by design (the two-key
  rule: a WARN can be waved through locally, a BLOCK needs a committed reviewable file). `tests-failed`
  is BLOCK tier. Refused.
* **`.aramid-suppressions.toml`** — applies at gate time. This is a pure ledger read, so a suppression
  cannot silence it. Same stored-vs-effective separation that ruled option (b) out in T-9.
* **`aramid rebaseline`** — works, and is a sledgehammer: `commands/rebaseline.py:34-38` discards *all*
  ratchet grandfathering to clear one stale row.
* **`ledger mark-rotated` / `mark-not-a-secret`** — both require `historical` status (`ledger_cmd.py:117`,
  `:150`). A ghost is `open`. Refused, correctly.

## 2. Approaches considered

**A — selected-tool set computed live from the repo (ADOPTED).** Ask the repo directly which tool names
it would produce findings under right now, reusing the gate's own applicability rules. Needs no run
history, so it works on ledgers written before this change — which is required, because the originating
case is exactly such a ledger.

**B — key on run history / skip streaks (REJECTED).** `status._skip_streak_lines:79` already computes
"tool absent from the last N consecutive runs" from `RUN_STARTED` payloads, so this is nearly free.
Rejected on two independent grounds. First, `scope_tools` admits only `ToolState.OK`, so a de-selected
tool and a *crashed* one leave a byte-identical signature — "break your tool for N runs, then retire the
finding" would become a supported path to dropping a BLOCK finding. Second, it flags every producer from
§1.2, whose absence streak is every run, forever; those four are gate surface (§7).

**C — record the selected set in `RUN_STARTED` and diff (ADOPTED, as a diagnostic only).** Extend the
event payload to record *selected* tools, not just OK ones, so the ledger itself can distinguish "was
selected but failed" from "was not selected". Not a substitute for A: it only answers after a fresh run
post-change, does nothing for existing ledgers, and needs the producer exclusion solved separately. It is
adopted alongside A because it makes the audit trail self-describing.

## 3. The predicate — `src/aramid/toolset.py` (A)

One new module with one job: answer *which tool names would this repo produce findings under, right now.*

```python
RUNNER_TOOL_NAMES: frozenset[str]        # the retireable universe
PRODUCER_TOOL_NAMES: frozenset[str]      # never retireable
def selected_tool_names(root, cfg) -> set[str]
def ghost_candidates(state: dict, selected: set[str]) -> dict[str, dict]
```

**The universe, measured this session** by reading every `RawFinding(...)` construction site in `src/`:

| Runner-produced — can enter `scope_tools` | Producer/consumer — never can |
|---|---|
| `gitleaks` `semgrep` `ruff` `eslint` `mypy` `tsc` `pip-audit` `npm` `pnpm` `yarn` `pytest` `tests` | `tdd` `red-proof` `mutation` `mutation-score` `llm-review` `js-mutation` `fuzz` `dast` `regression_pack` |

Sources: `runners/gitleaks.py`, `semgrep.py`, `ruff.py`, `eslint.py` (module `NAME`); `typecheck.py`
(`NAME_MYPY`, `NAME_TSC`); `deps.py:61` (`NAME_PIP_AUDIT`), `:237`, `:251` and the dynamic `tool=pm`
(package manager — `detect_package_manager` returns `npm`/`pnpm`/`yarn`); `tests.py:400,412,427`
(literal `tests`) and `:292-293` (`_run_one_within_deadline("pytest"/"npm", ...)`, whose results reach
findings via `tool=result.tool`). Producers: `tdd.py:67`, `red_proof.py:248`, `mutation_gate.py:22`,
`mutation_score_gate.py:45`, `consumers/{llm_review,mutation,js_mutation,fuzz,dast}.py`.

**This list is not to be trusted as written.** It is a starting point derived by reading; §10 pins it
with an empirical test that fails when it drifts.

**The predicate:**

```
candidate(finding) ⟺ finding.tool ∈ RUNNER_TOOL_NAMES
                   ∧ finding.tool ∉ selected_tool_names(root, cfg)
                   ∧ finding.status == "open"
```

`selected_tool_names` reuses `pipeline._is_applicable`'s rules (`pipeline.py:154-177`) over
`GATE_RUNNER_KEYS`, expanding runner keys to the sub-tool names those runners attach to findings. **The
expansion is not identity for three of the keys** — that is the whole reason this function has to exist
rather than being `set(_select_runners(...))`:

| Runner key | Tool names it can attach to a finding |
|---|---|
| `tests` | `detect_tests(root)` → `pytest` / `npm`, plus the literal `tests`; the `[tests].command` case makes the runner applicable with **no** detection at all (`pipeline.py:175`) |
| `deps` | `detect_package_manager(root)` → `npm`/`pnpm`/`yarn`, plus `pip-audit` when `requirements*.txt` exists |
| `typecheck` | `mypy` when `typecheck.has_mypy_config(root)`, `tsc` when `typecheck.has_tsconfig(root)` (`pipeline.py:159-160`) |
| `ruff` `eslint` `gitleaks` `semgrep` | themselves |

**The security property comes from the universe, not from a check.** The four producer families in §1.2
are gate surface (§7). They are not in `RUNNER_TOOL_NAMES`, so they can never be candidates and can never
be retired — including by a future caller who never considers the question. That is strictly stronger
than a guard clause someone can forget to write.

**Known conservative limitation, stated rather than fixed.** `npm` is emitted by two different runners:
`deps.py:237` for the JS dependency audit and `tests.py` for the npm test suite. One string, two
producers. A repo that loses its npm *test suite* while keeping its npm *deps audit* has a stranded
finding whose tool still reads as selected, so `mark-unreachable` will refuse it. This fails toward
refusing to retire, which is the safe direction. Disambiguating it is out of scope (§12).

## 4. The ledger transition

### 4.1 Naming

`EventType.FINDING_UNREACHABLE`, `Status.UNREACHABLE = "unreachable"`, command
`aramid ledger mark-unreachable <id> --reason R`.

"Unreachable", not "tool-removed": in the originating case nothing was removed. pawscout was
*mis-detected* as a pytest repo and the detector fix corrected it, so `pytest` was never right in the
first place. "Unreachable" states the property that justifies retirement — no run of this repo can
re-evaluate this finding — and stays true whichever way the tool went away. This is the same
naming-honesty constraint that produced `mark-not-a-secret` rather than reusing `mark-rotated`: the
`--reason` field is free text, but the event name is an assertion in an append-only audit ledger, and it
must be one that is true.

### 4.2 The transition, and only it

`open` → `unreachable`. Four refusals, each with its **own message** — not one shared string:

| Condition | Message tail |
|---|---|
| unknown finding id | `unknown finding id <id>` |
| tool ∉ `RUNNER_TOOL_NAMES` (a producer) | names the producer's own auto-resolve as the real mechanism; producer findings are never retired by hand |
| tool ∈ `selected_tool_names(...)` | not a ghost — the tool still runs here. If it is failing every run, that is `aramid doctor`, and retiring the finding would be a bypass |
| status ≠ `open` | per-status tail: already `unreachable`; `fixed`; `historical` (→ `mark-rotated` / `mark-not-a-secret`); `overridden`; `rotated`; `not_a_secret` |

`--reason` is required and non-empty, mirroring `ledger_cmd.py:103-106`.

**No overlap with T-9's territory.** `gitleaks` has no stack condition (`pipeline.py:176` — always
applicable), so a historical secret can never be a ghost candidate and the two retirement paths cannot
collide.

**Directional rule, inherited from T-9:** transitions move only toward more caution. There is no un-mark
and no `unreachable` → anything-else command. The one reverse transition (§5) is automatic, is a
*re-opening*, and is therefore more cautious, not less.

## 5. Resurrection

`ledger.py:80` currently re-detects only a `fixed` finding:

```python
if f.id not in state or state[f.id]["status"] in ("fixed",):
```

Every other terminal status is sticky, correctly: `overridden`, `rotated`, and `not_a_secret` are human
assertions *about the finding itself*, and a re-fire must not undo a person's judgment.

`unreachable` is a different kind of claim — it asserts something about the **tool's absence**, not about
whether the finding is real. So it joins the re-detect set:

```python
if f.id not in state or state[f.id]["status"] in ("fixed", "unreachable"):
```

If the tool returns and re-finds the problem, the finding re-opens on its own. Without this, a repo that
flips detection off and back on would permanently launder its open findings, and the ledger row would
assert something untrue.

**This change is only half-verified without its mirror.** A test must prove `unreachable` re-opens on
re-detect **and** a second must prove `overridden` / `rotated` / `not_a_secret` still do not.

## 6. Two silent-failure sites fixed in the same change

Both are instances of the class this project's ledger has now recorded four times: *a check whose passing
state and whose broken state are indistinguishable.*

**`ledger.compact():136`** holds a hardcoded terminal-event set:

```python
terminal_types = {FINDING_RESOLVED, FINDING_OVERRIDDEN, FINDING_ROTATED, FINDING_NOT_A_SECRET}
```

An event type missing from it is **deleted on compaction**, silently reverting the finding to `open`,
with no error — on a code path `ledger.py:112` documents as currently dead, so it would never be noticed.
`FINDING_UNREACHABLE` is added, with a test.

**`status._open_counts_line:38-43`** hardcodes its buckets (`historical`, `not_a_secret`, `overridden`).
A new status disappears from the `open` count and appears in none of the named buckets, so the printed
numbers quietly stop summing. Beyond adding the `unreachable` bucket, a test asserts the printed buckets
cover **every member of `Status`** — so the *next* status added fails a test instead of vanishing. This
is the T-11 move: make the failure mode mechanical rather than dependent on someone thinking to look.

## 7. Security analysis — gate surface

Unlike T-9 (reporting-only, zero gate surface), a new terminal status here **is** gate surface. Both of
these materialize block-tier findings by filtering ledger state for `status == "open"`:

* `review.llm_gate_findings` — `review.py:477-478`: `if rec.get("source") != "llm" or rec.get("status") != "open": continue`
* `mutation_gate.mutation_gate_findings` — same shape, keyed on `TOOL = "mutation"`

Retiring an `llm-review` or `mutation` finding would therefore silently drop a gate block. The design
closes this at the type level rather than with a check: those tools are in `PRODUCER_TOOL_NAMES`, never
in `RUNNER_TOOL_NAMES`, so the predicate in §3 cannot select them and the command in §4.2 refuses them.
§10 pins this with a test that attempts both and asserts refusal.

**The crashed-versus-de-selected bypass is closed by construction.** The retire guard consults A's live
predicate and **only** A. `selected` from run history (§8) is never an input to it. Were run
history ever allowed to decide retireability, "crash your tool for a while, then retire the finding"
would return through a different door.

Findings whose tool *is* still selected but is failing every run are explicitly **not** retireable. That
is a broken-toolchain problem and `aramid doctor` is its diagnostic.

## 8. `RUN_STARTED.selected` (C)

`Ledger.record_run` gains a keyword-only `selected_tools: set[str] | None = None`, recorded as
`payload["selected"]` beside the existing `payload["tools"]` (which stays as-is: the tools that came back
OK). Both lists live in the **same namespace** — sub-tool names — stamped by the same
`toolset.selected_tool_names`, so there is one source of truth rather than two lists that can disagree.

`record_run` has exactly three callers (verified via graphite, `decision_grade`):

| Caller | Passes `selected_tools`? | Why |
|---|---|---|
| `pipeline.run_gate` (`pipeline.py:526`) | **yes** | it is the only caller that selects runners |
| `drain._consume_item` | no | a consumer run selects no runners |
| `init._scan_history` | no | the full-history secret scan selects no runners |

So **"key absent = no information"** is a live state, not a legacy quirk — exercised by real code paths
on every drain and every init, not only by old rows. Readers must treat absent as *unknown*;
`payload.get("selected", [])` would make all of history, plus every drain and init run, read as "nothing
was selected".

**C is diagnostic, never authoritative** (§7). `selected − tools` is exactly "was selected but degraded",
the distinction the ledger cannot express today. It exists so a human reading the audit trail later can
tell why a finding was retireable, not to gate anything.

## 9. Surfaces

**`aramid status`** gains two things:

1. `unreachable` in the counts line (`_open_counts_line`).
2. A candidate section mirroring `_unrotated_historical_lines:104-113` — each candidate rendered with
   tool, rule, file and the exact command to run:
   `aramid ledger mark-unreachable <id> --reason ...`

Item 2 is the half of this the user chose auto-detection for. Without it the operator must already
suspect a finding is a ghost — which is precisely the discoverability defect T-9 existed to fix,
reproduced.

**`aramid ledger mark-unreachable`** — CLI wiring mirroring `mark-not-a-secret` (`cli.py`, `ledger_cmd.py`).

**Docs** — the implementer enumerates the set by following T-9's own doc commits rather than trusting a
count here. Two are known: `src/aramid/data/ARAMID.md.tmpl`, and therefore the rendered repo-root
`ARAMID.md`, which is now pinned by `tests/unit/test_aramid_md_template_sync.py` and **will fail** unless
it is regenerated through `_render_aramid_md` with the historical `Onboarded` date preserved.

## 10. Testing

**The load-bearing test is empirical, not a hand-written list.** Run the real runners and producers over
a fixture and assert every observed `finding.tool` falls in exactly one of `RUNNER_TOOL_NAMES` /
`PRODUCER_TOOL_NAMES`, and that the two sets are disjoint. A hand-maintained registry will drift the
first time someone adds a runner; this fails when it does. It also settles by measurement the one
question §3 leaves open: whether the aggregate `tests` or the sub-names `pytest`/`npm` reach
`scope_tools`, which depends on whether `sub_results` was populated (`runners/tests.py:311-312` — the
dual-stack path populates it; the single-suite path does not). **That must be measured during
implementation, not reasoned about.**

Then:

1. **One test per refusal in §4.2, asserting the message — not just `rc == 3`.** Four paths returning 3
   is exactly the indistinguishable-check trap already recorded in this project's ledger.
2. **Resurrection**: an `unreachable` finding re-fired by a returning tool re-opens.
3. **Its mirror**: `overridden`, `rotated`, `not_a_secret` still do **not** re-open on re-detect.
4. **`compact()` round-trip**: a compacted ledger holding an `unreachable` finding still materializes it
   as `unreachable`, not `open`. Proven to fail against the un-extended `terminal_types`.
5. **`Status` coverage** of `_open_counts_line`'s buckets (§6).
6. **Gate-surface invariant**: attempt `mark-unreachable` on an `llm-review` finding and on a `mutation`
   finding; both refuse.
7. **`selected` payload**: `run_gate` stamps it; `drain` and `init` do not; a reader distinguishes absent
   from empty.
8. **End-to-end**: build a repo whose detection strands a real finding, prove `status` names it as a
   candidate, retire it, prove it leaves the open count and the nag, then restore detection and prove it
   comes back open.
9. **Cross-runner label agreement** (§11): for every runner, the `RunnerResult.tool` it returns on the
   OK path equals the tool name its parser stamps on findings. This is the test that catches the next
   instance of case 5 mechanically, on whatever platform introduces it. It must be written so it
   **fails on Windows against the pre-fix tree** — a version that passes before the fix is not a test of
   anything.

Every test above must be **proven to fail** against the pre-change tree before being accepted. The
project's own ledger records a cache change that silently invalidated a regression guard, a docstring
rule and a design rationale, none of them visible in its diff.

## 11. Folded-in defect — the `tsc` label mismatch (case 5)

### 11.1 The defect

`runners/base.py:157` derives a runner's reported tool name from the binary it launched:

```python
def run_subprocess(argv, cwd, timeout_s, env=None) -> RunnerResult:
    tool = Path(argv[0]).name
```

Most runners never expose that name, because they re-label before returning — `eslint.py:49` passes
through `json_or_crashed(NAME, result, ...)` (`runners/_util.py:68` rebuilds the `RunnerResult` with the
passed-in tool), and `ruff`, `semgrep`, `gitleaks`, `pytest`, `npm`, and `mypy` all pass a bare tool name
as `argv[0]` so the basename is already correct.

`typecheck.run():76-81` is the exception — it returns `run_tsc(ctx)` unrelabeled, and `run_tsc:64-68`
returns `run_subprocess([str(binp), "--noEmit"], ...)` where `_tsc_bin:42-44` is:

```python
name = "tsc.cmd" if sys.platform == "win32" else "tsc"
return root / "node_modules" / ".bin" / name
```

So on Windows `RunnerResult.tool == "tsc.cmd"`, while `parse_tsc:93` stamps `tool=NAME_TSC == "tsc"`.
`pipeline.py:524` puts `"tsc.cmd"` into `scope_tools`; `ledger.py:87`'s `rec.get("tool") in scope_tools`
compares `"tsc"` against it and never matches. **A Windows repo's `tsc` findings never resolve, even
though the tool ran and passed.** On POSIX the basename is `"tsc"` and everything matches, which is why
the CI matrix's Linux and macOS legs would never surface it.

**Evidence grade: read, not executed.** This was derived by reading the four functions above. It must be
confirmed live on Windows before the fix is written — a failing test first, per §10's standing rule.

### 11.2 The fix

Re-label at `typecheck.run()`'s return so the `RunnerResult` carries `NAME_TSC`, matching what
`parse_tsc` stamps. One line, mirroring what `eslint.py:49` already does.

**This changes gate behavior on Windows**: `tsc` findings begin resolving where they previously never
did. That is the correct behavior and the whole point, but it is a behavioral change on a block-tier
path and must be called out in the branch's review rather than slipped in as a typo fix.

**The durable part is the test, not the fix** (§10 item 9): pin every runner's OK-path
`RunnerResult.tool` against the tool name its parser stamps. The one-line fix closes today's instance;
the test is what closes the next one.

### 11.3 Why it is folded in rather than filed

It is the same guard, in the same expression, with the same consequence — a finding no run can ever
resolve. Shipping §3–§9 without it would leave a class of permanently-stranded findings that the new
`status` section deliberately does *not* list (because `tsc` **is** in the selected set, so it is
correctly not a ghost) and that `mark-unreachable` correctly refuses. The user would be left with an
open finding, no explanation, and no route out.

## 12. Explicitly out of scope

* **The `scope_files` half of the resolution guard** — findings on files that left scope. That is ticket
  T-3 territory, whose "aramid is structurally blind to deletions" framing my own measurement refuted;
  folding it in would swallow this spec.
* **Disambiguating the `npm` deps-versus-tests collision** (§3). Fails conservatively toward refusing to
  retire.
* **Changing `_skip_streak_lines`' semantics** (`status.py:79-101`). It reports a *degraded* tool as
  "skipped" today and will continue to. C makes fixing that possible; it is separate work.
* **Wiring `compact()` into a command.** It stays dead code (`ledger.py:112-122` documents what wiring it
  would require). This spec only keeps it correct.
