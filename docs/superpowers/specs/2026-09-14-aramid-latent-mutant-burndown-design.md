# Latent mutant burn-down and ratchet -- design

**Date:** 2026-09-14
**Status:** the three decisions in section 3 were taken by the operator in
chat (2026-09-14 ~02:00Z); this write-up awaits the operator's review before
Task 1 starts. Plan: `docs/superpowers/plans/2026-09-14-latent-mutant-burndown.md`

## 1. The problem, measured

The drain confirms a mutant against the UNIT suite alone (`tests/unit`,
stage 1 by module mapping, then the full unit run). A source line the unit
suite never executes therefore holds mutants that no test can kill: they
are survivors by construction, and the drain reports them -- three per
row -- the first time an edit touches those lines. Five of them were just
paid for one at a time: `cmd_drain` (28/29, 2026-09-11), `cmd_check`,
`consumers.mutation.consume` (108/108, 0.17.2), and the other four
consumers' `consume` (114/114, 0.17.3).

Measured on 2026-09-14 01:42Z with `pytest tests/unit --cov=aramid`
(2066 passed) crossed with the generator:

| measure | value |
|---|---|
| unit-suite statement coverage | 81.0 % (8306 of 10252) |
| generator mutants in `src/aramid` | 3030 |
| mutants on never-executed lines | **375** (12.4 %) in 41 files |

Concentrations (latent / all mutants in the function):
`cli.py::main` 43/43; `commands/ledger_cmd.py` 53 (resolve 15,
mark_not_a_secret 10, mark_unreachable 10, mark_rotated 6, list 3);
`commands/doctor.py` 34 (`_sh_path_to_win` 9/9, `cmd_doctor` 9/16,
`_fix_gitleaks` 5); `commands/init.py` 33; `commands/override.py` 25
(`cmd_override` 12/16); `commands/fleet_cmd.py` 18 (`cmd_notices` 12/12);
`commands/agent_hook.py` 14 (`_pre_tool_use` 6/6, `cmd_agent_hook` 4/4,
both with zero executed lines); `commands/schedule.py` 14; `fuzzgen.py` 15;
`commands/pack_cmd.py` 12; `commands/triage_cmd.py` 9; then a tail of
one to eight per file.

## 2. Goal

Every function in `src/aramid` is executed by the unit suite, so the
generator's mutants are graded by the suite the drain confirms against;
and a ratchet in CI stops the never-executed count from rising again.

Non-goals: raising coverage for its own sake (executed-but-equivalent
mutants are fine); mutation-scoring the whole tree in CI; changing any
consumer-facing surface.

## 3. Decisions (operator, 2026-09-14)

1. **Burn-down plus a ratchet**, in that order per batch: pin modules,
   then install the guard so the gap cannot silently reopen.
2. **Three batch releases**, each a patch unless the operator says
   otherwise at the time: after the two high-consequence steps
   (agent_hook, `cli.main`); after the ledger-writing surface
   (ledger_cmd, override); a final one carrying doctor, init, the tail and
   the ratchet.
3. **The ratchet runs on one CI leg against a committed baseline.** No
   product surface, no pre-push cost, no drain cost.

## 4. Method per module (the loop that has now run five times)

1. List the module's latent mutants from `latent-mutants.txt` (or re-run
   `scripts/latent_mutants.py` once it exists) and read the function.
2. Write the unit twin on the seams the integration file already uses --
   fakes at the subprocess / probe / driver boundary, a real tmp git repo
   and a real ledger where the code reads them, a fixed or scripted clock
   where a budget is compared. File name follows the drain's stage-1
   mapping: `tests/unit/test_<stem>_<aspect>.py`. Every assertion exact
   (whole notes, whole `extra` dicts, whole call lists); a `_stats(res,
   **expect)` helper with every key defaulting to zero is what killed 107
   of 109 first time on `consume`.
3. Run it against the real code, then prove it against the generator in a
   detached worktree: `derive_function_deadline.py <rel> <function>
   <worktree> <stage-1 files...>` per function, stage 1 = the new file
   first plus the module's existing `test_<stem>*.py`, stage 2 =
   `tests/unit`. Deadline absolute (`YYYY-MM-DDTHH:MM`) before the next
   drain; `DERIVE_OVERLAY` when a source edit is part of the change.
4. A survivor is one of: a missing pin (add it), dead code (remove it, as
   `retest_skipped`'s initializer was), or an honest equivalent (document
   it in the commit; if the drain ever reports it, suppress it with the
   EQUIVALENT MUTANT reason, as c5326a9c).
5. CHANGELOG (Added), `aramid check --staged`, one commit per module (or
   per small group), `main_push.sh` on a quiet machine counted back from
   the next drain (gate ~28 min), CI 7/7, the next drain's rows read-only,
   a `progress.md` line. Never `--no-verify`; never `pip install -e .`
   on this machine; releases are the operator's.

## 5. The ratchet

**`scripts/latent_mutants.py`** (promoted from the scratch script that
produced the table above; stdlib + `aramid.mutation`):

- `latent_mutants.py measure <cov.json>` prints per-file and per-function
  counts and a total.
- `latent_mutants.py check <cov.json> --baseline tests/latent_mutants_baseline.json`
  exits 1 naming every file whose latent count EXCEEDS its baseline entry
  (a file absent from the baseline has baseline 0), 0 otherwise. Per-file,
  so a rise in one file cannot hide behind a fall in another.
- `latent_mutants.py write-baseline <cov.json> --baseline ...` writes the
  current counts. Only ever run to LOWER the baseline after pins land; a
  commit that raises an entry is a review question.

**`tests/latent_mutants_baseline.json`**: `{"<rel path>": <count>, ...,
"_total": N}`, sorted, committed. Starts at the measured floor when Task 10
lands (after the burn-down, so it is small); platform-only lines that the
ubuntu leg cannot execute (the win32 `mklink` branch in
`js_mutation._link_node_modules`) stay in it as a documented floor rather
than a `pragma`.

**CI** (`.github/workflows/aramid.yml`), on the `ubuntu-latest / 3.12`
leg only, after the full-suite step:

```
python -m pytest -q tests/unit --cov=aramid --cov-report=json:cov-unit.json
python -P scripts/latent_mutants.py check cov-unit.json --baseline tests/latent_mutants_baseline.json
```

`pytest-cov>=5` joins the `dev` extras. Cost: one extra unit run (~7 min)
on one of seven legs. The ratchet measures UNIT coverage on purpose --
that is the drain's confirm scope -- so it is a second run, not `--cov`
on the full-suite step.

**Its own pins**: `tests/unit/test_latent_mutants_script.py` covers
counting (a mutant on a missing line counts, on a covered line does not;
a function with no mutants contributes nothing), `check` (equal passes,
one over fails naming the file, a file absent from the baseline is 0),
`write-baseline` (sorted keys, `_total`), and exit codes;
`tests/unit/test_workflow_pinning.py` style guard that the step exists on
exactly one leg and names the baseline file.

## 6. Order and batches

| batch | tasks | latent mutants | release |
|---|---|---|---|
| A | agent_hook (14), `cli.main` (43) | 57 | patch |
| B | ledger_cmd (53), override (25) | 78 | patch |
| C | doctor (34), init (33), pure helpers (fuzzgen 15, jsmutate 7, fuzzdriver 4), commands tail (fleet_cmd 18, schedule 14, pack_cmd 12, triage_cmd 9, uninstall 8, arm 8, status 8, mutation_score 7, autolearn 5, rebaseline 3, resolvers 3), singletons (mcp 6, fleet 7, gitutil 4, review 4, ledger 2, pipeline 2, drain 2, hooks_template 2, fuzz 2, js_mutation 7, one each in agent_bypass, update_rules, health, mutation, mutation_score_gate, red_proof, runners/base, runners/deps, runners/typecheck, tdd, triage), then the ratchet | ~240 | patch (operator may call it minor for the CI guard) |

Rationale for A first: `_pre_tool_use` is the enforcement hook -- a
defect there is a bypass, not a test gap -- and `cli.main` is the most
edited function on the list (27 commits in 60 days) with the highest
single-function yield. B is the operator's truth surface: every command
in it writes a permanent row into an append-only ledger.

## 7. Risks and what bounds them

- **A harness that fakes the wrong seam proves nothing.** Every twin
  fakes at the same boundary its integration file does; the real tmp
  repo and real ledger stay real.
- **A pin that stops testing looks green** (literal dates, machine
  state): the hygiene guards in `tests/unit` already catch literal dates;
  the isolation fixture covers machine state.
- **Proof time.** ~5-20 s per stage-1 kill, ~7 min per stage-1 survivor;
  Task 2 (43) is ~15 min if clean. Everything runs in a detached
  worktree and never overlaps a scheduled drain (02/06/10/14/18/22Z).
- **The ratchet freezes platform-only lines** at their count; documented
  in the baseline's commit, not hidden behind `pragma: no cover`.
- **CI minutes**: +7 min on one leg; measured after Task 10 lands and
  written into its commit.
