# Latent Mutant Burn-down Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The resumable state for the maintenance loop stays in the gitignored `.superpowers/sdd/progress.md` (a `RESUME HERE` line per task).

**Goal:** Every function in `src/aramid` is executed by the unit suite the drain confirms against, so the 375 generator mutants that today sit on never-executed lines are graded rather than reported later as survivors; a per-file ratchet on one CI leg keeps the count from rising again.

**Architecture:** Tests-only commits, one unit twin per module on the seams its integration file already uses, each proven against the generator in a detached worktree before it lands; then one script (`scripts/latent_mutants.py`), one committed baseline (`tests/latent_mutants_baseline.json`) and one CI step on the `ubuntu-latest / 3.12` leg.

**Tech Stack:** Python stdlib; pytest with the fake-subprocess / fake-probe / fake-driver seams of `tests/integration/*`; `pytest-cov` (new `dev` extra) for the ratchet; the scratch `derive_function_deadline.py` and `latent_mutants.py` (session scratchpad; rebuild from the spec if lost).

**Spec:** `docs/superpowers/specs/2026-09-14-aramid-latent-mutant-burndown-design.md`

## Global Constraints

1. Tests only until Task 10; a source change inside a task is allowed only to remove dead code a survivor exposed (say so in the commit) -- never to make a mutant killable by changing behaviour.
2. Every twin's file name matches the drain's stage-1 mapping (`tests/unit/test_<stem>_<aspect>.py`); every assertion is exact (whole notes, whole `extra` dicts, whole call lists, whole argv).
3. Proof before commit: `derive_function_deadline.py` per function, stage 1 = new file first + the module's existing `test_<stem>*.py`, stage 2 = `tests/unit`; deadline absolute and before the next drain (02/06/10/14/18/22Z); the log is named in the commit message with the tally.
4. Every commit: CHANGELOG (Added), `python -P -m aramid check --staged`, then `python -P -m aramid ledger filter --status open` (six suppressed, nothing else); `git commit -F <file>`, trailers `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` + `Claude-Session: https://claude.ai/code/session_01PA6gwSThJtSo2GDRncnUrw`; never `--no-verify`.
5. Push with `main_push.sh` (full unit suite, then the gate, ~35 min) on a quiet machine counted back from the next drain; CI 7/7 (`gh run list`, then the jobs); read the next drain's rows read-only; write the `progress.md` line.
6. Never `pip install -e .` on this machine (CI may); heredoc bodies with a backslash or apostrophe go through the Write/Edit tools; times to the operator in London local alongside UTC.
7. Releases are the operator's: at the end of batches A, B and C hand over `chore(release)` + tag + the `!` approval line as for 0.17.3; never cut one unasked.
8. A survivor is a missing pin, dead code, or an honest equivalent -- decide which and record it; an equivalent stays in the commit message until the drain reports it, then `aramid override` with the EQUIVALENT MUTANT reason.

---

## Batch A -- the two high-consequence gaps (target: 0.17.4)

### Task 1: `commands/agent_hook.py` (14 latent mutants)

**Files:** Test `tests/unit/test_agent_hook_dispatch.py` (new; the stem `agent_hook` is what the drain's stage 1 maps on). Read `src/aramid/commands/agent_hook.py` and `tests/integration/test_agent_hook.py`, `test_agent_hook_cli.py`, `test_agent_hook_fleet.py` for the seams (stdin payload, ledger, registry).

- [ ] Step 1: list the 14 mutants (`_pre_tool_use` L82-103 6/6, `cmd_agent_hook` L51-59 4/4, the rest) with the scratch lister; note which lines are the block decision.
- [ ] Step 2: write the twin: `cmd_agent_hook` with every hook event the dispatcher accepts (SessionStart, PreToolUse, unknown), `_pre_tool_use` with a payload that must be BLOCKED (`--no-verify`, `-n`, bypass shapes) and one that must pass, the exact stderr/stdout text and exit code for each, a malformed payload, an empty stdin. Exact strings only.
- [ ] Step 3: run against the real code; prove: `derive_function_deadline.py src/aramid/commands/agent_hook.py _pre_tool_use ...` and `... cmd_agent_hook ...` (+ any other function on the list) with stage 1 = the new file + `tests/unit/test_agent_hook*.py` if any. Expect 14/14.
- [ ] Step 4: CHANGELOG, gate, commit `test(agent-hook): the PreToolUse block decision and the hook dispatcher have unit-scope pins (N/N generator mutants red)`, push, CI, drain rows, progress line.

### Task 2: `cli.py::main` (43 latent mutants, one known equivalent)

**Files:** Test `tests/unit/test_cli_main.py` (new). Read `src/aramid/cli.py::main` L271-396 and `tests/integration/test_cli_dispatch.py` (42 arms) -- the twin mirrors it with the command table replaced by fakes (`monkeypatch.setattr(cli, "<cmd>", fake)` or the dispatch dict) so no command body runs.

- [ ] Step 1: list the 43; mark c5326a9c (`1 -> 2` at L264: `code = exc.code if isinstance(exc.code, int) else 1` feeding `return 0 if code == 0 else 3`) as the documented equivalent -- 42 to kill.
- [ ] Step 2: write the twin: every subcommand name routes to its function with the parsed namespace (one arm per command, asserting the fake was called once with the expected attributes); `--version`; no args; unknown command; `SystemExit` with int / non-int / zero code mapped to 0 / 3; a command raising `KeyboardInterrupt` / a generic exception (whatever `main` does with each, pinned exactly); the `-P` / shadow guard if `main` has one.
- [ ] Step 3: run; prove `derive_function_deadline.py src/aramid/cli.py main <wt> tests/unit/test_cli_main.py tests/unit/test_cli*.py`. Expect 42/43 with L264 the one survivor, named in the log.
- [ ] Step 4: CHANGELOG, gate, commit, push, CI, drain rows, progress line.

### Task 3: release batch A

- [ ] Hand over: `release_0_17_4.py` (bump, CHANGELOG heading `## [0.17.4] — <date>`, link defs), `egg_info --egg-base src`, version tests, gate, commit, push, CI, `git tag -a v0.17.4`, `tag_push.sh`, `wait_release_pause.sh`, the `!` approval line; then digests x3, `promote_live.py --confirm` with the drain lock clear, verify twice + doctor, `rehearsal_push.sh`, graphite note (re-list first), memory, progress DONE.

## Batch B -- the ledger-writing surface (target: 0.17.5)

### Task 4: `commands/ledger_cmd.py` (53 latent mutants)

**Files:** Test `tests/unit/test_ledger_cmd_marks.py` (resolve, mark_not_a_secret, mark_unreachable, mark_rotated) and `tests/unit/test_ledger_cmd_list.py`; read `tests/integration/test_ledger_cmd.py` for the ledger seeding and argv shapes.

- [ ] Step 1: list the 53 by function (resolve 15, mark_not_a_secret 10, mark_unreachable 10, mark_rotated 6, list 3, others).
- [ ] Step 2: twin per command on a real tmp ledger: the happy path writes exactly one event with the exact payload (status, reason, actor, timestamp from an injected clock); unknown id; already-resolved id; missing `--reason`; a reason below the minimum length if there is one; `--json` output exact; exit codes; the stdout/stderr lines exact.
- [ ] Step 3: run; prove each function; expect 53/53 or documented equivalents.
- [ ] Step 4: CHANGELOG, gate, commit, push, CI, drain rows, progress line.

### Task 5: `commands/override.py` (25 latent mutants)

**Files:** Test `tests/unit/test_override_cmd.py`; read `tests/integration/test_override.py` and `test_override_invalidation.py` (the suppressions file write, the invalidation rule).

- [ ] Step 1: list the 25 (`cmd_override` 12/16 plus helpers).
- [ ] Step 2: twin: an override of an open WARN writes the suppressions entry and the ledger event with the exact shapes; a BLOCK-tier id is refused with the exact message; unknown id; duplicate override; `--reason` missing; the invalidation path (line moved / content changed) exact; exit codes.
- [ ] Step 3: run; prove; Step 4: CHANGELOG, gate, commit, push, CI, drain rows, progress line.

### Task 6: release batch B (as Task 3, version 0.17.5).

## Batch C -- the rest, then the ratchet (target: 0.17.6 or 0.18.0, operator's call)

### Task 7: `commands/doctor.py` (34 latent mutants)

- [ ] Step 1: `_sh_path_to_win` (9/9, pure): `tests/unit/test_doctor_sh_path.py`, one arm per shape (`/c/x`, `/f/Projects/x`, a path with no drive, already-Windows, trailing slash); prove; commit.
- [ ] Step 2: `_fix_gitleaks` (5) and `probe_relocated_shims` (3): twins with the download/PATH/shim seams the integration `test_doctor_fix_gitleaks.py` and `test_doctor_agent_probe.py` use.
- [ ] Step 3: `cmd_doctor` (9/16): the report assembly with every probe faked to a fixed verdict table; exact lines and exit code.
- [ ] Step 4: prove all; CHANGELOG, gate, commit, push, CI, drain rows, progress line.

### Task 8: `commands/init.py` (33 latent mutants)

- [ ] Step 1: pure slices first: `render_agent_settings_notice`, `render_agent_mcp_notice` (3 each), `_find_repos` / `_walk` (8): exact rendered text, exact walk results on a tmp tree with nested repos and ignored dirs.
- [ ] Step 2: `_scan_history` (5) on a real tmp repo with a planted secret in history (fake gitleaks via the runner seam).
- [ ] Step 3: `_init_one` (6): the write set on a fresh repo, an already-initialised repo, `--adopt`, the shim marker; every written file's content exact.
- [ ] Step 4: prove; commit; push; CI; drain rows; progress line.

### Task 9: pure helpers and the commands tail (about 130 latent mutants, several commits)

- [ ] Step 1: `fuzzgen.py` (`_is_supported` 8/14, `gen_value` 7/27), `jsmutate.py` (7), `fuzzdriver.py` (4): table-driven exact arms in the existing `test_fuzzgen.py` / new `test_jsmutate_ops.py` / `test_fuzzdriver_edges.py`; prove; one commit.
- [ ] Step 2: `commands/fleet_cmd.py` (`cmd_notices` 12/12, `cmd_fleet` 4) and `fleet.py::render_report` (5/6): exact rendered lines from a seeded notices/health store; one commit.
- [ ] Step 3: `commands/schedule.py` (12/20 in `cmd_schedule`), `commands/triage_cmd.py` (8/9), `commands/pack_cmd.py` (`_compiler_for` 6/6 + 6), `commands/mutation_score.py` (7/8): one twin each on the existing seams (`test_schedule.py`, `test_triage.py`, `test_pack.py`, `test_mutation_score.py`); prove; one or two commits.
- [ ] Step 4: `commands/uninstall.py` (6/6), `commands/arm.py` (8/33), `commands/status.py` (`_bake_lines` 4/5 + 4), `commands/autolearn_cmd.py` (4/14), `rebaseline.py` (3), `resolvers.py` (3), `update_rules.py` (1); prove; one or two commits.
- [ ] Step 5: singletons -- `mcp.py` (6), `gitutil.py` (4), `review.py` (4), `ledger.py` (2), `pipeline.py` (2), `commands/drain.py` (2), `hooks_template.py` (2), `consumers/fuzz.py` (2), `consumers/js_mutation.py` (7: `_link_node_modules` 6/6 is the win32 `mklink` branch -- pin what ubuntu can execute, document the rest as the platform floor), and one each in `agent_bypass`, `health`, `mutation`, `mutation_score_gate`, `red_proof`, `runners/base`, `runners/deps`, `runners/typecheck`, `tdd`, `triage`; prove; one commit.
- [ ] Step 6: after each commit: push, CI, drain rows, progress line.

### Task 10: the ratchet

**Files:** Create `scripts/latent_mutants.py` (from the scratch script: `measure`, `check --baseline`, `write-baseline`), `tests/latent_mutants_baseline.json`, `tests/unit/test_latent_mutants_script.py`; modify `pyproject.toml` (`pytest-cov>=5` in `dev`), `.github/workflows/aramid.yml` (two steps on the `ubuntu-latest / 3.12` leg, after the full-suite step, guarded by `if: matrix.os == 'ubuntu-latest' && matrix.python == '3.12'`), `docs/knowledge-base.md` (a row: what the ratchet measures and how to lower the baseline), CHANGELOG (Added).

- [ ] Step 1: tests first (`test_latent_mutants_script.py`): counting on a synthetic coverage JSON + tmp source (a mutant on a missing line counts, on an executed line does not, a function with no mutants contributes nothing, a non-`src/aramid` file is ignored); `check` exit 0 on equal, exit 1 naming the file on one over, a file absent from the baseline is treated as 0; `write-baseline` writes sorted keys and `_total`; the CLI usage error exit.
- [ ] Step 2: write the script; run the tests; run `measure` on a fresh `cov-unit.json` and record the floor.
- [ ] Step 3: `write-baseline` at the measured floor (expected: only the platform-only lines plus anything Task 9 documented); commit the baseline with the per-file floor explained in the message.
- [ ] Step 4: CI step + dev extra + a `test_workflow_pinning.py`-style guard that the step exists on exactly one leg and names the baseline file; prove the guard red-first by removing the step locally.
- [ ] Step 5: gate, commit `feat(ci): a per-file ratchet on the mutants the unit suite never executes`, push, CI 7/7 with the new leg's timing noted, drain rows, progress line.

### Task 11: close-out

- [ ] Re-run `measure` on a fresh coverage JSON; the total equals the baseline's `_total`; record both numbers in the CHANGELOG entry.
- [ ] Release batch C (as Task 3); graphite note names the ratchet and the floor; memory: update `derive-a-function-against-the-generator.md` with the ratchet's location and the "lower only" rule; progress DONE.
