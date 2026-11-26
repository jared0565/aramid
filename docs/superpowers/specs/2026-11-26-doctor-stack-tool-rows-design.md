# `aramid doctor`: rows for eslint, tsc and mypy

Date: 2026-11-26. Size: a small change. Operator decisions: 2026-11-25
(build it), 2026-11-26 (three tool rows only; revised design after audit).

## Intent

A JS/TS or typed-Python repo should learn from `aramid doctor` that eslint,
tsc or mypy is missing. Today the first sign is a degraded tool at pre-push
(and a skip streak in `aramid status`), with no row in doctor at all.
Doctor already reports cargo-audit and clippy this way (`probe_deps`,
`commands/doctor.py`); these three are the remaining stack tools.

## Goals

- A doctor row for each of eslint, tsc and mypy, only in a repo where the
  gate selects that tool.
- The row tells the truth about what was checked: whether the binary is
  where the gate looks for it. Nothing stronger.
- A missing tool says what is not being checked, where the gate looks, and
  what that costs at a gate.

## Non-goals

- No change to doctor's exit code. No `--fix` for these tools: they belong
  to the repo, not to aramid.
- Doctor does not run the tools, so it does not detect a missing eslint
  config or a broken `tsconfig.json`.
- No warning for "TypeScript files but no root `tsconfig.json`" (operator,
  2026-11-26: keep to the three rows).
- No change to how the gate selects or locates any tool.

## Anti-goals

- `OK` for a tool no gate runs. The typecheck runner runs ONE tool: tsc
  when `tsconfig.json` is at the root, mypy only otherwise
  (`runners/typecheck.py`, `run`). A mypy row that reads OK in a repo with
  both would be a control that looks like coverage and is not.
- A second copy of the selection rules in doctor that can drift from the
  runner's.
- Calling a missing tool "non-blocking". Measured 2026-11-26 in a scratch
  JS repo with a `tsconfig.json` and no `node_modules`: `aramid check
  --gate pre-push --all --strict` exits 1 with `degraded: eslint, tsc`
  ("not found"); without `--strict` it exits 2, degraded. (This line said
  0 until the same day: that was the pre-commit gate, which selects
  neither tool.) Hooks with CI parity on run `--strict`.

## Approaches

1. **Extend `probe_deps`' pattern (chosen).** Conditional rows built from
   the runners' own predicates and paths, report only. It matches what
   doctor already does for cargo-audit and clippy, and the operator chose
   it after the audit.
2. A separate "stack tools" registry that every runner declares itself in.
   More machinery than five tools need; dropped.
3. Make a missing stack tool fail doctor. Doctor would then report a
   failure the default gate never produces; `probe_deps` refuses this for
   the same reason. Dropped.

## Design

**One owner for "which typecheck tool runs".** `runners/typecheck.py`
gains a small public function that returns the tool `run` dispatches to for
a root: tsc, mypy or none. `run` uses it, and so does doctor. The
precedence then lives in one place.

**Rows**, appended by the doctor function that already adds the Rust rows:

| Tool | Row appears when | Looked for at |
|---|---|---|
| eslint | the `js` stack is detected (the gate's `_is_applicable` rule) | `<root>/node_modules/.bin/eslint[.cmd]` (`eslint._eslint_bin`) |
| tsc | the typecheck owner says tsc | `<root>/node_modules/.bin/tsc[.cmd]` (`typecheck._tsc_bin`) |
| mypy | the typecheck owner says mypy | `toolpath.resolve("mypy")`, which is what `run_subprocess` uses |

- Found: `OK <tool> <path>`. The path is the claim; no version probe.
- Not found: a non-OK row naming the path the gate looks at, what is not
  being checked, the detected package manager for the JS tools, and the
  gate consequence: shown as a degraded tool at pre-push, and refused by a
  `--strict` gate.
- A repo with both `tsconfig.json` and a mypy config also gets a WARN row
  for mypy: it is configured and does not run, because tsc takes the
  typecheck slot.

**Rust rows.** cargo-audit and clippy carry "(non-blocking: ... is not a
BLOCK-tier gate)". They reach the gate through the same MISSING-to-degraded
path, so the same `--strict` refusal is expected. The builder measures it
(a scratch crate, the tool hidden) and corrects the wording if it holds;
if the tools cannot be hidden on this machine, the wording stays and the
gap is recorded in the knowledge base.

## Constraints

- eslint and tsc are run at pre-push only (measured: the pre-commit run of
  the probe selected neither), so the wording says pre-push.
- Test-first. Tests sit beside the existing cargo-audit and clippy doctor
  tests and assert whole rows. The both-configs case and the "no row in a
  Python-only repo without a mypy config" case each get one.
- `tests/unit/test_cli_surface.py` is unaffected (no new option).
- Docs: CHANGELOG, the doctor section of `docs/user-guide.md`, the doctor
  entry of `docs/knowledge-base.md`. ARAMID.md only if it lists doctor's
  rows.

## Left to the builder

- The exact row text, within the claims above.
- The name and return type of the typecheck owner function.
- Whether the new rows go in `probe_deps` or a sibling function.
