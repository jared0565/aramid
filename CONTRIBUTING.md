# Contributing to aramid

Thank you for working on aramid. This document is the shortest path from a
fresh clone to a change that CI and aramid's own gate will accept. For how a
release is cut, see `RELEASING.md`; for how to report a vulnerability, see
`SECURITY.md`; for who maintains the project and what a successor needs, see
`MAINTAINERS.md`.

## Development setup

```bash
git clone https://github.com/jared0565/aramid
cd aramid
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
aramid doctor                                      # gitleaks must be on PATH
```

`aramid doctor` probes every analyzer (gitleaks, semgrep, ruff, pip-audit,
eslint, mypy) and offers a repair for anything missing. The Python analyzers
arrive as dependencies; gitleaks is a binary you install yourself (the CI
workflow pins 8.28.0).

Requires Python 3.11 or newer. CI runs 3.11 through 3.14 on Windows, Ubuntu
and macOS; anything platform-specific needs to work on all three or skip
cleanly with a stated reason.

## Running the tests

The suite has three tiers under `tests/`:

| Tier | Command | What it covers |
| --- | --- | --- |
| unit | `python -m pytest -q tests/unit` | pure logic, one module at a time |
| integration | `python -m pytest -q tests/integration` | commands against a real ledger and config |
| e2e | `python -m pytest -q tests/e2e` | real `git` hooks, real subprocesses, the built wheel |

The full suite (`python -m pytest -q`) takes 20 to 30 minutes on a laptop and
about as long on the Windows CI legs; run the tier you touched while
iterating and the whole thing before you push. When you read a run, check that
`collected` equals `passed + skipped + failed` with no unexplained deselects: a
slow suite that quietly stopped testing something looks exactly like one that
passed.

`pyproject.toml` sets `pythonpath = ["src"]`, so pytest tests the working tree
even if a released aramid is installed elsewhere on the machine. If a test
spawns a subprocess, that setting does not reach the child; pin `PYTHONPATH`
or pass the interpreter explicitly, as the existing subprocess tests do.

## The gate you are committing under

This repository is gated by aramid itself. Read `ARAMID.md` once.

- Before committing: `aramid check --staged`. Read any findings with
  `aramid ledger filter --status open`.
- **Never pass `--no-verify` (or `-n`) to `git commit`, or `--no-verify` to
  `git push`.** It disables secret scanning along with everything else, and
  the agent-side rejector denies it outright once armed.
- To suppress a WARN finding, use `aramid override <id> --reason "..."`. The
  override is logged in the ledger. Never edit a finding away by hand.
- The pre-push gate runs the test suite, so a push takes as long as the suite.
  Do not edit the working tree while a push is in flight; the gate is testing
  the live tree, and a mid-run edit manufactures a failure that will block the
  next push too.

Lint is ruff with the rule set pinned in `pyproject.toml`; the gate also arms
the bandit-derived `S` family against `src/`. A justified `# noqa: S6xx` with
a one-line reason on the line above is the accepted form for a subprocess call
that genuinely must exist. Tests are exempted from the `S` rules they trip by
design (asserts, fake secret fixtures, spawning `git`).

## Writing changes

- **Tests first.** Write the failing test, watch it fail for the reason you
  expect, then make it pass. A test that passed on its first run has proven
  nothing about the change.
- **Make the guard non-vacuous.** When a test enumerates files, runs, or
  findings, assert the input set is non-empty and contains the thing under
  test before asserting anything about it. Several tests in this repo exist
  because an earlier guard was green against an empty list.
- **Name the behaviour**, not the function:
  `test_a_red_tag_run_beside_a_green_main_run_on_the_same_sha_passes`, not
  `test_evaluate`.
- **Explain the why in the code.** Comments in this repository record the
  incident or measurement that motivated a decision, so the next reader can
  tell a deliberate choice from an accident. Follow that style; do not strip
  it.
- **Cross-file questions go through the code graph first.** `GRAPHITE.md`
  explains `python -m graphite context <file>` and `query "callers X"`.
  Grep is for literal text.
- **Every behaviour change gets a `CHANGELOG.md` entry** under `[Unreleased]`,
  in Keep a Changelog form. Do not bump `__version__` or add a version heading
  in a contribution; that is the release step.

## Commit messages

`type(scope): summary` on the first line (`fix`, `feat`, `test`, `chore`,
`docs`, `release`), then a body that says what was wrong, what changed, and
what evidence you have. Look at `git log` for the house style. If your shell
is bash, write the message with `git commit -F <file>` rather than `-m` when
it contains backticks; bash executes backticks inside double quotes and
silently strips the words.

## Pull requests

Work on a branch or fork and open a pull request against `main`. The seven-leg
CI matrix runs on every push and must be green; the workflow also dogfoods
aramid's gate against the repository at both tiers in `--strict` mode, so a
new finding in `src/` fails the build. A maintainer reviews and merges; there
is no CLA.

## Releases

Maintainers only. `RELEASING.md` is the procedure; the release workflow
enforces the parts that can be enforced (tag matches `__version__`, a green
CI run on the tagged commit, artifact gates, TestPyPI rehearsal, a required
reviewer before PyPI).
