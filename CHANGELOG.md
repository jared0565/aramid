# Changelog

All notable changes to aramid are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[semantic](https://semver.org/spec/v2.0.0.html).

`src/aramid/__init__.py`'s `__version__` is the single source of truth —
`pyproject.toml` derives its version from it, and the release workflow refuses
to publish a tag that disagrees with it.

## [Unreleased]

## [0.1.0] — unreleased

First packaged release. Everything below already existed in the repository;
what is new is that it can be installed without a source checkout.

### Added

- **Deterministic gate** at `pre-commit` and `pre-push`, running industry
  standard tools — gitleaks (secrets), semgrep (SAST, with a vendored OWASP
  ruleset), ruff (lint + the bandit-derived `S` family), pip-audit /
  cargo-audit (dependency CVEs), eslint, tsc/mypy, clippy, and the project's
  own test suite. The gate makes **zero LLM calls**.
- **Findings ledger** — an append-only event store with fingerprint-stable
  finding ids, a ratchet baseline, and scope-aware resolution.
- **Budgeted red team** — a scheduled drain that spends LLM quota only on the
  small, novel, high-risk slice of commits, with a spend cap and a
  cheap→mid→frontier model ladder.
- **TDD-enforcement gates** — code-without-test detection, surviving-mutant
  findings, mutation-score regression, and red-first proof, each behind its
  own arming flag.
- **Release plumbing** — tag-triggered workflow that builds the wheel, refuses
  a tag that disagrees with `__version__`, asserts the vendored ruleset is
  packaged, smoke-tests the built wheel in a clean virtualenv, and attaches
  the artifacts to a GitHub Release.

### Known limitations

Stated plainly because each one changes how you should deploy this:

- **The findings ledger is machine-local.** `aramid init` adds `.aramid/` to
  `.gitignore`, so triage decisions (`mark-not-a-secret`, overrides, the
  ratchet baseline) do not travel between developers or reach CI. Every clone
  re-reports findings another developer already judged. There is currently no
  tracked, per-finding suppression format; the tracked alternatives are
  `ignore_paths` in `aramid.toml` or a tool's own allowlist.
- **The scheduled drain is Windows-only.** `aramid schedule` registers a
  Windows Task Scheduler job; there is no cron or launchd equivalent. The gate
  itself is cross-platform and is tested on Linux, macOS and Windows.
- **Analyzer versions are not pinned.** ruff and semgrep are declared with
  lower bounds only, so two installs a month apart can resolve different
  versions, report different findings, and reach different verdicts. An
  upstream default change has already caused this once — see the
  `[tool.ruff.lint] select` pin in `pyproject.toml`.
- **`Gate.ALL` is unreachable from the CLI.** `--all` widens the *file* set,
  not the *runner* set; `--gate` accepts only `pre-commit` and `pre-push`.
- **semgrep ships unarmed.** A WARN-only bake is in effect per repo until
  `aramid arm` is run, so semgrep findings report but do not block. The same
  applies to the LLM, mutation, mutation-score and red-proof gates.
- **PyPI publishing is not set up.** Install from a GitHub Release artifact or
  from git; `pip install aramid` does not work.

[Unreleased]: https://github.com/jared0565/aramid/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jared0565/aramid/releases/tag/v0.1.0
