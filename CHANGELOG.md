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

### Fixed

- **Git hook shims pass `python -P`, so a repo-local `aramid.py` cannot hijack
  the gate.** `python -m aramid` puts the working directory on `sys.path[0]`
  and git runs hooks from the top of the tree, so an `aramid.py` file — or an
  `aramid/` directory — at a repo root beat the installed package. Measured:
  a package-shaped shadow produced a **full hijack exiting 0**, meaning the
  pre-commit gate was skipped and the commit proceeded with nothing scanned,
  indistinguishable from a clean run. All three generators are fixed
  (`render_shim`, `render_template_shim`, `render_triage_shim`), on both the
  `$INTERP` and `py -3` arms.

  **Already-installed hooks do not update themselves.** Re-run
  `aramid hooks install` (and `aramid hooks template install` for the global
  git template) to regenerate them; nothing gates this on a version bump.
- **Third-party GitHub Actions are pinned to commit SHAs.** `actions/checkout`,
  `actions/setup-python` and `gacts/gitleaks` were referenced by mutable major
  tag. CI is part of aramid's enforcement boundary — the dogfood steps are what
  prove the gate works — so a moved tag upstream would change what runs, and
  therefore what gets reported, with no diff in this repository. Readable
  versions stay in trailing comments, and `tests/unit/test_workflow_pinning.py`
  fails if either half regresses.
- **The release workflow names its artifacts instead of globbing `dist/*`**,
  so a stray file in the build directory cannot be published under a release.
  A missing expected artifact now fails the step rather than releasing a subset.
- **The fail-safe handlers say when they swallow something.** Eleven
  `except Exception: continue` guards across the gate and the drain skipped
  bad input silently. Skipping is correct — a malformed ledger record must
  never crash a gate, and a provider whose probe raises must never crash the
  drain — but a silent skip made a corrupt ledger produce output identical to
  a clean run. The highest-stakes one is `llm_gate_findings`, where a skipped
  record is a confirmed critical that never reaches the BLOCK gate. Behaviour
  is unchanged; each site now reports via the new `aramid.diagnostics`, one
  line per loop rather than one per record, and nothing at all on a clean run.
  Named individually where the identity is the message: which provider failed
  to load, which file was dropped from a review packet.
- **`aramid schedule install` can no longer destroy a crontab.** `crontab -l`
  exits non-zero both for a user who has no crontab and for a user whose
  crontab could not be read; the POSIX backend treated every non-zero exit as
  "empty" and then wrote that result back, so a transient read failure
  replaced every unrelated job — backups, certbot, monitoring — with aramid's
  single line. Only the literal "no crontab for" case now reads as empty;
  anything else aborts the install without writing.
- **The scheduled drain survives an interpreter path containing spaces.** cron
  hands the command to a shell, so an unquoted `/opt/my venv/bin/python3` ran
  `/opt/my` and the drain silently never fired.
- **A finding whose path escapes the repository is no longer auto-resolved.**
  `root / file` does not keep you inside `root` — an absolute path discards
  `root` outright and `..` is never normalized away. The check then landed on
  an unrelated path that did not exist, reported the file as departed, and
  silently resolved the finding. Escapes are now treated as "not departed",
  which leaves the finding open.
- **`aramid schedule` works on Linux and macOS**, not only Windows. It was
  Windows-only, so the scheduled red-team drain could not run on the platforms
  most servers use. POSIX installs a single marked crontab line; every unmarked
  line in your crontab is preserved, and re-installing replaces aramid's entry
  rather than adding another. `aramid status` learned to probe the right
  backend, so a successful cron install no longer reports "unknown".
- **The full-history secrets scan honours `.aramid-suppressions.toml`.** It
  applied only the path-level ignore filter, so the one reviewable, committed
  way to record "this history hit is a test fixture" was bypassed on exactly
  the path that produces those findings — leaving the machine-local
  `ledger mark-not-a-secret` as the only remedy. The suppressed count is
  printed, never silently dropped.
- **Analyzer dependencies carry upper bounds.** ruff 0.16.1 widened its default
  rule set and turned all seven CI legs red against a commit that was clean on
  0.15.18. Bounds are set where each project signals breaking change.

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
  `.gitignore`, so `aramid override` decisions and the ratchet baseline do not
  travel between developers or reach CI. The shareable path is a committed
  `.aramid-suppressions.toml`, which BLOCK-tier suppression already requires
  and which the full-history secrets scan now honours — but WARN-tier
  overrides remain local to whoever ran them.
- **Analyzer version bounds reduce drift, they do not eliminate it.** ruff,
  semgrep and pip-audit now carry upper bounds, so a breaking upstream release
  cannot silently change your verdicts. A patch release still can. If you need
  byte-identical results across machines, pin them yourself in a lockfile.
- **`Gate.ALL` is unreachable from the CLI.** `--all` widens the *file* set,
  not the *runner* set; `--gate` accepts only `pre-commit` and `pre-push`.
- **semgrep ships unarmed.** A WARN-only bake is in effect per repo until
  `aramid arm` is run, so semgrep findings report but do not block. The same
  applies to the LLM, mutation, mutation-score and red-proof gates.
- **PyPI publishing is not set up.** Install from a GitHub Release artifact or
  from git; `pip install aramid` does not work.

[Unreleased]: https://github.com/jared0565/aramid/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jared0565/aramid/releases/tag/v0.1.0
