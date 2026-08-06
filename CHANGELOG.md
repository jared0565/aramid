# Changelog

All notable changes to aramid are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[semantic](https://semver.org/spec/v2.0.0.html).

`src/aramid/__init__.py`'s `__version__` is the single source of truth —
`pyproject.toml` derives its version from it, and the release workflow refuses
to publish a tag that disagrees with it.

## [Unreleased]

### Fixed

- **An ignored file no longer manufactures a finding, and could no longer
  block a push.** eslint reports an explicitly-passed ignored file as a
  warning with a **null** `ruleId` ("File ignored because of a matching
  ignore pattern"), and the adapter mapped `ruleId or "eslint-parse-error"` —
  so every such file produced a WARN finding named `eslint-parse-error`,
  pointing at a file eslint had deliberately declined to lint. It fingerprints
  and enters the ledger like any real finding, so on pre-push it is a **new
  id**, and new ids are what the ratchet escalates to BLOCK: adding a path to
  `ignores` and touching a file under it could fail the push, citing a parse
  error in a file that parses fine.

  File-level notices are now told apart from findings by **shape** — no rule
  id, not fatal, no position — never by message text. A genuine parse error
  also carries a null `ruleId`; what distinguishes it is `fatal: true` plus a
  line and column, and it is still reported. Shape is also what keeps this
  working across eslint majors, which is why the adapter does not simply pass
  eslint 9's `--no-warn-ignored`: that option does not exist in eslint 8,
  where an unrecognised flag exits 2 and takes the runner to CRASHED.
- **`eslint` reports what it examined, so `ignores` can no longer forge a
  fix.** This is the same hole 0.1.0 closed for ruff, via eslint's own
  equivalent of `--force-exclude`: eslint exits cleanly having never opened an
  ignored file, so resolution recorded every open finding in it as **`fixed`**
  in the append-only ledger. Files eslint declined to lint, and files it could
  not parse, are both excluded from the vouched set — a file that fails to
  parse was analysed too, so leaving it in would mean a syntax error silently
  resolved every other open finding in that file.

  Unlike ruff this costs **no extra subprocess**: eslint's JSON formatter
  already emits one entry per file it processed, clean ones included. (ruff's
  JSON names only files *with* findings, which is why that adapter has to run
  `--show-files` separately.) The no-JS-files no-op now vouches for nothing
  rather than falling back to the gate's whole file set — narrow but real, as
  a repo whose eslint config lints `.vue`/`.svelte`/`.astro` has those paths
  in gate scope while the adapter's own suffix list does not name them.
- **`semgrep` reports what it examined.** A file semgrep cannot parse is
  listed under `paths.scanned`, produces no findings, and semgrep still exits
  **0** — so introducing a syntax error recorded every open semgrep finding in
  that file as `fixed`. Those files are now subtracted from the vouched set.
  (`PartialParsing` means semgrep parsed *part* of the file; partial analysis
  is still not analysis it can be held to.) Free, like eslint's: `paths.scanned`
  is already in the output.

  **Two mechanisms were measured and are NOT holes**, contrary to what the
  0.1.0 scope note implied: `.semgrepignore` is bypassed for explicitly-passed
  paths (an ignored file was scanned and did report a finding), and so is the
  default 1MB `--max-target-bytes` limit (a 1,224,024-byte file was scanned and
  did report a finding). What `paths.scanned` *does* legitimately narrow is
  file types — the adapter passes `ctx.files` unfiltered, with no suffix screen
  of its own, so `.md`, `.bin` and images reach semgrep and never come back.

  On a semgrep old enough not to emit `paths`, the adapter reports "cannot
  vouch" and falls back rather than blocking every semgrep resolution forever.
- **`clippy` reports what it examined, so a file that stops being compiled no
  longer resolves its own findings.** Delete a `mod foo;` and leave `foo.rs`
  in the tree and cargo never compiles it again — clippy exits 0 having never
  looked at it, and every open finding in it was recorded `fixed`.

  The JSON stream cannot answer this on its own: `compiler-artifact` records
  name only crate roots (`target.src_path`), so modules reached through `mod`
  never appear. The dep-info file cargo writes beside each artifact does, and
  is exact. Two measured properties shape how they are used — a fully cached
  re-run still emits every artifact record, so the artifact set is always
  available; but cached runs do **not** rewrite depfiles, so freshness cannot
  be established by timestamp. Since depfiles are never garbage-collected, a
  directory accumulates one per feature/profile combination ever built, and
  they are matched **structurally** instead: a depfile counts only if one of
  its own target lines is an artifact filename *this run* reported.

  Dependency paths resolve against the **package** root, not the repo root —
  rustc runs with cwd set to the package — so workspace members are handled
  correctly rather than quietly vouching for paths one directory level off.

  **Cost, measured:** 464 ms against a synthetic `deps/` holding 1001
  depfiles (the scale of a crate with a large dependency tree), where all
  1000 unrelated ones were rejected. Negligible against clippy's 240 s budget,
  though it is a visible fraction of a warm cached run.

### Notes

- **Where `examined` reporting stands.** Four of the file-list runners now
  report it — `ruff` (0.1.0), `eslint`, `semgrep` and `clippy` — which closes
  every hole named in the 0.1.0 scope paragraph.

  **`typecheck` remains open, and not because it cannot.** `tsc --listFiles`
  emits exactly the needed list (verified on TypeScript 7.0.2: it prints each
  compilation input alongside the diagnostics), the adapter simply does not
  pass it today. tsc is also the runner where this matters most, because it
  follows imports and so analyses far more than the files handed to it. The
  mypy arm was not assessed — mypy is not installed on this machine, so no
  claim is made about it either way.

  `gitleaks`, `deps` and `tests` are a different shape: they scan history,
  manifests, and a pass/fail suite rather than a file set.

## [0.1.0] — 2026-08-06

First packaged release. Everything below already existed in the repository;
what is new is that it can be installed without a source checkout.

### Fixed

- **A runner can no longer resolve findings in files it never examined.**
  Resolution required only that the tool exited `OK` and that the file was in
  the *gate's* file set — but every selective runner examines a subset of
  that. `ruff` passes `--force-exclude`, so it honours the repo's own
  `exclude` config even for explicitly-passed paths and still exits 0 with
  zero findings. Adding a path to `[tool.ruff] exclude` therefore recorded
  every open finding in it as **`fixed`** — a false repair written into an
  append-only audit trail, indistinguishable from a real one. Runners now
  report what they actually analyzed (`RunnerResult.examined`), and
  resolution intersects against that.

  **Scope, stated plainly:** the mechanism is general but only `ruff` reports
  today, via `ruff check --show-files` (measured cost: 0.19s on a 197-file
  repo). Every other runner reports `None`, which falls back to the previous
  behaviour — so the equivalent hole via `.eslintignore` or clippy exclusions
  is still open. `None` means "cannot vouch" and is deliberately *not* the
  same as the empty set, which is a positive claim that nothing was examined.
- **Git hook shims pass `python -P`, so a repo-local `aramid.py` cannot hijack
  the gate.** `python -m aramid` puts the working directory on `sys.path[0]`
  and git runs hooks from the top of the tree, so an `aramid.py` file — or an
  `aramid/` directory — at a repo root beat the installed package. Measured:
  a package-shaped shadow produced a **full hijack exiting 0**, meaning the
  pre-commit gate was skipped and the commit proceeded with nothing scanned,
  indistinguishable from a clean run. All three generators are fixed
  (`render_shim`, `render_template_shim`, `render_triage_shim`), on both the
  `$INTERP` and `py -3` arms.

  **Already-installed hooks do not update themselves**, and two separate
  commands write them: `aramid hooks install` regenerates the global git
  template (`init.templateDir`, which seeds new clones), and `aramid init`
  regenerates a repo's own `.githooks/`. Both are needed, and nothing gates
  either on a version bump.
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
