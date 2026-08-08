# Changelog

All notable changes to aramid are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[semantic](https://semver.org/spec/v2.0.0.html).

`src/aramid/__init__.py`'s `__version__` is the single source of truth —
`pyproject.toml` derives its version from it, and the release workflow refuses
to publish a tag that disagrees with it.

## [Unreleased]

### Fixed

- **`tests/unit/test_toolpath.py` no longer writes and executes four fresh
  interpreter copies, which had twice made aramid's own pre-push gate
  unusable.** `_fake_tool` did `shutil.copy(sys.executable, …)` into each
  test's `tmp_path` and the tests then *executed* those brand-new ~104 KB
  binaries. On Windows that is the shape most likely to draw a real-time scan
  of an unknown executable, and this file has twice been measured taking
  minutes instead of seconds — 2026-08-05, and again 2026-08-08 where a
  **single test exceeded 600s**, against ~2.5s on a quiet machine.

  Not cosmetic: `[tests].command` runs `pytest -q tests/unit` under a 600s
  budget, so when this file stalls the BLOCK-tier test gate times out,
  degrades, and **blocks every push** on aramid's own repo.

  Now one real copy per session (a `session`-scoped fixture), hard-linked into
  each test's tools dir thereafter — so materialising a fake tool writes no new
  executable bytes at all. The source is created under `tmp_path_factory`'s
  root rather than as a direct copy of the interpreter, deliberately: that puts
  it on the **same volume** as every `tmp_path`. On CI's Windows runner
  `sys.executable` is on `C:` (hostedtoolcache) while the temp root is on `D:`,
  so linking straight from the interpreter would raise `EXDEV` and fall back to
  copying on the one platform that needs this most. `shutil.copy` remains as a
  fallback for filesystems without hard links.

  Verified: `os.link` measured taking `st_nlink` 1 → 2 with the link executing
  cleanly (`rc 0`, `Python 3.14.5`); the file runs 7 passed in 1.30s; and the
  three tests that pin the managed-dir fallback still fail when
  `toolpath.resolve` is mutated to drop it.

  A new test guards the fix itself, because nothing else can: every existing
  assertion passes just as well with four copies, so a revert would be
  invisible. It asserts the deterministic properties — the source is a real
  runnable executable, and materialising a tool adds a hard link rather than
  new content — rather than a wall-clock threshold, which is precisely what
  made the hung-runner guard below flaky.

  **Honestly graded:** the stall is intermittent and concurrent foreign
  `pytest tests -q` runs were observed in this working tree while measuring, so
  this is not proof the stall is eliminated — it removes three of the four
  copy-and-execute cycles, which is the exposure, and is verifiable
  independently of machine mood.

- **The `windows-latest / py3.14` CI flake: a wall-clock assertion that CPU
  contention could close, not a product defect.**
  `test_hung_runner_does_not_block_past_gate_budget` asserted `elapsed < 1.0`
  against a `time.sleep(2.0)` and a 0.2s budget. `run_gate`'s own overhead on
  that path is not free — a real `git` spawn in `_discover_files`,
  `_write_logs`' filesystem writes, salt creation, ledger IO — so the 0.8s
  window between "returned at budget" and "joined the hung worker" was doing
  the discriminating.

  | | idle | 2× CPU oversubscription |
  |---|---|---|
  | `run_gate` overhead on this path | ~0.4s | **2.4 – 3.0s** |
  | failures in 10 runs | 0/6 | **9/10** (elapsed 1.63 – 4.11s) |

  **The production code is innocent, and that was measured rather than
  assumed.** A hang-duration sweep held everything else fixed and varied only
  the hang: elapsed stayed ~2.4s whether the runner hung for 0.5s, 2.0s or
  6.0s. Flat in the hang is exactly what *abandoned, not joined* looks like; a
  regression would have tracked it.

  Why this test, on this leg: CI step 8 runs `pytest -q tests/unit` **inside**
  the pre-push gate, concurrently with gitleaks, semgrep, ruff and pip-audit
  on a small Windows runner, while step 6 runs the same tests with the box to
  itself. Step 6 has never failed; step 8 did. Same commit, same runner, eight
  minutes apart — a strict subset failing while the superset passed.

  The fix is not a bigger sleep. A `threading.Event`, released the instant the
  measurement is taken, replaces the 0.8s judgement call with a gap nothing
  can bridge: ~0.4 – 3s correct against a full 30s wait if `run_gate` ever
  joins again. Verified both ways — the guard still turns red under a mutated
  `shutdown(wait=True)` (`assert 30.12 < 10.0`), and the same 24-hog load that
  produced 9/10 failures now produces none. Releasing on **every** path
  (`try/finally`) is load-bearing: `shutdown(cancel_futures=True)` does not
  cancel an already-running future, so an unreleased worker would stall
  interpreter exit for the full timeout.

  Honestly graded: the `.aramid/logs` from the original run are gone and the
  log-dump step postdates it, so this is strong circumstantial evidence, not a
  confirmed identification of that specific failure. The dump step now names
  the failing test on any recurrence, which will confirm or refute it.

  Scope checked, not assumed: the other absolute-time assertions in
  `tests/unit` were inventoried. `test_runner_base.py` allows `< 10` against a
  5s sleep, and `test_shared_budget_caps_the_second_suites_timeout` — despite
  a 50ms `pytest.approx` margin — survived 10/10 under the same load, so both
  were left alone rather than pre-emptively widened.

- **A repo whose test suite aramid cannot detect is now told so, instead of
  reading as covered.** `tests` is BLOCK-tier, but `detect_tests` recognises
  exactly two kinds — a pytest-shaped file, or an npm `test` script. `cargo
  test` and `go test` are neither. Measured on synthetic Rust and Go repos,
  each carrying a real working suite:

  | | before |
  |---|---|
  | `check --gate pre-push --all --strict` | **exit 0**, zero findings, nothing degraded |
  | runners that actually ran (Rust) | gitleaks, semgrep, clippy, cargo-audit — **no tests** |
  | runners that actually ran (Go) | gitleaks, semgrep — **no tests** |
  | stderr (Go) | **nothing at all** |
  | `doctor` | `OK tests (no test suite detected)`, then `all BLOCK-tier tools present.` |

  `--strict` does not catch it, because strict remaps *degraded* and *engine
  error* — and nothing here is degraded. It is reported as a clean run. That
  is the failure class this engine exists to prevent: a pass indistinguishable
  from a tier that never executed.

  The old notice was gated behind a Python-flavoured marker check (`tests/`,
  `pytest.ini`, `tox.ini`), so **Rust tripped it only by convention** — and
  got a message written entirely in pytest vocabulary that never mentions
  cargo — while **Go, whose `main_test.go` sits beside the source, got total
  silence**. The notice now fires whenever the gate has nothing to run, names
  the detected stack, names the two kinds that *are* recognised, and names
  both the remedy (`[tests].command`) and the opt-out (`[tests].enabled =
  false`). `doctor` grew a third state: the row renders `WARN`, not `OK`, and
  the summary no longer ends on the bare sentence `all BLOCK-tier tools
  present.`

  **Report, do not block** — the same rule `probe_deps` already applies to
  cargo-audit. Exit codes are unchanged and pinned by a test: a docs or config
  repo legitimately has no suite, and inventing a failure the gate would never
  produce would break `doctor` in exactly the repos most likely to run it
  first. A repo that genuinely has no tests declares it with `[tests].enabled
  = false`, which silences both surfaces.

  This does **not** add `cargo test` / `go test` support; it makes their
  absence impossible to mistake for a pass.
- **A semgrep run that produced no report no longer resolves every open
  semgrep finding.** `json_or_crashed(..., empty="{}")` substitutes `{}` for
  empty stdout while keeping `ToolState.OK`. `{}` has no `paths`, so
  `_examined` took its missing-`paths` fallback and returned `None` — "cannot
  vouch" — which keeps semgrep out of `pipeline._examined_by_tool` and lets
  `ledger.record_run` credit it with `scope_files`, the gate's **entire** file
  set. Every open semgrep finding was then written **`fixed`** into an
  append-only ledger by a run that analysed nothing it could name: a false
  repair, the exact defect class the `examined` work exists to close, for the
  one tool whose verdicts newly stop a push since semgrep was armed. eslint,
  clippy and tsc all return the empty set for their equivalent
  no-usable-output case; semgrep was the lone hold-out.

  The missing-`paths` fallback is still there and still reachable — it exists
  for a semgrep old enough not to emit the key, and blocking those users'
  resolution forever would be the worse answer. **The two cases needed no
  policy choice to separate:** an old semgrep still emits a real JSON report,
  it just omits `paths`, whereas `{}` is only ever aramid's own placeholder
  for no output at all. `run()` screens on the pre-normalisation `raw`, so no
  version probe is involved. Both directions are pinned: deleting the screen
  turns the new test red, and making it unconditional turns the old-semgrep
  fallback test red.

  Found by aramid's own `llm-review` against its own repository.
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

- **The scheduled drain survives an interpreter path containing `%`, and
  refuses one containing a line break.** 0.1.0 quoted the path for the shell;
  that addressed the lower of the two layers that parse a crontab line.
  crontab(5) says the command runs "up to a newline or a `%` character": an
  unescaped `%` becomes a newline, and everything after the first one is fed
  to the command as **stdin**. Quotes give no protection, because cron parses
  the line before any shell sees it — so `/opt/py%3/bin/python` installed a
  **truncated** command whose severed tail became stdin, and the drain never
  ran. `%` is now escaped as `\%`, after quoting, since cron unescapes first
  and the shell parses what is left.

  A line break cannot be escaped at any layer — a crontab line *is* the unit
  of the file — so the install is refused instead. Rendering it anyway would
  append a second, **unmarked** line that `strip_aramid_lines` could never
  remove, because the marker goes with whichever half it lands on. Same call
  `_read_crontab` already makes: an aborted install is a message you can act
  on, a corrupted crontab is not.

  Reachability is limited — the only call site passes `Path(sys.executable)` —
  so this is hardening rather than a reported failure. Ordinary paths render
  byte-identically, so already-installed entries still match a fresh render.

- **A blocking gate now says WHY, not just THAT.** When the BLOCK-tier
  `tests` runner failed, aramid reported `python exited 1: test suite failed`
  and wrote an **empty** log file — because `_write_logs` persisted only
  `stderr`, and a failing pytest returns `state=OK, returncode=1` with **zero**
  bytes of stderr and its entire report, the only thing naming the failing
  test, on stdout. Nothing aramid offered could tell you which test failed.

  That is not theoretical: a `windows-latest / py3.14` CI leg failed at exactly
  this step, passed on re-run with no code change, and the flake could not be
  identified from any artifact — the string that would have named it was
  collected, held in `RunnerResult.raw`, and discarded.

  stdout is now persisted alongside stderr, scrubbed through the same redactor
  (an assertion diff is precisely where a real secret surfaces, and this file
  goes to disk). Written **only** when the runner degraded or exited non-zero:
  a clean ruff or semgrep puts its whole JSON report on stdout, already
  surfaced as findings, and copying that on every green run would grow
  `.aramid/logs` for nothing — there is no rotation. Capped at 64 KB keeping
  the **tail**, since pytest prints its summary last. With no stdout to add,
  the file is byte-identical to its previous format.

- **`tsc` reports what it examined, closing the last of the resolution
  holes.** This runner type-checks the **project**, not `ctx.files`, so a
  source file left out of tsconfig's `include`/`files` is never checked at
  all — tsc exits 0, says nothing about it, and every open finding in it was
  recorded `fixed`. Narrowing `include` forged repairs, exactly as adding a
  `[tool.ruff] exclude` entry did.

  The adapter now passes `--listFiles`. Measured on TypeScript 7.0.2, that is
  **free in time** — 0.93 s against 0.98 s for a bare `--noEmit`, since tsc
  already reads every one of those files — but not free in *output*: with only
  `typescript` and `@types/node` installed it emitted 65 path lines to 1
  diagnostic, 63 of them lib/`node_modules` `.d.ts`, and a real application
  project emits thousands. Rather than accept that in the logs, or pay a
  second `--listFilesOnly` parse of the whole program, the path lines are
  **consumed** into `examined`; `raw` still holds exactly the diagnostics it
  held before.

  Paths outside the repository are dropped — tsc lists its own bundled
  `lib.es*.d.ts` from wherever TypeScript is installed, real inputs that
  cannot hold a repo finding. Unrecognised output is kept, so a message like
  `error TS5083: Cannot read file …` is never silently eaten.

  The **mypy** arm still reports "cannot vouch": it has no `--listFiles`
  equivalent, and reporting the empty set would block every mypy resolution
  outright rather than fall back.

### Added

- **PyPI publishing is wired up, and the package metadata that makes it worth
  doing.** `[project]` carried name, version, `requires-python` and
  dependencies — and nothing else. `twine check` said `long_description
  missing`: publishing would have produced a package page with **no
  description at all**, and nothing in the repo would have objected. The wheel
  was verified to contain its data files; what it said *about itself* was never
  checked. Now filled in from README.md and LICENSE rather than written fresh,
  so page and repo cannot drift: `description`, `readme`, SPDX `license`,
  `authors` (name only — putting a personal address on a public page is the
  maintainer's call, not a default), `keywords`, 11 classifiers, and
  `[project.urls]`.

  Three things that surfaced only by building and looking, not by reasoning:

  - **`Typing :: Typed` would have been a false claim** — there is no
    `src/aramid/py.typed`. Dropped rather than papered over by adding the
    marker, which would assert a level of type coverage nothing here verifies.
  - **Two README links were repo-relative** (`docs/user-guide.md`,
    `docs/knowledge-base.md`). Correct on GitHub, 404 on PyPI, which serves the
    README detached from the repository. Now absolute.
  - **PEP 639 makes a `License ::` classifier an error, not a warning**
    alongside an SPDX `license` expression — it broke the build outright, and
    the syntax also raises the `setuptools` floor to 77.

  `release.yml` gains `twine check`, a **clean-venv sdist smoke test**, and a
  separate `publish-pypi` job. The sdist was previously built and published but
  never installed: the wheel and the sdist are produced by different code
  paths, and any consumer whose platform or policy forces a source build gets
  that artifact. Publishing is its own job — gated on the `pypi` environment,
  `needs: release` so it cannot run unless every gate passed, and using
  **Trusted Publishing** (OIDC), so there is no API token or repository secret.
  `skip-existing: false` deliberately: a silent no-op on a release tag is the
  "green for a reason indistinguishable from success" shape this repo exists to
  prevent.

  `tests/unit/test_packaging_metadata.py` pins all of it — page-would-be-blank,
  relative links, the PEP 639 conflict, the unbacked `Typing` claim and the
  backend floor — each verified to fail against a deliberately reintroduced
  defect.

  **Not done, deliberately:** no version bump, no tag, no upload. Publishing
  needs a one-time *pending publisher* on pypi.org (and a separate one on
  test.pypi.org), which is an account-level action; and cutting a release is a
  "is this ready to ship?" judgement. Both are documented in `RELEASING.md`.
- **`[hooks].pre_push_match_ci` — make the pre-push shim run what CI runs.**
  The generated shim calls `aramid check --gate pre-push` with no scope flag,
  which `cli._check_mode` resolves to `range`: changed files only. CI runs
  `--all --strict`. So a finding in a file the push did not touch is invisible
  locally and caught on the seven-leg matrix — the main source of "green on
  push, red in CI" here. With the option on, the shim emits the argv CI step 8
  uses verbatim, and stops mapping exit 2 to 0.

  **Off by default, and that is load-bearing rather than timidity.** Moving a
  repo from `range` to `--all` surfaces every previously-unscanned finding at
  once; the ledger has never seen those ids, so the ratchet reads them as
  **new** and escalates them to BLOCK. The next push would be blocked by
  findings the developer did not introduce. Pair it with `aramid rebaseline`.
  The shim is generated, so the setting only takes effect on `aramid init`.
  `_match_ci` fails **closed**: an unparseable config yields the narrow shim,
  never the wider one.

  Scoped to pre-push. The pre-commit shim still maps both 2 and 3 to 0 — it is
  the fast local filter, and CI parity is a claim about the pre-push gate.
  `render_template_shim` (git's global `init.templateDir`) is deliberately
  untouched: it is written once, machine-wide, with no repo config in view.

  **A correction to how this gap was previously described.** The `2) exit 0`
  mapping is a much smaller divergence than it appears: `policy.
  escalate_degraded` already returns **1** at pre-push whenever a BLOCK-tier
  tool (gitleaks/semgrep/tests) degrades, so exit 2 only ever meant a
  *WARN*-tier tool degraded. Verified by running the gate against a Go repo
  with no Go toolchain — exit **1 without `--strict`**. The scope difference,
  not the exit-code mapping, is what this option is actually for.

  Enabled for aramid's own repo, where it is safe specifically because this
  ledger has been scanned with `--all` many times already.
- **`cargo test` and `go test` are detected and run.** `tests` is BLOCK-tier,
  but `detect_tests` recognised exactly two kinds — a pytest-shaped file, or
  an npm `test` script — so on a Rust or Go repo the gate exited 0 having
  never run the suite. Rust was the sharper case: `detect_stacks` already
  claims `rust` and clippy + cargo-audit already run there, so a test gate
  that could not run was an inconsistency with a promise already made.
  Measured on the same synthetic repos, after:

  | | runners that completed |
  |---|---|
  | Rust (cargo present) | gitleaks, semgrep, clippy, cargo-audit, **cargo-test** |
  | Go (toolchain absent) | exit **1**, `degraded: ['go-test']`, and `doctor` predicts it: `MISSING tests-go` |

  **Go is added as a test *kind*, not as a linted *stack*.** `detect_stacks`
  still does not claim Go — shipping `go test` without vet/staticcheck and
  calling Go "supported" would be a coverage claim aramid cannot honour.

  **Detection is filename-only, and that is a measured trade-off, not an
  oversight.** Sniffing `.rs` contents for `#[test]`/`#[cfg(test)]` would also
  catch inline unit tests — the commoner Rust layout — but cost **409 ms
  against 4 ms** for the filename walk on 500 files / 2.5 MB, in a function
  that runs on every gate, in a module whose history is a series of
  detector-walk regressions. A crate whose tests are all inline instead falls
  through to the "no suite detected" WARN added above, which names
  `[tests].command`. That is a known, loud gap rather than a silent one, and
  a test pins it so any future content-sniffing is a deliberate change.
  Detection keys on the walk rather than a root-level glob, so Cargo
  workspace members (`crates/<name>/tests/*.rs`) count.

  The runner's hardcoded pytest+npm pair is generalised to N suites sharing
  one deadline, preserving `[review M2]` worst-wins and the `.sub_results`
  order exactly — `tests/unit/test_runner_tests.py` passed **unmodified** as
  the regression gate. Before this, two detected kinds where neither was the
  npm half meant one ran and the other was dropped silently, which is the
  bug class that module exists to prevent. The npm lockfile gate is
  deliberately left scoped to the pytest+npm pairing: widening it would make
  its own notice ("running pytest only this run") false on an npm+cargo repo.

  cargo/go results are restamped to `cargo-test` / `go-test`. `run_subprocess`
  names a result `Path(argv[0]).name` — plain `cargo`, the same name clippy
  and cargo-audit derive before *they* restamp — and `_write_logs` keys its
  filename on `.tool`, so two runners sharing a name silently overwrite one
  another's diagnostic log.
- **A blocking gate in CI now says which test failed.** When the gate blocks,
  its reason lives in `.aramid/logs/<tool>-<run_id>.log` and nowhere else —
  the finding's `evidence` is a verbatim echo of its `message` (`"python
  exited 1: test suite failed"`), and the directory is gitignored and was
  never uploaded. One `windows-latest / py3.14` leg blocked on `tests-failed`
  minutes after the same job had run the whole suite green, and a re-run with
  no code change went green; nothing aramid emitted named the test. A new step
  runs `.github/scripts/dump_aramid_logs.py` under `if: failure()`, which
  fires for any earlier failed step even though the steps between it were
  skipped — so one step placed after both gate tiers covers both.

  It is a committed file rather than an inline `shell: python` block because
  it **always exits 0**: a dump that silently prints nothing is
  indistinguishable from one that correctly found nothing, which is the exact
  failure mode it exists to correct. Every branch is pinned by
  `tests/unit/test_ci_log_dump.py`, which runs it as a subprocess from a temp
  cwd, and five deliberate mutations of the script were each confirmed to turn
  the matching test red before it shipped.

  Three hardenings that measurement, not reasoning, asked for. UTF-8 is forced
  on stdout — a redirected pipe on Windows hands Python the locale encoding,
  and one box-drawing character out of pytest would raise
  `UnicodeEncodeError`, killing the dump on the very leg that flakes. A
  leading `::` in a log body is neutralised, because a body is untrusted text
  and `::add-mask::x` would make GitHub redact `x` from all later output —
  a failing test could suppress the diagnostic this step exists to print.
  Bodies are capped at the 40 newest **and the cap is announced**:
  `.aramid/logs` is never rotated, and a real dev checkout measured 477 files.

  Verified end to end rather than asserted: on a throwaway branch carrying a
  test rigged to fail only under the gate, step 6 stayed green, step 8 went
  red, step 9 was skipped, and the dump ran and printed the failing test's
  name — on all seven matrix legs, including `windows-latest / py3.14`.

  **Why publishing these logs is acceptable is narrower than "they get
  scrubbed",** and aramid's own llm-review was right to press on it.
  `redact.scrub` is fed only the secrets recovered from *successfully parsed*
  findings, so a crashed scanner would be redacted against an empty list; the
  scrub is a second line of defence, not the first. The first is that gitleaks
  writes its report to `--report-path` — a temp file that never reaches
  `.aramid/logs` — and runs without `-v`, so it prints no finding to any
  stream that is persisted. A real body, read back from a CI run, is 250 bytes
  of banner plus `INF … no leaks found`. Both halves are now pinned by a test
  rather than left as a comment asserting them.

### Changed

- **The 20 remaining `S`-family findings in `src/` are triaged and
  documented.** Each was assessed individually and each turned out to be a
  false positive at its call site, so each carries a per-line suppression
  naming the specific reason rather than a blanket per-file ignore:
  - **S603/S607 (14)** — `git config`, `schtasks`, `taskkill`, `cmd /c mklink`
    and the provider-CLI launcher. All fixed argv lists with no shell, taking
    only constants and paths aramid built itself. Resolution by PATH is
    deliberate where the binary's location varies by platform, and `mklink` is
    a `cmd.exe` builtin with no path to name at all.
  - **S310 (4)** — the two LLM provider endpoints. Both URLs are module-level
    **https literals**, never config- or response-derived, so no `file:` or
    custom scheme can reach `urlopen`; and urllib's own redirect handler
    rejects any redirect target outside http/https/ftp (verified on 3.14), so
    a hostile redirect cannot introduce one either.
  - **S311 (2)** — the auto-learn and fuzz seeds, where non-cryptographic is
    the *requirement*: both are seeded deterministically so a choice is
    reproducible in tests and a failing fuzz case is replayable from its
    report.

  Verified none of the suppressions is over-broad — with the `S` family and
  `RUF100` both enabled, ruff reports no unused directive among them.

- **The `src/` lint guard now runs ruff with `--ignore-noqa`, and its
  threat model is corrected.** Suppressing those 20 findings broke the guard
  that proves the `S` family is still armed for shipped code: it worked by
  finding a live `S` finding in a real `src/` file, and after the triage no
  such file existed. Ignoring noqa asks the question that actually matters —
  with documented per-site suppressions set aside, does the family still fire?

  The guard also claimed it would fail "if a blanket ignore is added at the
  top level". **Measured, that is not the threat:** a top-level
  `ignore = ["S603", "S607"]` changes nothing, because the runner passes
  `--extend-select S` on the command line and CLI selection outranks config
  `ignore` — 6 findings before, 6 after. The vector that genuinely disarms is
  `per-file-ignores`; `"src/**" = ["S603", "S607"]` takes the same file to 0.
  The guard is now teeth-checked against that one.

### Notes

- **Where `examined` reporting stands.** Every runner that analyses a file set
  now reports it: `ruff` (0.1.0), `eslint`, `semgrep`, `clippy` and `tsc`.
  That closes every hole named in the 0.1.0 scope paragraph and the one this
  release opened up in its place.

  Two adapters still report "cannot vouch", both for stated reasons rather
  than oversight. **mypy** has no `--listFiles` equivalent — and note this was
  not verified first-hand, because mypy is not installed on this machine, so
  it is a claim about the tool's documented surface only. **gitleaks**,
  **deps** and **tests** are a different shape entirely: they scan history,
  manifests, and a pass/fail suite rather than a file set.

- **A `noqa`-suppressed finding is recorded as `fixed`, not `overridden`.**
  Triaging the 20 `S` findings above moved the ledger from 27 open to 6, and
  every one of those 21 reads as `fixed` — but what changed for 20 of them is
  a documented justification, not the behaviour. aramid observes tool output;
  a suppression makes the tool silent, and nothing in that silence says
  whether the risk was removed or reviewed and accepted.

  This is worth stating plainly given the rest of this release is about
  `fixed` records that did not mean what they said. It is a narrower problem
  than those were — the decision is recorded, in-repo, next to the code, and
  reviewable in the diff, rather than invented by the gate — but a reader
  auditing the ledger alone cannot tell the two apart, and the `overridden`
  state that exists for this distinction is not reached by this path.

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
