# Changelog

All notable changes to aramid are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[semantic](https://semver.org/spec/v2.0.0.html).

`src/aramid/__init__.py`'s `__version__` is the single source of truth —
`pyproject.toml` derives its version from it, and the release workflow refuses
to publish a tag that disagrees with it.

## [Unreleased]

### Added

- **The gate reports test-suite progress while the suite runs.** A push on
  a repo whose suite takes minutes used to show nothing until the hook
  exited (this repo: ~19 min of silence). The tests runner now taps the
  suite's stdout as it arrives and, for a pytest-shaped command, asks
  pytest for `console_output_style=count` and turns each `[ N/M]` marker
  into one line on stderr -- `aramid: tests 1234/2394 (52%) 9m12s elapsed`
  -- which git relays live to the terminal the push was typed in. On a
  terminal the line overwrites itself in place; in a log or CI step it is
  written at most every 30 s, and the last state always lands. A
  configured `[tests].command` that already sets `console_output_style`
  is left alone, and a non-pytest suite (npm, cargo, go) prints nothing.
  Under the hood `run_subprocess` gained an opt-in `on_stdout_line` tap
  (default off: the plain path is unchanged) and `RunContext` a
  `progress` sink, provided only by `run_gate` -- the drain's consumers
  build their own context and stay silent.

### Changed

- `aramid drain --help` says that every drain except `--dry-run` ends by
  recomputing the machine-level readiness verdict, queue or no queue, so
  `drain --repo .` on an empty queue is how a repo turns green in `status`
  before the scheduled run (interop round 192 asked whether that was
  intended; it is). The `[fuzz]` example in the generated ARAMID.md no
  longer labels `"main", "_run"` as "this repo's additions" -- the file is
  rendered from a template, not from the repo's config -- and RELEASING.md
  gains the rehearsal step the 0.12.0 tag-push defect showed was missing:
  push and delete a throwaway annotated tag right after promoting, since a
  release's own tag is certified by the previous release's hook.

### Fixed

- **The pre-push certification refused every annotated-tag push.** git's
  pre-push stdin carries each ref's OBJECT id -- for an annotated tag the
  tag object, not the commit it peels to -- and that is also what
  `send-pack` ships at hook exit. The exit-time re-resolution asked git
  for `<ref>^{commit}`, so an annotated tag compared unequal to itself and
  the gate failed with `v1.0.1 moved during the gate: <tag object> ->
  <commit>; re-run the push` after an otherwise green run (interop round
  193, graphite-agent, on graphite's 1.0.1 tag; aramid's own v0.12.0 tag
  went out under the 0.11.0 shim, before the certification existed).
  Certified refs are now re-resolved UNPEELED (`git rev-parse <ref>`), like
  with like: a branch still compares commit to commit, an annotated tag
  compares tag object to tag object, and a tag re-created on the same
  commit during the gate is still reported moved, because a different tag
  object is what would ship. `HEAD` at start and exit is still the commit.

## [0.12.0] — 2026-09-04

### Added

- **The drain sweeps what killed consumers left in the temp dir.** Every
  worktree consumer and the red-proof gate step create
  `<tempdir>/aramid-<kind>-<random>/wt` and remove it in a `finally` that
  a kill never reaches; on Windows an open file held by a grandchild leaves
  a few-KB shell behind, and a stale `.git/worktrees` registration survives
  `git worktree prune` while the directory exists (measured: 34 shells over
  six weeks, one or two per scheduled drain, plus one dangling red-proof
  registration). `aramid.leftovers.sweep` now runs for every repo a drain
  probes: shells older than six hours go, with their registrations; a
  registration git reports as locked is live whatever its age; only the
  `aramid-mut-`/`-red-`/`-fuzz-`/`-jsmut-` prefixes are ever considered.
  The drain prints `removed N leftover worktree dir(s)`, `--dry-run`
  appends `leftovers=N`, a dir that will not go is named on stderr, and
  nothing here degrades the drain or reaches the ledger. The test suite
  isolates the sweep to a per-test temp dir (a first run of the drain
  suite swept the developer machine for real). Rounds 178/181/183.
- **The pre-push gate certifies the refs git handed it, and fails when one
  moved while it ran.** The gate now reads the `<local ref> <local sha>
  <remote ref> <remote sha>` lines git writes to the hook's stdin (only
  under `ARAMID_HOOK=pre-push`, which the managed shim exports -- re-run
  `aramid init` to get it into an existing shim), pins them plus `HEAD`
  before anything runs, and re-resolves them after the last runner returns.
  A moved ref fails the push with `aramid: pre-push: main moved during the
  gate: 12a1d68 -> 673c804; re-run the push`. The run row records both sides
  (`refs`, `head_at_start`, `hook` on `run_started`; `refs_moved`,
  `head_at_exit` on `run_finished`) and `check --json` carries `refs_moved`.
  Run by hand or in CI, `HEAD` at start is certified against `HEAD` at exit.
  An empty ref list under the marker (git's `Everything up-to-date`, or a
  delete-only push) ships nothing: the gate returns 0 without running the
  tools and without a run row (interop round 176).
- **A degraded tool says why.** `skipped (degraded tools):` lists
  `gitleaks (timeout after 120 s)`, `semgrep (not found)` or
  `ruff (crashed (exit 2))` instead of the bare name; `check --json` carries
  the map as `degraded_reasons`; the run's `run_finished` row carries it as
  `degraded` (empty when every selected tool ran, absent on rows from an
  older aramid); and a timed-out tool's log now holds the line
  `aramid: <tool> timed out after <N> s and was killed` instead of being a
  0-byte file. Until now a push refused on a degraded BLOCK-tier tool left
  no surface anywhere naming the budget it blew.
- **An item the drain leaves behind is deferred, shown, and opened first
  next time.** `drain --all` pops one item per repo under ONE drain-wide
  wall-clock budget checked only between items, so an active repo's item
  could spend the whole drain and a tied, quieter repo's item was left
  queued with the line saying so on a stdout the scheduler discards -- and
  the same order repeated at every drain (interop round 177). When the loop
  stops on the budget or the item limit, every candidate left behind gets a
  `queue_item_deferred` row in its own repo's ledger (`reason`, the repos
  the drain did open, elapsed and budget); `QueueItem.deferred` replays it;
  candidates sort most-deferred first, then by score; `drain --dry-run`
  prints `deferred=1 (drain budget)`; `status`'s queue line reads
  `deferred 1x: drain budget`; and `drain --help` names the exit codes
  (0 / 2 a consumer degraded or a repo could not be probed / 3 lock held or
  registry unusable). The budget stays drain-wide and a running item is
  never preempted.

### Changed

- **`aramid status`'s `last run:` line names the run's gate**, e.g.
  `last run: <at> (pre-push run <id>, 0 blocking, took 570s)` or
  `(historical-scan run <id>, ...)`. The newest run is whatever ran last,
  and after `aramid init` that is the full-history scan rather than a gate;
  without the label its line read like a gate's (interop round 172). A
  ledger whose run carries no gate keeps the old `(run <id>, ...)` shape.

### Fixed

- **A stage-1 kill of a `pending_retest` survivor is confirmed and claimed.**
  The mutation consumer confirmed (full suite) and claimed a stage-1 kill
  only when the fingerprint was among its OPEN findings; a survivor the
  gate had already moved to `pending_retest` (`gap_addressed`, waiting for
  exactly this re-test) was the one state a re-test could not claim. The
  row read `killed_s1 1` beside `retest_killed 0`, the note said `0
  killed`, no `mutant_killed` yield was written and the finding stayed
  `pending_retest` (interop round 188, graphite row 5207, the tightened
  test in the stage-1 file). The load-bearing set is now the recorded
  survivors -- open or `pending_retest` -- the same set `Repaired.examined`
  reports; `resolve_repaired` already accepted a `pending_retest` id. A
  parametrized test runs the stage-1 killer against both statuses; the
  `open` arm always passed.
- **The fuzz driver sees the worktree's own package.** The driver loads each
  target file by path, but the file's own imports resolve through
  `sys.path`, and `python -m` put only the worktree ROOT there -- so a
  src-layout package came from the installed distribution (worktree code
  fuzzed against installed dependencies) or, for a module the commit added,
  from nowhere: interop round 187 read `import_failures 1` on graphite's
  cache commit. The consumer now launches the driver with
  `worktree_import_env(wt)` (`<wt>/src`, `<wt>` first), the inversion
  red-proof and mutation each had once. The row also names what failed and
  why: `import_failed` maps each file to `<ExcType>: <message>`, where the
  count alone sent a reader guessing. The fuzz consumer tests had been
  exercising the INSTALLED wheel's driver (a bare child resolves
  site-packages); they now bind the checkout's `src` on the child's
  PYTHONPATH per test, so a driver change can fail a test again.
- **An accepted degradation passes -- under `--strict` and the CI-parity
  shim too.** `--accept-degraded` / `ARAMID_ACCEPT_DEGRADED` returned exit
  2 (pre-push BLOCK tier only); the plain shim mapped that to 0, but under
  `[hooks].pre_push_match_ci` the shim runs `--strict`, which remapped it to
  1 AFTER the `infrastructure_bypass` row was written, so the documented
  escape hatch refused the push with its acceptance on record. The gate now
  exits 0 on an accepted run, for any gate and any tier (a WARN-tier
  degradation was never covered), prints `degraded, ACCEPTED: <reason>
  (recorded in the ledger as infrastructure_bypass)` and carries
  `accepted_reason` in `check --json`. A genuine BLOCK finding still exits 1.
- **A completed mutation run records what it examined, so `mutant_killed`
  stops reading NEVER RAN.** The drain handed the ledger a repair claim only
  when it had ids, so a run that killed no recorded survivor wrote no
  `mutant_killed` yield row and the resolver census graded the pair NEVER
  RAN forever -- a consumer whose only survivor is overridden could never
  flip it (interop round 180). `Repaired` gains `examined` (the open /
  pending_retest survivors the run read); both mutation consumers report it
  on every completed run, kills or none; `resolve_repaired` counts
  `considered = |ids ∪ examined|` and yields on an empty claim. The census
  grades that NO OPPORTUNITY / NO CLEARS -- an outcome, not a defect.
- **llm-review falls through on a length-capped answer instead of degrading
  the item.** ollama-cloud's `done_reason: "length"` (the model ran to its
  output cap; one review produced 65,536 tokens in 166 s and no JSON) was
  read as the reviewer's malformed VERDICT. The provider now returns
  `error: truncated`, the arm loop falls through to the next arm on it, and
  when every arm is capped the item degrades under the `malformed response
  from <provider> (output cap hit)` note -- the family the three-strike
  give-up counts. The request also carries `options.num_predict = 16384`,
  bounding a runaway generation at the cap (interop rounds 179/180).
- **`ARAMID.md` documents `[fuzz].skip_name_patterns`.** The key was in the
  user guide and the packaged defaults but not in what `aramid init` writes,
  so a consumer read the installed wheel's source for its semantics; the
  template now shows the twelve packaged globs and states that a repo's
  list REPLACES them (interop round 180).
- **`check --all` no longer times gitleaks out on a big gitignored cache.**
  `--all` pointed `gitleaks dir` at the repo root, and `dir` walks
  everything under its one path with no exclude option (a global-allowlist
  `paths` entry stops the regexes, not the walk: measured 65.6 s with one
  against 67.7 s without). On aramid's own checkout the gitignored
  `.cache/` (15,388 files, 418 MB) cost 63 s of a 68 s scan against the
  runner's 120 s budget; a concurrent drain pushed it over, the pre-push
  gate degraded gitleaks, and `--strict` refused two pushes whose gates had
  nothing blocking. gitleaks now scans a temporary copy holding exactly the
  tracked files (`--all`'s definition, and the only files a push can ship),
  with each reported path rewritten back to the repo -- 381 files in 2.6 s
  here. Regular files only: a submodule, a deleted path or a symlink in
  `git ls-files` is skipped, never an error.
- **`aramid status` no longer reports the init history scan's secrets as
  "blocking".** `record_run` counted a run's `blocking` by verdict alone, and
  a secret's verdict is BLOCK, so after `aramid init` the `last run:` line
  read `3 blocking` beside a green gate -- the three were history hits the
  ledger records as historical and non-blocking by contract, and in that
  consumer's case already adjudicated `not-a-secret` (interop round 172).
  Historical findings are now excluded from the count; the hits are still
  reported where they belong, in the unrotated-historical-secrets section.
- **A repo-relative `[tests].command` now resolves in the drain.** A
  relative argv[0] that contains a path separator is anchored to the repo
  root and launched absolute, by the gate, the mutation consumer and
  `doctor` alike (one parsing rule, `runners.tests._argv`). It used to be
  resolved against the current process's cwd: the gate's happens to be the
  repo root, the scheduled drain's is whatever the scheduler gave it, so
  the same command ran at the gate and was `MISSING` in the drain -- 43
  `baseline failing` rows over three weeks, none of which ran a test
  (interop round 174). `toolpath.resolve` now always returns an absolute
  path; a relative hit used to come back relative and then be launched
  from a different cwd.
- **A baseline command that does not resolve is named as such.** A new
  note family, `baseline command not found: <argv0> (resolved from <cwd>;
  set ...)`, replaces `baseline failing` for the MISSING case; it is
  repo-scoped like the timeout family (three strikes on any items, released
  when the command changes) because no commit fixes a path. A genuinely
  red baseline keeps its head-scoped note byte-for-byte and now appends
  `-- rc N: <last output line>`; the last 60 lines of stdout and stderr go
  to `.aramid/logs/mutation-baseline-<item>-<head12>.log` (interop round
  174).
- **`mutation-score` no longer counts a confirm without a verdict as a
  survivor.** The per-target `survived_s1` was never undone when the
  full-suite confirm timed out, errored, was skipped by `confirm_cap`, or
  KILLED the mutant, so those read as survivors (and a full-suite kill as
  both killed and survived). Two additive per-target keys, `killed_s2` and
  `unconfirmed`, take the moved mutants; `survived_s1` now means "survived
  stage 1 and the full suite passed on it"; `rate` is kills of either stage
  over mutants with a verdict and `fully_mutated` compares that sum to
  `generated`. Rows written by earlier versions parse unchanged and to the
  same rate they always had (interop round 174).
- **A commit made while the pre-push gate ran no longer ships ungated over
  HTTPS.** git runs the pre-push hook first and, over smart HTTP, has
  `send-pack` resolve the refspec by name at hook exit, so the gate certified
  one tip and git shipped another while printing the pre-hook range
  (reproduced on git 2.53; a consumer's 18-minute gate certified `12a1d68`
  and GitHub received `673c804`). The gate's range was `@{u}..HEAD` resolved
  at start and it never read the hook's stdin. See Added above (interop
  round 176).

## [0.11.0] — 2026-09-04

### Added

- **Fleet readiness now needs fresh rows, not just green ones.** A new
  `[readiness].max_row_age_days` policy key (default 7; `0` disables) makes a
  registered repo whose latest fleet-health row is older than the window
  read `stale`: the verdict is `insufficient-data`, the streak resets, and
  the readiness line and `aramid fleet` name the repo, its row age and the
  window (`stale: graphite (9.3d) -- window 7d`). Before this, "held for 14
  days" was satisfied by two green rows and 14 idle days. `fleet_verdict.json`
  gains additive keys (`repos.<key>.stale`, `repos.<key>.age_days`,
  `fleet.stale_repos`, `policy.max_row_age_days`); no schema bump. Spec
  amendment A1.

## [0.10.0] — 2026-09-03

### Changed

- **pip-audit now audits pyproject-only Python repos.** With no
  `requirements*.txt` at the root, the deps runner hands pip-audit the repo
  itself (project-path mode) when `pyproject.toml` carries a `[project]`
  table, so the declared dependencies and their transitive closure are
  audited at pre-push (about 40 s; WARN tier, never BLOCK). Requirements
  files keep precedence when both exist -- pip-audit refuses to combine the
  two -- so requirements-based repos are unchanged. A tool-only pyproject
  (no `[project]` table) is still not a dependency source: pip-audit exits 1
  with empty output on it, and 1 is the "vulnerabilities found" code, so
  the runner never asks. One predicate (`runners.deps.python_sources`) now
  answers applicability for the pipeline, the expected-tools expansion that
  feeds skip streaks, and `doctor`, whose pip-audit WARN survives only for
  the tool-only case. Fleet criterion 5 (`dep_audit_ran`) can read green on
  such repos once this is promoted; it was the standing red on aramid's
  own repo since 0.9.0.
- The fleet verdict's arming blocker now reads `no repo is armed` instead of
  `no repo has an armed consumer`. The criterion never changed -- spec
  section 4, criterion 6: any `*_armed` flag true on some repo's latest row,
  so a semgrep or pack arm counts -- but the old wording read as "a drain
  consumer must be armed", and a consumer took it that way (channel round
  165). RELEASING.md's 1.0 gate says the same in words now.

### Fixed

- **The semgrep floor is 1.137, up from 1.100.** semgrep 1.136.0 and below
  pin `opentelemetry-instrumentation-requests ~=0.46b0`, whose
  `dependencies.py` imports `pkg_resources`; Python 3.13 ships no
  setuptools, so semgrep crashes on import and every semgrep-backed gate
  fails with it -- BLOCK tier, on every push. opentelemetry-instrumentation
  0.49b0 (2024-11-05) moved to `importlib.metadata`, and 1.137.0 is the
  first semgrep pinning that generation. This was not hypothetical: on
  2026-09-03 pip on one CI runner backtracked from 1.176.0 down to 1.136.0
  during an opentelemetry conflict and 13 tests failed on
  `ModuleNotFoundError: pkg_resources`, while the twin run on the same
  commit resolved 1.176.0 and passed. With the floor, that backtrack fails
  the install loudly instead of installing a gate that crashes.

## [0.9.0] — 2026-09-03

### Added

- **Fleet health and the 1.0 readiness verdict.** Every recording gate run
  appends one row for its own repo to `~/.aramid/fleet_health.jsonl` (skip
  streaks, consumer streaks, resolver defects, self-inflicted blocks,
  whether pip-audit ran, every `*_armed` flag); the drain judges every
  registered repo's rows into `~/.aramid/fleet_verdict.json` (`ready`
  only after every repo is green for 14 days across 2 aramid versions with
  an armed consumer somewhere) and posts `readiness-reached`,
  `readiness-broken` and `fleet-defect` notices to aramid's own channel,
  `~/.aramid/notices.jsonl`. New commands `aramid fleet [--json]` and
  `aramid notices [list|show <id>|ack <id>]`; the session-start hook and
  `aramid status` print the verdict and any notice due in the current repo;
  a gate run ends with a one-line pending count and `check --json` carries
  `fleet_notices_pending`. Policy in `~/.aramid/fleet.toml`. Everything is
  fail-open and offline; nothing is written into any repo and no process
  reads another repo's ledger. `RELEASING.md` gains "The 1.0 gate".
- `check --json` carries `stacks` on the result internally; no JSON change.

### Changed

- `aramid status`'s skip-streak, consumer and resolver-defect lines are now
  rendered from one `Health` snapshot (`aramid.health`) shared with the
  fleet row, so the two surfaces cannot disagree. Output is unchanged.

## [0.8.1] — 2026-09-02

### Added

- **The release workflow refuses to publish a commit CI has not passed.** A
  new first job, `verify-ci`, queries the Actions API for the `aramid`
  workflow's runs on the exact tagged commit and exits non-zero unless one is
  completed with conclusion `success`; `release`, `publish-testpypi` and
  `publish-pypi` all depend on it. A matrix still running is waited for
  (75-minute budget); every run finished and none green fails at once, naming
  the runs and the remedy. RELEASING.md step 4 ("wait for CI to be green")
  was a human step until now: the v0.8.0 tag's own CI run was red (a macOS
  runner was never acquired) and the release proceeded, saved only by the
  same commit having been green on main. Logic in
  `.github/scripts/require_green_ci.py`, every branch pinned by
  `tests/unit/test_require_green_ci.py`, wiring pinned too.
- `SECURITY.md` (private vulnerability reporting through GitHub security
  advisories, response targets, supported-versions policy, what is in and out
  of scope, how to verify a release), `CONTRIBUTING.md` (setup, test tiers,
  the gate rules, PR flow) and `MAINTAINERS.md` (the single-maintainer risk
  stated, and exactly what a successor needs to keep releasing). Dependabot
  now watches the SHA-pinned actions, the one dependency class here that never
  moves on its own. Private vulnerability reporting and dependency
  vulnerability alerts are enabled on the repository.

### Changed

- The release workflow's artifact actions moved to `upload-artifact` 7.0.1 and
  `download-artifact` 8.0.1 (Dependabot, the first PRs it opened here). Both
  are major bumps that CI never exercises, so the upload/download round-trip
  was rehearsed on a throwaway branch before this release: same pinned SHAs,
  name and globs, both files byte-identical at `dist/<file>`.

### Fixed

- **`ledger filter --status` accepts the spelling `status` prints and refuses
  unknown values.** `aramid status` reports `pending-retest: 2`; `ledger
  filter --status pending-retest` answered "no matching findings", because the
  ledger stores `pending_retest` and the comparison was raw -- an empty answer
  indistinguishable from a real absence, on the surface the release checklist
  reads. Hyphens and case are now normalised for `--status` and `--severity`,
  and a value outside the vocabulary exits 3 with the vocabulary listed
  instead of an empty match (`--json` included, which printed `[]`).

## [0.8.0] — 2026-09-01

### Added

- **`aramid init` writes a managed instruction block into CLAUDE.md and
  AGENTS.md.** The block is fence-scoped (`<!-- aramid:begin -->` /
  `<!-- aramid:end -->`) so a re-run refreshes only what it owns and
  leaves the rest of the file untouched; a file whose fence structure
  isn't trustworthy (an unterminated or doubled begin marker) or that
  can't be decoded as UTF-8 is left alone entirely and reported rather
  than written. `aramid uninstall` removes the block the same
  fence-scoped way, and `aramid doctor` reports each file's block state
  (`ok`/`stale`/`absent`/`damaged`/`unreadable`) advisory-only -- it never
  changes doctor's exit code.
- **`aramid init` registers a session-start agent hook, and `aramid
  agent-hook session-start` renders live gate posture.** The hook entry in
  `.claude/settings.json` is merged own-entry-by-marker (foreign tools'
  entries preserved; an unparseable file refused and reported), and the
  subcommand prints open findings, skip streaks, and bake posture for the
  agent session's context -- fail-open in every path, so a session can
  never be broken by it. `aramid doctor` grades the entry
  (`ok`/`absent`/`stale`/`tampered`/`unparseable`); a tampered entry --
  an aramid-named hook whose command differs from the template -- exits
  doctor `2`. `aramid status` gains an `agent surfaces:` line.
- `aramid agent-hook pre-tool-use`: token-level screening of agent tool
  calls for git hook-bypass invocations (`--no-verify` or `-n` on commit,
  `--no-verify` on push, `-c core.hooksPath=...` on either) -- advisory
  while baking, denied once armed via `aramid arm --agent` (new root
  config key `agent_block_armed`, default false).
- `python -P -m aramid.mcp`: a dependency-free stdio MCP server exposing
  the full loop (`aramid_check` as a read-only snapshot, `aramid_status`,
  `aramid_ledger_filter`, `aramid_resolvers`, and reason-required
  suppression tools with the CLI's authority and audit trail); `aramid
  init` registers it in `.mcp.json` (foreign servers preserved; doctor
  grades the entry, tampered exits 2).

### Changed

- `.claude/settings.json` template now registers a PreToolUse entry beside
  SessionStart, and grading is event-bound and whitespace-normalized: an
  aramid entry moved to a foreign event or edited grades tampered (doctor
  exit 2); a sub-2-era file with only the SessionStart entry grades stale
  -- re-run `aramid init`. The managed CLAUDE.md/AGENTS.md block gained
  "Armed repos reject the call outright." (existing blocks go stale until
  re-init; by design).

## [0.7.2] — 2026-08-30

### Fixed

- **`status` no longer reports the tests slot as skipped on every push.**
  `expected_tool_names` shared `_expand_keys` with `selected_tool_names`,
  which adds the literal registry key `tests` beside the suite's label (so
  mark-unreachable refuses while a test setup is still configured); the key
  therefore sat in `expected`, no run ever records it in `tools`, and the
  skip streak counted every pre-push run -- `tests: skipped last 210
  pre-push run(s)` on a consumer, 191 on aramid's own ledger, since the
  `expected` set was first recorded (interop round 155 s1). Dropped at that
  decision point; `selected` keeps it. The streak reads the newest run that
  recorded `expected`, so one pre-push run under this version clears it.
- **A fuzz driver that times out says which function it was in, and
  `status` reports the streak.** The driver printed its verdict once, at
  the end, so a target that never returns took the whole batch with it when
  the budget killed the process, and the consumer recorded `ok` with
  `cases_run=0` -- five drains, ~10 minutes, and no line anywhere (round
  155 s2). The driver now writes its position before every call; the
  consumer's note names the function (`driver timed out in src/x.py:serve
  (function 1 of 15)`), carries `hung_in` in the payload and names the
  remedy (`[fuzz].skip_name_patterns`); `status` lists the run under
  `consumers doing no work`, as it does mutation's. Still `ok`: `degraded`
  would pin the queue item.

### Added

- **`check --json` carries `run_id` and `recorded`** (both always present).
  `recorded: false` is a `--no-record` run -- a real report against a
  snapshot with no ledger row to match, which a saved copy could not
  previously say (round 155 s3).
- **`aramid ledger resolve` takes several ids per launch.** Every id is
  attempted (a refusal on one does not stop the rest) and the exit is the
  worst of them; 683 one-at-a-time retirements took ~11 minutes (round 155
  s4).

## [0.7.1] — 2026-08-30

### Fixed

- **The typecheck slot honours mypy's own `files`/`exclude`.** It handed
  mypy every `.py`/`.pyi` in range, so a repo whose `[tool.mypy] files =
  ["src/pkg"]` deliberately leaves tests/ and scripts/ untyped got 786
  block-tier findings from one whole-tree run (interop round 149 b).
  `run_mypy` now filters by `typecheck.mypy_scope(root)` (pyproject or
  mypy.ini; list or comma-string `files`; `exclude` as the regex mypy reads)
  and vouches only for what its scope let it see; `examines_path("mypy",
  path, root=…)` consults the same helper, so `resolve --out-of-scope` and
  `status`'s candidates agree with the runner and rows on untyped files can
  be retired with their reason. No `files` setting means everything in
  range, as before.
- **A real mypy run now vouches only for the files it was handed.** The
  no-op branch stamped `examined` as the empty set (0.6.1), but a run that
  actually invoked mypy came back with `examined=None`, which resolution
  reads as "could not report" and falls back to the gate's whole file
  scope -- so a `mypy:syntax` row recorded against `ci.yml` resolved as
  `fixed` off a push that carried `.py` files beside it, credited to a
  runner that never opened the file (interop round 149 s1; two rows on a
  consumer's ledger). The real run stamps exactly its argv's paths, as
  ruff does; a non-Python row can never resolve off a mypy run again.

### Added

- **`aramid check --no-record`** runs the gate against a snapshot of the
  ledger and writes nothing to `.aramid/ledger.db`. A consumer took a
  whole-tree `--all` measurement and it wrote 683 rows into their ledger
  (interop round 149 c); every `check` recorded, and there was no way to
  look without leaving a mark. The report is the real report: the
  snapshot carries the history the ratchet, `new_ids` and the fresh-ledger
  rule read. Runner logs are still written.
- **The `--json` report says when the fresh-ledger rule downgraded the
  exit.** `fresh_ledger_baseline: true` and `grandfathered: [ids]` (both
  keys always present; `false`/`[]` otherwise). A consumer's CI read
  `exit_code: 0` over 786 ratchet-escalated block-tier findings, on 0.6.1
  and again on 0.7.0, with only a stderr line to explain it (interop
  rounds 149 s3 / 150): `.aramid/` is gitignored, so every CI checkout is a
  fresh ledger, every CI run is "the first pre-push run", and the ratchet
  can never fail a CI step by rc alone. Designed, now visible where a CI
  step reads. The user guide and knowledge base say so.
- **`doctor` says when pip-audit is present but does not run.** The deps
  runner audits `requirements*.txt` at the repo root and nothing else, so
  on a pyproject-only Python repo pip-audit is selected by nobody and runs
  in no gate -- while `doctor` printed `OK  pip-audit` (interop round 149
  s2, two machines). Now a WARN line under the table; never the exit code,
  since `deps` is not BLOCK-tier and the gate would never fail on it.

### Changed

- **The mutation gate's optimistic resolve records `pending_retest`, not
  `fixed`.** `gap_addressed` resolves an open survivor when the push touches
  its module or a test named for it, so a dev who added a test is not
  blocked -- and promised that "the async re-drain is the authoritative
  backstop". Measured on aramid's own ledger: 21 such resolves, 20 never
  re-examined. The backstop was structurally void: range-mode mutation
  regenerates only mutants on changed lines and the id is content-keyed, so
  an old id can only return through the survivor re-test, which read `open`
  rows only; and the test-only push carrying the evidence scored 20 against
  a `min_score` of 40 and was never queued. Now: the resolve carries
  `pending_retest` (a new status that does not gate; older events keep
  reading `fixed`), the re-test considers pending rows and a confirmed kill
  closes them, a re-detect re-opens them, `status` counts the bucket, and
  triage's new `survivor-retest` signal (+40) queues a push whose changed
  test maps to a recorded survivor's module or whose changed source holds
  one. The gate also skips survivors bound by the tracked suppressions file
  -- an adjudicated equivalent mutant has no gap to address (one was written
  `fixed` twice).

## [0.7.0] — 2026-08-29

### Added

- **`aramid check --gate all` sees both tiers.** `ruff` runs only at
  pre-commit and `semgrep`/`tests` only at pre-push, so no hook gate could
  show both halves of one edit: annotating a line for one tool re-keyed
  the other tool's committed suppression id on that same line, and
  `--gate pre-push --all` read exit 0 while four ruff BLOCKs waited in the
  other tier (interop round 126 s4b). `Gate.ALL` was the pre-push list
  under another name -- so `rebaseline`, which runs it, never baselined a
  ruff finding either -- and was unreachable from the CLI. It is now the
  union of both tiers, pinned by a test that fails when a runner added to
  either tier is left out, and `--gate all` is accepted, defaulting to the
  whole tree. Informational: it never ratchets and no shim invokes it.
  The user guide's claim that `--all` "runs the full pre-push runner set
  regardless of gate" was false and is corrected: `--all` widens the FILE
  set only.

- **`aramid ledger resolve <id> --out-of-scope --reason …`** retires a
  finding whose tool still runs here but whose runner will never examine
  that path again. The case (interop rounds 139/144/145): once the
  typecheck runner was scoped to `.py`/`.pyi`, `mypy:syntax` rows recorded
  against `ci.yml` and `README.md` could neither re-report nor resolve,
  and `mark-unreachable` rightly refused because mypy was still selected.
  It records `finding_out_of_scope` -- its own event kind, chosen by the
  consumer so the ledger can tell "the tool left" from "the path left the
  tool's scope" without reading payloads -- and the row reads
  `out_of_scope` with the reason. Refuses while the runner can still
  examine the path (each runner's own suffix rule, read from the runner,
  never copied), refuses outright for a tool with no suffix scope, and
  redirects to `mark-unreachable` when the tool is not selected. `status`
  lists "out-of-scope candidates" with the exact command and counts the
  new bucket; `override` refuses the status; a re-detect re-opens it.

- **`doctor` reports a stale or missing relocated shim, read-only.** When
  another managing tool's trampoline occupies a hook slot, aramid's own
  shim survives relocated beside it; `install()` regenerates that sibling
  in place (interop round 112) but is a write, and no read-only surface
  said anything -- `probe_enforcement` is quiet because the slot itself
  exists. `probe_relocated_shims` compares the sibling against the
  current template rendered for its OWN baked interpreter and names it
  STALE, or names the gate as NOT running when no sibling survives at
  all; either exits `2` with `aramid init .` as the remedy. `doctor` still
  never rewrites a hook.

- **A rewritten line resolves as `superseded`, not `fixed`.** Ids hash
  content, so rewriting a flagged call re-keys its row: the old id vanished
  and a new one opened on the same call in the same run, and the ledger
  wrote `fixed` for the old one -- at exactly the moment the call was being
  rewritten, which is when the finding most needs re-reading (interop
  round 135 s3; `rebaseline` had documented the shape as expected).
  `record_run` now pairs each vanished open finding with the nearest NEW
  finding of the same tool, rule and file within 40 lines, each sibling
  claiming at most one; the resolve event carries `superseded_by`, the row
  reads `[superseded]` with `reason: rewritten -- superseded by <id>`, and
  `status` gains a `superseded:` bucket. Same tool/rule/file alone is not
  enough -- a site genuinely fixed while an unrelated one appears 300 lines
  away stays `fixed`. A superseded id re-detects if a revert brings its
  content back; `override` and `mark-unreachable` refuse it and name the
  successor, since that is the row that needs the decision.

- **`run_finished` now says when the run finished.** Every event in a
  run carries the run's `at`, which is its identity stamp -- so the
  ledger could not tell a ten-minute gate from a one-second one, and a
  consumer reading its own gate's history had to establish the wall clock
  from a push log's mtimes (interop round 130 s3). `record_run` takes a
  keyword-only `finished_at`, the gate passes a second clock read once
  every runner has returned, and `aramid status`'s last-run line adds
  `took Ns`. Written only when supplied and never copied from `at`: an
  older ledger reads as unknown, not as zero seconds.

## [0.6.1] — 2026-08-29

### Fixed

- **The typecheck runner hands mypy only Python files.** It passed the
  gate's whole file set, and mypy tokenises any explicit path as Python: a
  push whose only change was `.github/workflows/ci.yml` blocked on a
  BLOCK-tier `mypy:syntax` ("Leading zeros in decimal integer literals"),
  while two non-Python files in range made mypy bail on a duplicate
  `__main__` before parsing and the push passed -- the same edit
  false-failing or false-passing on what else was in the range. Reported
  with logs by the graphite agent (interop round 139). Now scoped to
  `.py`/`.pyi` like the ruff runner; with no Python in range it is a clean
  no-op that invokes nothing and vouches for nothing (`examined` is the empty
  set), so no finding resolves off a run that never looked. A mypy finding
  already recorded against a non-Python file stays open under its
  suppression -- this runner will never examine that file again -- which is
  a named follow-up, not a silent close.

- **Docs: `doctor` exits 2 on every CI checkout.** Hooks are not cloned, so
  a runner's checkout is "configured but NOT enforced" by construction, and
  GitHub's default `pwsh` step wrapper reports that 2 as 1 unless the script
  ends with `exit $LASTEXITCODE`. Reported as a crash in interop round 139,
  measured to be this in round 141; the user guide and knowledge base now
  say so, so the next reader skips the detour.

## [0.6.0] — 2026-08-29

### Added

- **The mutation consumer re-tests recorded survivors when a test changes.**
  A survivor recorded at one head was re-tested only when its own module
  changed again, so the ordinary way a survivor dies -- someone writes the
  test, in a test file, on a module the range never touches -- reached no
  resolver: `mutant_killed` never got a run, and the gate's `gap_addressed`
  needs a test-stem mapping plain names do not satisfy (`test_runner_shadow.py`
  never maps to `runners/shadow.py`; that survivor was killed by perturbation
  on 2026-08-28 and could not close). Now, when the item's range changes any
  test file, open mutation survivors are regenerated from their fingerprints
  and put through the identical stage-1 / full-suite confirmation path, and a
  confirmed kill is claimed as `mutant_killed` -- the proof stage 2 already
  makes, on the suite that defined the finding. Runs after the range's own
  mutants, skips survivors bound by `.aramid-suppressions.toml` (an
  equivalent-mutant entry says unkillable), leaves the range's mutation scores
  untouched, and is bounded by `[mutation].retest_cap` (3) inside the item's
  budget; `retest_open_survivors = false` switches it off. The note reads
  `re-tested N of M open survivor(s), K killed`.

### Changed

- **`aramid doctor` exits 2 when aramid itself is installed editable while
  any repo is registered.** Every registered repo's hooks resolve
  `python -P -m aramid` to the live install, so an editable live install
  gates all of them with a working tree, uncommitted edits included -- the
  state this project's own history calls a hazard. The `EDITABLE` notice was
  advisory because an editable install on a machine with no consumers is
  legitimate; it still is, and stays advisory with nothing registered. With
  consumers it now fails, the same widening of exit 2 as "configured but not
  enforced" and for the same reason: 0 was a false green light. The stderr
  line names the registered count and the remedy (`scripts/promote_live.py`).
  `init` prints doctor's report but keys on the toolchain probe directly, so
  onboarding is unchanged. Raised by the llm-review consumer twice (ledger
  53073121, then 02e89b6e disputing the suppression of the first); the
  suppression is retired with this change.

### Fixed

- **The mutation consumer's baseline no longer depends on which wheel is
  promoted.** `tests/unit/test_version.py::test_installed_metadata_matches_dunder_version`
  compared the tree's `__version__` with whatever distribution
  `importlib.metadata` answered for. In the checkout that is the regenerated
  egg-info; in a fresh drain worktree there is none, so the promoted wheel
  answered and the suite went red at every promotion for every queued item
  whose head predated it -- three drains on 2026-08-28 reported "baseline
  failing" over 1452 passing tests and one machine-shaped comparison, and
  three at one head trips the consumer's give-up. The guard now skips, naming
  both paths, unless the answering distribution describes the imported tree
  (metadata beside the package, or an editable install of this tree -- the
  CI shape, pinned hermetically); the artifact assertion moved to
  `tests/e2e/test_wheel_packaging.py`, where the wheel is compared with the
  tree it was built from (perturbation-proven: a static `version = "9.9.9"`
  fails it).

- **`aramid resolvers` graded the python `mutant_killed` resolver nowhere,
  and now cannot lose a resolver that way again.** `consumers/mutation.py`
  claims `Repaired(tool="mutation", reason="mutant_killed")` and
  `resolve_repaired` records the yield under that pair, but the report's
  registry knew `mutant_killed` only for `js-mutation`; `collect` walked the
  registry and dropped every observed pair it lacked, so this repo's own
  ledger -- three such yields since 2026-08-12, three resolutions -- rendered
  as "no resolver defects (11 resolvers graded)". A twelfth row now exists,
  and an observed pair the registry never learned is rendered as an
  `UNREGISTERED` defect row with its real numbers instead of vanishing.
  Found by reading the events table directly after a handover repeated the
  report's silence as fact. `status`'s "resolver defects: N" counts the new
  row like any other.

## [0.5.1] — 2026-08-28

### Fixed

- **`aramid arm` accepts every spelling TOML accepts -- and refuses, rather
  than corrupts, when it cannot.** The section and key patterns matched only
  the canonical column-0 form. An indented header (`  [shadow]`), a trailing
  comment on a header (`[shadow]  # bake started ...`), whitespace inside the
  brackets (`[ shadow ]`) or an indented key were all legal TOML that the
  loader read and `arm` could not see, so it appended a SECOND header or key,
  `tomllib` refused the result ("Cannot declare ('shadow',) twice"), and `arm`
  had already printed its success line and returned 0. The next `aramid check`
  then crashed in `load_config` -- on a file aramid itself had broken.
  Reported by the llm-review consumer against the 0.5.0 arm fix; reproduced on
  four shapes, not the one reported. Two layers: the patterns now accept
  indentation, inner whitespace and header comments, and re-emit a key's
  indentation; and every rewrite is parsed with the loader's own parser before
  it is written, with the key required to read `true` where the loader reads
  it. A spelling no line pattern can see (a dotted key, a quoted header) now
  ends in a refusal that names the key and leaves the file byte-for-byte
  unchanged, exit 3, instead of a success line over a broken config. A file
  that does not parse before `arm` runs is refused the same way.

- **`scripts/promote_live.py` no longer accepts an editable install as
  "already live" because its version matches.** The pre-check returned 0 on
  version equality alone. The one time anyone runs this script -- to undo an
  accidental `pip install -e .` right after a release -- is exactly when the
  checkout's `__version__` equals the version being promoted, so it printed
  "Nothing to do." and left every consumer on the working tree. The probe now
  also reports whether the installed distribution is editable
  (`direct_url.json`, the key `aramid doctor` reads), and one predicate decides
  both the pre-check and the post-install check: resolving inside the checkout,
  an editable distribution, or no distribution metadata at all is "not
  promoted", and the released wheel is reinstalled over it. Reported by the
  llm-review consumer. The script had no tests; it now has.

### Tests

- Four surviving mutants killed, each proven by applying the mutant and
  watching its test fail: `_misplaced_lines`'s empty-span sentinel (a key on
  line 1 with no section was silently exempt from the NOTE), the shadow
  runner's `line=1`, and both `_live()` branches in `promote_live.py`.
- Three llm-review notes that the code already answers at the cited line are
  suppressed in `.aramid-suppressions.toml`, each with the design it argues
  against and the alternative it proposes, so the open set is the set that
  needs reading. A fourth (the cli.py:210 mutant) was already suppressed as an
  equivalent mutant; `ledger list` shows it `[open]` because the tracked file
  is applied on read -- `ledger filter` is the view that answers "what is
  actually open".
- `test_version.py` binds its subprocess through the `checkout_env` fixture
  like every other subprocess test, with `-P`.

## [0.5.0] — 2026-08-27

### Added

- **`aramid arm --shadow`.** `shadow` was the only armable consumer with no CLI
  path: the key `[shadow].shadow_block_armed` was read by `policy.classify` from
  the moment the runner shipped, but `aramid arm --help` listed
  `--llm/--autolearn/--tdd/--mutation/--mutation-score/--red-proof` and nothing
  for it, so an operator reaching for the command that exists to arm things
  concluded it could not be armed. Reported by a consumer (interop round 126
  section 4a). The gap was the surface, not the mechanism.

  **Its message deliberately does not mirror its siblings.** Every other arm
  flag reports "now BLOCK at pre-push", because every other armable runner is
  pre-push only. `shadow` is in `pipeline._GATE_TOOLS` for `PRE_COMMIT`,
  `PRE_PUSH` and `ALL`, so arming it changes what happens at COMMIT time as
  well, and it says so. An operator told "pre-push" would not expect the next
  commit to be refused.

### Fixed

- **The suite's subprocess tests graded the installed wheel, not the
  checkout.** `pythonpath = ["src"]` is a pytest ini setting: it shapes the
  pytest process's `sys.path`, and a child process inherits none of it. So
  every test that spawned `python -m aramid` -- the CLI exit-code tests, the
  ledger encoding test, the triage dispatch test, and the six e2e commits that
  fire a real shim -- resolved whatever aramid the machine had INSTALLED. On a
  machine running the two-aramid separation that is the promoted wheel, a
  different program from the one under test, and the suite had run that way
  since the separation was built. Measured: with `aramid arm --shadow --llm`
  the wheel answered "unrecognized arguments: --shadow", the checkout answered
  "--llm: not allowed with argument --shadow", and both exited 3 -- so a
  mutual-exclusion test for a new flag passed against the wrong program for the
  wrong reason. CI never saw it: CI installs `-e`, and a bare child finds the
  checkout by accident of the install mode. The local pre-push gate, which runs
  this suite, is exactly where it landed. `tests/unit/test_version.py` had
  already solved this for itself, in isolation, and said why.

  Now a suite-wide `checkout_env` fixture (`tests/conftest.py`) prepends the
  parent's own `src/` to PYTHONPATH -- derived from `aramid.__file__`, so a
  perturbation run pointed at a scratch tree stays honest; prepended rather
  than assigned, the product's own `run_subprocess` rule -- and every launch
  site binds explicitly, with `-P`. Nothing mutates `os.environ`: that would
  silently re-bind the product's own gate subprocesses, whose tests assert what
  THEY prepend. Guarded by `tests/unit/test_checkout_env.py`, whose control
  measures whether a bare child on the running machine is a different program
  and SKIPS BY NAME where it is not (an editable install), so a vacuous
  identity test is reported rather than counted as a pass.

- **The launch guard flagged prose that cites the hazard as the hazard.**
  `tests/unit/test_launch_shadowing.py` (0.4.1) excluded docstrings and nothing
  else, so the first runtime string to *mention* `python -m aramid` -- the
  `arm --shadow` help text and its confirmation message -- was reported as an
  unguarded launch and blocked a correct commit. The discriminator is now
  mechanical rather than a list of exemptions: in `sh` a backtick is command
  substitution, so no real launch template can wrap its own command in a pair
  of them, and every prose mention does. Measured before relying on it (zero
  of the real templates contain one; three of three prose mentions do),
  applied per occurrence so a line that cites AND launches is still checked,
  and it fails closed on an unbalanced count. Because this *relaxes* a
  security guard, all three real launch shapes were perturbed back to
  unguarded and each was still caught.

- **`aramid arm` could rewrite a same-named key in the wrong place, report
  success, and arm nothing.** Every sectioned rewrite (`--llm`, `--mutation`,
  `--mutation-score`, `--red-proof`, and the new `--shadow`) searched the whole
  file for its key, so a stray `shadow_block_armed = false` at the TOP LEVEL --
  an easy mistake, because `semgrep_block_armed` and `tdd_block_armed`
  genuinely live there -- was rewritten to `true`, the command printed "now
  BLOCKS at every gate" and returned 0, and `[shadow].shadow_block_armed`, the
  only key `policy.classify` reads, stayed unset. The two root rewrites had the
  mirror hole: a twin inside some `[table]` would be rewritten while the loader
  reads the top level. Reported by the llm-review consumer on the commit that
  added `--shadow`, reproduced before anything was tagged, and the tag was held
  for it.

  Every rewrite is now scoped to the span the loader reads from -- the shape
  `--autolearn` already had -- through one shared pair of helpers. A same-named
  key outside that span is never the target: it is left exactly as written
  (it is the operator's text, not aramid's to delete) and named on stderr with
  its line number. The old docstrings justified the missing scope with "the
  key name is globally unique"; uniqueness across sections was never the risk,
  placement was.

## [0.4.1] — 2026-08-26

### Security

- **Two generated launches reached `python -m aramid` without `-P`, and both
  fire by themselves.** `aramid schedule install` rendered a Windows Scheduled
  Task `<Arguments>-m aramid drain --all</Arguments>` and a crontab line of the
  same shape. `-m` puts the current directory on `sys.path[0]`, so an
  `aramid.py` at whatever directory the launch happens to run from is imported
  instead of the installed package.

  Worse than a hook, for two reasons. These fire on a **timer**, so there is no
  human present to notice anything odd. And **cron's default working directory
  is `$HOME`** — user-writable, and not a repo root, so the `shadow` runner
  added in 0.4.0 does not scan it.

  ⚠️ **Upgrading does not fix an already-installed task or crontab line.**
  The generator is fixed; the artifact it wrote earlier is not. Re-run
  `aramid schedule install` **after upgrading** to regenerate it —
  `schtasks /Create` passes `/F` and the cron path replaces by marker, so both
  overwrite cleanly. Re-running it on 0.4.0 or earlier reinstalls the old,
  unguarded form.

- **aramid's own CI gate ran `python -m aramid` from the checkout root.**
  `.github/workflows/aramid.yml` invoked the gate twice with no `-P`, and
  GitHub Actions runs steps from the workspace root. A commit — or a fork
  pull request — adding `aramid.py` at the repo root would be imported
  instead of the installed package **in the job whose purpose is to detect that
  file**. The `shadow` runner cannot cover this: the hijack happens at import,
  before the gate that would have run the detector.

- **The guard against exactly this could not see either of them, and said it
  could.** `tests/unit/test_hook_shim_shadowing.py` read only `hooks.py`, and
  its non-vacuity check asserted `len(shims) == 2 * len(GATES) + 1` — both
  sides derived from the same hand-maintained list, so it proved the list was
  internally consistent, never that it was complete. Measured: adding a fourth
  renderer emitting `-m aramid` with no `-P` left all twelve of those tests
  green. Its docstring claimed that count was what would catch such a renderer;
  that claim is corrected rather than left standing.

  `tests/unit/test_launch_shadowing.py` replaces enumeration with **discovery**
  — it walks every string literal in the package by AST and asserts each one
  reaching `-m aramid` is preceded by `-P`, with a separate scan of
  `.github/workflows/`. Nothing to keep current, and nothing to escape by
  naming a renderer differently. Docstrings are excluded deliberately:
  `runners/shadow.py` documents this very attack, and flagging the description
  of a hazard as the hazard is how a guard accumulates exemptions until it
  means nothing.

### Fixed

- **`aramid override` refused a BLOCK-tier finding without ever saying that a
  gate-start sweep was why it was back.** Meeting a run of these on an
  unrelated push, "a local override is not permitted" answers a question the
  operator did not ask. The refusal now reads the ledger and — **only when a
  sweep actually revoked an earlier override of that finding** — names the
  sweep, its cause in the same words the gate-start notice uses, and how many
  findings that same sweep reopened, so a batch reads as one re-adjudication
  rather than N unrelated denials. A finding that is BLOCK-tier on first
  detection was never swept and is told nothing, because a fabricated causal
  claim is worse than no explanation.

- **`init` wrote or appended to `.gitignore` and said nothing about it.** The
  last of the three artifacts a fresh onboard leaves in a consumer's tree
  (`aramid.toml` was already announced; `ARAMID.md` was fixed in 0.4.0). It now
  names the file, distinguishes creating it from appending to it, and lists the
  entries it **actually** added rather than all of them — naming a line that
  was already there sends a teammate looking for it in a diff that does not
  contain it. Silent on re-init, by construction: only missing entries are ever
  written.

## [0.4.0] — 2026-08-26

### Added

- **`shadow` runner — a file at the repo root that hijacks `python -m` is now a
  gate finding.** `python -m <name>` puts the current directory on
  `sys.path[0]`, so `aramid.py` (or `aramid/__init__.py`) at a repo root is
  imported *instead of* the installed tool by every `-m` launch from that root:
  git hooks, agent hooks, MCP servers, editor tasks. Hooks discard output, so a
  hijack is silent. Requested by the operator via interop round 117.

  **It is a runner and deliberately not a self-check.** The obvious fix — a
  guard inside aramid that refuses when `aramid.__file__` is not the installed
  location — *cannot fire in the case it exists to catch*: when the shadow
  wins, the real package is never imported, so nothing inside it runs. Measured
  from a directory holding a hostile `aramid.py`, control firing:

  ```
  python -m aramid --version     -> *** SHADOW aramid.py EXECUTED ***  rc=0
  python -P -m aramid --version  -> aramid 0.3.1
  aramid --version (via PATH)    -> aramid 0.3.1
  ```

  A self-check would pass every test anyone could write for it and protect
  nothing. Detection has to be a claim about the *file*, made by a process that
  is not the one being hijacked — which is why `-P` (or a console script) is a
  **precondition** for this check rather than an alternative to it.

  The predicate excludes a measured false positive:

  ```
  <name>.py          at the root   -> HAZARD
  <name>/__init__.py at the root   -> HAZARD
  <name>/ without __init__.py      -> NOT a hazard, not reported
  ```

  A bare directory is only a PEP 420 namespace portion, and a namespace portion
  loses to a regular package wherever it sits on `sys.path`.

  Runs on **every** gate including pre-commit — the hazard fires on every
  commit, and the check is a handful of `stat` calls with no subprocess, so it
  can never be MISSING or TIMEOUT.

  **Ships disarmed.** The predicate is exact, but `graphite` is also a real
  distribution name and a repo may legitimately vendor one at its root; a new
  BLOCK-by-default would hand those repos an unattended red on upgrade. The
  reporting is the new capability — nothing reported this before. Arm with
  `[shadow] shadow_block_armed = true`; this repo arms it.

### Fixed

- **`aramid init` regenerated its own tracked `ARAMID.md` and said nothing about
  it.** The file is aramid-owned and ALWAYS regenerated, so a template change
  leaves a consumer's tree dirty with a file they did not write, no line of
  output naming it, and nothing that mentions it again. In one consumer it sat
  uncommitted long enough that a *different* repo's agent raised it as an open
  item — the tool making its own housekeeping somebody else's chore.

  `init` now names it and gives the command, on stderr, before the summary:

  ```
  aramid: init: ARAMID.md is not tracked yet -- aramid owns and regenerates it,
  aramid: init:   and other machines and agents read it from the repo:
  aramid: init:       git add ARAMID.md && git commit -m "chore: sync ARAMID.md"
  ```

  Silent when the committed copy already matches — a line on every re-init is
  noise that trains people to skip the summary — and silent when git cannot
  answer, because telling someone to commit a file in a directory git does not
  manage is worse than saying nothing.

  **Deliberately a notice and not an auto-commit.** Committing inside a
  consumer's repo picks their branch, author and signing policy for them, and
  would need `--no-verify` to stop `init` re-entering aramid's own pre-commit
  gate — shipping a hook bypass in the tool whose whole purpose is that the
  hook runs. Auto-commit is strictly more intrusive than a BLOCK verdict, and
  the `shadow` runner in this same release ships disarmed for exactly that
  reason. Known adjacent gap, unfixed: `_update_gitignore` is still silent
  about the `.gitignore` it creates or appends to.

- **Four integration tests were time bombs that armed on 2026-08-20 and
  blocked every push.** `cmd_drain` runs `queue.expire_stale(...)` against the
  wall clock with a 30-day default, and the tests enqueued at a hardcoded
  `2026-07-20T10:00:00+00:00`. Thirty-one days later the item aged out, drain
  found nothing, and four assertions failed with no clue why:

  ```
  aramid drain: 0 item(s) drained, 0 left
  E  AssertionError: drain must have run the mutation consumer
  ```

  They failed in 5s instead of the 35s they take when they do real work — the
  suite had gone vacuous before it went red. CI never caught it: the last run
  was 2026-08-15, four days before the expiry, so the tests were green in
  every run that ever executed them.

  Fixed by enqueueing relative to now (a shared `recent_iso` fixture) rather
  than at a literal date. `tests/unit/test_queue.py` already tested the expiry
  boundary correctly, in offsets from a clock it owns; that is the model.

  A new guard, `tests/unit/test_queue_test_hygiene.py`, keeps drain tests off
  literal enqueue dates. It is scoped to files that actually call `cmd_drain`,
  not to literal dates in general — `test_status.py` deliberately enqueues at a
  fixed date and asserts on that exact string in rendered output, which is
  correct. The hazard is the combination, so the guard names the combination,
  and it carries its own anti-vacuity test because a sweep that matches no
  files would pass while proving nothing.

- **A hook shim relocated by another tool could never receive a template fix,
  so the round-57 `-P` guard never reached it — on a hook that fires on every
  commit and swallows all output.** When another managed tool (graphite) owns
  `post-commit`, aramid's own shim survives beside it as `post-commit.local`
  and keeps running via that tool's chain. `install()` refused the *slot* —
  correctly, since chaining a managed hook double-runs both tools' gates — but
  the refusal was slot-level, so aramid's own relocated sibling was skipped
  too, permanently. Found by the graphite agent running `aramid init` and
  watching it fix two slots out of three (interop rounds 112/114).

  The artifact this left behind, in every graphite-managed repo that also runs
  aramid:

  ```
  "$INTERP" -m aramid triage HEAD --budget 15 >/dev/null 2>&1 || true
  ```

  `python -m aramid` with the repo root as `sys.path[0]`, no `-P`, on every
  commit, with all output discarded — so a shadowing `aramid.py` at the repo
  root would execute silently. Latent rather than live wherever no such file
  exists, but nothing reported it and re-running `init` did not fix it.

  `install()` now regenerates aramid's own relocated shim in place. Refusing
  the foreign slot and refreshing our own sibling were always different
  decisions; only the first was intended.

  It never rewrites `<hook>.aramid-chained` — that path is what a shim *execs*,
  so writing a shim into it would make it exec itself, an unbounded loop on
  every commit. It matches the same `startswith(hook)` + marker test as a real
  relocation, so the exclusion is explicit and pinned by its own test.

- **The notice for that slot asserted a staleness result from an arming
  check.** It read "not stale, nothing to resolve" whenever a relocated shim
  existed — but the check that produced it only established the shim was still
  *armed*, never that it was *current*. Those are different questions, and
  answering the second with the first is what kept a pre-`-P` shim invisible.
  The notice now reports what actually happened: regenerated, already current,
  or **stale and not regenerated**.

  That third state exists because regeneration is best-effort — a read-only or
  locked file must not fail the whole install — and "we could not rewrite it"
  is not "it did not need rewriting". The first draft of this fix collapsed
  those two into one boolean and so reported an unrepaired stale shim as
  current, reintroducing the same lie one layer down.


## [0.3.1] — 2026-08-15

### Fixed

- **The release workflow could not publish if the operator took more than a day
  to approve.** `gated-dist` was uploaded with `retention-days: 1`, while
  `publish-pypi` sits behind a required-reviewer gate that has no time limit.
  The two contradicted each other and the contradiction was invisible until the
  worst possible moment. Measured on the v0.3.0 run:

  ```
  artifact created   2026-08-12T07:33:40Z
  artifact expired   2026-08-13T07:33:40Z
  reviewer approved  2026-08-14T14:54:40Z    <- ~31h after the window shut
  ```

  ```
  ##[error]Unable to download artifact(s): Artifact not found for name: gated-dist
  ```

  The publish step then *skipped*, so nothing was published and the run went
  red — the operator having just authorised an irreversible upload. Now
  `retention-days: 90`, the public-repo ceiling; the correct bound is "longer
  than any human approval delay" and no smaller number expresses it.

  **What did not catch this is the interesting part.** The TestPyPI rehearsal
  exists to exercise "the gated-dist upload/download round-trip" before
  production, and it passed every time — because it runs immediately after the
  build, always inside the artifact's lifetime. A rehearsal that always runs
  inside the window cannot detect a window that closes. The gate being
  rehearsed was never the gate that failed.

  Recovery also needed the GitHub Release deleted first: `publish-testpypi`
  already anticipated re-runs with `skip-existing: true`, but `gh release
  create --verify-tag` collides with its own earlier output. Half the workflow
  was re-run aware and half was not, and nothing said so.

- **`RELEASING.md` told you to run the one command it also forbids.** Step 2
  read "Re-run `pip install -e .`", while the same document's "Never `pip
  install -e .` in this repo" section explains that doing so collapses the
  two-aramid separation and puts the uncommitted working tree in front of every
  consumer repo on the machine. The step predated the separation and was never
  revisited. Following the release process literally would have compromised the
  machine, with `aramid doctor` then reporting it. Step 2 now regenerates the
  gitignored `src/aramid.egg-info` in place, which writes nothing to
  `site-packages`.

- **`test_version_flag_prints_the_real_version` was comparing two different
  aramids.** It spawns `python -m aramid --version` as a subprocess, and a
  child inherits none of pytest's `pythonpath = ["src"]` ini setting — so it
  resolved the INSTALLED wheel and compared that to the checkout's
  `__version__`. The assertion passed only while the two happened to agree, and
  went red on the first version bump after the separation existed. It now pins
  `PYTHONPATH` for the child, derived from `aramid.__file__`. Both halves were
  live at the time, which is what made it legible:

  ```
  bare subprocess   ->  aramid 0.3.0   (the installed wheel)
  PYTHONPATH=src    ->  aramid 0.3.1   (the checkout under test)
  ```

  The recurring rule: a seam that must reach a subprocess has to be an
  environment variable. An ini setting, a monkeypatch or a `sys.path` edit stops
  at the process boundary.

- **`injection-dataflow.python-query-built-then-executed` flagged code where
  the interpolated string never reaches the database.** The rule's sequential
  patterns pair on the *name* `$Q`, and semgrep's `...` spans the statement
  that rebinds it — so building a query, replacing it with a constant, and
  running a parameterized execute was reported as injection. Reported by a
  downstream repo with a three-line repro, reproduced here before any fix.

  They also killed the obvious hypothesis before reporting it. A probe form —
  interpolate into an unused name, then execute a *different*, wholly constant
  query — is **not** flagged, so the pairing is not scope-level, and the rule's
  genuine catches were not earned by the same looseness that produced the false
  positive.

  **The fix requires the replacement to be the very next statement, and that
  adjacency is load-bearing.** The first version allowed `...` between the two
  assignments and was measured to drop a true positive: with `...` there, an
  intervening `if` matches too, so a rebind on only *one* branch reads as
  unconditional and the still-vulnerable else path stops being reported. A
  precision fix that costs a true positive is not a precision fix; both
  directions are now pinned.

  Recall was the explicit constraint — the reporter said they did not want it
  traded for this — so it was measured rather than assumed, on seven arms
  (five from the round-69 fixture plus the two forms this rule catches on the
  new one). All seven survive. The reported repro used an f-string; the defect
  was never specific to one, so the fix covers all five build forms for both
  `execute` and `executemany` — the concatenation variant was found here, not
  reported.

- **`aramid override` could suppress a finding that is BLOCK-tier right now**,
  because it read the ledger's *stored* verdict instead of computing the
  current one. `policy.classify` computes a verdict when a finding is detected
  and the ledger is append-only, so the row never moves again. Every armable
  tool therefore stores `warn` for anything drained while its `*_block_armed`
  flag was false — and arming is retroactive by design, so those findings are
  BLOCK-tier afterwards while the row still reads `warn`.

  Measured, not reasoned: with `mutation_block_armed = true` and
  `policy.classify` returning BLOCK for the finding, `aramid override`
  returned 0 and wrote the suppression.

  **For mutation this is terminal rather than merely misleading.**
  `mutation_gate.mutation_gate_findings` skips any record whose status is not
  `open`, so once the override flips the status the armed BLOCK never surfaces
  again — permanently, silently, through a gitignored file with no reviewable
  artifact. That is the exact defeat the LLM branch of this command was added
  to prevent; LLM findings got a dedicated `is_confirmed_critical_llm` guard
  *because* their stored verdict is always `warn`, and mutation, tdd and
  red-proof have no such guard while the stored value is their only signal.

  The new check is **ORed with the stored verdict, never a replacement**, so it
  can only refuse more. Recomputing alone would also *widen* the command —
  dropping a rule from `block_rules` would make its already-stored BLOCK
  findings locally overridable — and widening what a gitignored file may hide
  is the one direction this command must never move.

  **Failure refuses.** The first cut of this fix caught every exception and
  answered "not BLOCK-tier", justified in its own docstring as degrading to
  today's behaviour. It degraded to today's *bug*, on a path the person wanting
  the override controls: `aramid.toml` is an ordinary writable repo file, so one
  malformed line made `load_config` raise and handed the decision straight back
  to the frozen `warn` — a documented switch for turning this fix off. An
  unreadable config now refuses with its own message naming the config rather
  than the suppressions file, because "I could not answer the question" is not
  "you used the wrong channel".

  Note `[pack].pack_block_armed` defaults to **true**, unlike every other
  arming flag, so a pack-prefixed rule is BLOCK-tier even with no `aramid.toml`
  present. A pack finding stored `warn` is therefore one detected while pack
  was explicitly disarmed — exactly the case this fix is for, not a regression.

  **This left one residual, and it is CLOSED in this same release** by the
  gate-start invalidation sweep described below: an override recorded while a
  tool was *disarmed* used to survive arming. The paragraphs below are kept
  because the measurement in them was wrong in a way worth recording.

  That residual was **not theoretical, and this repo was an instance**. As
  originally measured on aramid's own ledger:

  ```
  aramid ledger filter --status overridden --tool <t> --json
    mutation   2      tdd  1      red-proof  6
  ```

  **That count — nine — was wrong, and the error was one of omission.** It
  enumerated three tools and silently dropped `llm-review`, which holds **ten**
  more. The real population is **19**, re-measured from the ledger rather than
  recalled:

  ```
  finding_overridden events                     22
  distinct findings, materialized "overridden"  19
    llm-review 10   red-proof 6   mutation 2   tdd 1
  ```

  The nine figure had already travelled: it was quoted to a downstream repo,
  who reasoned from it when arguing the migration policy for legacy rows. Their
  argument survived the correction — 19 is still bounded and still countable in
  advance — but the number did not, and nothing in either process would have
  caught it. A count enumerated tool-by-tool is only as complete as the list of
  tools you thought to type.

  All 19 store `verdict: "warn"` and all four tools are currently disarmed, so
  nothing was being defeated — they are legitimate bake-time suppressions. But
  arming any of those tools silently promotes the findings underneath them, and
  the two mutation rows would become permanently invisible to the gate, because
  `mutation_gate_findings` filters on `status == "open"` *before*
  `policy.apply_overrides` ever sees them. Note the asymmetry that makes
  mutation the severe case: freshly-scanned findings do reach `apply_overrides`,
  which re-checks the **current** verdict and refuses to downgrade a BLOCK
  (`test_override_does_not_downgrade_block_finding`), so for
  ruff/semgrep/tdd/red-proof a stale override is misleading rather than
  load-bearing.

  Fixing the existing rows was therefore a *different* change from refusing new
  ones: refusing future overrides does nothing about the 19 already recorded.
  What closes it had to decide what an override recorded under one arming state
  means under another — at the gate, not at the CLI. That is exactly what the
  sweep below does.

### Added

- **Arming now revokes an override that was granted while the class was
  disarmed.** An operator who suppressed a WARN was never asked whether they
  would suppress a BLOCK; arming asks a question their override never answered,
  so the override stops binding and the finding returns to `open` for
  re-adjudication. This closes the residual named under the `aramid override`
  fix above.

  **Recorded as an event, never computed from config at read time.** Computed,
  disarming would silently restore the suppression — the predicate just flips
  back, and a security decision would be undone by editing a TOML key with no
  record it ever applied. As an event, the append-only log makes revocation
  one-way for free: nothing about disarming emits a counter-event, so
  re-suppressing costs a new decision that leaves an artifact.

  **Emitted from a sweep at gate start, never from the detection path.** Every
  armed tool's gate skips records whose status is not `open` — mutation's is
  the sharpest — so an invalidation waiting for the finding to re-fire would be
  eaten by the very filter that makes a defeated block permanent: suppressed,
  therefore never re-detected, therefore never re-opened.

  The sweep reuses the *same* composite `aramid override` refuses on rather
  than mapping tools to their `*_block_armed` flags. Two implementations of one
  question drift, and a flag-keyed map gets the LLM case wrong:
  `policy.classify("llm-review", ...)` always returns WARN, so `llm_block_armed`
  promotes only confirmed-CRITICAL findings — a tool-keyed sweep would revoke
  overrides arming never touched, which is 10 of this repo's own 19 rows.

  Each invalidation records a **cause** — `recorded_disarmed` when the override
  carries the arming state it assumed, `arming_state_unrecorded` for rows
  written before that field existed — and the report gives the count broken
  down by cause rather than summed. "9 override(s) invalidated by arming:
  arming state was not recorded when they were made" is a different message
  from a bare notice, and it is the difference between an operator
  re-adjudicating and an operator hunting for a bug.

  `aramid override` now records the arming state in force when it grants a
  suppression, collected by *walking* the config for `*_armed` rather than from
  a literal list of today's six flags — a list is correct the day it is written
  and silently wrong the day someone adds the seventh.

  **Known and stated rather than discovered later:** this repo cannot dogfood
  the mechanism. Its blast radius here is a measured zero, because all four
  tools holding overrides are disarmed and no `llm-review` row is
  confirmed-critical. The first real firing will be on a consumer's machine.

- **`ledger list`, `show` and `filter` now report the tier a finding has NOW,
  not only the one frozen at detection.** The stored `verdict` is a snapshot
  `policy.classify` computed when the finding was detected, and the ledger is
  append-only so it never moves again — while arming is retroactive and rules
  get demoted. A row could read `warn` while the finding blocked today, with
  nothing on it saying so.

  `verdict` stays frozen deliberately: an auditor still needs "what would this
  be if the suppression were withdrawn". `verdict_now` is the missing other
  half, and it appears on **every** `--json` row, including those whose tier
  has not moved — a field present on some rows and absent on others invites the
  reader to infer meaning from the absence, and that inference is unverifiable
  from the row. Which value you are reading is therefore answered structurally
  rather than by a provenance flag nobody can check.

  The text surface is the deliberate exception: `[now: block]` appears only
  when the tier actually moved. That row never printed `verdict` at all, so
  there is no pair to disambiguate and an unconditional marker would be noise.

  An unreadable config now **refuses** these queries (exit 3) rather than
  emitting rows with a null tier, mirroring `aramid override`: being unable to
  read the config is being unable to answer. This deliberately differs from the
  suppressions handling in the same command, where a malformed file leaves the
  per-row marker absent — that is a marker whose absence carries meaning, this
  is a value promised on every row.

  The computation lives in a new `aramid.tier` module, shared with
  `override._is_block_tier_now`. What is *not* shared is the ratchet:
  `verdict_now` reports truth and may answer WARN for a row stored `block`,
  while `override` ORs with the stored verdict so it can only ever refuse more.
  Widening what a gitignored local suppression may hide is the one direction
  that command must never move, and a test pins it — proven to bite against a
  scratch copy with the composite collapsed.

- **The SQL blind-spot fixture is now an executable contract.** 14 forms in
  which every hazardous shape is paired with a safe twin that looks almost
  identical, so a matcher keying on syntax rather than flow is caught
  over-firing rather than rewarded for it — most sharply the `+=`-in-a-loop
  pair, where the *correct* variable-length-clause idiom differs from the
  injection by very little.

  **Four of the seven real hazards are not reported by this rule** —
  cross-function assembly, attribute targets, container-built-then-iterated,
  and `+=` in a loop.

  Three of the four are also missed by the reporter's independent taint oracle,
  which is the failure mode two independent implementations are meant to rule
  out: they fail together because they fail for the same structural reason,
  both reasoning within one scope about one name. Any recall figure derived by
  comparing them is uninformative on that class.

  **That cross-tool count is recorded here as attribution, not as a
  measurement, and the tests deliberately no longer state it.** It was four
  when first written and three under two hours later — fixing an unrelated
  defect in that oracle moved one form into its claimed set. It describes a
  tool in another repository that cannot be run or read from here, so it is
  inherited by construction and free to go stale silently, which it did, inside
  a comment that read like something measured. The tests now assert only what
  they can observe about this rule; the cross-tool status lives in the channel
  record where it is dated and attributed.

  Those four are marked `xfail`, **not** asserted absent. Asserting them absent
  would encode four defects as expected behaviour and hand a red "regression"
  to whoever eventually fixes one; a fix should flip them to XPASS. The fixture
  is a probe, not a benchmark — every shape in it came from a *published*
  blind-spot list, so it holds the gaps both sides already knew about and
  structurally cannot hold the ones they do not.

- **`ledger filter` now says which open findings anyone has actually looked
  at.** A committed suppression lives in `.aramid-suppressions.toml` and never
  reaches a ledger row, so an adjudicated finding and one nobody has ever
  examined were shape-identical: both `status: open`, both `verdict: block`,
  both `reason: null`. `check` distinguishes them (a suppressed finding renders
  INFO); `ledger filter` is the surface a reader uses to ask *what is
  outstanding*, and it did not.

  Reported from a downstream repo, where it hid a real never-adjudicated `S105`
  among nineteen reviewed rows — a finding that had been open for weeks because
  a range-scoped gate had never had that file in scope.

  `--json` gains `suppressed` and `suppressed_reason`; the text row gains a
  `[suppressed: <reason>]` marker. **`verdict` is deliberately left alone** —
  it is the finding's own tier, a suppression is a separate decision about it,
  and collapsing the two would lose the ability to ask what this would be if
  the suppression were withdrawn. Additive, so existing readers are unaffected.

  Replayed against aramid's own ledger before shipping, which immediately
  corrected a misreading of it: of four open findings, two are adjudicated. The
  session that added this had described all four as outstanding.

### Fixed

- **Three defects in this release's own fingerprint fix, found by aramid's own
  reviewer reviewing it.** The drain reviewed the commits above and raised
  three findings against them. All three were real.

  1. **The semgrep adapter resolved a tool-reported path against the wrong
     root.** `file=` was relativized with `ctx.root` while the line-content
     read got the raw `item["path"]` and a bare `Path(...)`, i.e. the aramid
     process's cwd. semgrep runs with `cwd=ctx.root` and reports
     invocation-relative paths, so whenever the process cwd differs the read
     either fails — silently reverting to the ref lookup the fix exists to
     avoid — or finds a **same-named file elsewhere and succeeds**,
     fingerprinting a line from an unrelated file. `scanned_line_reader` now
     takes the root as a required argument and resolves relative paths against
     it.

  2. **A failed read silently reverted to the skewed ref lookup.** The reader
     returned `None` on an unreadable file or an out-of-range row, and `None`
     already meant "this runner does not participate" — so the rare failure
     path quietly reinstated the exact hazard, with nothing in the output
     saying which source an id came from. A converted runner now always makes a
     positive statement: failures yield `CONTENT_UNREADABLE`, a value that
     cannot occur in source and therefore cannot collide with an adjudicated
     finding's id.

  3. **The widened-scope note quoted the pre-filter file count.** `len(files)`
     was interpolated inside `_discover_files`, before `run_gate` applies the
     ignore-path filter, so the note claimed coverage of files the runners were
     never handed — in the one report a reader uses to decide whether an absent
     finding means clean or unscanned. `_discover_files` now returns the cause
     and `run_gate` composes the note with the filtered count. Measured: 4
     tracked files, `vendor/**` ignored, note reads "scanned all 3".

  Known, not fixed here: running `check` from a **subdirectory** degrades
  semgrep and gitleaks entirely. Found while trying to exercise (1) end to end,
  which is why (1) is pinned by unit tests against `scanned_line_reader` rather
  than through the CLI.

- **`_skip_streak_lines`' docstring still specified the rule that was removed
  for a security reason.** `06e7f46` replaced "a gate's eligible set is the
  tools that have actually appeared at it" with a recorded `expected` set,
  because the old rule cannot see a scanner that never started. The inline
  comment explaining that landed; the docstring six lines above it kept
  presenting the old rule as the design — including its rationale ("no runner
  table to keep in sync"), which is the argument for reintroducing the blind
  spot.

  Found by not dismissing a stale-looking finding. aramid's own LLM reviewer
  had flagged this and the finding was still open; the reasonable-sounding read
  was "the code is fixed, so the finding is stale and `auto_resolve_llm` has a
  gap." Neither half was true. The reviewer had quoted the **docstring**, the
  docstring was still wrong, and the resolver was right not to fire — it
  resolves on the quote disappearing, and the quote was still there.

  This is the third recorded instance of `auto_resolve_llm`'s documented
  known limitation (a fix that does not move the quoted line leaves the finding
  open), and the first where the finding was still saying something true. The
  docstring now states what the code does and says plainly not to reintroduce
  the old rule.

- **A push could silently scan the whole repository instead of its own
  changes.** A downstream repo pushed a branch (0 blocking), then pushed a tag
  off the same tree thirteen minutes later and was blocked by 20 pre-existing
  findings in files its commits never touched — mid-release, with the tag
  already cut and a force push off the table. Nothing in the output
  distinguished a whole-tree scan from a delta scan, so it read as a
  regression.

  `_discover_files` falls back to the entire tracked tree whenever
  `gitutil.resolve_range()` returns `None`, and that fallback is correct: the
  alternative diffs against a bare `HEAD` and scans nothing, which is the worse
  failure. The defect is that the comment describing it said "brand-new repo,
  first push" while the actual trigger is "no upstream resolvable" — which also
  covers **a detached HEAD, a tag checkout, and any branch without an
  upstream**. Measured: a branch with an upstream resolves `@{u}..HEAD` and
  scans its delta; the same repo detached at a tag scans every tracked file.

  The fallback stays. What changes is that it announces itself, first, above
  the findings:

  ```
  note: scanned all 2 tracked file(s), not this push's changes: no upstream to
  diff against (detached HEAD, a tag checkout, or a first push). Pre-existing
  findings anywhere in the repo apply here
  ```

  Also on `GateResult.scope_widened` and in `--json`, so a consumer diffing
  finding counts between two runs can tell a regression from a scope change.
  `--all` stays silent — that widening is the operator's own request.

- **`# nosemgrep: <the rule id aramid prints>` could never match.** semgrep
  namespaces rule ids by config path, and this ruleset ships inside the
  installed package — so the id semgrep matches against contains an absolute
  path (including the username under a wheel install), while the id aramid
  prints is the canonical one, deliberately stripped so it is identical in
  every clone. That stripping is what makes ids safe to commit in
  `block_rules.toml` and a suppressions file, and it is exactly what makes the
  printed id useless in semgrep's own suppression syntax. A repo wrote 20
  markers with the printed id; every one silently did nothing.

  A semgrep finding now says how to suppress it: `.aramid-suppressions.toml`
  (portable, reviewed, binds by finding id), that `# nosemgrep: <rule>` will
  not match and why, and that a bare `# nosemgrep` works but silences every
  rule on the line. Shown only when a semgrep finding actually fired.

- **A suppression could be inherited by a line nobody adjudicated.** Reported
  from a downstream repo as "suppression ids bind to position, so a cosmetic
  edit un-suppresses". The premise was right and the mechanism was not, and the
  real one is a security defect rather than an ergonomic one.

  `compute_fingerprint` has no line number in it, and a *staged* comment
  insertion is perfectly stable — measured, as a control. What is not stable is
  the pair of sources `normalizer.normalize` was reading from: the line
  **number** came from the scanner, which read the **working tree**, while the
  line **content** came from a blob chosen by `_ref_for_builder` — the
  **index** at pre-commit. Those agree until anyone has an unstaged edit, and
  then `lines[raw.line - 1]` is a different line of code than the one that was
  flagged.

  Measured consequence, with a firing control (same suppression bound
  correctly when nothing was skewed):

  ```
  [select]      8c148186f0b3  S608 app.py:2  verdict=block   <- baseline
  [suppressed]  8c148186f0b3  S608 app.py:2  verdict=info    <- control
  [skew]        8c148186f0b3  S608 app.py:2  verdict=info    <- the DELETE line
  ```

  The index held a reviewed `"SELECT * FROM " + table`; the working tree held a
  never-reviewed `"DELETE FROM " + table`. The DELETE was reported under the
  SELECT's id and downgraded to INFO. **A decision made about one statement
  silently covered a different one** — the direction a security tool may not
  fail in. The reported symptom (adjudicated findings resurfacing) is the same
  bug pointing the other way.

  Fix: the runner already read the line, so it now carries it.
  `RawFinding.line_content` is optional and additive; `normalize` fingerprints
  it when present and falls back to today's ref lookup when absent.

  **Converted: `ruff` and `semgrep`** — both scan the working tree, and both
  produced this. **Not converted: `gitleaks`**, deliberately. Its history scan
  reports lines out of *old commits*, where the working tree is the wrong place
  to look and the existing `commit`/`ref_for` path is correct. Consumers are
  unchanged. Naming which runners moved matters: a half-restored invariant that
  reads as a whole one is the defect class this release keeps finding.

  **Id churn is limited to findings that were already skewed.** A fully-staged
  repo fingerprints identically before and after — the cross-mode stability
  test (pre-commit / pre-push / --all) still passes unchanged. Nobody needs to
  re-adjudicate a suppression that was binding correctly.

### Changed

- **One grammar down the `status` column: every head-scoped consumer note now
  reads `(last seen @ <sha>)` instead of a bare `@ <sha>`.** Requested by a
  downstream consumer, whose argument was about the column rather than any one
  note: the timeout family already said `(last seen @ ...)`, these sat directly
  beneath it, and *a reader learns the grammar from whichever note they meet
  first*. A bare `@ <sha>` teaches them to read the sha as a causal claim —
  precisely the misreading the timeout reword removed.

  The sha itself was never wrong here. A red baseline really was red at that
  head, and head-scoping is deliberate: a new commit can fix a red suite, so it
  deserves a fresh attempt. Only the wording moved.

  Six sites, five note families, three consumers — `mutation`, `js_mutation`
  and `dast`. The consumer only reported the first; the other four came from
  asking the code graph who else calls `prior_note_count`, which found `dast`'s
  pair after a string search for the two known literals had already come back
  "complete". Fixing three of five would have left the column bilingual and
  achieved nothing the request was about.

  These strings are load-bearing — the give-up counters match live ledger rows
  by prefix — so `mutation.failing_note_prefix()` and
  `js_mutation.link_note_prefix()` are now the single definition each counter
  and each emit site calls, making a half-applied reword unrepresentable.
  (`dast` already bound both prefixes to locals used at both ends.)

  **Deliberate one-time cost:** notes already in a ledger keep the old spelling
  and no longer satisfy the counters, so any item mid-streak restarts at zero
  and takes up to 3 more DEGRADED retries before standing down. Bounded,
  per-item, and pinned by a test so the next reader meets it as a decision
  rather than as a latch that looks broken.

  Also pinned: one test asserting the literal wording of all three families.
  Every other assertion here compares `res.note` to `failing_note_prefix(head)`
  — both sides from one function, which proves the producer is deterministic
  and would hold just as well if it returned `"potato"`. Verified against a
  perturbed copy of the source: the literal pin went red naming the change; the
  equality assertions passed.

### Fixed

- **`aramid status` could not report a scanner that never ran**, which is the
  case a missing security control actually looks like. Found by aramid's own
  LLM reviewer, in the diff that fixed the *opposite* bug — the 0.3.0 change
  that stopped a tier-absent tool being wrongly reported as skipped derived
  each gate's eligible set from tools that had **previously appeared** in that
  gate's runs. Misconfigure semgrep, rename it, or have it fail before it ever
  records, and it never enters the universe and is never reported at all.

  Pre-existing rather than introduced — the original built its tool set the
  same way — but it is the same *absent-renders-as-healthy* class as the rest
  of this work, left standing in the function being edited.

  Neither existing source could answer it. `toolset.selected_tool_names` unions
  across **every** gate (deliberately: ruff findings must count as selected
  when checking a pre-commit finding), and `GATE_RUNNER_KEYS` is gate-scoped
  but holds registry **keys**, which are not what runs record — the tests slot
  records `pytest`, never `tests`, so comparing keys to labels would report a
  healthy suite as skipped forever. Turning a blind spot into a false alarm is
  the worse trade.

  `RUN_STARTED` now records a gate-scoped `expected` set, computed in
  `run_gate` because that is the only place holding the gate and the config at
  once — `status` reads a historical event and can re-derive neither. New
  `toolset.expected_tool_names(root, cfg, gate)` shares the key→label expansion
  with `selected_tool_names` via `_expand_keys`, so the two cannot drift.

  Absent-vs-empty is load-bearing here too: a ledger with no `expected` key
  falls back to the old observed-universe rule, while an empty one is a
  positive claim that the gate expects nothing.

  Interim advice given to the consumer repo while this was outstanding, and
  still worth stating: **absence of a skip line was not presence of a
  scanner** — read `RUN_STARTED.tools` directly.

- **`check --json` undercounted which tools ran, and read like a complete
  count.** A consumer compared two of aramid's own surfaces for one run and got
  `['gitleaks', 'semgrep']` from `--json` against
  `['gitleaks', 'pytest', 'semgrep']` from the ledger.

  `_tool_provenance` is correct: `toolpath.PROVENANCE_TOOLS` holds only the
  three runner keys that are also executable names, and `tests` is excluded on
  purpose because there is no `tests.exe`. The **JSON name** was wrong — called
  `tools`, the provenance map reads as "the tools that ran", so anyone asking
  "did the suite run in this gate?" reasoned from an undercount.

  Fixed additively: `tools_ran` carries the same value `record_run` writes to
  `RUN_STARTED` — not a re-derivation, since the two disagreeing is the defect.
  Renaming `tools` would break anyone reading provenance, and provenance is not
  a superset of what ran, so one key cannot serve both questions.

  The consumer's framing of the class is better than the one in 0.3.0's notes
  and is adopted here: not only *what does a report print when it has nothing*,
  but **what does it print when it has only part of something.**

## [0.3.0] — 2026-08-12

Cut so a downstream consumer can pin to an immutable artifact instead of running
an editable install of this repo's working tree. Everything below came out of
interop rounds 64–69 with that consumer, which ran the gate against a real
2900-test repo for several days and reported what it saw.

**The whole release is one defect class**, found nine times: *a report that
cannot distinguish "absent" from "bad".* A timeout reported as a failing test. A
give-up recorded as success. `kill-rate n/a (0/0)` rendered like a low score. A
line number frozen while the code moved. `skipped` covering three different
states. A run that generated 18 mutants, tested none, and reported `ok`. Each
one sent a reader toward the opposite of the correct remedy.

### ⚠ Downgrading from 0.3.0 is one-way

`Ledger.events()` constructs `EventType(value)` strictly, so **an aramid that
does not know an event type raises on every read** — `status`, `check`, all of
it. 0.3.0 writes two event types 0.2.0 has never seen (`finding_moved`,
`resolver_yield`), so once a 0.3.0 gate has run, that repo's `.aramid/ledger.db`
can no longer be read by 0.2.0.

Verified, not inferred: `EventType('some_future_event')` raises `ValueError`.

Nothing is lost — the ledger is intact and 0.3.0 reads it fine — but a rollback
needs the ledger moved aside. Deliberately **not** "fixed" by making unknown
events skippable: silently ignoring an event a future version considered
important (a resolution, a suppression) is a worse failure than a loud one, in
an append-only audit trail. Flagged rather than papered over.

### Added

- `aramid ledger filter --json`, and `--gate`-free structured output generally:
  the one-line text row put id, `tool:rule`, `file:line` and a free-text message
  on one line, which silently mis-tagged a consumer's batch of 26 overrides.
- `[mutation].baseline_timeout_s` / `[js_mutation].baseline_timeout_s`.
- `finding_moved` ledger event, so a finding's reported line follows the code.
- `injection-dataflow.python-query-built-then-executed` — WARN-tier SQLi rule
  covering build-then-execute, which the existing call-site-only rule was blind
  to (measured 3/3 inline caught, 0/4 assigned).
- `aramid status`: `consumers stood down:` and `consumers doing no work:`.
- `check --json`: `escalated_by_ratchet` and `verdict_before_ratchet` per
  finding.

### Fixed

- **`check --json` reported `block` for findings the ledger recorded as `warn`,
  with no way to tell why.** Reported by a consumer that came within one step of
  concluding a deliberate WARN-tier rule decision had failed.

  Diagnosed first as staleness and **that diagnosis was wrong** — the consumer
  measured the disagreement at *first detection*, where staleness cannot reach.
  The real mechanism: `run_gate` calls `record_run` **before** the
  no-new-warnings ratchet, and the ratchet then rebinds `findings`. Both values
  are computed in the same run and both are correct for their own purpose — the
  ledger holds the intrinsic verdict, `--json` the effective one for this push.

  So `verdict: block` was covering two conditions with opposite remedies: fix
  the security issue, versus you added a new warning and it stops escalating
  once the finding is no longer new. `new_ids` was already in the payload and is
  **not** sufficient to derive this, since a brand-new finding can be BLOCK on
  its own merits. Now stated explicitly.

  aramid already knew: it is written down in
  `tests/integration/test_gates_end_to_end.py` as "an artifact of the ratchet" —
  in a place no consumer would ever read.

- Three more emitted strings carrying a literal U+2014, which a redirected
  Windows stdout writes as the invalid byte `0x97`.

- **A new vendored rule namespace was not registered, so its findings carried a
  machine-dependent id.** Introduced by the SQLi rule in `6c86ec9` and caught by
  the consumer repo that verified it (interop round 66): they queried the rule
  id we documented and got a clean, confident `[]`.

  `_canonical_rule_id` strips semgrep's config-path prefix by looking for a
  known namespace in `VENDORED_RULE_PREFIXES`. `injection-dataflow.` was never
  added, so live check_ids kept the prefix —
  `F.Projects.aramid.src.aramid.rules.injection-dataflow.…`, the absolute path
  of whoever's checkout produced them. `semgrep.py` documents this requirement
  in a comment directly above the tuple; the rule was added without it.

  Worse than the wrong report: **`compute_fingerprint` takes `rule` as an
  ingredient**, so the finding *id* was machine-dependent too, and a suppression
  or override written on one checkout would have bound nothing on another.

  The existing guard could not catch it — it iterated `VENDORED_RULE_PREFIXES`
  and checked those entries, validating the list against itself. The new test
  derives namespaces from the shipped `owasp.yml` and fails until each is
  registered, so the next new namespace cannot repeat this.

- **A mutation run that generated mutants and tested none reported `ok`.** The
  third instance of this round's defect class, and one that only appeared *after*
  the first two were fixed: with `baseline_timeout_s` raised, the baseline
  succeeds, the wall budget — whose clock starts before the baseline — is then
  already spent, and the run ends `state: ok`, `finding_count: 0`, note
  `0 confirmed survivor(s) of 0 mutant(s) tested`. Measured downstream at 18
  mutants generated, 0 tested, 690 s per drain, with neither a degraded streak
  nor a stand-down in `status`.

  **This is why raising the default budget alone would have been the wrong
  move**: it converts a loud stand-down into a silent success. The note now says
  `no mutants tested: N generated, 0 certified`, names `wall_budget_s` and the
  baseline's measured cost, and `status` gained a `consumers doing no work:`
  section — a streak, self-clearing, with the recurring cost stated.

  The drain state stays `ok` deliberately. `degraded` would stop the item being
  marked drained; the reporting repo measured a queue item stuck for **61 hours**
  from exactly that. Drain state and report answer different questions, and
  conflating them is what produced this bug and the give-up bug both.

- **A finding's recorded line froze at first detection while the code moved
  around it.** Reported from a consumer repo (interop round 64 item 6) auditing
  26 findings: the ledger named `storage.py:892` while the site had moved to
  905, so auditing by the recorded number reads the *wrong code*. They matched
  all 26 by content, by hand.

  The identity was never at fault — `compute_fingerprint` hashes the line's
  **content**, not its number, which is exactly why those findings survived the
  move and stayed matched. Only the reported number was stale, because
  `record_run` appends `finding_detected` solely for findings that are new or
  resurrecting, and `_materialize` copies the payload only from that event.

  New `FINDING_MOVED` event, emitted when a re-detected finding's line differs,
  applied by `_materialize` to `line` and nothing else. **Re-issuing
  `finding_detected` would have been the obvious fix and is wrong**:
  `_materialize` rebuilds a finding's whole record from that payload and resets
  `status` to open, so a move would silently un-override every triaged finding —
  which for the reporting repo would have quietly re-armed all 26 they had just
  audited. Guarded on an actual change, since this runs for every open finding
  on every gate run and the unguarded version trades a stale number for a ledger
  that grows a row per finding per run.

- **`mutation-score` rendered an absent measurement identically to a bad one.**
  Round 64 item 4's remainder. `kill-rate n/a (0/0) (partial)` for essentially
  every function reads as "coverage is poor" when it actually means nothing was
  measured at all — in the reporting repo, because the mutation baseline could
  never finish. Unmeasured targets now render `not measured (0 mutants tested)`,
  and when *no* target has a measurement the report says so once at the top and
  points at `aramid status`, where the degraded or stood-down consumer explains
  why. A genuine `0.00` — mutants tested, none killed — is deliberately left
  loud, and a test pins that it is not softened.

- **`status` called a tool "skipped" when it simply belongs to another gate's
  tier.** Round 64 item 8, reported as a puzzle rather than a bug: a persistent
  `ruff: skipped last 1 run(s)` whose `ruff check .` passed by hand.

  Nothing was broken. `GATE_RUNNER_KEYS` puts ruff at pre-commit only and
  semgrep/tests at pre-push only, and `_skip_streak_lines` counted absence from
  `RUN_STARTED.tools` across *all* runs — so every pre-push run read as a ruff
  skip. One word was carrying both "ran and failed" (a hole in the gate) and
  "not part of this gate" (the gate working as designed).

  The tool universe is now scoped **per gate**, derived from what has actually
  appeared in that gate's runs — so no runner table to keep in sync, and the
  tests-runner alias (`tests` the key, `python` the recorded label) needs no
  special case. The line names the gate. Confirmed on aramid's own `status`,
  which was reporting the identical false `ruff: skipped last 2 run(s)` and now
  reports nothing.

- **A mutation baseline TIMEOUT was reported as a baseline FAILURE**, so
  mutation testing was dead for three days in a consumer repo while `status`
  told the reader to go looking for a broken test. Reported from that repo
  (interop round 64) with the evidence that made it obvious in hindsight: 11
  consecutive baseline runs between 482.8 s and 486.6 s — **under 1 % spread,
  which is the shape of a budget, not of a failing suite** — against a suite
  that passes standalone in 985 s.

  `consumers/mutation.py` tested `base_res.state is not ToolState.OK or
  returncode != 0`, which swallowed `ToolState.TIMEOUT` into the
  failing-baseline branch. The two states demand opposite responses — fix a
  test, versus raise a budget — so one note for both is the whole defect.
  Fixing only the wording would have left mutation dead; fixing only the
  budget would have left the next timeout equally illegible.

  - The timeout branch is split out and names the budget it exceeded. The
    **elapsed time is deliberately not reported**: the process is killed *at*
    the budget, so "elapsed" there restates a number you already set. The real
    measurement is now recorded on runs that finish, as `extra["baseline_s"]`.
  - New `[mutation].baseline_timeout_s` (and `[js_mutation].baseline_timeout_s`),
    defaulting to the previous `mutant_timeout_s * 4`. A per-mutant timeout
    pressed into service as a whole-suite budget is a guess, and a repo whose
    suite legitimately exceeds it needs a setting it can point at. An
    auto-derived budget was considered and rejected: a suite that times out
    never yields a measurement to derive from.
  - **`consumers/js_mutation.py` carried the identical merged branch** and was
    fixed with it. Only the Python path was exercised downstream, so fixing one
    would have shipped the same bug alive on the other with nothing to find it.

- **The give-up path never latched, so a dead consumer kept running forever.**
  Same report. `consumers/base.prior_note_count` filters on `item_id`, and the
  mutation give-up prefix embedded `item.head[:12]`, giving the counter **two
  independent reset paths**: an advancing head changed the prefix, and a
  give-up returning `ok` let the drain drain the item so the next drain arrived
  with a fresh id and a count of zero. Downstream that produced exactly one
  give-up event, after which the same ~8-minute run resumed every 4 hours.

  A timeout give-up is now **repo-scoped** via the new
  `base.note_count_any_item`, because "this suite does not fit this budget" is
  a property of the repo and no commit changes it. The failing-baseline give-up
  stays head-scoped, because new code genuinely can fix a red suite.

  Repo-scoped means permanent, so the note is **keyed on (suite command,
  budget)** — the two things an operator can change. Raising the budget or
  narrowing the command stops the prefix matching and mutation retries. Without
  that release valve this would be a one-way door.

  The give-up deliberately still returns **`ok`, not `degraded`**: the drain
  refuses to mark an item drained while any consumer is degraded, so degrading
  here would pin the queue item and re-run every other consumer on it forever,
  trading a wasteful loop for a total stall.

- **A consumer that gave up reported as healthy.** Because a give-up returns
  `ok`, it ends the degraded streak `status` reports — so the moment a consumer
  permanently stopped, it started looking exactly like a working one. Making
  the latch above actually hold turns that from a rare accident into the steady
  state, so `aramid status` gained a `consumers stood down:` section, shipped in
  the same change. It states the cost (`stood down after N run(s), Xs spent`)
  and carries the note, which names the setting that clears it. Self-clearing,
  like the degraded streak beside it.

- **`aramid ledger list`/`filter` emitted invalid UTF-8 on redirect.**
  `_render_row` used a literal `—` (U+2014); Windows selects the ANSI code page
  for a redirected stdout, which writes it as the bare byte `0x97` — not valid
  UTF-8 in any position. A consumer repo's audit script got mojibake off a
  redirected `ledger filter`. Fixed at both levels: the separator is now ASCII
  `--`, matching every other rendered line in the codebase, and `cli.main`
  forces UTF-8 on non-tty streams so tool-authored text (semgrep messages,
  paths, snippets) cannot reintroduce the class.

- **`aramid ledger filter --json`**, which `mutation-score` already had. The
  one-line text row puts id, `tool:rule`, `file:line` and a free-text message on
  a single line, so a consumer splitting on whitespace swallows the message into
  the file field — that silently mis-tagged a downstream repo's first batch of
  26 overrides. An empty result prints `[]`, not prose, because a caller forced
  to special-case "no matching findings" is a caller that starts guessing.

### Security

- **aramid's own vendored SQL-injection rule missed the most common shape.**
  Reported as an upstream issue; it is not — the rule ships in
  `src/aramid/rules/owasp.yml`. All six of its patterns require the string
  operation to be visible **at the call site**, so it sees `execute(f"...")`
  and is blind to `q = f"..."` followed by `execute(q)`. Measured against a
  7-form fixture: **3/3 inline caught, 0/4 assign-then-execute caught.**

  New rule `injection-dataflow.python-query-built-then-executed` closes the
  assign-then-execute class; coverage on that fixture goes 3/7 → 6/7, with zero
  hits across five safe forms (parameterized queries, and an f-string that
  never reaches `execute`).

  It is **WARN tier, and its id is a tier decision**: `block_rules.toml`'s
  `[semgrep].block` list is fnmatch and contains the substring glob `*sqli*`,
  so the obvious name would have made a deliberately-broader rule blocking
  everywhere `semgrep_block_armed` is on. The repo that reported this had
  audited all 26 hits of the narrow rule and found 26 false positives, so a
  wider net at blocking tier would stop pushes on correct code — and a blocking
  rule people cannot satisfy is one they turn off, taking the true positives
  with it. `tests/unit/test_policy.py` pins the WARN classification **with
  blocking armed**, so a well-meaning rename cannot promote it silently.

  Remaining gap, stated rather than implied: a query assembled via
  `"".join(parts)` or through more than one intermediate variable is still
  missed. Closing it needs taint mode, which also re-reports every inline case
  and cannot tell a constant table name from a request parameter.

- **`check --all` did not scan for secrets, and marked secrets already found
  as fixed.** The most serious defect found so far, in the BLOCK tier, and
  found only by running the published wheel against a throwaway repo.

  `pipeline._discover_files` returns `rng = None` for `mode == "all"`, and
  `rng` overloaded `None` to mean **both** "staged" and "not range-based" —
  so gitleaks fell through to `git --staged`, met an empty index, scanned
  **nothing**, and reported `ToolState.OK`.

  Reporting `OK` is what made it dangerous rather than merely useless. `OK`
  puts gitleaks in `scope_tools`, and `record_run` then resolves any open
  gitleaks finding whose file is in scope — which under `--all` is the whole
  tracked tree. Measured end to end on 0.2.0: two committed secrets that
  gitleaks finds when run directly, `check --all` reporting "no findings",
  and both prior BLOCK findings written `finding_resolved` while the secrets
  sat untouched in the files. **Committing a leak is what marked it fixed**,
  permanently, into an append-only audit trail. Language-independent — the
  `.py` file was missed the same way. `--all` is the CI-parity mode
  `[hooks].pre_push_match_ci` runs on every push.

  Three changes, each forced by measuring the previous one:

  - `RunContext.full_tree` (set for `mode == "all"`) routes gitleaks to
    `gitleaks dir`, its working-tree scan. Range mode still wins, because
    only a history scan can attribute a leak to the commit that introduced
    it.
  - **Scan wide, report narrow.** `gitleaks dir` takes a single path and
    walks everything under it, *including files git ignores*: 24 hits here,
    of which 14 were in `.superpowers/` local review artifacts and
    `__pycache__/`. `--all` means all **tracked** files, and a finding in a
    path that can never be committed is one nobody can ever fix or retire.
    Filtered in `parse` rather than by narrowing the scan because passing a
    file list to `gitleaks dir` is silently ignored and it rescans the whole
    tree — confirmed rather than assumed.
  - **The budget follows the work, not only the gate tier.** A full-tree scan
    takes 9.4 s here and the pre-commit budget is **5 s**, because a commit
    hook has to feel instant — so `aramid check --all`, whose gate *defaults*
    to pre-commit, degraded the secret scanner on every run. `_BUDGET_KEY`
    already carried the intent (`Gate.ALL` → `pre_push`) but `Gate.ALL` is
    unreachable from the CLI. Now keyed on mode, so the ordinary staged
    pre-commit path keeps its tight budget.

  Verified on this repo: `degraded: []`, 10 findings reported (not 24), and
  on the throwaway repo the wrongly-resolved finding comes back as "STILL
  BLOCKING — seen before, and still failing this gate".

  **This shipped once, reverted, and came back — the revert is the
  interesting part.** The first attempt was verified only on the machine that
  wrote it, where the ledger holds weeks of triage and already carried every
  fixture hit as `not_a_secret`. CI clones fresh: `.aramid/` is gitignored, so
  there is no ledger, no baseline, and all of them are new BLOCK findings
  under `--strict`. Seven legs red. That is the same mistake this fix exists
  to expose, made one level up — the artifact was tested as a stranger to
  *find* the bug, then the fix was tested as its author.

  Two things the redo needed, neither of them guessable from the code:

  - **Two suppression entries, not ten.** Seven of the nine ids CI reported
    already matched `.aramid-suppressions.toml` unchanged. Only two moved,
    and only because gitleaks classifies that fixture differently by version:
    `aws-access-token` on 8.21.2 (which `doctor --fix` pins) and
    `generic-api-key` on 8.28.0 (which CI pins). The rule name is an
    ingredient of the fingerprint, so one fixture legitimately has two ids.
    `toolpath` resolves PATH-first and users run whichever gitleaks they
    have, so both are covered rather than forcing the versions to agree.
  - **Verification against the version CI actually runs.** gitleaks 8.28.0
    was downloaded and pointed at through a faked home directory — the first
    attempt at that used `PATH`, which silently did nothing, because
    `~/.aramid/tools/` wins over `PATH` for this tool. Confirmed by printing
    the resolved binary path rather than trusting the override. Both versions
    now measure `0` BLOCK findings and `0` stale suppressions.

  A third thing found on the way: the suppressions file **blocked on itself**
  the moment a fixture's literal key was quoted in an explanatory comment.
  Caught by the very scan being added.

### Fixed

- **A broken fuzz driver no longer reports itself healthy, and no longer eats
  the queue item.** Both driver-failure paths in `consumers/fuzz.py` returned
  `state="ok"` — one for a non-zero exit, one for output it could not parse.
  Measured on this repo's own ledger: **8 of 49 fuzz runs (16%) recorded `ok`
  having produced nothing parseable**, while every run reported zero findings
  and nothing anywhere distinguished that from clean code.

  The cost was not cosmetic. The drain marks a queue item drained *only* when
  every consumer finished cleanly, so `ok` from a broken driver consumed the
  item, dropped it, and never retried — the fuzzing opportunity was gone.
  `degraded` is the state the drain already understands (`ok = False`, item
  stays queued) and the state `dast` and `mutation` already use for exactly
  this. Fuzz was the sole outlier: a sweep of all six consumers found every
  other `state="ok"` to be a genuine skip (`no pack file`, `no js files in
  range`, `no dast target configured`) rather than a swallowed failure.

  Degrading alone would have traded a silent failure for a jammed queue, so
  the give-up comes with it: three broken attempts **at the same head** and
  the run reports `ok` with a permanent-skip note. Head-scoped, not
  item-scoped, because queue coalescing advances `item.head` under a stable
  `item.id` — counting per item would let new commits inherit an old head's
  verdict and never be fuzzed at all. This mirrors `mutation._BASELINE_GIVE_UP`
  and `dast`'s crash prefix down to the shape.

  A driver **timeout** is deliberately left `ok` and now pinned by a test: the
  wall budget doing its job is not a fault, and degrading it would put every
  budget-limited repo into a permanent retry loop.

- **`aramid status` shows consumers stuck in `degraded`.** The state was
  load-bearing and invisible — `last drain:` prints one consumer's name and
  finding count, and nothing printed state at all, so this repo's 38 degraded
  mutation runs appeared in no report. Reported as a streak of consecutive
  most-recent failures, mirroring the per-tool skip streaks directly above it:
  a lifetime count of a fault that has since been fixed is a line that never
  goes away, and a line that never goes away is one nobody reads. Carries the
  run's note, so the reader learns what broke without leaving `status`.

  Related, and checked rather than assumed: fuzz's zero findings across 3450
  cases is **honest**. Its 672 "contract exceptions" are the deliberate
  deep-crash oracle at work — only `IndexError`, `KeyError`,
  `ZeroDivisionError`, `AttributeError`, `UnboundLocalError`, `RecursionError`,
  `UnicodeError` and `OverflowError` count as crashes, and a `TypeError` or
  `ValueError` raised at fuzzed garbage is a function behaving correctly.

### Added

- **`aramid resolvers` — the gate now audits its own auto-resolvers.** Four
  times in this repo a resolver has been alive by every test and dead in
  production, and each was found by hand, once, by someone who happened to
  count. The largest: `gap_addressed` at **zero lifetime fires with eleven
  open mutation findings**, because `[hooks].pre_push_match_ci` runs the shim
  with `--all`, `--all` means mode `"all"`, and every range-scoped resolver
  sat behind `if mode == "range"`. Auto-resolution was entirely off for weeks
  and nothing reported it.

  Nothing *could*. **A resolution writes itself into the ledger; a
  non-resolution writes nothing**, so a resolver that examined a hundred
  candidates and declined them all leaves the same trace as one that was
  never called — none. `ledger.note_yield` records the missing half:
  `considered` alongside `resolved`, at the moment of looking, because
  opportunity cannot be reconstructed from the event log afterwards. All
  seven resolvers emit it.

  **The grading is the product, not the counting.** Two rows in this repo's
  real ledger both read zero — `mutant_killed` because no js-mutation
  findings exist here, `gap_addressed` because eleven candidates walked past
  it. Rendered identically they are noise, the report gets muted, and the
  detector for silent no-ops becomes one. So each row is graded against what
  was *available* to it: `live` / `no data` / `no opportunity` /
  `no clears yet` / `not instrumented` are healthy states, and only
  `NEVER RAN` and `BLIND` are defects. `aramid status` prints a pointer when
  any row is a defect, because a report that has to be remembered repeats the
  original failure one level up.

  **Only mechanism faults are defects, and that boundary was moved by
  measurement.** A first draft also flagged "saw candidates, cleared none".
  The first instrumented gate run in this repo returned two such rows, neither
  a fault: `evidence_gone/llm-review` (2 considered, 0 resolved — two ordinary
  WARN advisories nobody has fixed) and `file_departed/mutation` (2, 0). The
  second is the decisive one, because it is **near-permanent**: that resolver
  clears a finding only when its file has left the repository, so in a healthy
  repo it walks the open set every run and correctly resolves nothing, for
  ever. Flagging it brands a resolver broken for doing a rare job right.
  "Nothing cleared" is overwhelmingly "nothing was fixed", and a grade cannot
  tell those apart. That grade is now informational; `NEVER RAN` and `BLIND`
  survive because both say the resolver *could not* have worked.

  A correction worth recording, since it was shipped for one commit: the
  paragraph above previously argued the same conclusion from the two
  suppressed mutation findings, on the theory that a suppression binds by id
  without flipping ledger status and so its target can never resolve. **The
  first real run refuted that** — both resolved through `gap_addressed`,
  because the push touched their source file. The claim came from a replay
  that had *hard-coded* `resolved=0` rather than deriving what the resolver
  would do: asserting the input instead of computing it, which is the mistake
  the replay technique exists to prevent.

  Two distinctions a first draft would have merged. **`BLIND` is not
  redundant with counting clears**: a filter that matches nothing never
  produces a candidate to decline, so `resolved == 0` is never reached — a
  resolver keyed on tool `"llm"` against findings labelled `"llm-review"`
  would run forever and look healthy. That exact mistake is one commit away
  in this repo's history. And **`NEVER RAN` joins lifetime volume while
  `BLIND` joins the open count**: lifetime for BLIND would flag every
  producer whose findings were legitimately fixed, and the open count for
  NEVER RAN would miss a resolver dead for months whose backlog someone has
  since cleared.

  **Verified against the bug it exists to catch, end to end.** Two arms of a
  synthetic repo with a real upstream, a real delta and a seeded mutation
  finding, each running an actual `aramid check --gate pre-push --all`: at
  HEAD `gap_addressed` grades `live` (1 considered, 1 resolved, unflagged);
  with `if mode == "range"` restored in `pipeline.py` it grades `NEVER RAN`
  and flags. A detector never shown going red on its target is not a check.

  One thing the first live run got wrong and now handles: on a ledger older
  than the instrumentation, **eight rows graded `NEVER RAN` — including
  `evidence_gone`, which that same ledger records firing twelve times.** The
  grades were right about the events and wrong about the world. Zero yield
  events of *any* kind now grades `not instrumented` instead, which is safe
  only because the instrumentation is all-or-nothing: one gate run emits
  several, from resolvers that do not know about each other. The amnesty ends
  at the first gate run, so it forgives an un-instrumented *ledger*, never an
  un-instrumented *resolver*.

  Not on the blocking path, deliberately. A dead resolver is a fault in the
  gate's own machinery rather than a verdict on the code being pushed, and a
  diagnostic that can fail a push gets deleted rather than fixed.

- **`js-mutation`, `fuzz` and `dast` can now prove a repair.** All three had no
  resolver of *any* kind — nothing matched their tool names, `record_run`
  cannot reach them (it keys on runner labels), and `drain._consume_item`
  passes empty scopes deliberately. Their findings never resolved for any
  reason, so fixing the defect changed nothing. Each proves it differently, and
  the differences are the design:

  - **`js-mutation` — positive proof.** Single-stage is an advantage here:
    `<pm> test` *is* the full suite, so a non-zero exit is already a full-suite
    verdict and needs no second stage. The killed mutant's fingerprint is the
    finding's id, so no scope is involved. The residual risk is the
    *environment* — if the node_modules junction or node dies mid-run, every
    remaining mutant exits non-zero and reads as killed, mass false repair from
    one broken link. A confirming clean-tree baseline settles it, and is only
    paid for when a kill actually matches something open.
  - **`fuzz` — deterministic replay.** `fuzzgen.case_seed(file, func, i)`
    replays exactly the corpus that found the crash, so for a function that was
    really *called*, "no crash" is a re-examination rather than a coverage gap.
    The driver now reports `fuzzed` — what it actually called — because a
    function whose type hints were removed is skipped in silence and produces
    the same evidence as a clean run: nothing. Scoping by requested targets
    would have resolved findings in code that stopped being *checkable*.
  - **`dast` — complete re-scan.** Every check family runs against one
    response, so absence means clean — but only for endpoints that **answered**.
    `_check_exposed` silently `continue`s past a path it cannot reach, so
    `probe_scoped` now reports what it actually reached. A 404 counts (that is
    an answer); an unreachable route does not. Without this a target that
    merely went **down** would clear its own security findings, which is the one
    direction this tool may not fail in.

  Scope is matched on the function named in the crash *message*, not on the line
  number: lines move when a file is edited, which is exactly the situation a
  repair arises in, and a shifted line can land inside a different function's
  span.

- **`[mutation].test_command`**, falling back to `[tests].command`. The two
  answer different questions and had to stop sharing one knob — see below.

### Added

- **Three CI-only checks moved into the suite**, so they run on every push
  instead of costing a matrix round-trip. All three are
  environment-independent, which is exactly why they had no business being
  CI-only — unlike the seven-leg matrix, nothing about them needs another
  machine to discover.

  - **ruff over every tracked file.** `ruff` is PRE_COMMIT-tier only
    (`GATE_RUNNER_KEYS[PRE_PUSH]` has no ruff) and the local pre-commit hook
    sees the *staged* scope, so a finding in an untouched file surfaced only in
    CI. Teeth-checked by planting an `S110`: **untracked it passed vacuously,
    tracked it went red** — a live reminder that repo-wide guards only see what
    git tracks.
  - **Semgrep is in the pre-push tier and selected.** CI asserts post-hoc that
    the run actually completed semgrep; a test cannot inspect its own enclosing
    run, so this asserts the property that makes that assertion meaningful.
    Honest about strength: measured, `selected_tool_names` returns semgrep even
    for a JS-only repo, so the *tier membership* half is the discriminating one.
  - **Wheel build + packaged-data.** Expected files are derived from
    `pyproject`'s own globs rather than CI's three literals, so a new data file
    joins the expectation automatically. `build` is now in the `[dev]` extra so
    the test can never degrade into a skip.

  **A measured finding about the CI step this replaces:** it is weaker than it
  reads. Three perturbations — dropping `rules/*.yml` from package-data,
  reducing the globs to `data/*.toml`, and setting `include-package-data =
  false` alongside — each *verified to have actually landed* before building,
  and `owasp.yml` shipped every time. Under this backend every file under
  `src/aramid/` is packaged regardless of configuration, so that step cannot
  fail via the config it appears to guard. The test is kept for the regressions
  that would really bite (a data file moved or renamed out of the package
  directory, a build-backend change), with its limits written down.

  Not attempted, and not claimed: the matrix. Interpreter and platform
  differences cannot be reproduced on one machine, so CI stays the authority
  and a green local run is a filter rather than a proof.

### Changed

- **The pre-push gate now runs CI's whole test tree**, not `tests/unit`.
  `[tests].command` is the same command CI's test step runs, so what passes
  locally passes there; the ~370 integration and e2e tests it used to skip are
  the ones most likely to break on another machine. `[tests].timeout_s` and
  `[timeouts].pre_push` are raised to match — a per-runner cap above the
  whole-gate cap is a cap that never fires. Full parity is still not possible
  and is not claimed: CI runs seven legs (3 OS × 4 pythons) and a local push
  runs one, so platform-specific failures can still only surface there.

  **Mutation keeps its own bounded baseline** (`[mutation].test_command` =
  `tests/unit`). Its baseline runs inside `mutant_timeout_s * 4`; aiming that at
  a ~19-minute tree reproduces the original defect exactly — 44 drains, zero
  findings, every one reporting "baseline failing" when the truth was that it
  never finished. `test_this_repos_mutation_baseline_is_not_the_whole_tree`
  fails if the two ever converge again.

### Fixed

- **Turning on CI parity silently turned OFF every range-scoped auto-resolver.**
  `[hooks].pre_push_match_ci = true` runs the pre-push shim as
  `check --gate pre-push --all --strict`; `--all` resolves to `mode == "all"`;
  and mutation, tdd and red-proof resolution all sat behind
  `if mode == "range"`. So the flag was an off-switch for auto-resolution, with
  no output anywhere saying so, for as long as it was set.

  **This is the root cause of the two zero-yield resolvers reported below, and
  it supersedes them.** The mapped-test rule really was too narrow — that was
  measured by replay and is fixed — but fixing it changed nothing observable,
  because the call site was unreachable. Two locks on one door; the mapping was
  the second.

  How it was caught: `gap_addressed` and `test_added` had fired **zero** times
  across 182 `FINDING_RESOLVED` events, while `evidence_gone` (12),
  `red_proven` (3) and `suite_completed_clean` (2) — the resolvers that derive
  no range — had all fired. Then a prediction failed: a push whose delta
  contained `tests/unit/test_mutation_gate.py` should have cleared the three
  findings on `mutation_gate.py` and did not, while replaying the same resolver
  over a ledger copy cleared all three. Replay disagreeing with reality is what
  pointed at the call site rather than the function.

  **The guard is moved, not removed.** It existed for a real hazard: under
  `all`/`staged`, `scope_files` is the whole tracked tree, and resolving on it
  durably clears every open finding — `FINDING_RESOLVED` is appended and cannot
  be un-appended. `pipeline._resolution_scope` now computes the push's genuine
  delta from git independently of the scan mode, so `--all` still widens what
  is scanned and no longer widens what is resolved. No upstream yields the
  **empty set** rather than a fallback, which is load-bearing:
  `gitutil.changed_files` maps a falsy range to `HEAD`, so the check has to
  happen at this layer.

  Three tests, and the middle one is the only one that discriminates: mapped
  test *in* the delta resolves; mapped test tracked but *outside* the delta
  does not (an implementation that passes `scope_files` through passes the
  first test and fails this one); no upstream resolves nothing.

  The flag's own docstring documented the ratchet consequence and not this one.
  **That asymmetry is the lesson worth keeping — when one flag feeds two
  subsystems, an undocumented consequence is indistinguishable from an
  unintended one.** It now names both.

- **A mutation survivor now names the suite it survived.** `[mutation]
  .test_command` is `pytest -q tests/unit`, deliberately bounded — the whole
  tree (~1141 s) does not fit the `mutant_timeout_s * 4` baseline budget, and
  inheriting it recreated the "44 drains, zero findings" defect. The
  consequence was never written down: **any code whose only coverage is an
  integration or e2e test reports survivors forever**, and the message
  "mutant survived" reads as *you have a test gap* when it can equally mean
  *the engine never ran your test*.

  Proven, not inferred: two mutants in `pipeline._resolution_scope` were
  reported as survivors, and applying each by line number makes
  `tests/integration/test_resolution_scope.py` fail — including the
  no-upstream case that exists for exactly that inversion. The findings were
  true for the run and false as a claim about coverage.

  Messages now read `mutant survived: <op> (unkilled by: pytest -q tests/unit)`.
  The interpreter path is dropped: it is absolute, differs per machine, and
  inside a mutation worktree is a temp dir, so leaving it in would make one
  finding read as several. Asserted on the whole rendered string rather than a
  substring — a substring check confirms only what the author already believed
  about their own format.

  The two findings are suppressed in `.aramid-suppressions.toml` with the proof
  in the reason. **They are that file's first non-BLOCK entries and the first
  to reach a ledger-synthesized producer at all** — until yesterday it could
  not bind a mutation finding whatever it said. Suppressed rather than left
  open because a finding proven false is precisely the noise that teaches an
  operator to stop reading the tool; the correct way to retire them is to widen
  the mutation suite, and if `_resolution_scope` changes, both ids change and
  aramid reports the entries stale.

- **`prior_note_count` had no direct test, and `probe_tool`'s PATH prepend had
  none at all.** Found by re-probing the two modules whose findings were still
  open, rather than by waiting for a drain — mutation only mutates files inside
  a queue item's diff range, so a function stops being re-probed the moment
  pushes stop touching it. **Absence of a finding is not evidence of coverage.**

  `prior_note_count` is the give-up counter four consumers read (`dast`,
  `js_mutation`, `mutation`, and `llm_review._malformed_attempts`) to decide
  whether they have already failed enough times on a queue item to stop trying.
  All nine mutants against it survived its own mapped test file: each conjunct
  of the four-part filter, both comparisons, the `startswith`, the counter's
  init and increment, and the event-type guard inverted. Count too high and a
  consumer abandons healthy work; too low and it retries a poisoned item
  forever.

  **Stated precisely, because the first version of this claim was too strong:**
  its coverage was *incidental*, not absent. The wider suite does kill the
  inverted guard — four caller integration tests fail. That is a weaker
  guarantee than it sounds: the contract is asserted nowhere, so editing a
  consumer can silently narrow or widen it. Three direct tests now pin it, and
  kill all nine.

  `doctor.py` gave up two more: `.strip()` dropped (a tool whose `--version`
  opens with a blank line reports *no* version, since `splitlines()[0]` is then
  `""`), and PATH prepend → append.

  **The PATH one nearly hid twice.** That env line is written **twice** in
  `doctor.py` — `probe_tool` at 147 and `_version_of` at 173 — and a by-text
  probe using `replace(old, new, 1)` rewrites the *first*, so a mutant reported
  against `_version_of` was really applied to `probe_tool`. The test looked
  wrong when it was the probe that was. **Mutate by line number when a codebase
  spells the same contract more than once.** Isolating the two lines showed the
  `_version_of` mutant dying and the `probe_tool` one surviving all 31 tests in
  both doctor files — a genuine second gap, on the prepend whose stated purpose
  is that semgrep's launcher shells out to a sibling *by bare name*. Same
  family as the earlier scoping miss, where a call-graph query could not see a
  duplicated implementation.

- **The `skipped` counter in `auto_resolve_mutation` is pinned on its rendered
  output.** `skipped = 0 -> 1` and `skipped += 1 -> 2` both survived every test
  and were deferred once as "diagnostics only". That was the wrong reading:
  `diagnostics.note_skipped` is silent at zero and prints to stderr otherwise,
  so the first mutant makes **every clean run** tell the operator their ledger
  holds a malformed record when it does not. A security tool inventing a
  complaint about the user's own data is the noise that trains people to stop
  reading its output.

  Asserted on the stderr text, not the counter — the counter is not the
  contract, the message is the only part anyone sees. Needed a record that
  genuinely raises inside the `try` (`file` non-str and truthy, so
  `normalize_path` raises); a `None` file is caught by `if not path: continue`
  first and counts no skip, which is why the pre-existing "skips malformed rec"
  test could never have pinned this.

- **`auto_resolve_mutation`'s tool/status filter could be inverted without
  failing a single test.** `or -> and` on
  `if rec.get("tool") != TOOL or rec.get("status") != "open"` survived all 18
  tests over that function. Under the mutant the skip fires only when the tool
  is wrong *and* the status is not open — so **any open finding of any tool**
  is processed, and is resolved when the push touches its file. A mutation
  resolver would clear gitleaks and semgrep findings on sight, and the
  re-drain backstop this resolver leans on does not cover that: it re-reports
  mutants, not secrets.

  Reported by aramid's own drain against code committed minutes earlier, and
  confirmed by hand before being believed — the mutant was applied and all 36
  tests still passed. Two tests now reject it: another tool's open finding on a
  touched file, and an overridden mutation finding on a touched file.

  **Third instance in one day of a single shape** — after
  `consumers/base.py::open_findings_for`'s two filters: *a compound filter is
  only tested by data it is supposed to reject.* Every test seeded exactly one
  record of the right tool in the right status, so the rejecting branch was
  never executed. Worth treating as a review checklist item rather than three
  coincidences.

- **`auto_resolve_tdd` carried a fourth, inline copy of the mapped-test rule,
  and the fix below missed it.** `tdd.py` spelled
  `{f"test_{module}", f"{module}_test"}` in place rather than calling the
  shared helper, so widening `_module_tests` repaired
  `auto_resolve_mutation` and `mutation_score_gate_findings` and left this one
  exactly as broken. The scoping error is worth naming: the change was scoped
  by a call-graph query (*callers of `_module_tests`*, `decision_grade`), and a
  **duplicated implementation is invisible to that question** — it calls
  nothing. Scope by behaviour, not by call edges, when the thing being changed
  is a convention.

  Found by yield, not by reading: `test_added` had fired **zero** times across
  182 `FINDING_RESOLVED` events in aramid's own ledger, while `evidence_gone`
  (12), `red_proven` (3) and `suite_completed_clean` (2) had all fired. The
  pre-existing fire test could not have told anyone — it resolves `a.py` from
  `tests/test_a.py`, an input built to satisfy the rule, and so proves the
  mechanism works in principle while it never once worked in practice.

  **The generalisable signal, measured before being believed: opportunities
  without resolutions.** Per resolver, compare findings ever detected for its
  tool against times its reason fired. Run over this ledger it marks
  `gap_addressed` (9 detected / 0 fired) and `test_added` (1 / 0) as suspect,
  leaves the three working resolvers quiet, and correctly separates *never had
  an opportunity* (`fuzz`, `dast`: 0 / 0) from *had nine and never took one*.
  Both flags are real defects; one of them is this entry. Not yet a shipped
  diagnostic — recorded here because it is the cheapest known detector for the
  silent-no-op class that has produced four defects in a single day.

- **A mutation finding could not be resolved by the test that kills it, unless
  that test was named `test_<module>.py`.** `_module_tests` returned exactly
  `{test_<stem>, <stem>_test}`, so a module inside a subpackage was
  unreachable: nothing mapped `test_consumers_base.py` back to
  `consumers/base.py`, or `test_doctor_version_parsing.py` back to
  `commands/doctor.py`.

  Not theoretical — measured 2026-08-10 against aramid's own ledger. **Four of
  its five open findings were mutants the repo's own tests provably kill**;
  applying each mutant by hand turns the mapped test file red. They had been
  open for hours with the fix already committed, because a resolver that cannot
  see the fix leaves a finding immortal until someone happens to touch the
  source file again. That is the state that teaches an operator to ignore a
  security tool, and it was self-inflicted.

  `_maps_to_module(test_stem, module_path)` replaces it with three anchored
  forms: the original pair, `test_<parent>_<module>` for a subpackage, and
  prefix-anchored `test_<module>_<aspect>`.

  **The anchoring is the design, not a detail.** The obvious wider rule — "the
  module name appears as a token of the test name" — resolves
  `consumers/base.py` from `test_runners_base.py`, because `base` is a stem
  three source files share here (`consumers/`, `providers/`, `runners/`; a
  stem-frequency count over all 79 modules found `base` ×3, `mutation` ×2,
  `mutation_score` ×2). Qualifying on the module's own parent directory keeps
  them apart. Two of the four new tests are that boundary, and they are the
  ones that fail under the over-wide rule rather than under the old one.

  Applied to **both** call sites. `mutation_score_gate_findings` uses the same
  mapping as an ephemeral escape valve for a transition regression, and it was
  broken in exactly the same way — a developer who changed
  `test_consumers_base.py` and hit an armed BLOCK regression on
  `consumers/base.py` had no valve at all. Leaving one site strict would have
  kept a known-broken valve and split "the module-mapped test" into two
  different notions. `_stage1_argv` is deliberately untouched: it reaches these
  files already via its `-k <module>` fallback, and changing which tests run
  per mutant would change kill detection itself.

  Verified by replaying the real `auto_resolve_mutation` against a **copy** of
  the live ledger with the two test paths as `changed_files`: 4 of 4 map, where
  0 of 4 did before. The findings are not cleared by hand — the next push that
  touches those tests clears them legitimately, and until then the count
  honestly stays at 5.

- **`.aramid-suppressions.toml` now reaches the ledger-synthesized findings —
  and reports itself stale when it doesn't.** Carried as a known defect earlier
  the same day; the deferral reason was that fixing it changes a security-gate
  semantic, so it got its own increment. Measured 2026-08-10 against a real
  `mutation` finding, three parts:

  1. `policy.apply_overrides` *would* downgrade it to INFO — the entry is
     correctly formed and the mechanism works when handed the finding.
  2. It is never handed the finding. `apply_overrides` runs at
     `pipeline.py:755`; `mutation_gate.mutation_gate_findings`,
     `mutation_score_gate.…` and `review.llm_gate_findings` are appended at
     ~`:925`, *after*. Nothing re-applies overrides to them.
  3. Staleness cannot catch it either: a record is reported stale only on a
     **near miss** (same tool+rule+path present in that same finding list).
     No `mutation` finding is in the list at `:755`, so there is no near miss
     and no warning. The file's own docstring promises the opposite — "this
     entry stops matching, and aramid reports it as a stale suppression rather
     than silently covering nothing" — which holds for gitleaks fixtures and
     not for this class.

  The consequence inverts design doc section 6. For these three producers the
  *machine-local* `aramid override` is the only channel that works (it flips
  the ledger status, and the synthesizers require `status == "open"`), while
  the tracked, reviewed, tier-agnostic file — the one section 6 calls strictly
  more capable — binds nothing. Same silent-no-op class as the pre-2026-08-09
  BLOCK-only bug, one layer further out.

  **The tool strings are `llm-review`, `mutation`, `mutation-score`.** The
  version of this entry written before the fix said "llm", which is not a tool
  aramid emits — anyone acting on it would have written a second silent no-op.
  Binding is by **id**, so a wrong `tool` here does not break the suppression;
  it breaks the *stale report*, which is the only thing that would have said
  so. Same NAME≠TOOL trap as `consumers.base.Repaired` (`js_mutation` emits
  `tool="js-mutation"`).

  **The repair:** the three synthesized producers get their own
  `apply_overrides` pass, and `stale` is then recomputed over **both** lists
  (`policy.stale_records`, split out for it) so `matched_ids` is the union.
  That second pass is what finally makes part 3 above reportable: a suppression
  whose id has rotted now near-misses the synthesized finding and is announced,
  where before it stayed silent forever. Report-only today (`reporter.py` is
  its sole consumer; no exit code reads it).

  **The two channels are judged against different pools, and the first cut of
  this got it wrong.** `701b6bd` pooled everything, and the very next push
  reported aramid's own *working* override on
  `doctor.py:176 mutation/int-bound` as stale — because a different surviving
  mutant at line 180 shares its tool, rule and path. It would have fired on
  every push forever, and the remedy it printed ("re-affirm it") would have
  minted a second override for a dead id.

  The mechanism is the asymmetry: a **suppression** binds by ID while the
  finding is still in the list, so its target is present and absence really
  does mean the record is dead. An **override** binds by flipping the ledger
  *status*, and both synthesizers skip a record whose status is not `"open"` —
  so an override's target is absent from the synthesized list *exactly when it
  is working*. Absence is unambiguous for one channel and meaningless for the
  other. Suppressions are now judged against both pools; overrides against the
  runner findings alone, as they always were.

  Accepted limit: a genuinely dead override on one of these three producers
  stays unreported. Pre-existing behaviour, not a regression — nothing at this
  layer can tell it from a working one, and a guess is worse than the silence.

  **Correcting a second overclaim made while writing this**: the pooled
  composition was first justified as preventing a *false* stale report for
  suppressions, on the reasoning that a record binding a synthesized finding
  near-misses in the first list. It does not. The reason is structural — a
  near miss requires TOOL equality, and no runner emits `mutation`,
  `mutation-score` or `llm-review`, so no record can near-miss in one list and
  match in the other. Pooling is kept for being correct by construction rather
  than by that coincidence.

  Precision about what was actually measured, since the first version of this
  paragraph said "leaves every test green" and that was never run: swapping the
  pool for a plain concatenation was measured against the three tests then in
  `test_suppress_synthesized_findings.py`, before the channel-scoping change
  above, and left all three green. It has not been re-run against the full
  suite or against the scoped design. The claim above rests on the structural
  argument, not on that measurement.

  **What this newly permits, stated rather than slipped in:** a tracked
  suppression can now downgrade an armed, confirmed-critical **LLM BLOCK**.
  Deliberate — section 6 gives the committed file *any* tier, which it already
  exercised over gitleaks and semgrep BLOCKs. What is **not** widened is the
  other channel: `apply_overrides` keeps its `elif f.verdict is Verdict.WARN`
  branch, so a machine-local `.aramid/` override still cannot hide a BLOCK
  (`test_override_does_not_downgrade_block_finding` remains the guard). The
  ledger-override channel never reached these three anyway — both synthesizers
  skip a record whose `status` is not `"open"`, and `commands/override.py`
  refuses a confirmed-critical LLM finding at the CLI, armed or not.

  Covered by `tests/integration/test_suppress_synthesized_findings.py` (five
  tests, all red first — the three binding ones assert the armed BLOCK *before*
  suppressing it, so none can pass against a gate that never blocked; the
  fourth pins the stale report, and fails pre-fix with an empty
  `stale_overrides`, which is the silence itself; the fifth is the working
  override above, and came from dogfooding rather than from reasoning about the
  design). `mutation-score`
  findings are ephemeral — no ledger write, id recomputed every run — so two
  tests in `test_mutation_score_gate.py` pin that the id does not move with the
  score or the changed-file scope; without that, a suppression against one
  would be valid the day it was written and dead the next. The score half was
  teeth-checked by perturbation; the scope half stays green under that same
  perturbation and is a forward guard only, which its docstring records.

- **A producer could not prove a repair — only guess at one.**
  `mutation_gate.auto_resolve_mutation` already clears mutation findings at
  pre-push, and deliberately does so on **intent**: the push touched the
  source, or added a test whose basename is `test_<module>.py`. That is right
  for the gate — a dev who wrote the test should not be blocked — and its own
  docstring names the async re-drain as the authoritative backstop. But the
  backstop could only ever *re-report* a finding; nothing in the product could
  **confirm** a repair, so the ledger recorded `gap_addressed` (a guess) and
  never `mutant_killed` (a proof).

  The distance between the two is not theoretical: the mapping matches only
  `test_<module>.py` / `<module>_test.py`. Measured here — mutation reported
  three survivors in `doctor._version_of`, two were real test gaps, and the
  tests were written in `test_doctor_version_parsing.py`, which the mapping
  does not match. Nothing resolved. **A resolver keyed on a filename
  convention misses every fix that does not follow it**; proof does not care
  what the file is called.

  `record_run` cannot carry this (`scope_tools` holds *runner labels* from
  `Path(argv[0]).name`, and no consumer emits a `RunnerResult`), and
  `drain._consume_item` passes empty scopes deliberately — the drain runs a
  narrow ruleset, and semgrep's pack findings share a tool name with its OWASP
  findings, so "ran and didn't re-report" proves nothing there.

  `js-mutation`, `fuzz` and `dast` still have **no** resolver of any kind
  (only `mutation`, `red-proof`, `tdd`, `llm-review` and `tests` do). They are
  why this landed as a general mechanism rather than another bespoke one;
  wiring each needs that consumer to re-derive its own identities.

  `ConsumerResult.repaired` is a **positive assertion**, which is why it is
  safe where scope-based resolution is not: the producer hands back the exact
  fingerprints it *re-derived and disproved*, and nothing is inferred from
  silence. Mutation re-mutates the same line with the same operator and the
  suite kills it — `killed_fps` was already computed and thrown away. A
  producer that claims nothing resolves nothing, so the mechanism stays opt-in
  per producer, like `resolve_departed`.

  **A kill is not a repair until the full suite says so.** Stage 2 already
  existed so narrow stage-1 selection "can never manufacture a false test-gap
  finding" — it guards *survival*. Nothing guarded the *kill* direction,
  because until repair claims existed a false kill was free: it only meant no
  finding was emitted. It does not take a flake to fire — `s1.returncode in
  (1, 2)` counts **2 = collection error** as a kill, and stage 1 selects
  exactly one file by module name, so a test file that merely fails to
  *import* reads as "the suite killed this" for every mutant in that module.
  A kill is now confirmed by a full-suite run before it may be claimed, and
  only when it matches an id that is actually open — which is almost never, so
  the common case pays nothing. Pinned on the CALLS, since an outcome-level
  assertion cannot tell a skipped confirmation from a cheap one.

  Two traps worth recording. The claim carries its **tool** explicitly rather
  than reusing the consumer's `NAME`: `js_mutation`'s NAME is `js_mutation`
  while its findings are `tool="js-mutation"`, and inferring it would have made
  that consumer's claims a silent no-op. And the identity that makes cross-run
  matching work — `_mutant_fp` computing the same `compute_fingerprint` as
  `normalize` — is pinned by the **drain** test, not by the fingerprint-
  stability test whose name sounds like it: perturbing `_mutant_fp` leaves the
  latter green, because both sides shift together. Measured, and both
  docstrings now say which property they actually hold.

- **Two mutants that survived a real mutation run in `doctor._version_of`.**
  `(cp.stdout or cp.stderr)` — a tool answering `--version` on stderr read as
  *version unknown*; and `out.splitlines()[0]` — a notice line read as the
  version. 1598 tests missed both because every caller-level test in
  `test_toolpath_divergence.py` monkeypatches `_version_of` itself; measured,
  not assumed, by re-applying each mutant alone and watching all four stay
  green. The user-visible consequence is now pinned too: under the `or → and`
  mutant, `doctor` cries DRIFT over two copies of the **same** version — the
  exact notice the existing (vacuous) guard exists to prevent. The third
  survivor, `timeout 15 → 16`, is an equivalent mutant and deliberately gets no
  test; what is pinned instead is the docstring's load-bearing promise that
  `_version_of` never raises.

- **Mutation testing had never once run.** 44 attempts on this repo, **zero
  findings**, `degraded` on 38 of them, every time reporting
  `"baseline failing @ <sha>"`. The suite was never red — the baseline never
  *finished*. Three defects, each measured rather than argued:

  1. `_full_argv()` hardcoded a bare `pytest -q`, ignoring `[tests].command`
     outright, so the baseline ran the whole 1595-test tree — **1141 s** — inside
     `mutant_timeout_s × 4` = **480 s**. Honouring the configured command brings
     it to **305 s**. The note is why this survived 44 runs: *"baseline failing"*
     reads as *your tests are red*, not *we never let them finish*.
  2. None of the three worktree subprocesses passed `env=`, so under a pip
     editable install they imported the **live** source rather than the mutated
     worktree — every mutant would have been reported **survived**. This is
     `f462d27`, fixed for `red_proof` on 2026-07-25 and never propagated: the
     helper was a private `_base_import_env` with one caller and **no tests**,
     which is exactly how mutation came to miss it. Now
     `runners.base.worktree_import_env`, shared, with its first tests.
  3. Per-site budgets are not interchangeable. Stage-2 confirm runs the *same*
     whole command as the baseline; a 305 s command inside 120 s times out, and
     a stage-2 timeout is counted unattributable and emits **no finding**.
     Mutation would have flipped from `degraded` to `ok` with permanently zero
     findings — healthy-looking and silent, strictly worse than the bug. And
     `wall_budget_s` (600, clock starting *before* the baseline) left 295 s,
     under a single confirm; `aramid.toml` now states a measured 1800 s.

  **Why 1598 tests never caught it:** the mutation fixtures build a *flat*-layout
  repo with a `conftest.py` that inserts the root on `sys.path`, while aramid is
  *src*-layout and installed editable. The fixture cannot express the bug. The
  new tests therefore assert on the **calls**, not the outcome, and their teeth
  were proved separately and do not overlap — reverting the command handling
  reddens the argv and budget tests only; reverting import isolation reddens the
  isolation test only.

  **Verified end to end by a real drain, not by the tests alone:** first working
  run reported `ok`, **20 mutants tested, 3 confirmed survivors**, 1331 s (over
  the old 600 s ceiling, inside the new one). Triaged: `timeout=15→16` is an
  equivalent mutant — the WARN-tier noise this design accepts — while
  `cp.stdout or cp.stderr → and` and `splitlines()[0] → [1]` are **genuine test
  gaps** in `doctor._version_of`, a function added the previous day that had
  passed the full suite, review and seven-leg CI. Graphite confirms
  (`decision_grade`) it has one caller and no direct test.

- **A BLOCK-tier whole-suite finding could resolve on a run that never ran the
  suite.** `ledger._departed` decided whether a finding's file had left the
  repo by asking the filesystem — and the `tests` runner reports every
  whole-suite finding against the synthetic marker `<test-suite>`, which is not
  a path. No file of that name exists, so the marker read as **departed** and
  `record_run` resolved the finding, several steps before
  `tests_gate.auto_resolve_tests` — the resolver that exists to demand
  `suite_completed` evidence first — was ever consulted.

  `_departed`'s own docstring asserted the opposite, claiming the marker "is
  reported as present" because it is not a legal Windows filename and the check
  would raise. Measured false on both platforms: non-strict `Path.resolve()`
  does not validate the name and `.exists()` answers `False` rather than
  raising, while on Linux the marker is simply a legal name that does not
  exist. **The documented safety property held on no platform at all**, and the
  test pinning it passed only because it omitted the `root=` argument that the
  gate — the sole caller that reaches this path — always passes.

  Outcomes coincided with the correct ones by accident: `scope_tools` holds
  `Path(argv[0]).name`, and aramid's own `[tests].command` makes that
  `"python"`, so *"the suite ran OK"* and *"python is in scope_tools"* happen to
  be the same condition here. A repo whose labels diverge got a suite finding
  cleared on a run whose suite never executed.

  Measured in aramid's own ledger, which distinguishes the two routes by
  payload: of **4** historical resolutions of whole-suite findings, **3** carry
  an empty payload — `record_run` — and only **1** carries
  `auto_resolved: suite_completed_clean`. The resolver written to be the only
  thing that can clear these was beaten to it three times out of four, because
  `record_run` runs first and leaves nothing `open` behind.

  `_departed` now refuses synthetic `<...>` markers outright, matched by shape
  so a second marker inherits the guard; a tripwire test pins the shape to the
  live `_SUITE_FILE_MARKER` so a rename cannot escape it.

- **Findings from `red-proof` and `tdd` on a deleted file were immortal.** The
  departed-file resolution added in 0.1.0 sits *behind*
  `if rec["tool"] not in scope_tools: continue`, and `scope_tools` is
  `{r.tool for r in results if OK}` — runner labels. The synchronous producers
  emit no `RunnerResult`, so their names can never appear there, and unlike the
  runners they have no fallback resolver: `auto_resolve_red_proof` clears only
  via `proven_red`, which requires a base-tree pytest run on a file that no
  longer exists.

  Live instance in aramid's own ledger: `890d7493a3e3`, red-proof on
  `tests/unit/test_zz_ci_dump_rehearsal.py` — committed, judged, then the push
  was blocked and the commit rewritten without that file. It stayed open across
  every subsequent run and had to be closed by hand.

  Fixed with a new `ledger.resolve_departed`, which each producer **opts into**
  by name. The one-line alternative — moving the departed check ahead of the
  tool gate — was implemented, measured, and **reverted**: `_departed` answers
  "gone" for anything that does not exist, and not every producer stores a
  path. `consumers/dast.py` writes `file=f"{f.method} {f.path}"`, so
  `"GET /login"` joins to `root/GET/login`, passes the containment check, and
  reads as departed. That change would have written every open DAST finding
  `fixed` — a false repair, of security findings, into an append-only audit
  trail, which is the exact class the tool clause exists to prevent.

  So a producer that never opts in keeps its findings open: fail-safe by
  default, rather than a denylist of shapes each new consumer must remember to
  join. `llm-review` needs nothing, since `auto_resolve_llm` already fires when
  the stored evidence quote leaves `HEAD`. `dast` must never opt in.

  **`mutation` opted in too.** It writes `tool="mutation"` against real
  repo-relative paths (`consumers/mutation.py`), exactly the shape
  `resolve_departed` takes, and its own resolver cannot see deletions — it
  fires only when the push touches the file, and discovery filters
  `--diff-filter=ACMR`. It is further out of reach than the other two, since
  the **drain** records it and passes no `root` at all. Resolution here is also
  strictly more conservative than the resolver it already has, which is liberal
  by design (a wrong resolve re-fires on the next drain).

  That needed one fixture change worth recording, because the test suite had
  been relying on the bug: `test_pipeline._seed_mut` seeded on a deliberately
  **absent** `src/pkg/ghost.py`, which the opt-in resolved before the
  assertions ran. The fixture now writes a **present-but-untracked**
  `ghost.py` — present so `_departed` is False, untracked so it stays out of
  `ctx.files` and `auto_resolve_mutation` stays quiet too. Landing the fixture
  change alone, before the opt-in, confirmed it was behaviour-neutral.

  Still **not** opted in:

  - `js-mutation` and `fuzz` turn out to have **no resolver at all**, which is
    a strictly larger defect found while checking this one. No `auto_resolve_*`
    matches those tool names; `record_run` cannot reach them because it keys on
    runner labels and these are consumers; and `commands/drain._consume_item`
    passes empty tool/file scopes on purpose ("record detections but resolve
    NOTHING", so a narrow pack ruleset cannot clear a full-gate finding). Their
    findings are therefore immortal outright — not only after a deletion, but
    after a genuine fix. `dast` is in the same position. Reported, not fixed
    here: the right resolution rule for a fuzz crash is a design question, not
    a one-line opt-in.

    **SUPERSEDED, same release** — all three now resolve, via
    `ledger.resolve_repaired` rather than by opting into departed-file
    resolution (see "give js-mutation, fuzz and dast their own resolvers"
    above). The design question above is what took the work: the answer turned
    out to be different for each of them, and `dast` in particular must never
    opt in *here*, because its `file` is an endpoint rather than a path.

- **A whole-project runner could record findings as `fixed` in files the gate
  never scoped.** `ledger.record_run` **replaced** the gate's `scope_files`
  with the runner's examined set rather than **intersecting** them, so the
  moment a runner reported anything, the gate's own scope stopped constraining
  resolution.

  Both the 0.1.0 changelog and the module contract say *"resolution intersects
  against that."* The code did not — this is the same false-repair class the
  examined-set mechanism was introduced to close, reintroduced from the
  too-**wide** side.

  It bites runners that report more than the gate scoped: clippy's examined set
  is every `.rs` file cargo compiled in the crate; tsc's `--listFiles` is the
  whole program. A `range`-mode push touching one file compiles the crate, and
  because cargo replays no diagnostic for files it did not recompile, every
  open finding in an **untouched** file was written `fixed` into an append-only
  audit trail — indistinguishable from a real repair.

  `ruff` never exposed it, which is why the existing tests did not catch it: it
  is handed an explicit file list, so its examined set cannot exceed the scope.
  The new regression test is modelled on clippy for that reason. The
  departed-file clause is unchanged and still runs ahead of the check.

  Reported by `llm-review`, and correct in both premise *and* mechanism —
  including the exact one-line fix. Worth recording, since the previous four
  findings from the same producer were a duplicate, a refutation, and two
  already-fixed.

### Added

- **The CI log dump's disclosure argument is now enforced instead of asserted.**
  `dump_aramid_logs.py` prints every persisted runner log to a **public** job
  log on `if: failure()`, and its docstring justifies that tool by tool. That
  justification is prose: it does not fail when a runner is added, so a new
  scanner would start publishing with nobody re-reading the paragraph.

  A tripwire now compares `pipeline.GATE_RUNNER_KEYS` against a review record
  naming each runner and why its output is safe, and goes red when they
  disagree **in either direction** — a stale entry is also a defect, because it
  makes the record read as more thorough than it is. Red-proofed both ways.

  **Deliberately a tripwire and not an allowlist.** Withholding an unreviewed
  body would make the script go silent on exactly the leg that flakes, which is
  the intermittent it was written to diagnose. Keep printing; force a human to
  re-check when the set changes.

  Three findings closed against this file, and the review is most of what
  changed: the reported vector — "a failing pytest whose assertion diff carries
  credentials" — adds **zero** incremental disclosure, because
  `Run test suite` already runs `python -m pytest -q` unconditionally and that
  output is public regardless. The script is also **not packaged in the wheel**
  (verified against the built artifact), so the blast radius is aramid's own CI
  and never a consumer's. One of the three was a duplicate of another; a third
  claimed `sys.stdout.reconfigure` "may fail on older Pythons" when
  `requires-python` is `>=3.11` and every supported interpreter has it.

- **`aramid doctor` now reports `DRIFT` when it is about to run a different
  copy of an analyzer than the one shipped as aramid's dependency, and every
  gate run records which binary produced its findings.** Found by installing
  the published 0.2.0 wheel into a clean venv and driving it at a JS repo the
  way a first-time user would — `doctor` cheerfully reported `ruff 0.15.18`
  while `ruff 0.16.2` sat unused in the venv beside aramid.

  Measured on that pair, same input file: **0.15.18 reported one finding
  (`F401`); 0.16.2 reported three (`F401`, `I001`, `PLW1510`).** Same aramid,
  same code, different verdicts. Two consequences, both silent:

  - **The ratchet.** A finding that exists under one analyzer version and not
    the other is *new* to whichever side sees it first, so CI can block a push
    for something the developer's own gate never showed — precisely the
    local-vs-CI divergence `[hooks].pre_push_match_ci` exists to close,
    defeated one layer underneath it.
  - **Fingerprints.** A different rule id is a different finding id, so
    baselines and `.aramid-suppressions.toml` entries stop matching.

  **Resolution order is deliberately unchanged.** PATH-first is intended
  ("the operator's own toolchain always wins"), and a per-tool exception would
  restore the two-resolution-path arrangement `toolpath` exists to collapse.
  Venv-first would not buy determinism either — `ruff>=0.6,<0.17` still
  resolves differently on machines that installed aramid months apart. The
  defect was the *silence*, so that is what changed.

  `doctor` is quiet when both copies are the same version, and when there is
  no second copy at all — a notice on every run is a notice nobody reads. That
  case was found by **rendering the real output**, not by a test: `pip-audit`
  diverged by path at an identical 2.10.1 and the first version printed it as
  DRIFT. Unknown is still not treated as agreement: if either copy will not
  answer `--version`, it reports.

  `aramid check --json` gains a `tools` key — resolved path per runner, plus
  `dependency_copy` only when it differs. Always present, even when empty: an
  absent key means an aramid too old to record provenance, an empty one means
  it looked and found nothing.

  The tool list is checked against the installed package metadata by a test,
  because a hand-maintained "tools we depend on" set is exactly what goes
  stale in silence. `gitleaks` is deliberately excluded — it is a binary
  aramid downloads, and PATH beating it is the documented intent.

  **The first version of the provenance lookup added 1,146 ms to every gate
  invocation**, including the latency-sensitive pre-commit path — measured
  only because it was asked for, having shipped unmeasured in `d6167f8`. Two
  causes, and the larger one was a correctness bug wearing a performance
  costume:

  - It resolved **every selected runner key as a binary name**. `tests`,
    `deps`, `typecheck`, `eslint` and `clippy` are registry keys, not
    executables — there is no `tests.exe`; that slot runs pytest, npm, cargo
    or go depending on stack. Each was ~110 ms of `shutil.which` across a
    72-entry Windows `PATH` to discover nothing, and no entry was ever
    produced. Probing a name that cannot exist is a wrong question, not a slow
    success, so `PROVENANCE_TOOLS` now names only the keys that *are* the
    binary. Naming the others' real commands would mean duplicating each
    runner's own command construction — the second resolution path `toolpath`
    exists to prevent.
  - `divergence()` re-resolved internally, so every dependency tool was looked
    up twice per run for a value the caller already held. It now accepts
    `resolved=`.

  1,146 ms → **288 ms** at pre-push, **187 ms** at pre-commit.

### Fixed

- **The README told everyone `pip install aramid` does not work.** It opened
  with "aramid is not on PyPI" and pointed at hard-coded `v0.1.0` wheel URLs —
  false the moment 0.2.0 published, and on the most public page in the project.
  `RELEASING.md` led with the same sentence.

- **`RELEASING.md` and `release.yml` sent maintainers to the wrong PyPI page.**
  Both said *Your projects → Publishing*, which is where you attach a publisher
  to a project that **already exists**. Before the first upload there is nothing
  there; the pending-publisher form lives on the account-level page
  (`/manage/account/publishing/`). Also recorded: PyPI labels `Environment name`
  *optional* and renders a greyed placeholder that reads as pre-filled, and
  leaving it blank fails authorization at publish time with nothing naming the
  cause.

- `twine check`'s row in the gate table credited the missing-description fix to
  0.1.0. It landed in the 0.2.0 metadata work. Tag/undo examples now use
  `vX.Y.Z` rather than a concrete version that goes stale and invites pasting a
  tag that already exists.

### Added

- **Documented that the `pypi` environment carries a required reviewer**, so a
  tagged release halts after the TestPyPI rehearsal until a human approves it —
  live behaviour since 2026-08-09, previously described as an optional extra.
  Two findings from configuring it are recorded with it: the GitHub environment
  must exist *before* a reviewer can be attached, and the API accepts a
  `required_reviewers` rule with an **empty** reviewer list that reads back as
  `protection_rules=1` — a gate that looks configured and enforces nothing.

- `RELEASING.md` now states the three-way sha256 match as a **verified property**
  of the pipeline rather than an intention, with the 0.2.0 figures, and says
  plainly not to reintroduce a build step in a publish job.

## [0.2.0] — 2026-08-09

First release published to PyPI. 0.1.0 exists as a GitHub Release only, so
`pip install aramid` starts here.

### Fixed

- **The secret scanner's stdout is no longer persisted at all, so publishing
  `.aramid/logs` cannot depend on how gitleaks chooses to behave.** `_log_body`
  persists stdout whenever a runner degraded or exited non-zero, and
  `_write_logs` scrubs it with `raw_secrets` — the strings recovered from
  *this run's successfully parsed* gitleaks findings. Those two conditions come
  apart exactly where it matters: a gitleaks that crashed or timed out mid-scan
  parses nothing, so the redactor gets an **empty list** and has nothing to
  match on, while `state is not OK` means its stdout is written verbatim — and
  the `if: failure()` CI step prints every log to a **public** job log.

  Reported by `llm-review`. Its stated mechanism was **wrong** and the
  distinction matters: gitleaks writes findings to `--report-format json
  --report-path <file>`, never to stdout, and runs without `-v`, so no secret
  material was reaching that stream. The claim that the workflow justified
  publication on "it gets scrubbed" was also wrong — the comment already said
  the opposite in as many words.

  The **premise** was right anyway, and that is what got fixed. The existing
  guard (`test_gitleaks_never_prints_findings_to_a_stream_we_publish`) asserts
  on *aramid's argv* — that we do not ask for verbose output. It cannot show
  that a future gitleaks won't print matches by default, or on an error path.
  An external tool's output behaviour is not ours to guarantee, so
  `pipeline._NO_STDOUT_TOOLS` now drops that stream before it is ever written.
  Nothing diagnostic is lost: findings go to a report file this code never
  reads, and failures explain themselves on stderr, which is still persisted.

  Written test-first: the new guard fails against the old code with a crashed
  gitleaks and an **empty** secret list — deliberately empty, because seeding
  it with the secret would only prove the scrubber works when it already knows
  the answer.

- **PyPI would have received bytes that none of the release gates inspected.**
  The `release` job runs four integrity gates against specific files in
  `dist/` — `twine check`, the packaged-data-file check, a clean-venv wheel
  smoke test and a clean-venv sdist smoke test. `publish-pypi` then did a fresh
  `actions/checkout` and `python -m build`, discarding every inspected artifact
  and uploading newly produced bytes. `needs: release` ordered the jobs and
  proved nothing about what actually reached PyPI.

  The rationale in the workflow was mine, and it had this backwards: *"an
  artifact round-trip is one more place the bytes could differ … and the build
  is deterministic from the tag."* An artifact transfers the **exact** inspected
  bytes; a rebuild manufactures new ones no gate ever saw. Determinism was an
  assumption, not an enforced control — a different `setuptools`/`build`
  resolution at the second job's own `pip install build` is enough to diverge.

  It also meant **the GitHub Release and PyPI could carry different artifacts
  under the same version**, on two public channels, with PyPI unable to be
  re-uploaded once a version is taken. Caught by aramid's own `llm-review`
  consumer before the first publish, which is the one release where it would
  have been unrecoverable.

  `release` now uploads the gated distribution (`if-no-files-found: error`, so
  an empty upload fails instead of becoming a silent no-op publish), and
  `publish-pypi` downloads and publishes exactly those files — no checkout, no
  `setup-python`, no build. It also prints `sha256sum dist/*` before handing
  over, so the hashes we sent can be compared against the publish action's own
  `print-hash` output.

  New `tests/unit/test_release_workflow.py` pins the property structurally
  (not a digest, which would fail on every legitimate edit): publish must not
  rebuild, the upload and download artifact names must match, and the upload
  must fail on no files. Kill-checked — reintroducing a build step and
  mistyping the artifact name each turn the guard red with a named cause.

- **aramid could print its verdict and then refuse to exit — a hung `git push`
  after the gate had already decided.** Important #2 fixed only half of this.
  Dropping the executor's context manager made `run_gate` *return* at the
  budget, but a `ThreadPoolExecutor` worker is not a daemon, so both
  `concurrent.futures._python_exit` and `threading._shutdown` join it during
  **interpreter shutdown**. The verdict was printed on time and the process
  then sat there for as long as the abandoned runner ran:

  | hung runner | `run_gate` returned | **process exited** |
  |---|---|---|
  | 3s | 0.24s | **3.42s** |
  | 12s | 0.22s | **12.36s** |

  Exit time tracks the straggler exactly. The gate runs inside a git hook, so
  this is the push hanging — and it has **no ceiling**, because
  `run_subprocess` passes `timeout_s` to `communicate()`, which does not cover
  `subprocess.Popen`. A runner stuck in process creation hangs the hook
  indefinitely; that is not hypothetical, since a test whose subprocess was
  capped at 60s was measured running past 600s on this repo.

  The obvious one-line fix does not work, and was measured rather than
  assumed: detaching the pool's threads from
  `concurrent.futures._threads_queues` gave **10.21s against 10.23s unfixed**,
  because `threading._shutdown` joins non-daemon threads regardless of what
  the futures module thinks. `t.daemon = True` cannot be set after a thread
  starts, so getting daemon threads at all means owning them — `_run_selected`
  now uses raw daemon threads with an `Event`-based budget wait. Exit drops to
  **0.63s**.

  Written test-first: the guard failed at **45.4s against a 15s bound** with
  `RETURNED` already in stdout — proving the verdict was produced and the
  process then hung — and passes in 1.75s after. It measures a **child**
  process, because interpreter shutdown is not observable from inside the
  interpreter performing it. The existing `test_hung_runner_does_not_block_past_gate_budget`
  could never have caught this: it measures `run_gate`'s return, which was
  always fine.

  **The trade, stated rather than buried:** a daemon thread is killed at
  interpreter exit, so an abandoned runner's child process can outlive the
  gate. Its result was already discarded as `TIMEOUT`, and `run_subprocess`
  deliberately launches children detached
  (`CREATE_NEW_PROCESS_GROUP`/`start_new_session`) so they were never ours to
  reap. A short-lived orphan analyzer beats a hung push.

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

  **aramid's own `red-proof` consumer then flagged that new test, correctly.**
  Its first version branched on `after == before` and asserted only a size
  match in that branch, so it passed whether a link *or* a copy happened — it
  could not fail, making it the very defect it was written to prevent.
  Hard-link support is now established by an **independent probe** on the same
  filesystem rather than inferred from the outcome under test, so the fallback
  and the regression are no longer the same observation. The discriminator is
  measured: `shutil.copy` leaves `st_nlink` at 1 while `os.link` takes it to 2,
  so the assertion provably separates them. Noted because it is the session's
  own lesson landing on its own work — and because the gate caught it, not me.

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

- **`aramid override`'s BLOCK refusal now prints the ready-to-paste
  `[[suppress]]` entry.** It always named `.aramid-suppressions.toml` as the
  correct channel and then left the operator to hand-assemble the entry from
  `aramid ledger list` output — including `id`, an opaque content fingerprint
  and the one field nobody can retype. Both ways of getting it wrong are
  quiet ones: a missing `reason` makes the loader **drop** the entry entirely,
  and a wrong `id` reads as a stale near-miss.

  The emitted TOML is escaped, because `--reason` is free user text — a quote
  or a Windows path's backslash would otherwise produce a snippet that fails to
  parse, or parses into something other than what was typed. Both guards assert
  by **round-trip** rather than substring: the emitted text is written to a real
  `.aramid-suppressions.toml`, loaded through the real `load_suppressions`, and
  required to yield a record matching the finding.

- A `.aramid-suppressions.toml` section in the user guide. The file was
  referenced four times as the thing to use and its format appeared nowhere.

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

- **`.aramid-suppressions.toml` is now tier-agnostic: it accepts a reasoned
  WARN entry as readily as a BLOCK one.** The committed file was BLOCK-only,
  and the ledger (`aramid override`) WARN-only, as a strict partition. That
  made a WARN id in the committed file a **silent no-op** — measured, not
  inferred: it matched neither branch of `policy.apply_overrides`, *and* it was
  not reported stale either, because its id **is** among the findings, so the
  stale loop's `continue` skipped it. No effect and no diagnostic, which is the
  exact failure shape this tool exists to catch.

  The file could authorize the *dangerous* suppression (silencing a BLOCK) but
  not the *safe* one. Design doc section 6 never asked for that: "a BLOCK
  **requires** the committed file" is a floor on what BLOCK needs, and it was
  implemented as a ceiling on what the file may carry. The section now carries
  a dated amendment saying so.

  **"It's only a warning" was never a defence, which is what makes this worth
  fixing rather than noting.** A brand-new WARN is escalated to BLOCK by the
  pre-push ratchet on first sighting, so a teammate's fresh clone *blocks* on a
  finding the team had already reviewed and thought they had recorded. The
  new end-to-end test drives `run_gate` twice against a second, empty ledger —
  keeping the finding NEW, the only state in which the ratchet has teeth — and
  its red-proof against the old code returns **BLOCK**, not WARN.
  `apply_overrides` running before the ratchet is what makes the suppression
  work, and that ordering is now pinned.

  The ledger stays WARN-only, and `aramid override` still refuses BLOCK-tier
  findings — `.aramid/` is gitignored, so a BLOCK hidden there is an
  unreviewable decision. The resulting rule: **ledger override** = "quiet this
  for me, on this machine"; **suppressions file** = "the team decided this,
  reviewably", any tier.

  The two branches are deliberately *not* collapsed into
  `if f.id in suppress_ids or f.id in override_ids` — that one-line
  simplification would let a machine-local ledger entry hide a BLOCK finding,
  re-granting one layer down exactly what the CLI refuses.
  `test_override_does_not_downgrade_block_finding` was verified to fail against
  that shape before the real fix went in, and a second test pins the mixed case
  where one id sits in each channel.

  Stale detection needed no change and was pinned rather than edited:
  `matched_ids` was always tier-blind. `init._scan_history` is likewise
  unaffected — it filters on the id set directly and never calls
  `apply_overrides`.

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

[Unreleased]: https://github.com/jared0565/aramid/compare/v0.12.0...HEAD
[0.12.0]: https://github.com/jared0565/aramid/releases/tag/v0.12.0
[0.11.0]: https://github.com/jared0565/aramid/releases/tag/v0.11.0
[0.10.0]: https://github.com/jared0565/aramid/releases/tag/v0.10.0
[0.9.0]: https://github.com/jared0565/aramid/releases/tag/v0.9.0
[0.8.1]: https://github.com/jared0565/aramid/releases/tag/v0.8.1
[0.8.0]: https://github.com/jared0565/aramid/releases/tag/v0.8.0
[0.7.2]: https://github.com/jared0565/aramid/releases/tag/v0.7.2
[0.7.1]: https://github.com/jared0565/aramid/releases/tag/v0.7.1
[0.7.0]: https://github.com/jared0565/aramid/releases/tag/v0.7.0
[0.6.1]: https://github.com/jared0565/aramid/releases/tag/v0.6.1
[0.6.0]: https://github.com/jared0565/aramid/releases/tag/v0.6.0
[0.5.1]: https://github.com/jared0565/aramid/releases/tag/v0.5.1
[0.5.0]: https://github.com/jared0565/aramid/releases/tag/v0.5.0
[0.4.1]: https://github.com/jared0565/aramid/releases/tag/v0.4.1
[0.4.0]: https://github.com/jared0565/aramid/releases/tag/v0.4.0
[0.3.1]: https://github.com/jared0565/aramid/releases/tag/v0.3.1
[0.3.0]: https://github.com/jared0565/aramid/releases/tag/v0.3.0
[0.2.0]: https://github.com/jared0565/aramid/releases/tag/v0.2.0
[0.1.0]: https://github.com/jared0565/aramid/releases/tag/v0.1.0
