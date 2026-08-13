# Changelog

All notable changes to aramid are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[semantic](https://semver.org/spec/v2.0.0.html).

`src/aramid/__init__.py`'s `__version__` is the single source of truth —
`pyproject.toml` derives its version from it, and the release workflow refuses
to publish a tag that disagrees with it.

## [Unreleased]

### Fixed

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

  **Still open, and named here rather than quietly fixed:** an override
  recorded while a tool is *disarmed* still survives arming. Closing that means
  refusing every override for any tool with an arming flag, regardless of its
  state, which is a much broader behaviour change than this fix and an
  operator-facing policy call — not something to ship as a side effect of a
  security repair.

### Added

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

[Unreleased]: https://github.com/jared0565/aramid/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jared0565/aramid/releases/tag/v0.2.0
[0.1.0]: https://github.com/jared0565/aramid/releases/tag/v0.1.0
