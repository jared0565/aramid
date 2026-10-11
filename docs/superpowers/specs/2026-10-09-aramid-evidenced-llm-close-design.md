# Evidenced close for a fixed LLM finding (FN-36) — design

Status: BUILT 2026-10-10 as a command-line close; the MCP tool is not built
and waits on three questions for the operator (section 8.6). Shape chosen by
the operator ("go with your recommendations": shape 2 of FN-36). The four
questions in section 5 were answered by the operator on 2026-10-10; sections
2 and 4 below are amended to match, and each amendment says so. **Section 8
records what was built and holds where it disagrees with an earlier
section**: red proof backs out the one commit and has a control (8.2), and
`ledger show` had to be taught to print the evidence (8.4).

## 1. The problem, re-measured

An llm-review finding closes only when its whitespace-stripped evidence
quote is gone from its own file at HEAD (`review.auto_resolve_llm`). A fix
that guards the path to the quoted line, re-reads after it, or moves the
check to a caller leaves the quote byte-identical. The finding then stays
`open`. pawscout-worker has nine such findings, all fixed and tested (channel
round 316).

The only exit today is `aramid override <id> --reason "fixed in <sha>"`.
FN-36's report objects to it for two reasons:

- an override records a fix as an accepted risk;
- editing the quoted line just to make the quote vanish edits a finding away.

**Verified 2026-10-09: the safety net the docstring promises does not exist
on the override path.** `auto_resolve_llm`'s docstring says that after an
override "the next drain re-reviews the file and either re-raises the
finding, meaning the fix was incomplete, or does not". Read at HEAD:

- The llm-review consumer drops a candidate whose id the ledger holds as
  `open`, `overridden` or `historical` before it records anything (the
  pre-refute dedupe, `consumers/llm_review.py` ~326-345).
- `Ledger.record_run` writes a new `finding_detected` only for an id that is
  absent, or whose status is `fixed`, `unreachable`, `superseded`,
  `out_of_scope` or `pending_retest` (`ledger.py` ~706).
- The consumer writes no `finding_resolved` at all.

So an overridden finding that a later drain raises again stays `overridden`
with no event and no signal. The docstring's "re-raises ... meaning the fix
was incomplete" cannot happen. Fixing that docstring is part of this work
whatever else is decided.

**The same facts give this design its main property.** A finding closed as
`fixed` IS re-opened when a drain raises it again: it passes the dedupe, and
`record_run` writes a fresh detection. The evidenced close therefore writes
`fixed`, not a new status, and inherits the safety net that override cannot
have.

## 2. The command

```
aramid ledger resolve <id> --fixed <commit> --test "<test command>" --reason "..." [--red-proof]
```

`--red-proof` (decided 2026-10-10, section 5 questions 1 to 3) also runs the
test against the tree before the fix and requires it to FAIL there. It is:

- optional at the command line for an ordinary finding;
- required for a confirmed-critical finding, at the command line and through
  MCP alike;
- always applied to a close made through the MCP tool, for every finding.

How the pre-fix run is built (a throwaway worktree at `<commit>^`, and what
happens to a test file that did not exist there) follows the existing
`[red_proof]` machinery and is settled when the build is planned.

`--test` takes the command that runs the test, for example
`npx vitest run src/orders.test.ts -t "routes CN"` or
`python -m pytest tests/test_x.py::test_y`. aramid splits it with
`shlex.split`, runs it with no shell from the repo root, and records the
argv verbatim.

The reason for this shape: the report that created FN-36 (round 316) came
from pawscout-worker, a TypeScript repo whose nine fixes are vitest tests.
A pytest node id could never have accepted any of them. Each runner names a
single test differently, so the command, not aramid, says how.

Refusals each exit 3 with a message naming what to do instead. The command
refuses when:

1. the id is unknown, or its status is not `open`;
2. the finding's tool is not `llm-review`. Mutation survivors have a verified
   re-test, and deterministic tools re-run every gate, so neither needs a
   manual close;
3. the finding is confirmed-critical (`review.is_confirmed_critical_llm`,
   armed or not) and red proof was not run, or the test did not fail before
   the fix. *Amended 2026-10-10 (section 5, question 1):* the draft refused
   every confirmed critical, mirroring `override`. A confirmed critical now
   closes, but only with red proof;
4. `<commit>` is not an ancestor of HEAD. It is also refused when it is an
   ancestor of the `head` the finding was raised at (recorded on its
   detection), because a fix cannot predate the finding. The commit need NOT
   touch the finding's file: one of round 316's nine fixes (82d77aaa) landed
   only in a caller;
5. the command's executable cannot be resolved (the same `toolpath.resolve`
   the runners use);
6. the command does not exit 0 at HEAD within `[tests].timeout_s`. A
   timeout or crash is a refusal, not a pass;
7. `--reason` is empty.

On success it appends one `finding_resolved` event with this payload:

```
{"auto_resolved": "evidenced_close", "commit": "<full sha>",
 "test_argv": ["..."], "test_rc": 0, "reason": "...", "head": "<HEAD sha>"}
```

*Amended 2026-10-10:* the payload also records whether red proof ran and
what the pre-fix run returned, so a reviewer can tell a close that showed
the test failing from one that did not (section 5, question 2). The field
names are fixed when the build is planned.

The status fold already maps a plain `finding_resolved` to `fixed`. No new
status and no fold change are needed. `ledger show` prints the payload, so
the evidence sits on the event.

## 3. Why not the other shapes

- **Re-review on touch** (shape 1): every commit touching the finding's file
  would cost a refute-or-confirm call. Tokens per touch, for every open
  finding, forever. It is also non-deterministic: the same fix can be
  refuted once and confirmed the next time.
- **A new `fixed_by_evidence` status**: round 316 asked for one, "so it is
  never mistaken for an automatic clear". This design departs from that
  request on purpose, and the operator may overrule it (section 5, question
  4). A new status would lose the re-open path in section 1, unless
  `record_run`'s re-open list and the consumer's dedupe both learned it.
  That is two more places to keep in step. The event's `auto_resolved:
  evidenced_close` already tells this close from an automatic one in
  `ledger show`, and `ledger filter --json` can expose it as a field.
- **Loosening the quote match**: this is how a confirmed critical gets
  resolved away. The resolver's docstring rules it out, and that reasoning
  still holds.

## 4. What it does not do

- Without `--red-proof` it does not prove that the command tests the finding
  at all. A command that runs no test (`true`) satisfies rule 6. The recorded
  argv and the reason are the human evidence, and both sit on the event for
  review. Red proof is the stronger check: optional for a person closing an
  ordinary finding, and never optional for a confirmed critical or for a
  close made through MCP (section 5).
- It does not cover `historical` or `overridden` rows. An already-overridden
  fixed finding stays as it is; its owner can leave it.

## 5. Questions for the operator (all decided 2026-10-10)

1. **Confirmed-critical findings.** The draft's rule 3 refused them, as
   `override` does. But a fixed critical then has no exit except editing the
   quoted line or a `.aramid-suppressions.toml` entry, which asserts
   "acceptable", not "fixed". Option: allow it only when the test also FAILS
   at `<commit>^` (question 2), which is the evidence a critical deserves.

   **Decided: allowed, red proof required.** At the command line and through
   MCP alike.
2. **Red proof (optional flag `--red-proof`).** Run the test at `<commit>^`
   in a throwaway worktree and require it to fail there. This proves the test
   detects what the commit fixed. It costs a worktree and a second test run,
   and aramid already has the machinery (`[red_proof]`). Proposed: optional
   for ordinary findings, required for confirmed-critical ones if question 1
   is answered yes.

   **Decided: an optional flag for an ordinary finding.** The event records
   whether it ran.
3. **MCP.** Should the tool be exposed as `aramid_ledger_resolve`? An agent
   could then close its own findings, with the same rules. Proposed: yes;
   the rules are the guard, and `override` is already exposed. Given the
   `true` case in section 4, an agent's close could require `--red-proof`.

   **Decided: yes, and a close through MCP always requires red proof**, for
   an ordinary finding too. A person at the command line keeps it optional
   (question 2).
4. **Its own status, as round 316 asked?** Proposed: no; `fixed` plus the
   payload (section 3) keeps the re-open path. Say yes if a filterable
   status matters more than that path, and the re-open list and the dedupe
   gain it too.

   **Decided: no new status.** The close writes `fixed` with the evidence on
   the event; `ledger show` prints it and `ledger filter --json` exposes the
   close kind as a field.

## 6. Tests (to write first)

- Each refusal, one test apiece, with the exit code and message asserted
  whole.
- Success writes exactly one event with the payload above, and status reads
  `fixed`.
- **The safety net, end to end:** a resolved finding that the llm-review
  consumer raises again (faked provider) is `open` again after `record_run`.
  The control: an OVERRIDDEN finding raised again stays `overridden`. That
  pins the asymmetry this design rests on.
- A command that fails, times out, or cannot be resolved at HEAD each
  refuses, and each writes nothing.
- A commit that touches only another file (the caller case) is accepted; a
  commit that predates the finding's detection head is refused.
- The argv is recorded exactly as split, for a pytest command and for an
  npx command alike.

## 7. Docs

- user guide, section 5 *An LLM finding you fixed that stays open anyway*:
  the new exit, before `override`;
- section 12's *An LLM finding can stay open after a real fix*;
- KB section 4 command reference;
- `review.auto_resolve_llm`'s docstring: correct the "re-raises" claim
  (section 1);
- CHANGELOG `Added`.

## 8. As built (2026-10-10)

Read from the code and tried in scratch repositories before anything was
written in the tree. This section settles what sections 2 and 5 left open
and corrects what they got wrong. Where it disagrees with an earlier
section, this one holds.

### 8.1 The subcommand already existed

`aramid ledger resolve <id>... --out-of-scope --reason R` shipped in 0.6.1.
It retires a RUNNER finding whose path left its runner's scope, and it
refuses every producer finding, llm-review included. The evidenced close is
a second mode of the same subcommand:

- `--fixed <commit>` selects it, and `--test` and `--red-proof` belong to it;
- `--fixed` together with `--out-of-scope` is refused, and so is `--test` or
  `--red-proof` without `--fixed`;
- `--fixed` takes exactly one id, because each finding needs the test that
  proves its own fix. `--out-of-scope` still takes several.

### 8.2 Red proof backs out one commit, and has a control

Section 2 said the pre-fix run "follows the existing `[red_proof]`
machinery". That machinery runs `python -m pytest` and reads pytest's exit
codes. It cannot serve a vitest command, and vitest is the case FN-36 was
filed for. A command can also fail in a fresh worktree for reasons that say
nothing about the fix: the test file is not committed, dependencies are not
installed there, the selector matches nothing. Exit codes do not tell those
apart across runners.

So one throwaway worktree of HEAD is used twice:

1. As checked out, the command must exit 0. This is the control. The repo's
   `node_modules` is linked in when it has one, the way the js_mutation
   consumer does it.
2. The fixing commit is backed out with `git revert --no-commit` (`-m 1` for
   a merge commit). The command must then exit non-zero.

Only that commit is backed out, so commits after it stay and the proof reads
"fails without `<commit>`". Three kinds of path the commit changed are put
back to their content at HEAD after the back-out:

- its test files, by the two naming rules aramid already has (pytest's and
  the js_mutation consumer's). A test added with the fix has to exist to be
  run against the tree without it;
- any file the command names. A test in a file no naming rule recognises is
  still the file under test;
- every file the commit added. Taking one away fails the command when it is
  test support, and that failure would read as red.

HEAD decides what "put back" means for each, not what the commit did to the
path: a kept path that HEAD holds is checked out from it, and one HEAD does
not hold is removed. The checkout is given literal pathspecs.

Refused, each with nothing recorded:

- a `<commit>` with no parent;
- a `<commit>` that changes no existing source file (only tests, or only new
  files): nothing is left to back out;
- a control run that does not exit 0;
- a `<commit>` git can no longer back out, because a later commit changed
  the same lines of a path that has to be backed out. The refusal names the
  path (the first by name, and how many more). A guess at the tree without
  the commit would prove nothing. A conflict in a kept path is not a
  refusal: that path is put back as HEAD has it whatever the back-out did;
- a back-out that fails and leaves no conflict git can list. The refusal
  quotes git;
- a run without the fix that exits 0, times out or cannot start.

**The first design was wrong, and a prototype showed it.** It put every
non-test path that differs between `<commit>^` and HEAD back to its content
at `<commit>^`. Two faults:

- it proved "fails without everything since `<commit>^`", not "fails without
  `<commit>`";
- a helper or a test in an unrecognised location, added by any later commit,
  went missing with the rest, and the command then failed for that reason.
  That is a false red.

Tried in scratch repositories, nine shapes: plain, with CRLF files under
`core.autocrlf`, a later commit in another file, a later commit in another
hunk of the fixed file (with and without autocrlf), a later commit on the
fix's own lines (refused), a fix that adds a helper outside `tests/`, a fix
made only of new files (refused), and a test in an unrecognised file named
in the command. Each came out as intended, the repo's own tree was untouched
and no worktree was left behind.

Hooks, measured: `git worktree add` runs the repo's `post-checkout` hook, as
it does for every worktree aramid builds. It runs before the control, so
both runs see what it did. Putting the kept paths back is a `git checkout`
too and would run the hook between the two runs; that call is made with
hooks off. `git revert --no-commit` runs no hook.

What red proof still cannot tell, two things:

- test support that the fixing commit MODIFIED, outside every recognised
  test location and not named in the command, is backed out with the fix. A
  failure caused by that reads as red;
- HEAD with one commit taken out is a tree nobody ever committed. When a
  later commit uses something the fix introduced (a function, a
  parameter), the command fails there because the tree no longer fits
  together, and that also reads as red. It shows the test needs the commit,
  which is less than showing it detects the bug. Seen while reviewing the
  build, not measured.

**Replayed on real state, and what it found (2026-10-10 18:15Z).** This
repo has one finding of FN-36's kind: `ea21b2a8`, an llm-review finding
raised 2026-09-07 at `mutation.py:88`, fixed the next day in `5eba4d3` in
the resolver, not at the quoted line, and open ever since under a
suppression entry. Fourteen later commits touch the two files that fix
changed. The built command was run from the committed tree
(`c6a1589`) in a scratch clone, against a copy of this repo's ledger file
(the main database file only, without its write-ahead log; the real ledger's
path was never opened by the command):

- with `--red-proof`: **refused**. "`5eba4d3d1e8f` can no longer be backed
  out of HEAD ... a later commit changed the same lines". Nothing recorded.
  Tried by hand in the same clone: `git revert --no-commit 5eba4d3`
  conflicts in six of the eight files the commit changed. Both source files
  with later edits are among them, and so are `CHANGELOG.md` and the user
  guide, which a later release rewrites whatever the fix was;
- without it: closed. The named unit test passes at HEAD, `ledger show`
  prints the three evidence lines with `red proof: not run`, and
  `ledger filter --json` gives `resolved_by: evidenced_close`.

The refusal is the command doing what it says. It is also a limit that
matters, found on the first real case tried: **once the lines a fix
changed have been edited again, red proof cannot be shown, and this repo's
one real case, a month old, is in that state.** How common that is has not
been measured beyond this one case. Two consequences for decisions already
made:

- A confirmed critical closes only with red proof (section 5, question 1).
  One whose fix was edited later has no exit again, which is the gap that
  decision was meant to close.
- "A close through MCP always requires red proof" (question 3) would refuse
  every finding in that state that an agent tries to close.

A way out exists and is not built, because it changes what the proof
claims: when the commit cannot be backed out of HEAD, show red at the fix
itself. Check out `<commit>`, bring in the named test as it is at HEAD,
require the control to pass there, back the commit out (always clean, it is
the tip) and require the test to fail. That proves "the test passes with
the fix and fails without it, as the code stood when the fix was made",
not "at HEAD". The source in both runs is a state that was committed
(`<commit>` and its parent), so the second limit above does not apply to
it; its own limit is a test that no longer runs against the old code, which
the control would refuse. It is a question for
the operator (8.6). (Decided 2026-10-11 and built, with two changes to this
sketch: section 9.1.)

**Second pass, the same evening: four defects in the committed back-out,
fixed before any push.** The replay's six conflicts included two test files,
which are kept at HEAD whatever the back-out does to them. That was the
first defect, and measuring git for it in a throwaway repository showed
three more. Each is now a test:

- A conflict in a kept path refused the proof. Measured: a `git revert
  --no-commit` that conflicts still backs out every path it can, and `git
  checkout <head> -- <path>` puts an unmerged kept path back. So only a
  conflict in a path that has to be backed out is a refusal, and it names
  the path.
- A file the fix added that a later commit deleted refused the proof with
  "git could not put the test files back": `git checkout` refuses a path
  its tree does not hold. Measured.
- A test the fix deleted that a later commit brought back unchanged was
  removed again, because the rule looked at what the commit did to the path.
  Measured: that back-out is clean and leaves the file in place; the old
  rule then deleted it. A command that needs the file fails for a missing
  file, and that reads as red. This one was a false red, not a refusal.
- A kept path named `app/[id]/page.test.ts` is a pattern to `git checkout`.
  Measured: checking out that one path also restored `app/i/page.test.ts`.
  Had the fix changed that neighbour, it would have come back and the test
  would have passed without the fix, a wrong refusal.

The rule now is the one stated above: HEAD decides which kept paths come
back, and the pathspecs are literal.

The replay was run again with that code (imported from the working tree,
acting on a fresh scratch clone of `c6a1589` and a fresh copy of the ledger
file): still **refused**, now as "`5eba4d3d1e8f` can no longer be backed out
of HEAD -- it conflicts with later changes to CHANGELOG.md and 3 more
file(s)". The four are `CHANGELOG.md`, the user guide and the two source
files; the two test files no longer count. So the limit stood as written,
and the question for the operator with it. Section 9.1 is the answer.

### 8.3 The event

```
{"auto_resolved": "evidenced_close", "commit": "<full sha>",
 "test_argv": ["..."], "test_rc": 0, "reason": "...", "head": "<HEAD sha>",
 "red_proof": null,
 "via": "cli"}
```

With red proof, `red_proof` is
`{"at": "head", "base": "<sha of the commit's first parent>", "control_rc": 0, "pre_fix_rc": N, "backed_out": K}`,
where K is the number of the commit's paths that were backed out. `at` was
added with the second build; a proof shown at the fix commit records
`"at": "commit"` and two more keys (9.1). `via` is `cli`; `mcp` is reserved
for 8.6.

### 8.4 `ledger show` and `ledger filter --json`

Sections 2 and 5 said `ledger show` prints the event's payload. It did not
[V, 2026-10-10: it printed each event's time, type and run id]. The build
adds three lines under an evidenced close: the commit with who closed it and
why, the test command with the HEAD it passed at, and the red proof or "red
proof: not run".

`ledger filter --json` gains `resolved_by` on every row. It is the resolver
named on the row's last resolution, and `evidenced_close` for this command.
It is null on a row that is not resolved, and on one its own tool resolved
by no longer reporting it, since that route names no resolver.

### 8.5 Rules settled from the code

- `<commit>` may be any rev git resolves. The event records the full sha.
- A finding whose detection recorded no `head` (detections before
  2026-09-06) skips the "a fix cannot predate its finding" check. Refusing
  would strand every older finding.
- No tracked file may have uncommitted changes. The event records the commit
  the test passed at, and an edited tracked file makes the tree something
  else. Untracked files do not count.
- The finding's status is read again after the test ran. A test can run for
  minutes, and a gate or an override may have changed the row meanwhile.
- Each run is bounded by `[tests].timeout_s`: one at HEAD, and two more with
  red proof, or three more when the proof moves to the fix commit (9.1: the
  control at HEAD has run by then, and the fix commit needs its own). A value the config loader has already called wrong (text, a
  boolean, zero or less, or a `tests` that is not a table) is read as the
  default, 300 s.
- `--test` is split POSIX-style, like a string `[tests].command`. On Windows
  a path in it wants forward slashes.
- Rule 5 of section 2, as built: the command goes through
  `runners.tests._argv` and `run_subprocess`, as a `[tests].command` does. A
  relative path to a program is anchored at the repo root, so it names the
  same program in the worktree, and a program that cannot be found is a
  refusal.

### 8.6 The MCP tool is not built: three questions for the operator

(All three were answered on 2026-10-11. Section 9 has the answers and what
was built from each.)

Section 5, question 3 was decided: expose `aramid_ledger_resolve`, and always
require red proof through it. Found while planning the build: `--test` is a
command line. Through MCP that makes aramid's server run whatever program
the caller names. No MCP tool does that today: `aramid_check` runs only the
repo's own test suite, which is the command its tracked config declares or
the suite aramid detects. An agent host that allows aramid's tools without
asking, but asks before a shell command, would be bypassed by it.

The command-line close does not have this problem: whoever can type it can
already run the program. So the command-line close is built, and the MCP
tool waits for the operator to choose its shape:

1. test selectors only: the caller names tests, and aramid appends them to
   a command the repo declares in tracked config;
2. any command, as at the command line;
3. no MCP tool.

A second point for the same decision: an agent with a shell can run the
command-line close without `--red-proof`. If "an agent's close always shows
red proof" is meant for those agents too, the agent hook is where it would
be enforced. The hook today looks at git commands only (`--no-verify`, a
changed hooks path); it does not read an `aramid` command line, so that
would be a new kind of rule for it.

A third question came out of the replay in 8.2: whether red proof should
fall back to the fix commit itself when the commit can no longer be backed
out of HEAD. Without it, "always red proof" for MCP and for a confirmed
critical refuses every fix whose lines were edited afterwards.

Waiting on the first two answers: the `ARAMID.md` template. Its command list
is where an agent in a consumer repo learns what exists, and it does not
name the close yet, because the line to write depends on both answers (an
MCP tool name or the command line, and whether red proof is required).
Changing the template also makes every consumer's `ARAMID.md` stale until
`aramid init` is run again there, so it is done once, not twice.

### 8.7 Tests, as written

`tests/unit/test_ledger_resolve_fixed.py` holds the command's tests at unit
scope, because the drain confirms a mutant against the unit suite alone.

- A small real git repository is built once for the module. Tests that only
  read it share it; a test that commits, edits a file or builds a real
  worktree gets a private copy.
- Five tests build a real worktree and really run the checks, because what
  they pin is the tree git leaves: what is backed out, what stays, what a
  later rewrite of the fix does (since 9.1: the proof at the fix commit,
  with a check written after the fix brought in from HEAD), what later
  changes to the kept paths do, that a kept path with brackets in its name
  brings back only itself, and that no hook runs between the two runs.
- The rest decide nothing about the tree, so `git worktree`, `git revert`
  and `git checkout` answer without acting and the runs are scripted.

The safety net of section 6 is in `tests/unit/test_llm_consumer.py`: a
finding closed on evidence that a review raises again is `open` again, and
an overridden one is not raised and stays `overridden`.

## 9. Second build: the operator's decisions of 2026-10-11

The three questions of 8.6, and one from the plan, were asked one at a time.
Each answer was the recommended option.

| # | Question | Decision |
|---|----------|----------|
| 1 | Shape of the MCP tool (8.6) | Test selectors only, appended to a command the repo declares in tracked config. |
| 2 | Red proof when the fix cannot be backed out of HEAD (8.2) | Show it at the fix commit instead; the event says which proof it was. |
| 3 | An agent's command-line close without `--red-proof` (8.6) | The agent hook refuses it. |
| 4 | FN-41, the `claude -p` reviewer | Restrict it and prove the restriction with one or two real calls. Plan item FN-41, not this spec. |

### 9.1 Red proof at the fix commit (built 2026-10-11)

When the back-out of HEAD conflicts in a path that has to be backed out, the
proof is no longer refused. HEAD's worktree is removed and a second one is
checked out at `<commit>`:

1. The files the command names that HEAD holds are brought in as HEAD has
   them (`git checkout <head> -- <paths>`, literal pathspecs, hooks off).
   The test on offer is the one at HEAD. It may have been written after the
   fix, and then `<commit>` does not have it.
2. The command must exit 0 there. That is the control. If it does not, the
   close is refused: "`<commit>` can no longer be backed out of HEAD -- it
   conflicts with later changes to `<file>` [and N more file(s)] -- and at
   `<commit>` itself the test exits N: as it is at HEAD it does not run
   against the code as it stood when the fix was made".
3. The paths that would have been backed out at HEAD are put back as the
   commit's first parent has them (`git checkout <parent> -- <paths>`).
   Each of them was modified or deleted by the commit, so the parent holds
   it. The commit's tests, the files it added and the files the command
   names stay, by the rule of 8.2.
4. The command must exit non-zero.

Two things in the sketch of 8.2 and in the first draft of this section were
dropped before the build:

- "Run the commit's own copy of the test first, and bring HEAD's in only if
  that fails." That is two controls, and which of them passed would decide
  which test the proof is about. One rule instead: the test on offer is
  HEAD's, always.
- "Back the commit out with `git revert`; always clean, because it is the
  tip." It is not clean once HEAD's copy of a test is in the tree and the
  commit touched that file too: git refuses to revert over the local change
  [V, 2026-10-11, throwaway repository]. A checkout of the parent's copy of
  each path needs no merge.

What it proves: the test, as it is at HEAD, passes with the fix and fails
without it, in the code as it stood when the fix was made. With the first
check of every close (the command exits 0 at HEAD) that is the evidence
offered. It does not prove "fails without the fix at HEAD", and the event
says which was shown:

    "red_proof": {"at": "commit", "base": "<parent sha>", "control_rc": 0,
                  "pre_fix_rc": N, "backed_out": K,
                  "head_conflicts": M, "brought": B}

M is the number of paths in conflict at HEAD among those that had to be
backed out, B the number of files brought in from HEAD. The ordinary proof
records `"at": "head"` and the four keys of 8.3. The line the command prints
ends "failed (exit N) without the fix as the code stood at `<commit>`", and
`ledger show` prints "red proof at the fix commit (it can no longer be backed
out of HEAD: M file(s) in conflict): exit N with it backed out against
`<parent>` -- K of its path(s); B test file(s) brought in from HEAD".

Not moved to the fix commit: a commit with nothing to back out, a control
that fails at HEAD, a test that passes without the fix at HEAD, and a
back-out that git refuses without leaving a conflict it can list. Those say
something about the test, the commit or git, not about later edits.

A confirmed critical closes on either proof. The question was asked because
such a finding had lost its exit (8.2), and a proof at the fix commit gives
it back.

Limits:

- The first of 8.2 holds here too: test support the commit modified goes
  back with the fix.
- The second does not arise in the form 8.2 gives it, because no later
  commit is in this tree. The tree without the fix is still one nobody
  committed: the parent's source, with the commit's own tests and added
  files, and HEAD's copy of the named test.
- A new one. Nothing here shows that `<commit>` is what makes the test pass
  at HEAD. A later commit may have replaced the fix with another; the test
  passing at HEAD then shows the bug gone, but not by the commit named. The
  proof at HEAD does not have that gap.

**Replay 3 (2026-10-11 07:37Z).** The case of 8.2 again: the working tree's
code, acting on a fresh scratch clone at `7a016ca` and a fresh copy of the
ledger file. **Closed.** `5eba4d3` changed eight paths. Three are tests and
stay. Five are backed out, and four of those conflict at HEAD, 231 commits
later: the two source files with later edits, `CHANGELOG.md` and the user
guide. The named test is in `tests/unit/test_mutation_gate.py`, a file that
commit itself wrote to. HEAD's copy of it was brought in, the test passed at
`5eba4d3`, and it failed (exit 1) with the five paths put back to `5e445c6`.
The real ledger file's hash was the same before and after.

Tests: the real-worktree test of a later rewrite now ends in a close at the
fix commit, with a check that only HEAD holds. Twelve scripted tests pin the
order of git's calls there, what is brought in, both refusals of the
control, both refusals of the run without the fix, each git failure, that
each worktree gets and loses its own `node_modules` link, and that a
confirmed critical closes on this proof. Every limb was perturbed in a
scratch copy of the tree and seen to fail its test.

### 9.2 The MCP tool: `aramid_ledger_resolve` (decided, not built yet)

Arguments: `id`, `commit`, `tests` (one or more selectors), `reason`.

- The command is `[tests].select_command` from the `aramid.toml` that HEAD
  holds (read with `git show HEAD:aramid.toml`, so neither the user-level
  config nor an uncommitted edit can supply it), with the selectors appended.
  A repo that declares none is refused, naming the key.
- A selector is `<path>`, or `<path>::<rest>` when the declared command is
  pytest. `<path>` must be a file HEAD holds, and a selector may not start
  with `-`. So a selector is only ever a positional argument that names
  committed test code: never an option, never a file outside the repository.
- A selector is also held to a set of plain characters. On Windows a
  declared command such as `npx vitest run` starts a `.cmd` shim, and
  cmd.exe reads `&`, `|`, `<`, `>`, `^`, `%` and a double quote in an
  argument as syntax.
- Red proof is always run. The event records `"via": "mcp"`.
- Everything else is the command-line close: same checks, same refusals,
  same event.

### 9.3 The agent hook rule (decided, not built yet)

The pre-tool-use hook also reads an `aramid ledger resolve` command line:
`--fixed` without `--red-proof` is an advisory while the agent surface
bakes and a denial once it is armed, like a hook bypass. Token-level, like
the git rules: the values of `--test`, `--reason` and `--fixed` are skipped,
so text inside them cannot match, and the abbreviations argparse accepts
(`--fix`, `--red`) are read as the flags they stand for. The table of flags
is checked by a test against the real parser, so a flag added to `ledger
resolve` later cannot go unread. Launch forms: `aramid`, `aramid.exe`,
`aramid.cmd` and `python [-P] -m aramid`.
