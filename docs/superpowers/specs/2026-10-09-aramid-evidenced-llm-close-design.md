# Evidenced close for a fixed LLM finding (FN-36) — design

Status: DECIDED 2026-10-10, not built. Shape chosen by the operator ("go with
your recommendations": shape 2 of FN-36). The four questions in section 5
were answered by the operator on 2026-10-10; sections 2 and 4 below are
amended to match, and each amendment says so.

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
