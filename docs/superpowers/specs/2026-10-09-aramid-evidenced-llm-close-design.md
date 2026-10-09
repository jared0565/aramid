# Evidenced close for a fixed LLM finding (FN-36) — design

Status: DRAFT, 2026-10-09. Shape chosen by the operator ("go with your
recommendations": shape 2 of FN-36). Not built.

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
aramid ledger resolve <id> --fixed <commit> --test <pytest node id> --reason "..."
```

Refusals each exit 3 with a message naming what to do instead. The command
refuses when:

1. the id is unknown, or its status is not `open`;
2. the finding's tool is not `llm-review`. Mutation survivors have a verified
   re-test, and deterministic tools re-run every gate, so neither needs a
   manual close;
3. the finding is confirmed-critical (`review.is_confirmed_critical_llm`),
   armed or not. This mirrors `override`'s refusal; see section 5, question 1;
4. `<commit>` is not an ancestor of HEAD, or does not touch the finding's
   file. The fix must be in the history being certified, and must be about
   this file;
5. `--test` does not name a test that exists at HEAD;
6. the test does not pass at HEAD. aramid runs it through the repo's
   `[tests].command`, or `python -m pytest`, with the node id appended, under
   `[tests].timeout_s`. A timeout or crash is a refusal, not a pass;
7. `--reason` is empty.

On success it appends one `finding_resolved` event with this payload:

```
{"auto_resolved": "evidenced_close", "commit": "<full sha>",
 "test": "<node id>", "test_rc": 0, "reason": "...", "head": "<HEAD sha>"}
```

The status fold already maps a plain `finding_resolved` to `fixed`. No new
status and no fold change are needed. `ledger show` prints the payload, so
the evidence sits on the event.

## 3. Why not the other shapes

- **Re-review on touch** (shape 1): every commit touching the finding's file
  would cost a refute-or-confirm call. Tokens per touch, for every open
  finding, forever. It is also non-deterministic: the same fix can be
  refuted once and confirmed the next time.
- **A new `fixed_by_evidence` status**: this would lose the re-open path in
  section 1, unless `record_run`'s re-open list and the consumer's dedupe
  both learned it. That is two more places to keep in step, for a
  distinction `ledger show` already makes from the event payload.
- **Loosening the quote match**: this is how a confirmed critical gets
  resolved away. The resolver's docstring rules it out, and that reasoning
  still holds.

## 4. What it does not do

- It does not prove that the test exercises the finding. A passing test that
  is unrelated satisfies rule 6. Rule 4 (the commit touches the file) and
  the reason are the human evidence. Section 5, question 2 offers a stronger,
  optional check.
- It does not cover `historical` or `overridden` rows. An already-overridden
  fixed finding stays as it is; its owner can leave it.

## 5. Open questions for the operator

1. **Confirmed-critical findings.** Rule 3 refuses them, as `override` does.
   But a fixed critical then has no exit except editing the quoted line or a
   `.aramid-suppressions.toml` entry, which asserts "acceptable", not
   "fixed". Option: allow it only when the test also FAILS at `<commit>^`
   (question 2), which is the evidence a critical deserves.
2. **Red proof (optional flag `--red-proof`).** Run the test at `<commit>^`
   in a throwaway worktree and require it to fail there. This proves the test
   detects what the commit fixed. It costs a worktree and a second test run,
   and aramid already has the machinery (`[red_proof]`). Proposed: optional
   for ordinary findings, required for confirmed-critical ones if question 1
   is answered yes.
3. **MCP.** Should the tool be exposed as `aramid_ledger_resolve`? An agent
   could then close its own findings, with the same rules. Proposed: yes;
   the rules are the guard, and `override` is already exposed.

## 6. Tests (to write first)

- Each refusal, one test apiece, with the exit code and message asserted
  whole.
- Success writes exactly one event with the payload above, and status reads
  `fixed`.
- **The safety net, end to end:** a resolved finding that the llm-review
  consumer raises again (faked provider) is `open` again after `record_run`.
  The control: an OVERRIDDEN finding raised again stays `overridden`. That
  pins the asymmetry this design rests on.
- A test that fails, times out, or does not exist at HEAD each refuses, and
  each writes nothing.

## 7. Docs

- user guide, section 5 *An LLM finding you fixed that stays open anyway*:
  the new exit, before `override`;
- section 12's *An LLM finding can stay open after a real fix*;
- KB section 4 command reference;
- `review.auto_resolve_llm`'s docstring: correct the "re-raises" claim
  (section 1);
- CHANGELOG `Added`.
