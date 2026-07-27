# Plan — retire a historical secret that was never a secret (T-9)

## Context

`aramid init` runs a one-time full-history gitleaks scan and records hits as
`historical`, non-blocking findings. `aramid status` then lists them under
"unrotated historical secrets" until they are retired with
`aramid ledger mark-rotated <id> --reason ...`.

That is the **only** exit, and it appends a `finding_rotated` event — an
assertion that a credential was rotated. When the hit is a false positive there
is nothing to rotate, so the operator must either live with a permanent nag or
write a false statement into an append-only audit ledger.

This is not a bug. `phase1-design.md:409` records that an "unrotatable
`historical` status" was already caught as a spec defect and fixed — by adding
`mark-rotated`. But `:280-286` models every historical hit as a real leak
("deleting the line does not fix the leak — rotate the credential"), even
exemplifying the reason as `"rotated in <system>"`. The false-positive case is
simply absent from the design.

It is not a corner case. gitleaks' `generic-api-key` rule is high-false-positive;
the motivating repo (pawscout-worker) is 3 for 3 false positives — one public
Shopify client ID, and two versions of a test fixture that base64-decodes to the
literal ASCII string `test-master-key-32-bytes-long!!!`.

**This plan was adversarially reviewed before any code was written.** The review
verified the security argument, refuted one stated rationale (C1 below), and
found a design hole in transition ordering. All findings are folded in.

## Global Constraints

These bind every task. Read them before implementing any single task.

1. **Exact names, used verbatim everywhere:**
   - `EventType.FINDING_NOT_A_SECRET = "finding_not_a_secret"` (in `models.py`)
   - materialized status string: `"not_a_secret"`
   - CLI subcommand: `mark-not-a-secret`
   - status.py display label: `not-a-secret` (hyphens, display only)

   The underscore/hyphen split is the EXISTING convention, verified: every
   status string is snake_case (`ledger.py:29-39`), every multi-word CLI
   subcommand is hyphenated (`mark-rotated`, `mutation-score`, `update-rules`).
   Do not "fix" one to match the other.

2. **Why a separate event type rather than `FINDING_ROTATED` + a payload flag.**
   Because the materialized STATUS is what three consumers key on, and one of
   them is dangerous: `pack_cmd.py:16` promotes gitleaks findings whose status
   is `rotated` into committed semgrep re-introduction rules, which
   `pipeline.py:431-433` then loads at EVERY gate. Reusing `rotated` for a false
   positive would compile that false positive's pattern into a permanent BLOCK
   rule. A distinct status gets correct behaviour in every consumer for free.
   Do not "simplify" this into a payload flag.

3. **SECURITY — the `historical`-only restriction is load-bearing.**
   `mark-not-a-secret` MUST refuse with exit 3 unless the target's materialized
   status is exactly `"historical"`. Be precise about why: because
   `not_a_secret` is inert at gate time (Constraint 4), removing this guard
   would NOT create a gate bypass — it would create a **reporting** bypass, an
   uncommitted way to drop an open BLOCK finding out of `status` counts,
   sidestepping the committed-and-reviewable `.aramid-suppressions.toml` that
   BLOCK suppression deliberately requires. Do not reason "the gate ignores it,
   so the guard is cosmetic". Never relax this to "any secret finding".

4. **The gate surface must stay at zero.** Verified first-hand, twice:
   `pipeline.py` and `policy.py` contain no reference to `historical`, and
   `_overrides_from_ledger` (`pipeline.py:402-409`) selects on the exact string
   `rec.get("status") == "overridden"`. `policy.apply_overrides` downgrades only
   on exact id-set membership — no tool/rule/path fallback. This change is
   REPORTING-ONLY. If any task finds itself editing `pipeline.py` or
   `policy.py`, stop — that is out of scope and means something has been
   misunderstood.

5. **Transitions may only move toward MORE caution, never away.** This is the
   rule that governs ordering, and it is asymmetric on purpose:
   - `mark-not-a-secret` accepts **`historical` only**.
   - `mark-rotated` accepts **`historical` or `not_a_secret`** (Task 2 widens
     it). Discovering that a supposed false positive is a real credential, and
     then rotating it, is strictly safety-improving and must never be blocked.
   - There is no un-mark and no path from `rotated` back to `not_a_secret` —
     that would rewrite a safety assertion. The ledger is append-only.

   Without the widening, first-writer-wins would permanently block the one
   correction that matters. Marking the same finding twice the same way still
   returns 3 (see Task 2's message table).

6. **Two places record a status transition, and both must be updated.**
   `ledger.py` has `_materialize` (:22-40) and a SEPARATE `terminal_types` set
   inside `compact()` (:132-134). Updating only the first is the easy mistake:
   `compact()` would treat the new event as non-terminal and delete it,
   silently reverting the status to `historical`. `compact()` is currently dead
   code (see its own LANDMINE comment) — update it anyway and test it directly.

7. **Do not change `_unrotated_historical_lines` (`status.py:102-109`).** It
   filters on `rec.get("status") == "historical"`. Once marked, the status is
   `not_a_secret`, so it drops out automatically. An explicit exclusion there
   would be redundant code that hides how the mechanism works.

8. **Style:** match `mark-rotated`'s existing shape exactly — same argument
   order `(root, finding_id, reason)`, same `--reason` required check returning
   3, same `Ledger(root / ".aramid" / "ledger.db")` + `try/finally: close()`,
   same `uuid.uuid4().hex`, same `_now()`. This is a sibling command; it should
   read like one.

9. **Never run the full pytest suite.** ~16 minutes; the controller runs it. Run
   only the files your task touches, e.g.
   `python -m pytest tests/integration/test_ledger_cmd.py -q`.

10. **Invocation:** `python -m aramid`, `python -m pytest`. Do not edit
    `graph-out/`. No backticks inside `git commit -m` strings — use `-F` with a
    file or a stdin heredoc.

11. **Every new test must be proven able to fail** — EXCEPT the one test Task 3
    explicitly exempts and gives a substitute proof method for. Before claiming
    a test passes, confirm it fails against unmodified behaviour. A test that
    passes both before and after is not a regression guard.

## Task 1 — ledger core: the event and its replay

**`src/aramid/models.py`** — two edits:

a. Add to `EventType` (:27-43), beside `FINDING_ROTATED` (:33) so the
   finding-lifecycle events stay grouped:

```python
FINDING_NOT_A_SECRET = "finding_not_a_secret"
```

b. Add `NOT_A_SECRET = "not_a_secret"` to the `Status` StrEnum at `:14-19`.
   Note: `Status` is currently DEAD CODE — zero references repo-wide. Add the
   member anyway so the file does not contain a status enum missing a status
   that exists; do not wire it up to anything, and do not delete the enum.

**`src/aramid/ledger.py`** — two edits:

a. In `_materialize` (:22-40), add a branch after the `finding_rotated` branch,
   following the identical shape:

```python
elif e.type.value == "finding_not_a_secret":
    if e.finding_id in state:
        state[e.finding_id]["status"] = "not_a_secret"
        state[e.finding_id]["reason"] = e.payload.get("reason", "")
```

   It materializes `reason` like the `finding_overridden` branch (:33-36) does.
   Task 2 adds the display path that makes this visible — today NO reader
   prints a materialized `reason` (the adversarial review confirmed
   `pipeline.py:408` is its only consumer, and that value is never printed).
   Do not add a display path here, and do NOT change `finding_rotated` to
   materialize its reason — that is a separate pre-existing gap, deliberately
   out of scope. (Precision: `mark-rotated` DOES persist `reason` in the event
   payload at `ledger_cmd.py:117`; it is only `_materialize` that drops it. Do
   not "fix" the payload — it is already correct.)

b. In `compact()`, add `EventType.FINDING_NOT_A_SECRET.value` to the
   `terminal_types` set (:132-134). See Constraint 6.

**Tests** — put the compact test in `tests/unit/test_ledger_compact.py` beside
`test_compact_preserves_override_reason` (:38), which is a line-for-line
template. Put the materialization tests with the existing ledger unit tests.

- A `finding_detected` with `historical: true` followed by
  `finding_not_a_secret` materializes to status `not_a_secret`.
- The stored `reason` survives materialization.
- A `finding_not_a_secret` for an id with no prior detect is ignored — no
  KeyError, no phantom entry (matches the `if e.finding_id in state` guard).
- `compact()` PRESERVES the event when it is the latest terminal transition
  after the latest detect; assert the status is still `not_a_secret` after a
  `compact()` round-trip. This is the Constraint 6 guard and it provably fails
  with `terminal_types` unchanged (the event is dropped from `keep` and
  deleted, reverting the status to `historical`).

## Task 2 — the `mark-not-a-secret` command, and widening `mark-rotated`

**`src/aramid/commands/ledger_cmd.py`** — four edits:

a. Add `cmd_ledger_mark_not_a_secret`, mirroring `cmd_ledger_mark_rotated`
   (:95-121) exactly: same guards, same exit codes, appending
   `EventType.FINDING_NOT_A_SECRET` with `payload={"reason": reason}`.
   Success message: `aramid: ledger: {finding_id} marked not-a-secret ({reason})`

   The refusal message MUST vary by the status found, because the generic
   "use a committed suppression" advice is only correct for `open`:

   | status found | message tail |
   |---|---|
   | `open` | `-- mark-not-a-secret only applies to historical secrets from init's full-history scan. For a live BLOCK finding use a committed .aramid-suppressions.toml entry; for a WARN use \`aramid override\`.` |
   | `not_a_secret` | `-- already marked not-a-secret.` |
   | `rotated` | `-- already retired by rotation. A rotated finding is never downgraded to not-a-secret.` |
   | anything else (`fixed`, …) | `-- mark-not-a-secret only applies to historical secrets from init's full-history scan.` |

   All four return 3 and append NOTHING.

b. Widen `cmd_ledger_mark_rotated`'s guard (:110) to accept `historical` OR
   `not_a_secret`, per Constraint 5. Update its refusal message to name both
   accepted statuses. Check the existing tests for this guard still pass — they
   should, if they exercise `open`.

c. Add `"reason"` to the hardcoded key tuple in `cmd_ledger_show` (:55-56), so
   the reason materialized in Task 1 is actually visible. Without this the field
   is decorative — the adversarial review confirmed no display path exists.

d. Update the module docstring (:1-6): it currently claims "`mark-rotated` is
   the only mutating subcommand", which this task makes false.

**`src/aramid/cli.py`** — three edits, mirroring `mark-rotated`:
- add `cmd_ledger_mark_not_a_secret` to the import block (:25-30, alphabetical —
  it sorts before `cmd_ledger_mark_rotated`)
- add the subparser beside :95-97:
  ```python
  p_nas = ledger_sub.add_parser("mark-not-a-secret")
  p_nas.add_argument("id")
  p_nas.add_argument("--reason", required=True)
  ```
- add the dispatch branch beside :205-206, and update the "a subcommand is
  required" message (:207) to `(list|show|filter|mark-rotated|mark-not-a-secret)`

**Tests** (`tests/integration/test_ledger_cmd.py`):

- marking a `historical` finding returns 0 and transitions the status
- marking a finding whose status is `open` returns 3 AND appends no event
  (assert the event count is unchanged — the refusal must be total, not just a
  message)
- marking an unknown id returns 3
- empty/whitespace `--reason` returns 3 (direct function call)
- OMITTING `--reason` entirely is an argparse path: `required=True` raises
  `SystemExit(2)`, which the CLI remaps to 3. This test must go through
  `cli.main([...])`, not a direct call to the command function.
- double-mark: `mark-not-a-secret` twice → second returns 3 with the
  "already marked" message
- cross-mark, both directions (Constraint 5): `mark-not-a-secret` then
  `mark-rotated` → **0**, status becomes `rotated`. `mark-rotated` then
  `mark-not-a-secret` → **3**, status stays `rotated`.
- reachable through real CLI dispatch (mirror what
  `tests/integration/test_cli_dispatch.py` does for `mark-rotated`)
- `ledger show` prints the reason for a marked finding

## Task 3 — status reporting + gate-inertness guard

**`src/aramid/commands/status.py`** — `_open_counts_line` (:38-41) gains the new
count. Always show it, including at zero, matching how `overridden: 0` is
always shown:

```python
return (f"open findings: {counts.get('open', 0)} "
        f"(historical: {counts.get('historical', 0)}, "
        f"not-a-secret: {counts.get('not_a_secret', 0)}, "
        f"overridden: {counts.get('overridden', 0)})")
```

The module docstring is `:1-8` (not `:1-7`); it does not enumerate the counts,
so it needs no change — confirm rather than assume.

Blast radius was measured: exactly one test asserts on this line
(`tests/integration/test_status.py:131`, `"open findings: 2" in out`), a prefix
match that survives the addition.

**Tests:**

- `test_status.py`: a marked finding is counted under `not-a-secret` AND no
  longer appears in the "unrotated historical secrets" listing (Constraint 7 —
  assert the absence, because that behaviour is inherited rather than written,
  and inherited behaviour is what regresses unnoticed).
- **Gate-inertness regression test** (Constraint 4). Put it in
  `tests/unit/test_pipeline.py` beside `test_overrides_from_ledger_carries_reason`
  (:1363). Assert a finding with materialized status `not_a_secret` produces NO
  `OverrideRecord` from `pipeline._overrides_from_ledger`. Name it
  `test_not_a_secret_is_not_an_override_at_gate_time`, with a docstring stating
  that this command must never become a BLOCK-suppression path.

  **This test is EXEMPT from Constraint 11's usual proof method** and is the
  only exemption in this plan. It cannot fail against pre-Task-1 code, because
  the state is unconstructible: without `EventType.FINDING_NOT_A_SECRET`, a
  hand-inserted `type='finding_not_a_secret'` row makes `Ledger.events()` raise
  `ValueError` at `ledger.py:61`. It is a forward guard. Prove it instead by
  temporarily adding `or rec.get("status") == "not_a_secret"` to
  `_overrides_from_ledger` (`pipeline.py:405`), confirming the test goes red,
  then reverting. Report that you did this.

## Task 4 — documentation

Update every place that presents `mark-rotated` as the only retirement path.
All line numbers verified 2026-07-27 and re-verified by adversarial review.

- **`docs/superpowers/specs/2026-07-12-aramid-phase1-design.md`** — the spec of
  record. Four sites: `:87-88` (command table), `:214` (status list — add
  `not_a_secret`), `:248-252` (the EVENT enumeration — add
  `finding_not_a_secret`; omitting it would reproduce the exact stale-spec
  defect class this plan's Context cites at `:409`), and `:280-286` (the
  historical-secret lifecycle). State that a historical hit has two exits —
  rotation for a real leak, not-a-secret for a false positive — and that the
  latter is restricted to `historical` status so it cannot become a reporting
  bypass. Document the directional rule from Constraint 5.
- **`docs/user-guide.md`** — SEVEN sites, not four: `:87`, `:234` (status-output
  description), `:245` (the documented `ledger show` field list — Task 2 adds
  `reason` to it), `:248` (the prose framing rotation as *the* path — this one
  will directly contradict the new command if left), `:251` (command example),
  `:254` (the sentence documenting the `historical`-only guard), and `:573`
  (which is under `## 11. Troubleshooting` at `:555`, NOT the findings-handling
  section). Give not-a-secret a worked example; the pawscout case is a good one
  — a public Shopify client ID that gitleaks reads as a generic API key.
- **`docs/knowledge-base.md`** — `:411` (the `aramid ledger` signature line),
  `:415` (semantics — both commands' accepted statuses), `:489` (exit-code
  table), and `:423` (see the `pack compile` note below).
- **`src/aramid/data/ARAMID.md.tmpl`** — `:95` and `:108`. This template is
  written into consumer repos by `init`, so keep the addition to one line.

**Also document these two operator-facing consequences**, which are real and
currently unwritten:

- **`pack compile` asymmetry** (`knowledge-base.md:423`, `user-guide.md:531`):
  `aramid pack compile` auto-promotes gitleaks findings marked **rotated** into
  committed semgrep re-introduction rules that run at every gate
  (`pack_cmd.py:16` → `pipeline.py:431-433`). Findings marked **not-a-secret**
  correctly get no such rule. That is the intended difference between the two
  exits and operators should know it before choosing.
- **Irreversibility**: neither mark can be undone (append-only ledger, no
  un-mark). `not_a_secret` → `rotated` is the ONLY permitted correction.

**Do not** state or imply that not-a-secret suppresses anything at gate time.
It does not (Constraint 4).
