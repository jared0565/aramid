# Aramid — Fleet readiness: parked repos (amendment A2)

**Date:** 2026-11-27
**Baseline:** `main` @ `bb570fb` (release v0.20.24, published and promoted on this machine).
**Amends:** `2026-09-02-aramid-fleet-readiness-design.md`, sections 3.4, 6 and 8, and its amendment A1.
**Status:** written for the operator's approval. Nothing is built.
**Size:** medium. One judging function, three report surfaces, one notice kind, about 36 existing judge tests to re-read, three documents.

Who decided what is marked throughout: **operator** for a decision the operator made in chat on 2026-11-27, **my call** for one made while writing this, open to being struck.

---

## 1. Intent and why

A registered repo that nobody commits to for 7 days is `stale` (A1). One stale repo makes the verdict `insufficient-data` and resets the streak, and it stays that way until someone runs a gate there or deregisters the repo by hand. On 2026-11-27 three repos had to be deregistered by hand for that reason, and deregistering has a cost that was not obvious: the registry is also the list the drain walks, so a deregistered repo loses its background mutation testing, review and fuzzing until `aramid init` is run there again.

**Operator's request:** aramid should notice by itself when a repo has gone quiet and when it is worked on again, with no manual deregister and no manual `init`, and the event should be logged.

**What this is for:** less hand-keeping of the fleet between now and 1.0, without losing drain coverage.

**What this will not do**, measured on this machine's rows the same day: it does not bring 1.0 closer by much. Over the last 30 days at least one registered repo recorded a red row on 22 days, and the longest streak a replay of this design produced over the whole history since 2026-09-03 was 3.6 days. Red rows stop the streak; staleness is the smaller problem. That is a separate piece of work (section 9).

**Shelf life (operator):** the streak stays as the 1.0 bar and is removed as part of the 1.0 release. This amendment is removed with it.

## 2. Goals, non-goals, anti-goals

**Goals**

- A quiet repo whose last row was green stops counting toward the verdict by itself, and counts again from its next gate row.
- The registry is never rewritten by this. A parked repo keeps its drain. A repo the operator deregistered stays deregistered.
- Every surface says which repos are parked and since when.

**Non-goals**

- Detecting work that has not been committed. Only gate rows are read, so a repo edited for more than 7 days without a commit or push parks. The operator suggested a session signal (the handover file) for this; it is left out here and named in section 9.
- Making the drain write health rows (section 9).
- Reducing red rows.

**Anti-goals** (each would make this a failure even if it ran)

- `ready` reached because the fleet shrank.
- A repo leaving the count while its last row is red.
- A parked repo's old row supplying `armed_anywhere`.
- Any change to a gate's, the drain's or the hook's exit code (the fleet module's fail-open contract stands).

## 3. Approaches

**A — derive it from the rows. CHOSEN (operator).** At each judgement a registered repo is *active* when its latest row is fresh, and *parked* when it is not. No stored state. The registry is untouched.

**B — a `parked_at` flag in the registry.** The drain writes it, a gate run clears it. Rejected: two background writers on the registry, a flag that can disagree with the rows, more code for the same visible result.

**C — deregister and re-register for real.** The drain removes the entry, the next gate adds it back. Rejected: aramid cannot tell "parked by itself" from "removed by the operator" without storing the reason, so a repo the operator removed would rejoin on its next commit; a registry backup file is written per park; and the repo loses its drain while out.

**Not built, and still available with no code:** raising `[readiness].max_row_age_days` in `fleet.toml`. Quiet repos then hold the streak for longer, on older evidence.

## 4. Decisions

1. **A returning repo restarts the streak (operator).** A row from a repo that was parked just before that row resets the streak, which then starts at that row if the fleet is green there. A repo's first-ever row is a return too.
2. **A repo whose latest row is red never parks (my call).** It stays a red member, however old the row, until it gates green or is deregistered.
3. **A floor on active repos (my call).** New policy key `[readiness].min_active_repos`, default `3`. Below it the verdict cannot be `ready`. The count of active repos can only fall inside a streak (a return restarts it), so checking the floor at `now` covers the whole streak.
4. **One threshold (my call).** A repo parks when its latest row is older than `max_row_age_days`, the window A1 already defines. `0` still disables the window; then nothing parks and A1's original text applies.
5. **A repo with no rows (my call).** Registered within the window: it is waiting, and blocks the verdict as today (`no rows:`). Registered longer ago than the window: parked. Rows older than 180 days are compacted away, and without this a long-parked repo would turn into "no rows" and block for ever. An entry with no readable `registered_at` is treated as waiting.
6. **Logging (my call).** A `repo-parked` notice when a repo parks, cleared by itself when it returns or leaves the registry. The notice store is append-only, so this is the durable log the operator asked for. Notices repeat daily in each repo until acked; if that is too loud, the alternative is the verdict note alone.

## 5. Judge (amends §6 and A1.3)

`W` is the window. A row is fresh at `t` when `t - row.at <= W` (A1, unchanged).

**Membership at time `t`.** A registered repo is

- **active** when its latest row is fresh at `t`, or its latest row is red (decision 2);
- **waiting** when it has no row yet and was registered no more than `W` before `t` (or has no readable `registered_at`);
- **parked** otherwise.

A missing-path repo is handled as today and is none of these.

**During the walk.** For each row, in time order:

1. Work out which repos were active just before this row. If the row's repo was not one of them and a streak is open, the streak resets (decision 1), and the verdict records which repo returned and when.
2. Apply the row; the disarm rule is unchanged.
3. The fleet is green at this row when no repo is waiting and every active repo's latest row is green. A parked repo is not consulted.
4. Green: the streak starts here if none is open, and the row's version joins the streak's versions. Not green: the streak resets, as today.

A1's rule "a latest row ageing past the window inside the walk resets the streak" is replaced by step 1: ageing past the window parks the repo and the streak carries on; the cost is paid when the repo comes back.

**At `now`.**

- No repos registered: `insufficient-data`, as today.
- A missing-path or waiting repo: `insufficient-data`, as today.
- No active repo at all: `insufficient-data`, reason `no active repos`.
- Any active repo red: `not-ready`. A red row older than the window is listed with its age; the label `stale` now means only that.
- Otherwise the ready checks, with one more blocker: `active repos N < min_active_repos`.
- `armed_anywhere` reads the latest rows of **active** repos only.

A parked repo no longer makes the verdict `insufficient-data` and no longer resets the streak at `now`.

**Output (additive; `schema_version` unchanged; the `fleet --json` keys are outside the compatibility promise, user guide section 13).**

- Per repo: `parked: bool`, `parked_since: <ISO time> | null` (latest row plus `W`, or `registered_at` plus `W` for a repo with no rows). `stale` stays, true only for a red row older than `W`. `green` is unchanged (a property of the row).
- Fleet: `active_repos: [<name>, ...]`, `parked_repos: [<name>, ...]`, both sorted case-insensitively; `stale_repos` keeps its key with the narrower meaning. `notes` gains `streak restarted by <name> returning at <at>`, beside the existing disarm note.
- Policy block: `min_active_repos`.

## 6. Notices (amends §7)

- `repo-parked`, key `parked:<repo key>:<parked_since>`: posted by the drain's judgement when a repo is parked and the previous verdict did not show it parked. Title `<name> parked -- no gate run since <latest row date>`. Body says what parked means, that the drain still walks the repo, and that its next gate run restarts the streak.
- Cleared when the repo is active again (`returned`) or no longer registered (`deregistered`).
- `readiness-reached` names the active repos and counts them; its body lists the parked ones separately.
- `readiness-broken` and `fleet-defect` are unchanged.

## 7. Surfaces (amends §8; every line gets a full-line test)

**Readiness line** (`aramid status`, the session-start hook, `init`, `fleet deregister`): the count is of active repos, and a `parked:` entry follows `red:` and `no rows:`.

```
fleet: 1.0 readiness NOT READY -- 5/6 active repos green, streak 0.0d, versions 0/2; red: pivot-parlor (consumers_healthy); parked: bytesTTS (since 2026-11-29), demo-store2 (since 2026-11-28)
```

**`aramid fleet`**: a parked repo keeps its row and cells, followed by one line, the way a worktree row is annotated today:

```
  demo-store2                      202  2026-11-21T01:51:16.893532+00:00  ok          ok          ok          ok          ok
                                   (parked since 2026-11-28T01:51:16+00:00 -- no gate run in 7 days; its next one restarts the streak)
```

The streak block gains `active repos: 6 (floor 3)`. The header is unchanged.

A verdict file written before this amendment has no `parked` keys and renders as it does today.

## 8. Constraints

- `fleet.py`'s contract: no function here raises out of its seam or changes an exit code. The judgement budget (30 s) stands.
- The registry gains no key and is not written by the judge.
- A new policy key is new surface, so by A1.6's precedent this ships in a MINOR release (0.21.0). It adds nothing to, and changes nothing in, the declared compatibility surface, so the API freeze is not affected; the changelog entry describes a behaviour change of the fleet verdict.
- `registered_repos()` returns names only today; the judge needs each entry's `registered_at`. How that is passed is left to the builder.
- Documents to change with it: `docs/user-guide.md` section 7 (the verdict paragraph, "Leaving the fleet", the policy block), `RELEASING.md` "The 1.0 gate" (every *active* registered repo), `CHANGELOG.md`, and a pointer from the 2026-09-02 spec to this one.

## 9. Known limits and follow-ups (not in this amendment)

- **A repo worked on every 8 to 13 days** parks and returns each time and restarts the streak each time. It still has to be deregistered by hand.
- **Any commit in a parked repo restarts the 14 days**, which a commit in a deregistered repo does not. Close to a 1.0 tag, parked repos are better left alone or deregistered first.
- **A drain fault can hide behind a park.** Rows are written by gate runs only. A consumer the drain finds degraded after a repo's last gate run is not on any row, so the repo parks green. Today the stale rule forces the gate run that would show it. Making the drain write a row for a repo it worked on would close this; `health.snapshot` already accepts a call without a gate result, but whether such a row should count as a return is undecided, and a row on every drain pass would stop anything from parking.
- **Uncommitted work is invisible** (section 2). A session signal would need a row written from the session-start hook or the handover command.
- **Red rows.** 22 of the last 30 days had one. Until that falls, no rule about quiet repos makes the streak reachable.

## 10. Testing

Table-driven over `judge`, no sleeps, each case naming the production change that would break it:

- a green repo silent past the window parks; the streak carries on; the verdict is not `insufficient-data`;
- its next row restarts the streak at that row, and the note names it; a red return row leaves no streak;
- a red repo silent past the window stays a member, `not-ready`, listed with its age;
- three active repos held 14 days over two versions with two others parked: `ready`; the same with two active: `not-ready`, blocker `active repos 2 < 3`; `min_active_repos = 1` restores `ready`;
- the only armed repo parks: `armed_anywhere` false;
- a repo with no rows registered 3 days ago blocks (`no rows:`); registered 30 days ago it is parked; no `registered_at`, it blocks;
- every repo parked: `insufficient-data`, `no active repos`;
- `max_row_age_days = 0`: nothing parks, and A1's disabled-window cases still pass unchanged;
- exactly `W` old is still active;
- a row from a worktree of a parked repo is that repo's return;
- a missing-path repo is unaffected.

Policy: `min_active_repos` default 3, `0` accepted, negative and string fall back. Notices: posted once per park, not again at the next judgement, cleared on return and on deregistration. Rendering: full-line assertions for the readiness line and both `aramid fleet` additions, and for a pre-amendment verdict file.

Before release, replay the built judge against this machine's real rows (the scratch replay of 2026-11-27 read: 9 parks in history, no return inside a streak, no `ready`), and say what changed.

## 11. Left to the builder

- How `registered_at` reaches `judge`.
- Whether A1's existing tests are edited in place or kept beside new ones under `max_row_age_days = 0`.
- The exact wording of the `repo-parked` body.
