# Fleet Parked Repos (Amendment A2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A registered repo whose latest gate row is green and older than the freshness window stops counting toward the 1.0 verdict by itself, and counts again (restarting the streak) from its next row.

**Architecture:** Everything is derived inside `fleet.judge` from the rows and each registry entry's `registered_at`; no state is stored and the registry is never written. The verdict gains additive keys (`parked`, `parked_since`, `active_repos`, `parked_repos`, `min_active_repos`), which the readiness line, `aramid fleet` and a new `repo-parked` notice read.

**Tech Stack:** Python 3.11+, pytest. No new dependency.

**Spec:** `docs/superpowers/specs/2026-11-27-aramid-fleet-parked-repos-design.md` (amends `2026-09-02-aramid-fleet-readiness-design.md` and its A1).

## Global Constraints

- `fleet.py`'s contract: no function raises out of its seam or changes a gate's, the drain's or the hook's exit code. `JUDGE_BUDGET_S = 30.0` stands.
- The registry gains no key and is not written by the judge.
- `SCHEMA_VERSION` stays `1`. All new verdict keys are additive. A verdict file without them renders exactly as today.
- `max_row_age_days = 0` disables the window: nothing parks, and every existing disabled-window test passes unchanged except for the policy constant (Task 1).
- "Exactly `W` old is still fresh": fresh at `t` when `t - row.at <= W`.
- Test-first: each test is run and seen to fail before the code that passes it. Tests are table-driven on explicit timestamps; no sleeps; `now` is an argument.
- Every rendered line is asserted whole (`==`), never by substring.
- Commit with `git commit -F <file>`; never `--no-verify`. Trailer: `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`.
- Never `pip install -e .`. Run tests with `python -m pytest <path> -q` from the repo root.
- Ships in a MINOR (0.21.0). The release itself is not part of this plan; this plan ends at a pushed `main` with the entry under `## [Unreleased]`.

## Plan decisions the spec left open

- **`registered_at` plumbing:** new `fleet.registration_times(entries=None) -> dict[str, str]` and a new keyword `registered_at: dict[str, str] | None = None` on `judge`. Missing key, non-string or unparsable value means *waiting*.
- **A1's tests** are edited in place to the A2 behaviour (the old behaviour no longer exists under a non-zero window); the disabled-window tests stay as they are.
- **Test policies:** the default floor is 3 and the fixtures have two repos, so `POLICY`/`DEFAULT` in existing test files gain `min_active_repos=2` (comment: "two-repo fixtures; the floor has its own tests"). New floor tests use the true default.
- **No active repo at `now`** also clears the streak (an idle fleet holds no streak, as A1 said).
- **Readiness-line count:** numerator is active green repos; denominator is every registered repo that is not parked (active + waiting + missing path); the word is `active repos green`. A verdict without `fleet.active_repos` keeps `repos green`.
- **Notice posting** relies on `notices.post`'s own de-duplication by id (key includes `parked_since`) instead of comparing with the previous verdict; the visible result is the same.
- **`parked_since` format:** `isoformat(timespec="seconds")`.

## Review Focus

1. `registered_at` that is an int, an empty string, a naive time, or in the future: the repo is waiting (`no rows:`), nothing raises. (Task 2)
2. `run_judgement` with a previous verdict file written by 0.20.24 (no `parked` keys) and a pending `repo-parked`-free notice store: no `KeyError`, the verdict is written. (Task 3)
3. A repo that is both vanished (path gone) and has old green rows: `missing path`, `parked` false, absent from `parked_repos`, no notice. (Tasks 2, 3)
4. A repo parks, its notice is acked, it returns and parks again: a second notice is posted (new `parked_since`, new id). (Task 3)
5. A verdict with `parked: true` and `parked_since: null` (hand-edited or torn): both renderers print the repo as parked without a date and do not raise. (Task 4)

---

### Task 1: Policy key `min_active_repos`

**Files:**
- Modify: `src/aramid/fleet.py:66-114` (`Policy`, `load_policy`)
- Test: `tests/unit/test_fleet_store.py`

**Interfaces:**
- Produces: `Policy.min_active_repos: int = 3`, read from `[readiness].min_active_repos` through `_int_or` (so `0` is accepted; negative, string and bool fall back to 3).

- [ ] **Step 1: Write the failing tests** in `tests/unit/test_fleet_store.py`

```python
def test_policy_min_active_repos_defaults_to_three_and_reads_the_key():
    assert fleet.Policy().min_active_repos == 3
    p = fleet.policy_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('[readiness]\nmin_active_repos = 1\n', encoding="utf-8")
    assert fleet.load_policy().min_active_repos == 1
    p.write_text('[readiness]\nmin_active_repos = 0\n', encoding="utf-8")
    assert fleet.load_policy().min_active_repos == 0


def test_policy_min_active_repos_negative_or_string_falls_back():
    p = fleet.policy_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    for bad in ('-1', '"three"', 'true'):
        p.write_text(f'[readiness]\nmin_active_repos = {bad}\n', encoding="utf-8")
        assert fleet.load_policy().min_active_repos == 3
```

Also extend the two existing whole-`Policy` equality assertions in this file (`test_policy_defaults_when_fleet_toml_is_absent`, `test_policy_reads_every_key`) with the new field.

- [ ] **Step 2:** Run `python -m pytest tests/unit/test_fleet_store.py -q`. Expected: the two new tests FAIL with `AttributeError: ... min_active_repos`.
- [ ] **Step 3:** Add the field to `Policy` (after `max_row_age_days`, docstring gains one clause naming A2) and the `_int_or` line to `load_policy`.
- [ ] **Step 4:** Run the same command. Expected: all pass.
- [ ] **Step 5:** Commit `feat(fleet): policy key min_active_repos (A2)`.

---

### Task 2: The judge parks and returns repos

**Files:**
- Modify: `src/aramid/fleet.py` — `judge` (342-525), `run_judgement` (704-728); add `registration_times` beside `registered_repos` (278)
- Create: `tests/unit/test_fleet_parked.py`
- Modify (expectations): `tests/unit/test_fleet_judge.py`, `tests/unit/test_fleet_missing_path_with_rows.py`, `tests/unit/test_fleet_worktree.py`, `tests/unit/test_fleet_judgement.py`

**Interfaces:**
- Consumes: `Policy.min_active_repos` (Task 1).
- Produces:
  - `registration_times(entries: list[dict] | None = None) -> dict[str, str]` — `repo_key(path)` → the entry's `registered_at` when it is a `str`; consumer shells excluded, like `registered_repos`.
  - `judge(..., registered_at: dict[str, str] | None = None)` — new keyword only.
  - Per repo in `verdict["repos"]`: `parked: bool`, `parked_since: str | None`. `stale` is now true only for a **red** latest row older than `W`.
  - `verdict["fleet"]`: `active_repos: list[str]`, `parked_repos: list[str]` (display names, sorted case-insensitively); `stale_repos` keeps its key with the narrower meaning; `returned_in_streak: bool`.
  - `verdict["policy"]["min_active_repos"]`.
  - Note text: `streak restarted by <name> returning at <at>`. Blocker text: `active repos <N> < <floor>`, appended after the three existing blockers (streak, versions, armed). Reason text: `no active repos`.

**The algorithm** (the tests below do not fully determine it):

```
W = window or None (0 disables)
is_active(row, t)   = W is None or t - row.at <= W or not row_green(row)
waiting(key, t)     = key not in latest and (W is None
                        or parse(registered_at.get(key)) is None
                        or t - registered_at[key] <= W)

for (t, r) in rows in time order:
    repo = r.repo
    was_active = repo in latest and is_active(latest[repo], t)
    if not was_active and streak open:           # decision 1; a first-ever row is a return
        reset streak, versions, disarm
        returned = {name, at}
    apply r; disarm rule exactly as today
    members = [k for k in registered if k in latest and is_active(latest[k], t)]
    green = no registered key is waiting at t
            and all(row_green(latest[k]) for k in members)      # members is never empty here
    green: start streak here if none open; add version
    else:  reset streak, versions, disarm, returned

at now, per registered repo not vanished:
    active  = has row and is_active(row, now)
    waiting = waiting(key, now)
    parked  = neither;  parked_since = (row.at + W) or (registered_at + W), timespec seconds
    stale   = has row and W set and not fresh and not green
vanished: as today; parked False, parked_since None
streak cleared at now when: any vanished (as today) or no active repo
verdict order: no repos -> waiting/missing path (as today) -> no active repos (INSUFFICIENT)
               -> any active red (NOT_READY; "stale: <name> (<age>d) -- window Wd" appended
                  for red-and-old rows) -> ready checks + blocker "active repos N < floor"
armed_anywhere: latest rows of ACTIVE repos only
all_green_now: registered and no waiting and no vanished and >=1 active and every active green
notes: the returned note beside the disarm note, in the ready-checks branch only
```

A1's pre-apply reset (`fleet.py:400-401`) and the `if stale or gone` reset's `stale` half are removed; the walk's green check no longer asks `_fresh` of every registered repo.

- [ ] **Step 1: Write the failing tests** in `tests/unit/test_fleet_parked.py`. Copy `_at`, `_row`, `ARMED`, `NOW_DT`, `NOW` from `test_fleet_judge.py` (tests/unit is not a package; say so in a comment). Fixtures: `R_A, R_B, R_C, R_D, R_E = "f:/projects/a" ... "e"`; `P = fleet.Policy()` (true default: 7-day window, floor 3); `_weekly(repo, first, last, armed=None)` returns rows every 5 days from `first` to `last` days ago, version `0.8.0` when `days_ago > 10`, else `0.9.0`. `OLD = {k: _at(60) for k in (...)}` as `registered_at`.

  Each test carries a one-line comment naming the production change that would break it.

```python
def test_a_quiet_green_repo_parks_and_the_streak_carries_on():
    # a, b, c active to day 0; d green, last row 10 days ago.
    rows = sum((_weekly(k, 20, 0, ARMED) for k in (R_A, R_B, R_C)), []) + _weekly(R_D, 20, 10)
    v = fleet.judge(rows, REG4, P, NOW)
    assert v["verdict"] == "ready" and v["reasons"] == []
    assert v["fleet"]["streak_started_at"] == _at(20)
    assert v["fleet"]["active_repos"] == ["a", "b", "c"] and v["fleet"]["parked_repos"] == ["d"]
    assert v["fleet"]["stale_repos"] == []
    d = v["repos"][R_D]
    assert (d["parked"], d["parked_since"], d["stale"], d["green"]) == (
        True, "2026-09-17T12:00:00+00:00", False, True)
    assert v["repos"][R_A]["parked"] is False and v["repos"][R_A]["parked_since"] is None
    assert v["policy"] == {"min_days": 14, "min_versions": 2, "max_row_age_days": 7,
                           "min_active_repos": 3}


def test_a_returning_repo_restarts_the_streak_at_its_row_and_is_named():
    rows = sum((_weekly(k, 20, 0, ARMED) for k in (R_A, R_B, R_C)), [])
    rows += [_row(R_D, 20, "0.8.0"), _row(R_D, 2, "0.9.0")]
    v = fleet.judge(rows, REG4, P, NOW)
    assert v["fleet"]["streak_started_at"] == _at(2)
    assert v["fleet"]["returned_in_streak"] is True
    assert v["verdict"] == "not-ready"
    assert v["reasons"] == ["streak 2.0d < 14d", "versions 1/2 in streak",
                            f"streak restarted by d returning at {_at(2)}"]


def test_a_red_return_row_leaves_no_streak():
    rows = sum((_weekly(k, 20, 0, ARMED) for k in (R_A, R_B, R_C)), [])
    rows += [_row(R_D, 20), _row(R_D, 2, red=("resolvers_ok",))]
    v = fleet.judge(rows, REG4, P, NOW)
    # a, b, c gated again after d's red row (day 0), so the fleet is red there too.
    assert v["fleet"]["streak_started_at"] is None and v["verdict"] == "not-ready"
    assert v["reasons"] == ["d: resolvers_ok"]


def test_a_red_repo_silent_past_the_window_never_parks():
    rows = sum((_weekly(k, 20, 0, ARMED) for k in (R_A, R_B, R_C)), [])
    rows += [_row(R_D, 9, red=("consumers_healthy",))]
    v = fleet.judge(rows, REG4, P, NOW)
    d = v["repos"][R_D]
    assert (d["parked"], d["stale"], d["green"]) == (False, True, False)
    assert v["verdict"] == "not-ready"
    assert v["reasons"] == ["d: consumers_healthy", "stale: d (9.0d) -- window 7d"]
    assert v["fleet"]["stale_repos"] == ["d"] and v["fleet"]["parked_repos"] == []
    assert v["fleet"]["active_repos"] == ["a", "b", "c", "d"]


def test_the_floor_blocks_ready_and_the_policy_key_lowers_it():
    rows = _weekly(R_A, 20, 0, ARMED) + _weekly(R_B, 20, 0)
    rows += _weekly(R_C, 20, 10) + _weekly(R_D, 20, 10) + _weekly(R_E, 20, 10)
    v = fleet.judge(rows, REG5, P, NOW)
    assert v["verdict"] == "not-ready" and v["reasons"] == ["active repos 2 < 3"]
    assert v["fleet"]["blockers"] == ["active repos 2 < 3"]
    low = fleet.Policy(min_active_repos=1)
    assert fleet.judge(rows, REG5, low, NOW)["verdict"] == "ready"


def test_three_active_two_parked_held_fourteen_days_is_ready():
    rows = sum((_weekly(k, 20, 0, ARMED) for k in (R_A, R_B, R_C)), [])
    rows += _weekly(R_D, 20, 10) + _weekly(R_E, 20, 10)
    v = fleet.judge(rows, REG5, P, NOW)
    assert v["verdict"] == "ready" and v["fleet"]["parked_repos"] == ["d", "e"]


def test_the_only_armed_repo_parking_leaves_nothing_armed():
    rows = sum((_weekly(k, 20, 0) for k in (R_A, R_B, R_C)), []) + _weekly(R_D, 20, 10, ARMED)
    v = fleet.judge(rows, REG4, P, NOW)
    assert v["fleet"]["armed_anywhere"] is False
    assert v["verdict"] == "not-ready" and v["reasons"] == ["no repo is armed"]


def test_a_repo_with_no_rows_waits_inside_the_window_and_parks_after_it():
    rows = sum((_weekly(k, 20, 0, ARMED) for k in (R_A, R_B, R_C)), [])
    recent = fleet.judge(rows, REG4, P, NOW, registered_at={R_D: _at(3)})
    assert recent["verdict"] == "insufficient-data" and recent["reasons"] == ["no rows: d"]
    assert recent["repos"][R_D]["parked"] is False
    old = fleet.judge(rows, REG4, P, NOW, registered_at={R_D: _at(30)})
    assert old["verdict"] == "ready"
    assert old["repos"][R_D]["parked"] is True
    assert old["repos"][R_D]["parked_since"] == "2026-08-28T12:00:00+00:00"   # 30 - 7 days ago
    assert old["fleet"]["parked_repos"] == ["d"]


def test_an_unreadable_registered_at_waits_and_never_raises():      # Review Focus 1
    rows = sum((_weekly(k, 20, 0, ARMED) for k in (R_A, R_B, R_C)), [])
    future = (NOW_DT + timedelta(days=2)).isoformat()
    for bad in (None, {}, {R_D: ""}, {R_D: "t"}, {R_D: 7}, {R_D: future}):
        v = fleet.judge(rows, REG4, P, NOW, registered_at=bad)
        assert v["verdict"] == "insufficient-data" and v["reasons"] == ["no rows: d"], bad
    naive = fleet.judge(rows, REG4, P, NOW, registered_at={R_D: "2026-08-01T00:00:00"})
    assert naive["repos"][R_D]["parked"] is True       # a naive time is read as UTC, like a row's


def test_every_repo_parked_is_insufficient_data():
    rows = _weekly(R_A, 30, 10, ARMED) + _weekly(R_B, 30, 10)
    v = fleet.judge(rows, {R_A: "a", R_B: "b"}, P, NOW)
    assert v["verdict"] == "insufficient-data" and v["reasons"] == ["no active repos"]
    assert v["fleet"]["active_repos"] == [] and v["fleet"]["parked_repos"] == ["a", "b"]
    assert v["fleet"]["streak_started_at"] is None and v["fleet"]["all_green_now"] is False
    zero = fleet.Policy(min_active_repos=0)
    assert fleet.judge(rows, {R_A: "a", R_B: "b"}, zero, NOW)["reasons"] == ["no active repos"]


def test_a_disabled_window_parks_nothing():
    rows = _weekly(R_A, 30, 10, ARMED) + _weekly(R_B, 30, 10) + _weekly(R_C, 30, 10)
    off = fleet.Policy(max_row_age_days=0)
    v = fleet.judge(rows, REG3, off, NOW, registered_at={R_A: _at(60)})
    assert v["verdict"] == "ready" and v["fleet"]["parked_repos"] == []
    assert all(r["parked"] is False and r["parked_since"] is None for r in v["repos"].values())


def test_exactly_the_window_old_is_still_active():
    rows = sum((_weekly(k, 20, 0, ARMED) for k in (R_A, R_B, R_C)), []) + [_row(R_D, 7)]
    assert fleet.judge(rows, REG4, P, NOW)["repos"][R_D]["parked"] is False
    rows[-1]["at"] = _at(7.01)
    assert fleet.judge(rows, REG4, P, NOW)["repos"][R_D]["parked"] is True


def test_a_worktree_row_is_the_parked_repos_return():
    rows = sum((_weekly(k, 20, 0, ARMED) for k in (R_A, R_B, R_C)), []) + [_row(R_D, 20)]
    wt = {**_row("f:/projects/d-wt", 2), "worktree_of": R_D}
    v = fleet.judge(rows + [wt], REG4, P, NOW)
    assert v["repos"][R_D]["parked"] is False and v["fleet"]["streak_started_at"] == _at(2)


def test_a_vanished_repo_with_old_green_rows_is_missing_path_not_parked():   # Review Focus 3
    rows = sum((_weekly(k, 20, 0, ARMED) for k in (R_A, R_B, R_C)), []) + _weekly(R_D, 20, 10)
    v = fleet.judge(rows, REG4, P, NOW, vanished={R_D})
    d = v["repos"][R_D]
    assert (d["missing_path"], d["parked"], d["parked_since"]) == (True, False, None)
    assert v["fleet"]["parked_repos"] == [] and v["verdict"] == "insufficient-data"


def test_registration_times_maps_the_registry_key_to_its_time(tmp_path):
    entries = [{"path": str(tmp_path / "a"), "registered_at": "2026-09-01T00:00:00+00:00"},
               {"path": str(tmp_path / "b")},
               {"path": str(tmp_path / "c"), "registered_at": 5}]
    assert fleet.registration_times(entries) == {
        fleet.repo_key(tmp_path / "a"): "2026-09-01T00:00:00+00:00"}
```

- [ ] **Step 2:** Run `python -m pytest tests/unit/test_fleet_parked.py -q`. Expected: every test FAILS — `KeyError: 'active_repos'` / `'parked'`, `TypeError: ... registered_at`, `AttributeError: registration_times`. A test that passes here is testing existing behaviour: fix the test before going on.
- [ ] **Step 3:** Implement `registration_times`, then `judge` per the algorithm block and Interfaces. Rewrite the `judge` docstring's A1 sentence to describe A2. Pass `registered_at=registration_times(entries)` from `run_judgement`.
- [ ] **Step 4:** Run the same command. Expected: all pass.
- [ ] **Step 5: Re-read the existing judge tests.** Run `python -m pytest tests/unit -q -k "fleet"`. Every failure must be one of the kinds below; anything else is a regression in Step 3, not a test to edit.

  | Test | New expectation |
  |---|---|
  | `test_fleet_judge.py` `POLICY`, `DEFAULT` | add `min_active_repos=2`, with the comment from "Plan decisions" |
  | every `v["policy"] == {...}` | add `"min_active_repos": 2` |
  | every whole-repo dict equality (`v["repos"][R_A] == {...}`) | add `"parked": False, "parked_since": None` |
  | `test_idle_past_the_window_is_insufficient_data_and_resets_the_streak` | verdict `insufficient-data`, reasons `["no active repos"]`, `stale_repos == []`, `parked_repos == ["a", "b"]`, `repos[R_A]["stale"] is False`, `["parked"] is True`; streak still `None`; the disabled-window line unchanged |
  | `test_exactly_window_old_is_still_fresh` | second half: `insufficient-data`, `parked_repos == ["a", "b"]` |
  | `test_a_cross_repo_gap_inside_the_walk_restarts_the_streak_at_the_return` | same streak start; reasons gain a third entry `f"streak restarted by b returning at {_at(2)}"` |
  | `test_a_same_repo_gap_in_a_single_repo_fleet_restarts_the_streak` | add `min_active_repos=1` to both policies used; reasons gain `f"streak restarted by a returning at {_at(2)}"` |
  | `test_no_rows_beats_stale_and_stale_beats_red` → rename `test_no_rows_beats_red_and_an_old_red_row_is_named_stale` | first verdict `not-ready`, reasons `["a: dep_audit_ran", "stale: a (9.0d) -- window 7d"]`; with `c`: `insufficient-data`, `["a: dep_audit_ran", "no rows: c"]`, `stale_repos == ["a"]` |
  | `test_the_readiness_line_names_stale_repos_and_the_window` | leave failing; Task 4 owns it (mark `xfail(strict=True, reason="Task 4")` and remove the mark there) |
  | `test_fleet_missing_path_with_rows.py` control in `test_a_vanished_repo_with_old_rows_is_missing_path_not_stale` | the control (no `vanished`) becomes `fleet.judge(rows, REG, DEFAULT, NOW)["fleet"]["parked_repos"] == ["b"]`; the vanished half unchanged |
  | `test_fleet_worktree.py::test_a_row_written_before_worktree_of_counts_for_nothing` | `(repo["rows"], repo["parked"]) == (1, True)` |
  | `test_fleet_judgement.py::test_going_stale_from_ready_posts_readiness_broken_on_the_prior_streak` | reasons `["no active repos"]`; title `fleet readiness lost -- no active repos`; rename to `..._going_idle_from_ready_...`; the docstring says A2 |
  | `test_fleet_judgement.py` `_judge` | pass `policy=fleet.Policy(min_active_repos=2)` |

- [ ] **Step 6:** Run `python -m pytest tests/unit -q -k "fleet"`. Expected: all pass, one strict xfail.
- [ ] **Step 7:** Commit `feat(fleet): a quiet green repo parks, its next row restarts the streak (A2)`.

---

### Task 3: The `repo-parked` notice

**Files:**
- Modify: `src/aramid/notices.py:18` (`KINDS`), `src/aramid/fleet.py` (`_post_transitions`, new `_post_parks`, `run_judgement`)
- Test: `tests/unit/test_fleet_judgement.py`

**Interfaces:**
- Consumes: `verdict["repos"][key]["parked"|"parked_since"|"name"|"latest_at"]`, `verdict["fleet"]["active_repos"|"parked_repos"]` (Task 2).
- Produces: `_post_parks(verdict: dict, now: str) -> None`, called in `run_judgement` after `_post_defects`. Notice kind `repo-parked`, key `parked:<repo key>:<parked_since>`, evidence `{"repo", "name", "parked_since", "latest_at"}`.

Exact copy:

- Title, repo with rows: `<name> parked -- no gate run since <latest_at[:10]>`
- Title, repo without rows: `<name> parked -- no gate run since it was registered`
- Body: `<name> has recorded no gate run in <W> days and its last row was green, so it no longer counts toward 1.0 readiness. The drain still walks it. Its next gate run counts it again and restarts the streak. To take it out for good: ``aramid fleet deregister <name>``. This notice clears itself when the repo returns.` (single backticks in the string; `W` from `verdict["policy"]["max_row_age_days"]`)
- Clear reasons: `returned` (the repo is in the verdict and not parked, or parked under a different `parked_since`), `deregistered` (the repo key is not in `verdict["repos"]`).
- `readiness-reached`: `names` becomes `info["active_repos"]`; body's first sentence becomes `Every active repo has been green on every criterion since <start>: <names>.`; when `info["parked_repos"]` is non-empty append ` Parked, not counted: <names>.` before the `aramid fleet` sentence.

- [ ] **Step 1: Write the failing tests** (use the file's `_seed`, `_entries_rows`, `_judge`; the fixture has two repos, so use `policy=fleet.Policy(min_active_repos=1)` where a verdict must be ready with one parked)

```python
def _parked_notices():
    return [n for n in notices.pending() if n["notice_kind"] == "repo-parked"]


def test_a_park_posts_one_notice_and_not_again_at_the_next_judgement():
    rows = _ready_rows()[:-1]                 # b's last row is 8 days old; a's is 2
    _seed(_entries_rows(rows))
    v = _judge()
    key_b = [k for k, r in v["repos"].items() if r["name"] == "b"][0]
    (n,) = _parked_notices()
    assert n["key"] == f"parked:{key_b}:{v['repos'][key_b]['parked_since']}"
    assert n["title"] == "b parked -- no gate run since 2026-09-12"
    assert n["evidence"]["name"] == "b" and "restarts the streak" in n["body"]
    _judge(LATER)
    assert len(_parked_notices()) == 1


def test_the_notice_clears_when_the_repo_returns_and_a_second_park_posts_again():   # Review Focus 4
    _seed(_entries_rows(_ready_rows()[:-1]))
    _judge()
    notices.ack(_parked_notices()[0]["id"], repo="x", now=NOW)
    _seed(_entries_rows([_row(R_B, -1), _row(R_A, -1)]))        # both gate a day after NOW
    _judge((NOW_DT + timedelta(days=1, hours=1)).isoformat())
    assert [n for n in notices.uncleared() if n["notice_kind"] == "repo-parked"] == []
    # a keeps gating; b goes quiet again and parks a second time
    _seed(_entries_rows([_row(R_A, -8)]))
    _judge((NOW_DT + timedelta(days=9)).isoformat())
    assert len(_parked_notices()) == 1


def test_the_notice_clears_when_the_parked_repo_is_deregistered():
    _seed(_entries_rows(_ready_rows()[:-1]))
    _judge()
    assert len(_parked_notices()) == 1
    fleet.run_judgement(LATER, aramid_version="0.9.0", entries=ENTRIES[:1],
                        policy=fleet.Policy(min_active_repos=1))
    assert _parked_notices() == []


def test_a_previous_verdict_without_parked_keys_is_judged_normally():      # Review Focus 2
    _seed(_entries_rows(_ready_rows()[:-1]))
    v = _judge()
    for r in v["repos"].values():
        del r["parked"], r["parked_since"]
    del v["fleet"]["active_repos"], v["fleet"]["parked_repos"]
    fleet.write_verdict(v)
    assert _judge(LATER) is not None and fleet.read_verdict()["fleet"]["parked_repos"] == ["b"]


def test_readiness_reached_counts_active_repos_and_lists_the_parked_ones():
    _seed(_entries_rows(_ready_rows()[:-1]))
    fleet.run_judgement(NOW, aramid_version="0.9.0", entries=ENTRIES,
                        policy=fleet.Policy(min_active_repos=1))
    (n,) = [x for x in notices.pending() if x["notice_kind"] == "readiness-reached"]
    assert n["title"].endswith("across 1 repos")
    assert "Every active repo has been green" in n["body"] and "Parked, not counted: b." in n["body"]
    assert n["evidence"]["repos"] == ["a"]
```

  `_row(repo, -1)` is a row one day after `NOW` (negative `days_ago`).

- [ ] **Step 2:** Run `python -m pytest tests/unit/test_fleet_judgement.py -q`. Expected: the five new tests FAIL (no `repo-parked` notice; body wording).
- [ ] **Step 3:** Add `"repo-parked"` to `notices.KINDS`; write `_post_parks`; change `_post_transitions`' `readiness-reached` branch (fall back to every repo name when `active_repos` is absent); call `_post_parks(verdict, now)` in `run_judgement`. A vanished repo is never parked, so it gets no notice (Review Focus 3: add one assertion to `test_fleet_missing_path_with_rows.py` if a `run_judgement`-level test exists there; otherwise Task 2's judge test covers it).
- [ ] **Step 4:** Run `python -m pytest tests/unit/test_fleet_judgement.py tests/unit/test_notices.py tests/unit/test_fleet_cmd_report.py -q`. Expected: all pass. Update the existing `readiness-reached` body/title assertion (`test_fleet_judgement.py:106`) only if it now fails on the "Every active repo" wording.
- [ ] **Step 5:** Commit `feat(fleet): repo-parked notice, cleared on return or deregistration (A2)`.

---

### Task 4: Surfaces — readiness line and `aramid fleet`

**Files:**
- Modify: `src/aramid/fleet.py` — `readiness_line` (758-791), `render_report` (836-879)
- Test: `tests/unit/test_fleet_parked.py`, `tests/unit/test_fleet_judge.py`, `tests/unit/test_fleet_cmd_report.py`
- Modify (expectations): `tests/unit/test_fleet_missing_path_with_rows.py`, `tests/unit/test_init_onboarding.py`, `tests/integration/test_agent_hook_fleet.py`, `tests/integration/test_status_fleet.py` (every `repos green` built from a judged verdict)

**Interfaces:**
- Consumes: the Task 2 verdict keys.
- Produces (exact strings):
  - Readiness line, verdict carrying `fleet.active_repos`: `fleet: 1.0 readiness <LABEL> -- <active green>/<registered minus parked> active repos green, streak ..., versions .../...`; tail order `red:`, `no rows:`, `missing path:`, `stale:`, `parked: <name> (since <parked_since[:10]>), ...` (names sorted case-insensitively; `parked: <name>` alone when `parked_since` is null), then blockers, then notes.
  - Verdict without `fleet.active_repos`: byte-for-byte today's line.
  - `render_report`, after a parked repo's row (and after its worktree line if any): `  {'':<width}  (parked since <parked_since> -- no gate run in <W> days; its next one restarts the streak)`; with `parked_since` null: `  {'':<width}  (parked -- its next gate run restarts the streak)`. `W` is `verdict["policy"]["max_row_age_days"]`.
  - `render_report`, after `  armed anywhere: ...`, only when `active_repos` is present: `  active repos: <N> (floor <min_active_repos>)`.

- [ ] **Step 1: Write the failing tests** in `tests/unit/test_fleet_parked.py`

```python
def test_the_readiness_line_counts_active_repos_and_names_the_parked():
    rows = sum((_weekly(k, 20, 0, ARMED) for k in (R_A, R_B)), [])
    rows += [_row(R_C, 1, red=("consumers_healthy",))] + _weekly(R_D, 20, 10) + [_row(R_E, 20), _row(R_E, 9)]
    v = fleet.judge(rows, REG5, P, NOW, aramid_version="0.9.0")
    assert fleet.readiness_line(v) == (
        "fleet: 1.0 readiness NOT READY -- 2/3 active repos green, streak 0.0d, versions 0/2; "
        "red: c (consumers_healthy); parked: d (since 2026-09-17), e (since 2026-09-18)")


def test_the_fleet_report_annotates_a_parked_repo_and_prints_the_floor():
    rows = sum((_weekly(k, 20, 0, ARMED) for k in (R_A, R_B, R_C)), []) + _weekly(R_D, 20, 10)
    lines = fleet.render_report(fleet.judge(rows, REG4, P, NOW), P, now=NOW).splitlines()
    at = next(i for i, ln in enumerate(lines) if ln.startswith("  d "))
    assert lines[at + 1] == ("     (parked since 2026-09-17T12:00:00+00:00 -- no gate run in 7 days; "
                             "its next one restarts the streak)")
    assert lines[lines.index("  armed anywhere: yes") + 1] == "  active repos: 3 (floor 3)"


def test_a_parked_repo_without_a_date_still_renders():              # Review Focus 5
    rows = sum((_weekly(k, 20, 0, ARMED) for k in (R_A, R_B, R_C)), []) + _weekly(R_D, 20, 10)
    v = fleet.judge(rows, REG4, P, NOW)
    v["repos"][R_D]["parked_since"] = None
    assert fleet.readiness_line(v).endswith("; parked: d")
    assert "     (parked -- its next gate run restarts the streak)" in fleet.render_report(
        v, P, now=NOW).splitlines()
```

  The name column is 4 wide here (`repo` heading), so the annotation's indent is `2 + 4 + 2` spaces minus the `(`: write the expected string from the format above and confirm it by reading the failure output once, not by copying it blindly.

  In `tests/unit/test_fleet_judge.py`: remove the Task 2 xfail and set `test_the_readiness_line_names_stale_repos_and_the_window` to the A2 line for two parked repos:
  `"fleet: 1.0 readiness INSUFFICIENT DATA -- 0/0 active repos green, streak 0.0d, versions 0/2; parked: a (since 2026-09-17), b (since 2026-09-17)"`. (`no active repos` is a verdict reason, not a blocker or a note, so the line does not carry it; the label and `0/0` say it.) Rename the test `test_the_readiness_line_names_parked_repos`.
  `test_a_verdict_written_before_a1_renders_unchanged`: also delete the A2 keys from the verdict before rendering; the expected string is unchanged (`2/2 repos green`).
  `tests/unit/test_fleet_cmd_report.py::test_render_report_whole` must pass **unchanged** (its verdict is hand-built without the new keys).

- [ ] **Step 2:** Run `python -m pytest tests/unit/test_fleet_parked.py tests/unit/test_fleet_judge.py -q`. Expected: the three new tests and the un-xfailed one FAIL on string mismatch.
- [ ] **Step 3:** Implement both renderers per Interfaces.
- [ ] **Step 4:** Run `python -m pytest tests -q -k "fleet or onboarding or agent_hook or status"`. Fix every `repos green` expectation that came from a judged verdict to `active repos green`; a hand-built verdict's expectation must not change. Expected after edits: all pass.
- [ ] **Step 5:** Commit `feat(fleet): the readiness line and aramid fleet show parked repos (A2)`.

---

### Task 5: Documents

**Files:**
- Modify: `docs/user-guide.md` (section 7: the verdict paragraph at ~876, the notices sentence at ~878, "Leaving the fleet" at ~880, the policy block at ~886), `RELEASING.md:135`, `CHANGELOG.md` (`## [Unreleased]`), `docs/superpowers/specs/2026-09-02-aramid-fleet-readiness-design.md` (a pointer line to A2 beside the A1 pointer), `docs/knowledge-base.md` if it lists notice kinds or fleet policy keys
- Test: `tests/unit/test_fleet_docs.py`

- [ ] **Step 1: Write the failing test**

```python
def test_the_guide_and_the_gate_describe_parked_repos():
    guide = _read("docs/user-guide.md")
    for needle in ("min_active_repos = 3", "repo-parked", "parked since",
                   "its next gate run restarts the streak"):
        assert needle in guide, needle
    assert "every active registered repo" in _read("RELEASING.md")
    unreleased = _read("CHANGELOG.md").split("## [Unreleased]", 1)[1].split("\n## [", 1)[0]
    assert "parked" in unreleased and "min_active_repos" in unreleased
```

- [ ] **Step 2:** Run `python -m pytest tests/unit/test_fleet_docs.py -q`. Expected: FAIL on the first needle.
- [ ] **Step 3:** Write the documents. Content each must carry:
  - **User guide, verdict paragraph:** replace the "older than the freshness window ... or the clock restarts" sentence. A repo whose latest row is green and older than the window is *parked*: not counted, shown as `parked since <time>`; its next gate run restarts the streak; the drain still walks it. A repo whose latest row is red never parks. A repo with no rows blocks for the window after `aramid init`, then is parked. Fewer than `min_active_repos` active repos cannot read `ready`; no active repo is `insufficient-data`. The 8-to-13-day case and "any commit in a parked repo restarts the 14 days; deregister it first if that matters" from spec section 9.
  - **Notices sentence:** add `repo-parked` and that it clears itself.
  - **"Leaving the fleet":** one sentence on when to deregister instead of letting a repo park (deregistering stops its drain; a parked repo keeps it).
  - **Policy block:** `min_active_repos = 3    # fewer active repos than this cannot read ready`.
  - **RELEASING.md item 1:** "every active registered repo green ... (a repo with no gate run in 7 days whose last row was green is parked and not counted; at least 3 active)", plus the A2 spec path.
  - **CHANGELOG, Unreleased:** a `Changed` entry for the fleet verdict (outside the compatibility surface; say so in the entry) and an `Added` entry for `[readiness].min_active_repos` and the `repo-parked` notice. State the visible change to the status line (`active repos green`, `parked:`) and that a fleet of fewer than three repos now reads `active repos N < 3` until the key is lowered.
- [ ] **Step 4:** Run `python -m pytest tests/unit -q -k "docs or guide or changelog or governance"`. Expected: all pass (the guide has drift guards; a failure names the string it wants).
- [ ] **Step 5:** Commit `docs(fleet): parked repos in the guide, the 1.0 gate and the changelog (A2)`.

---

### Task 6: Whole-tree verification and replay

**Files:** none in the repo. Replay script: `C:\Users\fbmac\.claude\projects\F--Projects-aramid\session-tools\replay_parked.py`.

- [ ] **Step 1:** Run the full suite: `python -m pytest tests -q -n 6 > <log> 2>&1; echo rc=$?`. Expected: `rc=0`. Any failure is reported by name, including one this plan did not cause.
- [ ] **Step 2:** Run the WSL ratchet on `HEAD` (the push gate does not run it; `fleet.py` and `notices.py` are `src` changes). Expected: its own pass line.
- [ ] **Step 3: Replay against this machine's real rows, read-only.** The script puts `F:/Projects/aramid/src` first on `sys.path` in-process, runs from a cwd outside the repo, calls only `read_rows`, `registered_repos`, `registration_times`, `vanished_repos`, `spurious_entries`, `load_policy` and `judge`, writes nothing, and prints: verdict, reasons, active, parked (with `parked_since`), streak start, and the same for the installed 0.20.24 judge beside it. Falsifier: it also prints `fleet.__file__`, which must be under `F:\Projects\aramid\src`; a path under `site-packages` means the replay measured the old judge. Compare with the 2026-11-27 scratch replay (9 parks in history, no return inside a streak, no `ready`) and report what differs.
- [ ] **Step 4:** Read the open ledger findings (`aramid ledger filter --status open`) for anything this branch added.
- [ ] **Step 5:** Stop and report to the operator. Pushing `main` needs their go; the 0.21.0 release is a separate request.
