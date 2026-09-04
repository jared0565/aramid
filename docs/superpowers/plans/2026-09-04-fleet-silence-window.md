# Fleet Readiness Freshness Window (Amendment A1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A registered repo's latest fleet-health row counts toward the 1.0 readiness streak only while it is no older than a policy window (default 7 days); a stale row makes the verdict `insufficient-data`, resets the streak, and is named on every surface.

**Architecture:** One new policy key (`[readiness].max_row_age_days`) flows through `fleet.Policy` into `fleet.judge`, which gains a freshness predicate applied twice: during the time-ordered walk (so a gap between rows resets the streak) and at `now` (so an idle fleet reads `insufficient-data`). The verdict grows additive keys; `readiness_line` and `render_report` render them. No new module, no schema bump, no change to any tracked consumer file.

**Tech Stack:** Python 3.12+ stdlib only; pytest with the repo's existing fixtures (`tmp_path`, `capsys`, the autouse `ARAMID_FLEET_DIR` isolation in `tests/conftest.py`). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-02-aramid-fleet-readiness-design.md`, section "Amendment A1 (2026-09-04): the freshness window" (A1.1 to A1.6), plus the three in-place edits it made to sections 3.4, 6 and 8. The plan argues from A1; read it before any task. Decision announced to graphite-agent as channel round 171.

## Global Constraints

Every task's requirements implicitly include this section. Values are copied from the spec verbatim.

1. **Fail-open, always.** No fleet call ever changes a gate's, the drain's, or the hook's exit code, or raises out of its seam (spec section 9.1). Nothing in this plan adds a raise path: `judge` stays pure, `run_judgement` keeps its `except Exception`.
2. **Policy key, exactly:** `[readiness].max_row_age_days`, integer days, default `7`; `0` disables the window; negative or non-integer falls back to the default through the existing `_int_or` (A1.2).
3. **Freshness, exactly:** a row is fresh at time `t` when `t - row.at <= window`; exactly `window` old is fresh (A1.3). `age_days` is `(now - latest.at)` in days, rounded to two decimals, `null` with no rows.
4. **Label precedence:** no repos registered -> no rows -> **stale** -> red -> ready checks (A1.3). Stale and red both list their reasons.
5. **Line shapes are contracts** (A1.4). Reason and tail: `stale: <name> (<age:.1f>d), <name> (<age:.1f>d) -- window <W>d`. `aramid fleet` header: `fleet health -- 1.0 readiness (policy: 14 days, 2 versions, 7-day row window)` or `..., no row window)`. Full-line assertions for every new or changed line. ASCII `--`, never U+2014, in anything printed.
6. **Additive only.** New verdict keys: `repos[<key>].stale`, `repos[<key>].age_days`, `fleet.stale_repos`, `policy.max_row_age_days`. `schema_version` stays `1`. A verdict file written before A1 renders exactly as before.
7. **Test commands** run as `python -m pytest <path> -q -p no:cacheprovider` from the repo root (`pyproject.toml` sets `pythonpath = ["src"]`, so the checkout, never the installed wheel, is under test). Never `pip install -e .` in this repo.
8. **Every commit goes through the gate:** `python -P -m aramid check --staged` before `git commit`, never `--no-verify`. After every gate: `python -P -m aramid ledger filter --status open`. Commit messages go in a scratchpad file and are passed with `git commit -F <file>` (backticks in `-m` get shell-expanded). Each message ends with:
    ```
    Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
    Claude-Session: https://claude.ai/code/session_01Swr1yPAqMtUnH36YVhune9
    ```
9. **Heredoc bodies mangle backslashes on this machine.** Any file content containing a backslash (the policy tests write `'\n'`-joined TOML) is written with the Write/Edit tools, never a shell heredoc.
10. **Stay inside this repository.** Nothing here reads or writes graphite's repo; the fleet store under test is the isolated one the conftest fixture points `ARAMID_FLEET_DIR` at.

---

## File Structure

- Modify `src/aramid/fleet.py` -- `Policy` (new field, last so positional construction keeps working), `load_policy` (reads the key), `judge` (freshness during the walk and at `now`, additive output), `readiness_line` (stale tail), `render_report` (header clause). One file: the judge, its policy and its renderers already live together and the change is ~40 lines.
- Modify `tests/unit/test_fleet_store.py` -- policy loading.
- Modify `tests/unit/test_fleet_judge.py` -- streak math (legacy tests run with the window disabled; new A1 tests use the production default) and the readiness-line tail.
- Modify `tests/unit/test_fleet_judgement.py` -- the `_ready_rows` fixture becomes an active fleet (rows at most 6 days apart) so the drain orchestration runs under the default window; one new stale-transition test.
- Modify `tests/integration/test_fleet_cmd.py` -- both header lines.
- Modify `docs/user-guide.md`, `CHANGELOG.md`.

---

### Task 0: Commit the spec amendment and this plan

**Files:**
- Already modified: `docs/superpowers/specs/2026-09-02-aramid-fleet-readiness-design.md`
- Create: `docs/superpowers/plans/2026-09-04-fleet-silence-window.md` (this file)

- [ ] **Step 1: Stage and gate**

Run: `git add docs/superpowers/specs/2026-09-02-aramid-fleet-readiness-design.md docs/superpowers/plans/2026-09-04-fleet-silence-window.md && python -P -m aramid check --staged`
Expected: exit 0, no new findings. Then `python -P -m aramid ledger filter --status open` shows the same 3 open (2 llm-review suppressed, 1 equivalent mutant).

- [ ] **Step 2: Commit**

Message file content:
```
docs(spec): amendment A1 -- the fleet readiness freshness window, decided

The operator chose a 7-day window on every registered repo's latest row;
a stale row reads insufficient-data and resets the streak. Amends spec
sections 3.4, 6 and 8 in place and records the decision, the options
rejected, the judge semantics, the line shapes and the tests as A1.
Plan alongside. Announced as channel round 171.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Swr1yPAqMtUnH36YVhune9
```
Run: `git commit -F <scratchpad>/msg0.txt`

---

### Task 1: The policy key

**Files:**
- Modify: `src/aramid/fleet.py:65-109` (`Policy`, `load_policy`)
- Test: `tests/unit/test_fleet_store.py:25-57`

**Interfaces:**
- Produces: `fleet.Policy.max_row_age_days: int = 7` (sixth and last field); `load_policy()` reads `[readiness].max_row_age_days` through `_int_or`.

- [ ] **Step 1: Write the failing tests**

In `tests/unit/test_fleet_store.py`, replace the two existing policy tests and add two (use the Edit tool: the TOML strings carry `\n`):

```python
def test_policy_defaults_when_fleet_toml_is_absent():
    assert fleet.load_policy() == fleet.Policy(min_days=14, min_versions=2,
                                               repeat_hours=24, defect_rows=3,
                                               gate_trailer=True, max_row_age_days=7)


def test_policy_reads_every_key(tmp_path):
    p = fleet.policy_path()
    p.parent.mkdir(parents=True)
    p.write_text('schema_version = 1\n[readiness]\nmin_days = 3\nmin_versions = 1\n'
                 'max_row_age_days = 5\n'
                 '[notices]\nrepeat_hours = 6\ndefect_rows = 2\ngate_trailer = false\n',
                 encoding="utf-8")
    assert fleet.load_policy() == fleet.Policy(3, 1, 6, 2, False, 5)


def test_policy_zero_row_window_is_accepted_as_disabled():
    # Amendment A1.2: 0 disables the window; it is a value, not a mistake.
    p = fleet.policy_path()
    p.parent.mkdir(parents=True)
    p.write_text('[readiness]\nmax_row_age_days = 0\n', encoding="utf-8")
    assert fleet.load_policy().max_row_age_days == 0


def test_policy_negative_or_string_row_window_falls_back():
    p = fleet.policy_path()
    p.parent.mkdir(parents=True)
    p.write_text('[readiness]\nmax_row_age_days = -1\n', encoding="utf-8")
    assert fleet.load_policy().max_row_age_days == 7
    p.write_text('[readiness]\nmax_row_age_days = "week"\n', encoding="utf-8")
    assert fleet.load_policy().max_row_age_days == 7
```

- [ ] **Step 2: Run them and read the failure**

Run: `python -m pytest tests/unit/test_fleet_store.py -q -p no:cacheprovider`
Expected: 4 failures -- `TypeError: Policy.__init__() got an unexpected keyword argument 'max_row_age_days'` on the defaults test, `TypeError ... takes from 1 to 6 positional arguments but 7 were given` on the every-key test, `AttributeError: 'Policy' object has no attribute 'max_row_age_days'` on the other two.

- [ ] **Step 3: Implement**

In `src/aramid/fleet.py`, the dataclass gains one field, last:

```python
@dataclass(frozen=True)
class Policy:
    """Operator policy from `fleet.toml` (spec section 3.4). The defaults ARE
    the user's chosen strict threshold: 14 days and 2 aramid versions, and
    (amendment A1) a latest row no older than 7 days per repo -- 0 disables
    that window."""
    min_days: int = 14
    min_versions: int = 2
    repeat_hours: int = 24
    defect_rows: int = 3
    gate_trailer: bool = True
    max_row_age_days: int = 7
```

and `load_policy`'s return adds one line after `min_versions=`:

```python
        max_row_age_days=_int_or(readiness.get("max_row_age_days"), defaults.max_row_age_days),
```

- [ ] **Step 4: Run the file again**

Run: `python -m pytest tests/unit/test_fleet_store.py -q -p no:cacheprovider`
Expected: all pass.

- [ ] **Step 5: Gate and commit**

Run: `git add src/aramid/fleet.py tests/unit/test_fleet_store.py && python -P -m aramid check --staged && python -P -m aramid ledger filter --status open`
Commit message: `feat(fleet): [readiness].max_row_age_days policy key, default 7, 0 disables (A1.2)` plus the two trailers.

---

### Task 2: The judge -- freshness during the walk and at `now`

**Files:**
- Modify: `src/aramid/fleet.py:286-397` (`judge`)
- Test: `tests/unit/test_fleet_judge.py`, `tests/unit/test_fleet_judgement.py`

**Interfaces:**
- Consumes: `Policy.max_row_age_days` from Task 1.
- Produces: verdict keys `repos[k]["stale"]: bool`, `repos[k]["age_days"]: float | None`, `fleet["stale_repos"]: list[str]`, `policy["max_row_age_days"]: int`; reason string `stale: a (10.0d), b (10.0d) -- window 7d`.

- [ ] **Step 1: Adjust the legacy streak-math tests**

In `tests/unit/test_fleet_judge.py` replace the module-level `POLICY` line with:

```python
# The streak-math tests below place rows 10 to 20 days apart on purpose and
# predate amendment A1: they run with the freshness window DISABLED so they
# keep testing streak math alone. The A1 tests at the bottom use the
# production default (7 days).
POLICY = fleet.Policy(min_days=14, min_versions=2, max_row_age_days=0)
DEFAULT = fleet.Policy()
```

In `test_ready_when_every_condition_holds`, the `repos[R_A]` dict gains `"stale": False, "age_days": 10.0` (after `"red_criteria": []`), the policy assertion becomes `{"min_days": 14, "min_versions": 2, "max_row_age_days": 0}`, and one line is added: `assert v["fleet"]["stale_repos"] == []`.

In `test_a_registered_repo_without_rows_is_insufficient_data`, the `repos["f:/projects/c"]` dict gains `"stale": False, "age_days": None`.

- [ ] **Step 2: Write the failing A1 tests**

Append to `tests/unit/test_fleet_judge.py`:

```python
# --- Amendment A1: the freshness window -------------------------------------

def _active_rows(step=6, span=20):
    """Both repos push every `step` days for `span` days (20, 14, 8, 2 days
    ago): the cadence an active fleet has, every gap inside the default
    window, two versions across the run."""
    rows = []
    for days_ago in range(span, -1, -step):
        version = "0.8.0" if days_ago > span / 2 else "0.9.0"
        rows += [_row(R_A, days_ago, version, armed=ARMED), _row(R_B, days_ago, version)]
    return rows


def test_default_window_lets_an_active_fleet_reach_ready():
    v = fleet.judge(_active_rows(), REG, DEFAULT, NOW, aramid_version="0.9.0")
    assert v["verdict"] == "ready"
    assert v["fleet"]["streak_started_at"] == _at(20) and v["fleet"]["days_held"] == 20.0
    assert v["fleet"]["stale_repos"] == []
    assert v["repos"][R_A]["stale"] is False and v["repos"][R_A]["age_days"] == 2.0
    assert v["policy"] == {"min_days": 14, "min_versions": 2, "max_row_age_days": 7}


def test_idle_past_the_window_is_insufficient_data_and_resets_the_streak():
    rows = _ready_rows()      # latest rows 10 days ago: green, two versions, 20 idle-held days
    v = fleet.judge(rows, REG, DEFAULT, NOW)
    assert v["verdict"] == "insufficient-data"
    assert v["reasons"] == ["stale: a (10.0d), b (10.0d) -- window 7d"]
    assert v["fleet"]["stale_repos"] == ["a", "b"]
    assert v["fleet"]["streak_started_at"] is None and v["fleet"]["days_held"] == 0.0
    assert v["fleet"]["all_green_now"] is False and v["fleet"]["blockers"] == []
    assert v["repos"][R_A]["stale"] is True and v["repos"][R_A]["age_days"] == 10.0
    # The same rows with the window disabled are the spec as first written: ready by silence.
    assert fleet.judge(rows, REG, POLICY, NOW)["verdict"] == "ready"


def test_exactly_window_old_is_still_fresh():
    rows = [_row(R_A, 20, "0.8.0", armed=ARMED), _row(R_B, 20, "0.8.0"),
            _row(R_A, 14, "0.9.0", armed=ARMED), _row(R_B, 14, "0.9.0"),
            _row(R_A, 7, "0.9.0", armed=ARMED), _row(R_B, 7, "0.9.0")]
    v = fleet.judge(rows, REG, DEFAULT, NOW)
    assert v["fleet"]["stale_repos"] == [] and v["verdict"] == "ready"
    rows[-1]["at"] = rows[-2]["at"] = _at(7.01)
    v = fleet.judge(rows, REG, DEFAULT, NOW)
    assert v["verdict"] == "insufficient-data" and v["fleet"]["stale_repos"] == ["a", "b"]


def test_a_cross_repo_gap_inside_the_walk_restarts_the_streak_at_the_return():
    # a pushes every 5 days; b is silent from day 20 to day 2, so the fleet
    # was stale from day 13 to day 2 and the streak cannot predate b's return.
    rows = [_row(R_A, d, "0.9.0", armed=ARMED) for d in (20, 15, 10, 5, 2)]
    rows += [_row(R_B, 20, "0.9.0"), _row(R_B, 2, "0.9.0")]
    v = fleet.judge(rows, REG, DEFAULT, NOW)
    assert v["fleet"]["stale_repos"] == []
    assert v["fleet"]["streak_started_at"] == _at(2)
    assert v["verdict"] == "not-ready"
    assert v["reasons"] == ["streak 2.0d < 14d", "versions 1/2 in streak"]


def test_a_same_repo_gap_in_a_single_repo_fleet_restarts_the_streak():
    # No row falls inside the gap, so only the pre-apply check can see it.
    reg = {R_A: "a"}
    rows = [_row(R_A, 20, "0.8.0", armed=ARMED), _row(R_A, 2, "0.9.0", armed=ARMED)]
    v = fleet.judge(rows, reg, DEFAULT, NOW)
    assert v["fleet"]["streak_started_at"] == _at(2)
    assert v["fleet"]["versions_in_streak"] == ["0.9.0"]
    assert v["verdict"] == "not-ready"
    assert v["reasons"] == ["streak 2.0d < 14d", "versions 1/2 in streak"]
    assert fleet.judge(rows, reg, POLICY, NOW)["verdict"] == "ready"


def test_no_rows_beats_stale_and_stale_beats_red():
    stale_and_red = _ready_rows() + [_row(R_A, 9, red=("dep_audit_ran",), armed=ARMED, dep=False)]
    v = fleet.judge(stale_and_red, REG, DEFAULT, NOW)
    assert v["verdict"] == "insufficient-data"
    assert v["reasons"] == ["a: dep_audit_ran", "stale: a (9.0d), b (10.0d) -- window 7d"]
    assert v["fleet"]["breaking_row"]["run_id"] == "a-9"
    v = fleet.judge(stale_and_red, {**REG, "f:/projects/c": "c"}, DEFAULT, NOW)
    assert v["verdict"] == "insufficient-data"
    assert v["reasons"] == ["a: dep_audit_ran", "no rows: c"]
    assert v["fleet"]["stale_repos"] == ["a", "b"]
```

- [ ] **Step 3: Run and read the failures**

Run: `python -m pytest tests/unit/test_fleet_judge.py -q -p no:cacheprovider`
Expected: the two adjusted legacy tests fail on the missing `stale`/`age_days`/`max_row_age_days` keys; the six A1 tests fail with `KeyError: 'stale_repos'` or a wrong verdict (`ready` where `insufficient-data` is expected). `test_default_window_lets_an_active_fleet_reach_ready` fails only on the `policy` and `stale_repos` keys -- note that, it is the happy path.

- [ ] **Step 4: Implement `judge`**

In `src/aramid/fleet.py`, `judge` changes in five places. After `cutoff = ...`:

```python
    # Amendment A1: a row is fresh at time t while t - at <= window; exactly
    # `window` old is still fresh. 0 disables the window (the spec as first
    # written, reachable on purpose).
    window = timedelta(days=policy.max_row_age_days) if policy.max_row_age_days > 0 else None

    def _fresh(row: dict, at_dt: datetime) -> bool:
        if window is None:
            return True
        row_at = _parse(row.get("at"))
        return row_at is not None and at_dt - row_at <= window
```

Inside the walk, the first lines of the loop body become:

```python
    for _at, r in live:
        repo = r["repo"]
        prev = latest.get(repo)
        # A1: the gap the green check below cannot see -- some repo's latest
        # row (this repo's previous one included) went stale before this row
        # arrived, with no row inside the gap to evaluate. Reset like a red.
        if streak_start is not None and not all(_fresh(x, _at) for x in latest.values()):
            streak_start, versions, disarm = None, set(), None
        latest[repo] = r
        counts[repo] += 1
```

and the green check gains freshness:

```python
        green = all(k in latest and health_mod.row_green(latest[k].get("criteria", {}))
                    and _fresh(latest[k], _at) for k in registered)
```

The per-repo output block becomes:

```python
    repos_out: dict[str, dict] = {}
    for key, name in sorted(registered.items(), key=lambda kv: kv[1].casefold()):
        row = latest.get(key)
        if row is None:
            repos_out[key] = {"name": name, "rows": 0, "latest_at": None, "green": False,
                              "red_criteria": [], "criteria": {}, "stale": False,
                              "age_days": None}
            continue
        crit = dict(row.get("criteria", {}))
        row_at = _parse(row["at"])
        age = round(max(0.0, (now_dt - row_at).total_seconds() / 86400.0), 2)
        repos_out[key] = {"name": row.get("name") or name, "rows": counts[key],
                          "latest_at": row["at"], "green": health_mod.row_green(crit),
                          "red_criteria": _red_criteria(crit), "criteria": crit,
                          "stale": not _fresh(row, now_dt), "age_days": age}
    missing = sorted((v["name"] for v in repos_out.values() if v["rows"] == 0), key=str.casefold)
    stale = sorted((v["name"] for v in repos_out.values() if v["stale"]), key=str.casefold)
    all_green_now = (bool(registered) and not missing and not stale
                     and all(v["green"] for v in repos_out.values()))
    if stale:
        # A1 step 3: an idle fleet holds no streak.
        streak_start, versions, disarm = None, set(), None
```

The verdict branch gains one `elif` between `missing` and `not all_green_now`:

```python
    elif stale:
        verdict = INSUFFICIENT
        reasons.append("stale: " + ", ".join(f"{v['name']} ({v['age_days']:.1f}d)"
                                             for v in repos_out.values() if v["stale"])
                       + f" -- window {policy.max_row_age_days}d")
```

And the return dict: `"policy"` gains `"max_row_age_days": policy.max_row_age_days`; the `"fleet"` dict gains `"stale_repos": stale` (after `"armed_anywhere"`).

- [ ] **Step 5: Run the judge tests**

Run: `python -m pytest tests/unit/test_fleet_judge.py -q -p no:cacheprovider`
Expected: all pass.

- [ ] **Step 6: Make the drain fixtures an active fleet and add the stale transition**

In `tests/unit/test_fleet_judgement.py`, replace `_ready_rows`:

```python
def _ready_rows():
    # An ACTIVE fleet: both repos push every 6 days (20, 14, 8, 2 days ago),
    # so these rows are ready under the production default window
    # (amendment A1) rather than by silence. Streak since _at(20), 20 days,
    # versions 0.8.0 then 0.9.0.
    return [_row(R_A, 20, "0.8.0", armed=ARMED), _row(R_B, 20, "0.8.0"),
            _row(R_A, 14, "0.8.0", armed=ARMED), _row(R_B, 14, "0.8.0"),
            _row(R_A, 8, "0.9.0", armed=ARMED), _row(R_B, 8, "0.9.0"),
            _row(R_A, 2, "0.9.0", armed=ARMED), _row(R_B, 2, "0.9.0")]
```

In `test_compaction_drops_rows_older_than_180_days_once_a_day` the three counts move from `5`, `4`, `5` to `9`, `8`, `9`.

Append:

```python
def test_going_stale_from_ready_posts_readiness_broken_on_the_prior_streak():
    """Amendment A1: a READY fleet left idle past the window reads
    insufficient-data with no breaking row, so the notice keys on the prior
    verdict's streak start (the existing no-breaking-row branch)."""
    _seed(_entries_rows(_ready_rows()))
    prior = _judge()
    assert prior["verdict"] == "ready"
    later = (NOW_DT + timedelta(days=6)).isoformat()      # latest rows are now 8 days old
    v = _judge(later)
    assert v["verdict"] == "insufficient-data"
    assert v["reasons"] == ["stale: a (8.0d), b (8.0d) -- window 7d"]
    broken = [n for n in notices.pending() if n["notice_kind"] == "readiness-broken"]
    assert len(broken) == 1
    assert broken[0]["key"] == "streak:" + prior["fleet"]["streak_started_at"]
    assert broken[0]["title"] == "fleet readiness lost -- stale: a (8.0d), b (8.0d) -- window 7d"
```

- [ ] **Step 7: Run both unit files**

Run: `python -m pytest tests/unit/test_fleet_judge.py tests/unit/test_fleet_judgement.py -q -p no:cacheprovider`
Expected: all pass. If `test_reaching_readiness_posts_one_notice_and_only_once` fails on the title, the fixture's first row is not `_at(20)` -- fix the fixture, not the assertion.

- [ ] **Step 8: Gate and commit**

Run: `git add src/aramid/fleet.py tests/unit/test_fleet_judge.py tests/unit/test_fleet_judgement.py && python -P -m aramid check --staged && python -P -m aramid ledger filter --status open`
Commit message: `feat(fleet): the judge applies the freshness window -- a stale latest row is insufficient-data and resets the streak (A1.3)` plus the two trailers.

---

### Task 3: Rendering -- the readiness-line tail and the `aramid fleet` header

**Files:**
- Modify: `src/aramid/fleet.py:617-641` (`readiness_line`), `src/aramid/fleet.py:671-675` (`render_report` header)
- Test: `tests/unit/test_fleet_judge.py`, `tests/integration/test_fleet_cmd.py:46-60`, and `tests/integration/test_drain_fleet.py:62-64` (found in execution: its end-to-end fixture places rows 10 days apart and runs under the production default, so it becomes the same 20/14/8/2-day active fleet as the unit fixture)

**Interfaces:**
- Consumes: the verdict keys from Task 2.
- Produces: tail `stale: <name> (<age:.1f>d) -- window <W>d`; header clause `<W>-day row window` / `no row window`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_fleet_judge.py`:

```python
def test_the_readiness_line_names_stale_repos_and_the_window():
    v = fleet.judge(_ready_rows(), REG, DEFAULT, NOW, aramid_version="0.9.0")
    assert fleet.readiness_line(v) == (
        "fleet: 1.0 readiness INSUFFICIENT DATA -- 2/2 repos green, streak 0d, versions 0/2; "
        "stale: a (10.0d), b (10.0d) -- window 7d")


def test_a_verdict_written_before_a1_renders_unchanged():
    v = fleet.judge(_ready_rows(), REG, POLICY, NOW, aramid_version="0.9.0")
    for repo in v["repos"].values():
        del repo["stale"], repo["age_days"]
    del v["fleet"]["stale_repos"], v["policy"]["max_row_age_days"]
    assert fleet.readiness_line(v) == (
        "fleet: 1.0 readiness READY -- 2/2 repos green, streak 20d, versions 2/2")
```

In `tests/integration/test_fleet_cmd.py`, `test_fleet_report_full_lines` line 0 becomes:

```python
    assert lines[0] == ("fleet health -- 1.0 readiness (policy: 14 days, 2 versions, "
                        "7-day row window)")
```

and add after it:

```python
def test_fleet_report_header_says_when_the_row_window_is_disabled(capsys):
    fleet.policy_path().parent.mkdir(parents=True, exist_ok=True)
    fleet.policy_path().write_text("[readiness]\nmax_row_age_days = 0\n", encoding="utf-8")
    fleet.write_verdict(_full_verdict())
    assert cmd_fleet() == 0
    assert capsys.readouterr().out.splitlines()[0] == (
        "fleet health -- 1.0 readiness (policy: 14 days, 2 versions, no row window)")
```

(Use the Edit tool for this one: the TOML string carries `\n`.)

- [ ] **Step 2: Run and read the failures**

Run: `python -m pytest tests/unit/test_fleet_judge.py tests/integration/test_fleet_cmd.py -q -p no:cacheprovider`
Expected: the stale-line test fails (no `stale:` tail), both header tests fail (old header), the pre-A1 test passes already (it guards against a regression in Step 3).

- [ ] **Step 3: Implement**

In `readiness_line`, after the `missing` block and before `tail.extend(info.get("blockers", []))`:

```python
    stale = [f"{v['name']} ({float(v.get('age_days') or 0.0):.1f}d)"
             for v in repos.values() if v.get("stale")]
    if stale:
        window = verdict.get("policy", {}).get("max_row_age_days")
        tail.append("stale: " + ", ".join(stale) + (f" -- window {window}d" if window else ""))
```

In `render_report`, the header becomes:

```python
    window = (f"{policy.max_row_age_days}-day row window" if policy.max_row_age_days > 0
              else "no row window")
    out = [f"fleet health -- 1.0 readiness (policy: {policy.min_days} days, "
           f"{policy.min_versions} versions, {window})", ""]
```

- [ ] **Step 4: Run the fleet test set**

Run: `python -m pytest tests/unit/test_fleet_judge.py tests/unit/test_fleet_judgement.py tests/unit/test_fleet_store.py tests/integration/test_fleet_cmd.py tests/integration/test_status_fleet.py tests/integration/test_agent_hook_fleet.py tests/integration/test_drain_fleet.py -q -p no:cacheprovider`
Expected: all pass. The hook and status fixtures carry no `stale` keys and must render byte-identically.

- [ ] **Step 5: Gate and commit**

Run: `git add src/aramid/fleet.py tests/unit/test_fleet_judge.py tests/integration/test_fleet_cmd.py && python -P -m aramid check --staged && python -P -m aramid ledger filter --status open`
Commit message: `feat(fleet): name stale repos on the readiness line and the row window in the fleet header (A1.4)` plus the two trailers.

---

### Task 4: Documentation

**Files:**
- Modify: `docs/user-guide.md:545-560` (the readiness paragraph and the policy block)
- Modify: `CHANGELOG.md` (`## [Unreleased]`)

- [ ] **Step 1: user-guide**

In the paragraph beginning `The verdict is \`ready\` only when every registered repo's latest row is green`, after the sentence `A registered repo with no rows makes it \`insufficient-data\`;` change `anything else is \`not-ready\`` so the sentence reads:

```
A registered repo with no rows makes it `insufficient-data`, and so does a registered repo whose latest row is older than the freshness window (7 days by default): a streak is held by rows, not by silence, so every registered repo has to record a gate run at least weekly for the whole 14 days or the clock restarts. Anything else is `not-ready` with the red repos and criteria named.
```

In the policy block, after `min_versions = 2` add `max_row_age_days = 7   # 0 disables the freshness window`.

- [ ] **Step 2: CHANGELOG**

Under `## [Unreleased]`:

```
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
```

- [ ] **Step 3: Gate and commit**

Run: `git add docs/user-guide.md CHANGELOG.md && python -P -m aramid check --staged && python -P -m aramid ledger filter --status open`
Commit message: `docs: the freshness window in the user guide and changelog (A1.6)` plus the two trailers.

---

### Task 5: Full verification and push

- [ ] **Step 1: The whole suite through the pre-push gate, in the background**

Run (background, with its own log): `python -P -m aramid check --gate pre-push > <scratchpad>/prepush-a1.log 2>&1; echo rc=$? >> <scratchpad>/prepush-a1.log`
Do not touch the tree while it runs. Expected: `rc=0`, `3 findings open in ledger` unchanged.

- [ ] **Step 2: Ledger**

Run: `python -P -m aramid ledger filter --status open`
Expected: the same 3 suppressed findings, nothing new.

- [ ] **Step 3: Push in the background and watch CI**

Run (background, own log): `git push origin main > <scratchpad>/push-a1.log 2>&1; echo rc=$? >> <scratchpad>/push-a1.log`
Then: `gh run list --commit <FULL sha> --json databaseId,status,conclusion`; want 7/7 legs green on attempt 1. If a leg is red, read the job log before anything else.

- [ ] **Step 4: Record**

Append a resume point to `.superpowers/sdd/progress.md`; update the memory `fleet-readiness-parked-decision` (the parked item is now DECIDED and implemented at <sha>). Propose the MINOR release to the operator; do not cut it unasked.
