# Aramid Fleet Health, 1.0 Readiness and Notices Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every gate run appends its own repo's health row to a machine-level store, the scheduled drain judges the fleet against the strict 1.0 readiness policy and posts notices to aramid's own channel, and the session-start hook, `aramid status` and the gate itself surface the verdict and pending notices in whatever repo the operator is working in.

**Architecture:** A new `aramid/health.py` computes ONE `Health` snapshot per repo (skip streaks, consumer streaks, resolver defects, per-run block/audit facts) that `status` renders and the fleet row grades, so the two surfaces cannot disagree. `aramid/fleet.py` owns the store under `~/.aramid` (`fleet_health.jsonl` rows, `fleet_verdict.json`, `fleet.toml` policy), the push seam `record_health` called from `cmd_check`, and the judge `run_judgement` called from `cmd_drain`. `aramid/notices.py` is the event-sourced channel (`notices.jsonl`: notice / shown / ack / cleared). Two new commands, `aramid fleet` and `aramid notices`, read the store; every fleet call is fail-open and never touches an exit code.

**Tech Stack:** Python 3.12+ stdlib only (json, tomllib, hashlib, os.O_APPEND, dataclasses); pytest with the repo's existing fixtures (`tmp_path`, `monkeypatch`, `capsys`, `checkout_env`); no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-02-aramid-fleet-readiness-design.md` (approved by the user 2026-09-02; committed as b749f31). The plan argues from it; read sections 3 to 9 before any task.

## Global Constraints

Every task's requirements implicitly include this section. Values are copied from the spec verbatim.

1. **Fail-open, always.** No fleet or notices call ever changes a gate's, the drain's, or the hook's exit code, or raises out of its seam (spec section 9.1). `record_health`, `run_judgement` and `delivery_lines` catch `Exception` internally and print one stderr line.
2. **No network, ever. No other repo's ledger, ever.** The drain reads only `~/.aramid/fleet_health.jsonl` (spec section 9.2 and 9.3). `CLAUDE.md`: stay inside this repository.
3. **The store is one directory.** `fleet.store_dir()` is `Path.home() / ".aramid"` unless the environment variable `ARAMID_FLEET_DIR` overrides it. The override is an env var, not a monkeypatchable function, because git hooks spawn the gate in a child process (the `toolpath.TOOLS_DIR_ENV` precedent in `tests/conftest.py`). The autouse fixture added in Task 1 sets it for every test; a test that needs the real home directory does not exist and must not be written.
4. **Schema and policy values:** `schema_version = 1` on every row, verdict and notice event. Policy defaults: `min_days = 14`, `min_versions = 2`, `repeat_hours = 24`, `defect_rows = 3`, `gate_trailer = true`. Rows older than 180 days are ignored and compacted away. Budgets: push 2 s, judge 30 s; both report on stderr and skip on overrun.
5. **Criteria keys, exactly:** `no_skip_streak`, `consumers_healthy`, `resolvers_ok`, `no_self_inflicted_block`, `dep_audit_ran` (tri-state `true`/`false`/`null`). A row is green when the first four are `true` and the fifth is `true` or `null`. Verdicts: `ready`, `not-ready`, `insufficient-data`. Notice kinds: `readiness-reached`, `readiness-broken`, `fleet-defect`. Notice id = first 12 hex characters of `sha256("<kind>:<key>")`.
6. **Line shapes are contracts.** Every user-facing line in spec section 8 gets a full-line assertion (memory: render user-facing strings before shipping). ASCII `--` separators, never U+2014, in anything printed (the reporter's own rule).
7. **Writes:** single-line `O_APPEND` writes for the two `.jsonl` files (plus `O_BINARY` on Windows so `\n` stays `\n`); tmp + `os.replace` for `fleet_verdict.json` and for compaction. No locks.
8. **Additive only.** New `GateResult` fields carry defaults; existing construction sites, JSON keys and console lines stay byte-identical except for the additions the spec names (trailer line, `fleet_notices_pending` key, the `fleet:` lines).
9. **TDD per task:** write the failing test, run it and read the failure, implement, run again, then commit. Test commands run as `python -m pytest <path> -q -p no:cacheprovider` from the repo root (`pyproject.toml` sets `pythonpath = ["src"]`, so the checkout, never the installed wheel, is under test). Never `pip install -e .` in this repo.
10. **Every commit goes through the gate:** `python -P -m aramid check --staged` before `git commit`, never `--no-verify`. Commit messages are written to a file in the scratchpad and passed with `git commit -F <file>` (backticks in `-m` get shell-expanded). Each message ends with the two trailer lines:
    ```
    Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
    Claude-Session: https://claude.ai/code/session_01CJLQVnjeWxvcG7gQkt3Ste
    ```
11. **Graphite-first** for any cross-file "who calls / who reads" question during implementation (`python -P -m graphite query "callers <name>"`); the strict hook rejects multi-file greps that name graph symbols. Literal single-file `sed -n`/`grep -n <file>` is fine.
12. **No tree edits while a background push or suite is running** (memory: a backgrounded gate runs the suite on the live tree).

---

## File Structure

| File | Responsibility |
| --- | --- |
| `src/aramid/health.py` (new) | `Health` dataclass; the five ledger-derived signals moved out of `commands/status.py` (`skip_streaks`, `degraded_consumers`, `stood_down`, `no_work`, `resolver_defects`); `snapshot(cfg, ledger, result=None, *, gate=None, engine_error=False)`; `criteria(h)`, `row_green(crit)`; the `*_lines(h)` renderers `status` prints. Pure computation. |
| `src/aramid/fleet.py` (new) | Store paths and the `ARAMID_FLEET_DIR` seam; `Policy` + `load_policy`; row I/O (`build_row`, `append_line`, `append_row`, `read_rows`); `record_health` (push seam, 2 s budget); `judge` (streak and verdict math); `read_verdict`/`write_verdict`; `run_judgement` (transitions, defect notices, compaction, 30 s budget); `readiness_line`, `delivery_lines`, `render_report`. |
| `src/aramid/notices.py` (new) | The channel: `notice_id`, `read_events`/`append_event`, `materialize`, `pending`, `pending_count`, `post`, `clear`, `ack`, `mark_shown`, `due`, `render_line`. |
| `src/aramid/commands/fleet_cmd.py` (new) | `cmd_fleet(as_json)` and `cmd_notices(action, notice_id, root)`. |
| `src/aramid/commands/status.py` (modify) | The five `_x_lines(ledger)` functions become one-line delegations to `health`; `cmd_status` builds one snapshot and appends the `fleet:` block. |
| `src/aramid/commands/check.py` (modify) | Push seam after `print(output)` and in the mid-run engine-error branch; sets `fleet_notices_pending` / `fleet_trailer` on the result before rendering. |
| `src/aramid/commands/drain.py` (modify) | Judge seam after the autolearn rollup. |
| `src/aramid/commands/agent_hook.py` (modify) | Fleet lines after the bake lines in `_session_context`. |
| `src/aramid/pipeline.py` (modify) | `GateResult` gains `stacks`, `fleet_notices_pending`, `fleet_trailer`; `run_gate` populates `stacks`. |
| `src/aramid/reporter.py` (modify) | Console trailer; JSON key `fleet_notices_pending`. |
| `src/aramid/cli.py` (modify) | `fleet` and `notices` subparsers and dispatch. |
| `tests/conftest.py` (modify) | Autouse `_isolated_fleet_store` fixture. |
| `tests/unit/test_fleet_store.py`, `test_gate_result_stacks.py`, `test_health.py`, `test_fleet_rows.py`, `test_notices.py`, `test_fleet_judge.py`, `test_fleet_judgement.py`, `test_reporter_fleet.py`, `test_fleet_docs.py` (new) | Unit tests per task. |
| `tests/integration/test_check_fleet.py`, `test_drain_fleet.py`, `test_agent_hook_fleet.py`, `test_status_fleet.py`, `test_fleet_cmd.py` (new) | Integration tests per task. |
| `docs/user-guide.md`, `RELEASING.md`, `MAINTAINERS.md`, `CHANGELOG.md` (modify) | Operator documentation and the 1.0 gate. |

Two deviations from the spec's letter, both decided here so no implementer re-derives them:

- **Criterion 5 reads `pip-audit` presence in `tools_ran`, not `RunnerResult.examined`.** `runners/deps.py:run_python` never sets `examined` (it is `None`, "cannot report") and returns `MISSING` when it finds no requirements file, so an `OK` state already proves at least one file was audited. "Expected" means the `deps` runner key is in this gate's `GATE_RUNNER_KEYS` and the repo's detected stacks include `python`. That is what makes a pyproject-only Python repo read `false` at pre-push, which the spec names as the intent. `GateResult` gains `stacks` for this (Task 2).
- **A disarm inside the streak restarts the streak at the disarming row** rather than pinning the verdict at `not-ready` forever. `fleet.disarm_in_streak` in the verdict stays and is `true` when the current streak began at a disarm; the reason text names the repo, flag and time.

---

### Task 1: Store seam, suite isolation, and policy loader

**Files:**
- Create: `src/aramid/fleet.py`
- Modify: `tests/conftest.py:19` (import) and append one fixture
- Test: `tests/unit/test_fleet_store.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `fleet.SCHEMA_VERSION = 1`; `fleet.FLEET_DIR_ENV = "ARAMID_FLEET_DIR"`; `fleet.store_dir() -> Path`; `fleet.health_path()`, `fleet.verdict_path()`, `fleet.policy_path() -> Path`; `fleet.Policy` (frozen dataclass: `min_days: int = 14`, `min_versions: int = 2`, `repeat_hours: int = 24`, `defect_rows: int = 3`, `gate_trailer: bool = True`); `fleet.load_policy() -> Policy`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_fleet_store.py
"""The fleet store lives in ONE directory and every test is kept off the
real one. `ARAMID_FLEET_DIR` is an env var rather than a patched function
for the reason `toolpath.TOOLS_DIR_ENV` is: a gate driven through a real git
hook runs in a child process, and a monkeypatch cannot reach it."""
import os
from pathlib import Path

from aramid import fleet


def test_suite_isolates_the_store_from_the_real_home(tmp_path):
    # The autouse fixture in tests/conftest.py must already be in force.
    assert os.environ[fleet.FLEET_DIR_ENV].startswith(str(tmp_path))
    assert fleet.store_dir() == tmp_path / "aramid-fleet"
    assert fleet.health_path() == tmp_path / "aramid-fleet" / "fleet_health.jsonl"
    assert fleet.verdict_path() == tmp_path / "aramid-fleet" / "fleet_verdict.json"
    assert fleet.policy_path() == tmp_path / "aramid-fleet" / "fleet.toml"


def test_store_dir_defaults_to_home_dot_aramid(monkeypatch):
    monkeypatch.delenv(fleet.FLEET_DIR_ENV, raising=False)
    assert fleet.store_dir() == Path.home() / ".aramid"


def test_policy_defaults_when_fleet_toml_is_absent():
    assert fleet.load_policy() == fleet.Policy(min_days=14, min_versions=2,
                                               repeat_hours=24, defect_rows=3,
                                               gate_trailer=True)


def test_policy_reads_every_key(tmp_path):
    p = fleet.policy_path()
    p.parent.mkdir(parents=True)
    p.write_text('schema_version = 1\n[readiness]\nmin_days = 3\nmin_versions = 1\n'
                 '[notices]\nrepeat_hours = 6\ndefect_rows = 2\ngate_trailer = false\n',
                 encoding="utf-8")
    assert fleet.load_policy() == fleet.Policy(3, 1, 6, 2, False)


def test_policy_unreadable_falls_back_to_defaults_with_one_note(capsys):
    p = fleet.policy_path()
    p.parent.mkdir(parents=True)
    p.write_text("this is = not [toml\n", encoding="utf-8")
    assert fleet.load_policy() == fleet.Policy()
    err = capsys.readouterr().err
    assert err.startswith("aramid: fleet: ") and "unreadable" in err
    assert "using default policy" in err


def test_policy_key_of_the_wrong_type_falls_back_individually():
    p = fleet.policy_path()
    p.parent.mkdir(parents=True)
    p.write_text('[readiness]\nmin_days = "soon"\nmin_versions = 5\n', encoding="utf-8")
    pol = fleet.load_policy()
    assert pol.min_days == 14
    assert pol.min_versions == 5
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_fleet_store.py -q -p no:cacheprovider`
Expected: collection error `ModuleNotFoundError: No module named 'aramid.fleet'`.

- [ ] **Step 3: Create `src/aramid/fleet.py`**

```python
"""fleet -- machine-level fleet health: the append-only health store every
gate run writes one row to, the drain-time 1.0 readiness judgement over it,
and the operator policy that tunes both. Spec:
docs/superpowers/specs/2026-09-02-aramid-fleet-readiness-design.md.

Everything here lives under ONE directory (`store_dir()`, `~/.aramid` by
default) and nothing here opens a ledger other than the current repo's: a
gate run pushes its own repo's row, the drain reads only the rows. No
network, ever. `aramid uninstall` does not touch the store -- it is fleet
state, not repo state.

FAIL-OPEN IS THE CONTRACT, stated as policy (spec section 9): no function in
this module may change a gate's, the drain's, or the hook's exit code, or
raise out of its seam. `record_health`, `run_judgement` and `delivery_lines`
catch everything and say so on stderr, once.
"""
import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = 1

# An env seam rather than a monkeypatchable function, for the reason
# `toolpath.TOOLS_DIR_ENV` is one: the gate runs in a SPAWNED process under a
# git hook, and a monkeypatch in the pytest process cannot reach it. The
# suite-wide autouse fixture in tests/conftest.py sets this, so no test --
# and no gate a test drives through a real hook -- ever writes to the
# developer's real store.
FLEET_DIR_ENV = "ARAMID_FLEET_DIR"

HEALTH_FILE = "fleet_health.jsonl"
VERDICT_FILE = "fleet_verdict.json"
POLICY_FILE = "fleet.toml"


def store_dir() -> Path:
    override = os.environ.get(FLEET_DIR_ENV)
    if override:
        return Path(override)
    return Path.home() / ".aramid"


def health_path() -> Path:
    return store_dir() / HEALTH_FILE


def verdict_path() -> Path:
    return store_dir() / VERDICT_FILE


def policy_path() -> Path:
    return store_dir() / POLICY_FILE


@dataclass(frozen=True)
class Policy:
    """Operator policy from `fleet.toml` (spec section 3.4). The defaults ARE
    the user's chosen strict threshold: 14 days and 2 aramid versions."""
    min_days: int = 14
    min_versions: int = 2
    repeat_hours: int = 24
    defect_rows: int = 3
    gate_trailer: bool = True


def _int_or(value, default: int) -> int:
    # bool is an int subclass; `gate_trailer = true` under the wrong table
    # must not read as 1.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return default
    return value


def load_policy() -> Policy:
    """Absent -> defaults. Unreadable -> defaults plus ONE stderr note (the
    registry precedent). A key of the wrong type falls back to its own
    default rather than discarding the whole file."""
    p = policy_path()
    if not p.exists():
        return Policy()
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError) as exc:
        print(f"aramid: fleet: {p} unreadable ({exc}); using default policy",
              file=sys.stderr)
        return Policy()
    readiness = data.get("readiness")
    notices = data.get("notices")
    readiness = readiness if isinstance(readiness, dict) else {}
    notices = notices if isinstance(notices, dict) else {}
    defaults = Policy()
    trailer = notices.get("gate_trailer", defaults.gate_trailer)
    return Policy(
        min_days=_int_or(readiness.get("min_days"), defaults.min_days),
        min_versions=_int_or(readiness.get("min_versions"), defaults.min_versions),
        repeat_hours=_int_or(notices.get("repeat_hours"), defaults.repeat_hours),
        defect_rows=_int_or(notices.get("defect_rows"), defaults.defect_rows),
        gate_trailer=trailer if isinstance(trailer, bool) else defaults.gate_trailer,
    )
```

- [ ] **Step 4: Add the autouse fixture to `tests/conftest.py`**

Change the import line `from aramid import autolearn, config, registry, toolpath` to `from aramid import autolearn, config, fleet, registry, toolpath`, and append after `_isolated_user_config`:

```python
@pytest.fixture(autouse=True)
def _isolated_fleet_store(tmp_path, monkeypatch):
    """Keep every fleet write (`fleet.store_dir()`) off the real `~/.aramid`.

    `cmd_check` appends a fleet health row on every recording run and
    `cmd_drain` writes the verdict and notices; without this, every gate a
    test runs -- hundreds per suite -- would land in the developer's real
    store and the drain tests would judge a fleet that includes tmp repos.
    Set via ENV VAR, like the tools dir above, because several tests drive
    the gate through a real git hook in a spawned process that a monkeypatch
    cannot reach. A later `monkeypatch.setenv` in a test body still wins."""
    monkeypatch.setenv(fleet.FLEET_DIR_ENV, str(tmp_path / "aramid-fleet"))
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/unit/test_fleet_store.py tests/unit/test_registry.py -q -p no:cacheprovider`
Expected: all PASS (registry tests prove the conftest edit broke nothing).

- [ ] **Step 6: Commit**

```bash
git add src/aramid/fleet.py tests/conftest.py tests/unit/test_fleet_store.py
python -P -m aramid check --staged
git commit -F <scratchpad>/msg-task1.txt
```

Message: `feat(fleet): store seam, suite isolation and policy loader` with a body naming the env seam and why it is an env var, then the two trailer lines.

---

### Task 2: `GateResult.stacks`

**Files:**
- Modify: `src/aramid/pipeline.py` (`GateResult` fields after `recorded`, and the `return GateResult(...)` at the end of `run_gate`)
- Test: `tests/unit/test_gate_result_stacks.py`

**Interfaces:**
- Produces: `GateResult.stacks: tuple[str, ...]` (default `()`), sorted names from `detectors.detect_stacks`, e.g. `("python",)`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_gate_result_stacks.py
"""The fleet health row asks 'should pip-audit have run here', which is a
question about the repo's STACK, not about which requirements files exist.
`run_gate` already detects the stacks for runner selection; the result has
to carry them so the row does not re-walk the tree at push time."""
import subprocess
from types import SimpleNamespace

from aramid import config, pipeline
from aramid.ledger import Ledger
from aramid.models import Gate
from aramid.runners.base import RunnerResult, ToolState


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _python_repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "a.py")
    _git(r, "commit", "-q", "-m", "initial")
    return r


def test_run_gate_carries_the_detected_stacks(tmp_path, monkeypatch):
    root = _python_repo(tmp_path)
    cfg = config.load_config(root)
    ledger = Ledger(tmp_path / "ledger.db")
    monkeypatch.setitem(pipeline.RUNNERS, "fake",
                        SimpleNamespace(run=lambda ctx: RunnerResult("fake", ToolState.OK),
                                        parse=lambda result, ctx: []))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["fake"])

    result = pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger)

    assert result.stacks == ("python",)
    ledger.close()


def test_stacks_defaults_empty_for_hand_built_results():
    r = pipeline.GateResult(exit_code=0, findings=[], degraded=[], new_ids=[],
                            stale_overrides=[], run_id="r")
    assert r.stacks == ()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/unit/test_gate_result_stacks.py -q -p no:cacheprovider`
Expected: `AttributeError: 'GateResult' object has no attribute 'stacks'`.

- [ ] **Step 3: Add the field and populate it**

In `GateResult`, after `recorded: bool = True`:

```python
    # Which language stacks this run detected (`detectors.detect_stacks`),
    # sorted. Carried for the fleet health row (aramid.health): "should
    # pip-audit have run here" is a question about the repo's stack, not
    # about which requirements files happen to exist -- a pyproject-only
    # Python repo is exactly the case that criterion exists to catch -- and
    # `ctx.stacks` is already computed, so re-walking the tree at push time
    # would spend the row's own budget on a fact the run had in hand.
    # Additive; the default keeps every construction site valid.
    stacks: tuple = ()
```

In the `return GateResult(...)` at the end of `run_gate`, add after `tools_ran=tuple(sorted(scope_tools))`:

```python
                       stacks=tuple(sorted(ctx.stacks)))
```

(`ctx` is the `RunContext` built at `pipeline.py:866`, in scope for the whole function.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/unit/test_gate_result_stacks.py tests/unit/test_pipeline.py -q -p no:cacheprovider`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/pipeline.py tests/unit/test_gate_result_stacks.py
python -P -m aramid check --staged
git commit -F <scratchpad>/msg-task2.txt
```

Message: `feat(pipeline): GateResult carries the detected stacks`.

---
### Task 3: `aramid/health.py` -- one snapshot, rendered by `status` and graded by the row

**Files:**
- Create: `src/aramid/health.py`
- Modify: `src/aramid/commands/status.py` (replace the bodies of `_skip_streak_lines`, `_consumer_health_lines`, `_stood_down_lines`, `_no_work_lines`, `_resolver_defect_lines`; remove the moved constants; `cmd_status` builds one snapshot)
- Test: `tests/unit/test_health.py`; the existing `tests/integration/test_status.py` and `tests/integration/test_agent_hook.py` must stay green unchanged.

**Interfaces:**
- Consumes: `GateResult.stacks` (Task 2), `GateResult.tools_ran`, `.degraded`, `.degraded_block_tier`, `.findings`, `.run_id`, `.exit_code`; `config.arming_state(cfg)`; `yield_report.collect(ledger)`; `pipeline.GATE_RUNNER_KEYS`; `runners.deps.NAME_PIP_AUDIT`.
- Produces:
  - `health.CRITERIA = ("no_skip_streak", "consumers_healthy", "resolvers_ok", "no_self_inflicted_block", "dep_audit_ran")`
  - `health.ConsumerFault(name: str, count: int, spent_s: float, note: str)` (frozen)
  - `health.Health` (frozen dataclass): `skip_streaks: dict[str, dict[str, int]]`, `degraded_consumers: tuple[ConsumerFault, ...]`, `stood_down: tuple[ConsumerFault, ...]`, `no_work: tuple[ConsumerFault, ...]`, `resolver_defects: tuple[tuple[str, str, str], ...]` (resolver, tool, verdict), `open: int`, `armed: dict[str, bool]`, `gate: str | None`, `run_id: str | None`, `exit_code: int | None`, `blocking: int`, `bad_tools: tuple[str, ...]`, `degraded_block_tier: bool`, `engine_error: bool`, `dep_audit_ran: bool | None`
  - `health.snapshot(cfg, ledger, result=None, *, gate=None, engine_error=False) -> Health` (`cfg` and `ledger` may be `None`)
  - `health.criteria(h) -> dict[str, bool | None]`; `health.row_green(crit: dict) -> bool`
  - `health.skip_streaks(ledger)`, `degraded_consumers(ledger)`, `stood_down(ledger)`, `no_work(ledger)`, `resolver_defects(ledger)`
  - `health.skip_streak_lines(h)`, `degraded_consumer_lines(h)`, `stood_down_lines(h)`, `no_work_lines(h)`, `resolver_defect_lines(h) -> list[str]` (line shapes byte-identical to today's `status` output)

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_health.py
"""One snapshot, two readers. `aramid status` renders these signals and the
fleet health row grades them; if they were computed twice they would drift.
Every criterion is exercised in BOTH directions from a real ledger, and the
last test perturbs the snapshot by ADDING a member and asserts the rendered
line and the graded criterion move together."""
import dataclasses
from datetime import datetime, timezone

from aramid import health
from aramid import ledger as ledger_mod
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict
from aramid.pipeline import GateResult

NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc).isoformat()


def _f(fid, tool="semgrep", rule="r", verdict=Verdict.WARN, file="a.py"):
    return Finding(fid, tool, rule, "high", Severity.HIGH, verdict, file, 1, "m", "e",
                   Gate.PRE_PUSH)


def _run(lg, run_id, tools, gate="pre-push", expected=None):
    payload = {"gate": gate, "tools": list(tools)}
    if expected is not None:
        payload["expected"] = list(expected)
    lg.append(Event(EventType.RUN_STARTED, run_id, NOW, payload=payload))


def _consumer(lg, name, state, note, duration_s=0.0):
    lg.append(Event(EventType.CONSUMER_RUN_FINISHED, "d", NOW,
                    payload={"consumer": name, "state": state, "note": note,
                             "duration_s": duration_s, "finding_count": 0}))


def _result(**kw):
    base = dict(exit_code=0, findings=[], degraded=[], new_ids=[], stale_overrides=[],
                run_id="run-1")
    base.update(kw)
    return GateResult(**base)


def _crit(lg, **kw):
    return health.criteria(health.snapshot(None, lg, **kw))


# ------------------------------------------------------ 1. no_skip_streak ---

def test_skip_streak_present_reads_red(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    _run(lg, "p1", ["gitleaks", "semgrep"], expected=["gitleaks", "semgrep"])
    _run(lg, "p2", ["gitleaks"], expected=["gitleaks", "semgrep"])
    h = health.snapshot(None, lg)
    assert h.skip_streaks == {"pre-push": {"semgrep": 1}}
    assert health.criteria(h)["no_skip_streak"] is False
    assert health.skip_streak_lines(h) == ["  semgrep: skipped last 1 pre-push run(s)"]
    lg.close()


def test_every_expected_tool_ran_reads_green(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    _run(lg, "p1", ["gitleaks", "semgrep"], expected=["gitleaks", "semgrep"])
    _run(lg, "p2", ["gitleaks", "semgrep"], expected=["gitleaks", "semgrep"])
    h = health.snapshot(None, lg)
    assert h.skip_streaks == {}
    assert health.criteria(h)["no_skip_streak"] is True
    assert health.skip_streak_lines(h) == []
    lg.close()


# --------------------------------------------------- 2. consumers_healthy ---

def test_degraded_streak_reads_red(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    _consumer(lg, "fuzz", "ok", "0 crash finding(s)")
    _consumer(lg, "fuzz", "degraded", "fuzz driver broken @ abc: boom")
    _consumer(lg, "fuzz", "degraded", "fuzz driver broken @ abc: boom")
    h = health.snapshot(None, lg)
    assert h.degraded_consumers == (health.ConsumerFault("fuzz", 2, 0.0,
                                                         "fuzz driver broken @ abc: boom"),)
    assert health.criteria(h)["consumers_healthy"] is False
    assert health.degraded_consumer_lines(h) == [
        "  degraded consumer runs:",
        "    fuzz: degraded last 2 run(s) -- fuzz driver broken @ abc: boom"]
    lg.close()


def test_stood_down_reads_red_and_counts_the_give_up_run(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    for _ in range(3):
        _consumer(lg, "mutation", "degraded", "baseline timeout: x", duration_s=100.0)
    _consumer(lg, "mutation", "ok", "mutation giving up: nope", duration_s=0.0)
    h = health.snapshot(None, lg)
    assert h.stood_down == (health.ConsumerFault("mutation", 4, 300.0,
                                                 "mutation giving up: nope"),)
    assert health.criteria(h)["consumers_healthy"] is False
    assert health.stood_down_lines(h) == [
        "  consumers stood down:",
        "    mutation: stood down after 4 run(s), 300s spent -- mutation giving up: nope"]
    lg.close()


def test_no_work_streak_reads_red(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    for _ in range(2):
        _consumer(lg, "mutation", "ok", "no mutants tested: 18 generated, 0 certified",
                  duration_s=10.0)
    h = health.snapshot(None, lg)
    assert h.no_work == (health.ConsumerFault(
        "mutation", 2, 20.0, "no mutants tested: 18 generated, 0 certified"),)
    assert health.criteria(h)["consumers_healthy"] is False
    assert health.no_work_lines(h) == [
        "  consumers doing no work:",
        "    mutation: 2 run(s) certified nothing, 20s spent -- "
        "no mutants tested: 18 generated, 0 certified"]
    lg.close()


def test_recovered_consumer_reads_green(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    _consumer(lg, "fuzz", "degraded", "boom")
    _consumer(lg, "mutation", "ok", "no mutants tested: 1 generated, 0 certified")
    _consumer(lg, "fuzz", "ok", "0 crash finding(s) from 200 case(s)")
    _consumer(lg, "mutation", "ok", "2 confirmed survivor(s) of 11 mutant(s) tested")
    h = health.snapshot(None, lg)
    assert (h.degraded_consumers, h.stood_down, h.no_work) == ((), (), ())
    assert health.criteria(h)["consumers_healthy"] is True
    lg.close()


# -------------------------------------------------------- 3. resolvers_ok ---

def test_never_ran_resolver_reads_red(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    lg.record_run("r0", NOW, "pre-push", set(), set(),
                  [_f("a" * 64, tool="mutation", rule="bool-swap")])
    ledger_mod.note_yield(lg, "r1", NOW, resolver="evidence_gone", tool="llm-review",
                          considered=0, resolved=0)
    h = health.snapshot(None, lg)
    assert ("gap_addressed", "mutation", "NEVER RAN") in h.resolver_defects
    assert health.criteria(h)["resolvers_ok"] is False
    assert health.resolver_defect_lines(h) == [
        "  resolver defects: 3 (run `aramid resolvers`)",
        "    file_departed/mutation, gap_addressed/mutation, mutant_killed/mutation"]
    lg.close()


def test_blind_resolver_reads_red(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    lg.record_run("r0", NOW, "pre-push", set(), set(),
                  [_f("b" * 64, tool="mutation", rule="bool-swap")])
    for resolver in ("gap_addressed", "file_departed", "mutant_killed"):
        ledger_mod.note_yield(lg, "r1", NOW, resolver=resolver, tool="mutation",
                              considered=0, resolved=0)
    h = health.snapshot(None, lg)
    assert all(v == "BLIND" for _r, _t, v in h.resolver_defects)
    assert health.criteria(h)["resolvers_ok"] is False
    lg.close()


def test_healthy_resolvers_read_green(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    ledger_mod.note_yield(lg, "r1", NOW, resolver="evidence_gone", tool="llm-review",
                          considered=0, resolved=0)
    h = health.snapshot(None, lg)
    assert h.resolver_defects == ()
    assert health.criteria(h)["resolvers_ok"] is True
    assert health.resolver_defect_lines(h) == []
    lg.close()


# ------------------------------------------ 4. no_self_inflicted_block ------

def test_a_crashed_block_tier_tool_reads_red(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    h = health.snapshot(None, lg, _result(exit_code=1, degraded=["semgrep"],
                                          degraded_block_tier=True), gate=Gate.PRE_PUSH)
    assert h.bad_tools == ("semgrep",)
    assert health.criteria(h)["no_self_inflicted_block"] is False
    lg.close()


def test_a_block_on_a_genuine_finding_reads_green(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    h = health.snapshot(None, lg, _result(exit_code=1,
                                          findings=[_f("s1", tool="gitleaks",
                                                       verdict=Verdict.BLOCK)]),
                        gate=Gate.PRE_PUSH)
    assert h.blocking == 1 and h.exit_code == 1
    assert health.criteria(h)["no_self_inflicted_block"] is True
    lg.close()


def test_engine_error_reads_every_criterion_red_and_audit_null(tmp_path):
    h = health.snapshot(None, None, None, gate=Gate.PRE_PUSH, engine_error=True)
    assert health.criteria(h) == {"no_skip_streak": False, "consumers_healthy": False,
                                  "resolvers_ok": False, "no_self_inflicted_block": False,
                                  "dep_audit_ran": None}
    assert h.exit_code == 3 and h.engine_error is True


# ---------------------------------------------------------- 5. dep_audit_ran

def test_pip_audit_ran_on_a_python_repo_at_pre_push_reads_true(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    res = _result(tools_ran=("gitleaks", "pip-audit", "semgrep"), stacks=("python",))
    assert _crit(lg, result=res, gate=Gate.PRE_PUSH)["dep_audit_ran"] is True
    lg.close()


def test_pip_audit_missing_on_a_python_repo_at_pre_push_reads_false(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    res = _result(tools_ran=("gitleaks", "semgrep"), stacks=("python",))
    assert _crit(lg, result=res, gate=Gate.PRE_PUSH)["dep_audit_ran"] is False
    lg.close()


def test_pip_audit_not_expected_reads_null(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    py = _result(tools_ran=("gitleaks", "ruff"), stacks=("python",))
    js = _result(tools_ran=("gitleaks", "semgrep"), stacks=("js",))
    assert _crit(lg, result=py, gate=Gate.PRE_COMMIT)["dep_audit_ran"] is None
    assert _crit(lg, result=js, gate=Gate.PRE_PUSH)["dep_audit_ran"] is None
    assert _crit(lg)["dep_audit_ran"] is None
    lg.close()


# ------------------------------------------------------------ row_green -----

def test_row_green_table():
    green = {k: True for k in health.CRITERIA}
    assert health.row_green(green) is True
    assert health.row_green({**green, "dep_audit_ran": None}) is True
    assert health.row_green({**green, "dep_audit_ran": False}) is False
    for key in health.CRITERIA[:4]:
        assert health.row_green({**green, key: False}) is False
    assert health.row_green({}) is False


# ------------------------------------- two computations that must agree -----

def test_status_line_and_criterion_move_together(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    clean = health.snapshot(None, lg)
    assert health.criteria(clean)["consumers_healthy"] is True
    assert health.stood_down_lines(clean) == []

    # Perturb by ADDING a member, never by breaking one.
    perturbed = dataclasses.replace(
        clean, stood_down=(health.ConsumerFault("dast", 3, 9.0, "dast giving up: x"),))
    assert health.criteria(perturbed)["consumers_healthy"] is False
    assert health.stood_down_lines(perturbed) == [
        "  consumers stood down:",
        "    dast: stood down after 3 run(s), 9s spent -- dast giving up: x"]
    lg.close()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_health.py -q -p no:cacheprovider`
Expected: `ModuleNotFoundError: No module named 'aramid.health'`.

- [ ] **Step 3: Create `src/aramid/health.py`**

The five compute functions are the bodies of `status._skip_streak_lines`, `_consumer_health_lines`, `_stood_down_lines`, `_no_work_lines`, `_resolver_defect_lines` with the rendering split off. Move their docstrings with them (they carry the history: the per-gate scoping, the `expected` fallback, the give-up and no-work markers). The code:

```python
"""health -- one snapshot of a repo's gate health, computed once and read
everywhere. Spec: docs/superpowers/specs/2026-09-02-aramid-fleet-readiness-
design.md, sections 4 and 5.

`aramid status` prints skip streaks, degraded / stood-down / no-work consumer
streaks and resolver defects; the fleet health row (aramid.fleet) grades the
same five signals as booleans. Two computations of one fact drift, so both
surfaces read ONE `Health` built here: `status`'s `_x_lines` render from it,
`criteria()` grades it, and tests/unit/test_health.py perturbs a snapshot
and asserts the line and the grade move together.

Pure computation over a ledger plus, optionally, one `GateResult`. Every
ledger-derived signal degrades to "nothing found" on a ledger-shaped fault,
the way `status` already did -- a broken diagnostic must not take down the
report, and must not take down the gate that records the row.
"""
from collections import defaultdict
from dataclasses import dataclass, field

from aramid import config as config_mod
from aramid import yield_report
from aramid.models import EventType, Gate, Verdict
from aramid.pipeline import GATE_RUNNER_KEYS
from aramid.runners.deps import NAME_PIP_AUDIT

CRITERIA = ("no_skip_streak", "consumers_healthy", "resolvers_ok",
            "no_self_inflicted_block", "dep_audit_ran")

# A give-up note's shared marker. Every consumer that stands down says
# "giving up" (mutation, js mutation, llm_review, fuzz, dast), so one marker
# reaches all of them -- and a consumer that invents different wording simply
# goes unreported here rather than breaking anything.
_GIVE_UP_MARK = "giving up"
# A run that finished cleanly and certified nothing. Distinct from a give-up:
# the consumer has NOT stopped, it will run again next drain and burn the same
# time again. `degraded` would pin the queue item, so these runs are
# legitimately `ok` and would otherwise be invisible.
_NO_WORK_MARKS = ("no mutants tested", "no cases run")


@dataclass(frozen=True)
class ConsumerFault:
    name: str
    count: int          # streak length, or runs since the last real one
    spent_s: float
    note: str


@dataclass(frozen=True)
class Health:
    skip_streaks: dict = field(default_factory=dict)   # gate -> {tool: streak}, > 0 only
    degraded_consumers: tuple = ()
    stood_down: tuple = ()
    no_work: tuple = ()
    resolver_defects: tuple = ()                       # (resolver, tool, verdict)
    open: int = 0
    armed: dict = field(default_factory=dict)
    # Per-run facts; meaningful only when built from a GateResult or an
    # engine error.
    gate: str | None = None
    run_id: str | None = None
    exit_code: int | None = None
    blocking: int = 0
    bad_tools: tuple = ()
    degraded_block_tier: bool = False
    engine_error: bool = False
    dep_audit_ran: bool | None = None


# --- the five ledger signals -------------------------------------------------

def skip_streaks(ledger) -> dict[str, dict[str, int]]:
    """For every tool eligible for a gate, how many of that gate's most recent
    consecutive runs it was ABSENT from. (Move status._skip_streak_lines's
    full docstring here: per-gate scoping, the `expected` fallback rule and
    why the observed-universe rule must not be reintroduced.)"""
    runs = [e for e in ledger.events() if e.type is EventType.RUN_STARTED]
    if not runs:
        return {}
    by_gate: dict[str, list] = defaultdict(list)
    for e in runs:
        by_gate[str(e.payload.get("gate", "?"))].append(e)
    out: dict[str, dict[str, int]] = {}
    for gate in sorted(by_gate):
        gate_runs = by_gate[gate]
        expected: set[str] | None = None
        for e in reversed(gate_runs):
            if "expected" in e.payload:
                expected = {str(t) for t in (e.payload.get("expected") or ())}
                break
        if expected is None:
            expected = set()
            for e in gate_runs:
                expected.update(e.payload.get("tools", []))
        streaks: dict[str, int] = {}
        for tool in sorted(expected):
            streak = 0
            for e in reversed(gate_runs):
                if tool in e.payload.get("tools", []):
                    break
                streak += 1
            if streak:
                streaks[tool] = streak
        if streaks:
            out[gate] = streaks
    return out


def _consumer_runs(ledger) -> dict[str, list[tuple[str, str, float]]]:
    runs: dict[str, list[tuple[str, str, float]]] = defaultdict(list)
    for e in ledger.events():
        if e.type is EventType.CONSUMER_RUN_FINISHED:
            runs[str(e.payload.get("consumer", "?"))].append(
                (str(e.payload.get("state", "")),
                 str(e.payload.get("note", "")),
                 float(e.payload.get("duration_s") or 0.0)))
    return runs


def _degraded(runs) -> list[ConsumerFault]:
    faults = []
    for name in sorted(runs):
        streak, note = 0, ""
        for state, run_note, _duration in reversed(runs[name]):
            if state not in ("degraded", "error"):
                break
            streak += 1
            note = note or run_note
        if streak:
            faults.append(ConsumerFault(name, streak, 0.0, note))
    return faults


def _stood_down(runs) -> list[ConsumerFault]:
    faults = []
    for name in sorted(runs):
        seq = runs[name]
        if not seq or _GIVE_UP_MARK not in seq[-1][1]:
            continue
        count, spent = 0, 0.0
        for state, run_note, duration in reversed(seq):
            if state not in ("degraded", "error") and _GIVE_UP_MARK not in run_note:
                break
            count += 1
            spent += duration
        faults.append(ConsumerFault(name, count, spent, seq[-1][1]))
    return faults


def _certified_nothing(note: str) -> bool:
    return any(mark in note for mark in _NO_WORK_MARKS)


def _no_work(runs) -> list[ConsumerFault]:
    faults = []
    for name in sorted(runs):
        seq = runs[name]
        if not seq or not _certified_nothing(seq[-1][1]):
            continue
        count, spent = 0, 0.0
        for _state, note, duration in reversed(seq):
            if not _certified_nothing(note):
                break
            count += 1
            spent += duration
        faults.append(ConsumerFault(name, count, spent, seq[-1][1]))
    return faults


def degraded_consumers(ledger) -> list[ConsumerFault]:
    """Consumers stuck in `degraded`, as a STREAK. (Move
    status._consumer_health_lines's docstring here.)"""
    try:
        return _degraded(_consumer_runs(ledger))
    except Exception:
        return []


def stood_down(ledger) -> list[ConsumerFault]:
    """Consumers that have permanently STOPPED. (Move
    status._stood_down_lines's docstring here.)"""
    try:
        return _stood_down(_consumer_runs(ledger))
    except Exception:
        return []


def no_work(ledger) -> list[ConsumerFault]:
    """Consumers that keep finishing cleanly while certifying nothing. (Move
    status._no_work_lines's docstring here.)"""
    try:
        return _no_work(_consumer_runs(ledger))
    except Exception:
        return []


def resolver_defects(ledger) -> list[tuple[str, str, str]]:
    """Every resolver `aramid resolvers` flags, as (resolver, tool, verdict).
    Never raises: a broken diagnostic must not take down its readers."""
    try:
        rows = yield_report.collect(ledger)
    except Exception:
        return []
    return sorted((r.resolver, r.tool, r.verdict) for r in rows if r.flagged)


# --- the snapshot -------------------------------------------------------------

def _dep_audit_ran(gate, result, tools_ran: set[str]) -> bool | None:
    """Tri-state (spec section 4, criterion 5). None: the deps runner is not
    part of this gate, or this is not a Python repo. True: pip-audit
    finished OK -- `runners.deps.run_python` returns MISSING when it finds no
    requirements file, so OK already means at least one file was audited
    (`RunnerResult.examined` is None for this runner; there is nothing
    further to check). False otherwise -- and a pyproject-only Python repo
    lands here on every pre-push, which is the open `aramid doctor` lead
    this criterion exists to keep visible until it is fixed."""
    if gate is None or result is None:
        return None
    try:
        keys = GATE_RUNNER_KEYS.get(Gate(str(gate)), ())
    except ValueError:
        return None
    if "deps" not in keys or "python" not in (getattr(result, "stacks", ()) or ()):
        return None
    return NAME_PIP_AUDIT in tools_ran


def snapshot(cfg, ledger, result=None, *, gate=None, engine_error: bool = False) -> Health:
    """THE health computation. `cfg` None -> no armed flags known; `ledger`
    None -> no ledger signals (the engine-error path where the ledger never
    opened); `result` None -> no per-run facts. `engine_error` marks a run
    that died before it produced a result: every criterion reads red except
    the audit, which reads unknown."""
    armed = config_mod.arming_state(cfg) if cfg is not None else {}
    streaks: dict = {}
    degraded: list = []
    down: list = []
    idle: list = []
    defects: list = []
    open_n = 0
    if ledger is not None:
        try:
            streaks = skip_streaks(ledger)
        except Exception:
            streaks = {}
        try:
            runs = _consumer_runs(ledger)
        except Exception:
            runs = {}
        degraded, down, idle = _degraded(runs), _stood_down(runs), _no_work(runs)
        defects = resolver_defects(ledger)
        try:
            open_n = sum(1 for rec in ledger.open_findings().values()
                         if rec.get("status") == "open")
        except Exception:
            open_n = 0
    base = dict(skip_streaks=streaks, degraded_consumers=tuple(degraded),
                stood_down=tuple(down), no_work=tuple(idle),
                resolver_defects=tuple(defects), open=open_n, armed=armed,
                gate=str(gate) if gate is not None else None,
                engine_error=engine_error)
    if engine_error or result is None:
        return Health(**base, exit_code=3 if engine_error else None)
    tools_ran = {str(t) for t in (getattr(result, "tools_ran", ()) or ())}
    return Health(**base,
                  run_id=str(getattr(result, "run_id", "") or "") or None,
                  exit_code=result.exit_code,
                  blocking=sum(1 for f in result.findings if f.verdict is Verdict.BLOCK),
                  bad_tools=tuple(result.degraded),
                  degraded_block_tier=bool(result.degraded_block_tier),
                  dep_audit_ran=_dep_audit_ran(gate, result, tools_ran))


def criteria(h: Health) -> dict:
    """The five per-row criteria (spec section 4), keyed as the row records
    them. A block on a GENUINE finding is green for criterion 4 -- that is the
    gate working; only aramid's own machinery failing (a BLOCK-tier tool
    missing/crashed/timed out, or an engine error) is red."""
    if h.engine_error:
        return {"no_skip_streak": False, "consumers_healthy": False,
                "resolvers_ok": False, "no_self_inflicted_block": False,
                "dep_audit_ran": None}
    return {
        "no_skip_streak": not h.skip_streaks,
        "consumers_healthy": not (h.degraded_consumers or h.stood_down or h.no_work),
        "resolvers_ok": not h.resolver_defects,
        "no_self_inflicted_block": not h.degraded_block_tier,
        "dep_audit_ran": h.dep_audit_ran,
    }


def row_green(crit: dict) -> bool:
    """Green when criteria 1-4 are true and 5 is true or null."""
    return (all(crit.get(k) is True for k in CRITERIA[:4])
            and crit.get("dep_audit_ran") in (True, None))


# --- rendering, byte-identical to what `status` printed before this module --

def skip_streak_lines(h: Health) -> list[str]:
    return [f"  {tool}: skipped last {streak} {gate} run(s)"
            for gate in sorted(h.skip_streaks)
            for tool, streak in sorted(h.skip_streaks[gate].items())]


def degraded_consumer_lines(h: Health) -> list[str]:
    faults = [f"    {f.name}: degraded last {f.count} run(s)"
              + (f" -- {f.note}" if f.note else "")
              for f in h.degraded_consumers]
    return ["  degraded consumer runs:", *faults] if faults else []


def stood_down_lines(h: Health) -> list[str]:
    faults = [f"    {f.name}: stood down after {f.count} run(s), "
              f"{f.spent_s:.0f}s spent -- {f.note}"
              for f in h.stood_down]
    return ["  consumers stood down:", *faults] if faults else []


def no_work_lines(h: Health) -> list[str]:
    faults = [f"    {f.name}: {f.count} run(s) certified nothing, "
              f"{f.spent_s:.0f}s spent -- {f.note}"
              for f in h.no_work]
    return ["  consumers doing no work:", *faults] if faults else []


def resolver_defect_lines(h: Health) -> list[str]:
    if not h.resolver_defects:
        return []
    names = ", ".join(sorted({f"{r}/{t}" for r, t, _v in h.resolver_defects}))
    return [f"  resolver defects: {len(h.resolver_defects)} (run `aramid resolvers`)",
            f"    {names}"]
```

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `python -m pytest tests/unit/test_health.py -q -p no:cacheprovider`
Expected: PASS.

- [ ] **Step 5: Make `status.py` render from the snapshot**

Replace the five function bodies (keep the names: `agent_hook._session_context` imports `_skip_streak_lines` and tests monkeypatch these names) and delete the moved constants `_GIVE_UP_MARK`, `_NO_WORK_MARK`, `_NO_WORK_MARKS`, `_certified_nothing`:

```python
from aramid import health


def _skip_streak_lines(ledger: Ledger) -> list[str]:
    """Rendered from `health.snapshot`; the streak rule and its history live
    in aramid.health.skip_streaks."""
    return health.skip_streak_lines(health.snapshot(None, ledger))


def _consumer_health_lines(ledger: Ledger) -> list[str]:
    return health.degraded_consumer_lines(health.snapshot(None, ledger))


def _stood_down_lines(ledger: Ledger) -> list[str]:
    return health.stood_down_lines(health.snapshot(None, ledger))


def _no_work_lines(ledger: Ledger) -> list[str]:
    return health.no_work_lines(health.snapshot(None, ledger))


def _resolver_defect_lines(ledger: Ledger) -> list[str]:
    return health.resolver_defect_lines(health.snapshot(None, ledger))
```

In `cmd_status`, build one snapshot and render from it (replacing the five `lines.extend(_x_lines(ledger))` calls and the `streaks = _skip_streak_lines(ledger)` block):

```python
        h = health.snapshot(cfg, ledger)
        lines.extend(health.resolver_defect_lines(h))
        lines.extend(health.degraded_consumer_lines(h))
        lines.extend(health.stood_down_lines(h))
        lines.extend(health.no_work_lines(h))

        streaks = health.skip_streak_lines(h)
        if streaks:
            lines.append("  per-tool skip streaks:")
            lines.extend(streaks)
```

Remove the now-unused imports from `status.py` (`defaultdict` from `collections`, `yield_report`) and run `python -m ruff check src/aramid/commands/status.py src/aramid/health.py` until clean.

- [ ] **Step 6: Run the status, hook and health suites**

Run: `python -m pytest tests/unit/test_health.py tests/integration/test_status.py tests/integration/test_agent_hook.py tests/unit/test_yield_report.py -q -p no:cacheprovider`
Expected: PASS, every existing status assertion unchanged.

- [ ] **Step 7: Commit**

```bash
git add src/aramid/health.py src/aramid/commands/status.py tests/unit/test_health.py
python -P -m aramid check --staged
git commit -F <scratchpad>/msg-task3.txt
```

Message: `refactor(status): one Health snapshot, rendered by status and graded for the fleet row` -- body: why the two surfaces share one computation, and the criterion-5 decision (pip-audit presence in `tools_ran`, python stack, deps gate).

---
### Task 4: Health rows -- build, append, read, and the budgeted fail-open `record_health`

**Files:**
- Modify: `src/aramid/fleet.py` (append after `load_policy`)
- Test: `tests/unit/test_fleet_rows.py`

**Interfaces:**
- Consumes: `health.snapshot`, `health.criteria`, `health.Health` (Task 3); `fingerprint.normalize_path`.
- Produces: `fleet.PUSH_BUDGET_S = 2.0`; `fleet._monotonic` (module attribute, `time.monotonic`, the budget seam); `fleet.repo_key(root) -> str`; `fleet.build_row(root, h, *, aramid_version, now) -> dict`; `fleet.append_line(path, obj) -> None`; `fleet.append_row(row, path=None) -> None`; `fleet.read_rows(path=None) -> list[dict]`; `fleet.record_health(root, cfg, ledger, result, *, gate, aramid_version, now, engine_error=False) -> None`.
- Row shape (spec section 3.1), keys exactly: `schema_version, at, repo, name, aramid_version, gate, run_id, exit_code, engine_error, criteria, evidence`; `evidence` keys exactly: `skip_streaks, degraded_consumers, stood_down, no_work, resolver_defects, bad_tools, degraded_block_tier, armed, open, blocking`. `resolver_defects` entries are strings `"<resolver>/<tool> <VERDICT>"`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_fleet_rows.py
"""One row per gate run, appended as one line; a store that is missing,
torn, corrupt or newer reads as what it can, with one stderr note; and the
push never raises and never exceeds its budget."""
import json
from pathlib import Path

from aramid import fleet, health
from aramid.fingerprint import normalize_path
from aramid.ledger import Ledger
from aramid.pipeline import GateResult

NOW = "2026-09-03T12:00:00+00:00"


def _result(**kw):
    base = dict(exit_code=0, findings=[], degraded=[], new_ids=[], stale_overrides=[],
                run_id="run-1", tools_ran=("gitleaks", "semgrep"), stacks=("python",))
    base.update(kw)
    return GateResult(**base)


def test_build_row_has_exactly_the_spec_shape(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    h = health.snapshot(None, lg, _result(), gate="pre-push")
    row = fleet.build_row(tmp_path, h, aramid_version="0.9.0", now=NOW)
    assert set(row) == {"schema_version", "at", "repo", "name", "aramid_version", "gate",
                        "run_id", "exit_code", "engine_error", "criteria", "evidence"}
    assert set(row["evidence"]) == {"skip_streaks", "degraded_consumers", "stood_down",
                                    "no_work", "resolver_defects", "bad_tools",
                                    "degraded_block_tier", "armed", "open", "blocking"}
    assert row["schema_version"] == 1
    assert row["repo"] == normalize_path(str(tmp_path.resolve()))
    assert row["name"] == tmp_path.resolve().name
    assert (row["gate"], row["run_id"], row["exit_code"]) == ("pre-push", "run-1", 0)
    assert row["engine_error"] is False
    assert row["criteria"] == {"no_skip_streak": True, "consumers_healthy": True,
                               "resolvers_ok": True, "no_self_inflicted_block": True,
                               "dep_audit_ran": False}
    assert row["evidence"]["armed"] == {}
    lg.close()


def test_append_then_read_round_trips_in_order(tmp_path):
    fleet.append_row({"schema_version": 1, "at": "a", "repo": "r", "criteria": {}, "n": 1})
    fleet.append_row({"schema_version": 1, "at": "b", "repo": "r", "criteria": {}, "n": 2})
    assert [r["n"] for r in fleet.read_rows()] == [1, 2]
    raw = fleet.health_path().read_bytes()
    assert raw.count(b"\n") == 2 and b"\r\n" not in raw


def test_read_rows_on_a_missing_store_is_empty(capsys):
    assert fleet.read_rows() == []
    assert capsys.readouterr().err == ""


def test_read_rows_skips_garbage_and_torn_lines_with_one_note(capsys):
    p = fleet.health_path()
    p.parent.mkdir(parents=True)
    good = json.dumps({"schema_version": 1, "at": "a", "repo": "r", "criteria": {}})
    p.write_text("not json\n" + good + "\n" + good[:20], encoding="utf-8")
    rows = fleet.read_rows()
    assert len(rows) == 1
    err = capsys.readouterr().err
    assert err == "aramid: fleet: skipped 2 unreadable row(s) in fleet_health.jsonl\n"


def test_read_rows_ignores_newer_schema_rows_with_one_note(capsys):
    p = fleet.health_path()
    p.parent.mkdir(parents=True)
    newer = json.dumps({"schema_version": 2, "at": "a", "repo": "r", "criteria": {}})
    good = json.dumps({"schema_version": 1, "at": "a", "repo": "r", "criteria": {}})
    p.write_text(newer + "\n" + good + "\n", encoding="utf-8")
    assert len(fleet.read_rows()) == 1
    assert capsys.readouterr().err == \
        "aramid: fleet: ignored 1 row(s) newer than schema 1 in fleet_health.jsonl\n"


def test_record_health_appends_one_row(tmp_path):
    lg = Ledger(tmp_path / "l.db")
    fleet.record_health(tmp_path, None, lg, _result(), gate="pre-push",
                        aramid_version="0.9.0", now=NOW)
    rows = fleet.read_rows()
    assert len(rows) == 1 and rows[0]["run_id"] == "run-1" and rows[0]["at"] == NOW
    lg.close()


def test_record_health_engine_error_row(tmp_path):
    fleet.record_health(tmp_path, None, None, None, gate="pre-push",
                        aramid_version="0.9.0", now=NOW, engine_error=True)
    (row,) = fleet.read_rows()
    assert row["engine_error"] is True and row["exit_code"] == 3
    assert row["criteria"] == {"no_skip_streak": False, "consumers_healthy": False,
                               "resolvers_ok": False, "no_self_inflicted_block": False,
                               "dep_audit_ran": None}


def test_record_health_fails_open_when_the_store_cannot_be_appended(tmp_path, capsys):
    fleet.health_path().mkdir(parents=True)          # a DIRECTORY where the file goes
    lg = Ledger(tmp_path / "l.db")
    fleet.record_health(tmp_path, None, lg, _result(), gate="pre-push",
                        aramid_version="0.9.0", now=NOW)   # must not raise
    err = capsys.readouterr().err
    assert err.startswith("aramid: fleet: health row not recorded (")
    lg.close()


def test_record_health_skips_the_row_over_budget(tmp_path, monkeypatch, capsys):
    ticks = iter([0.0, 5.0, 5.0])
    monkeypatch.setattr(fleet, "_monotonic", lambda: next(ticks))
    lg = Ledger(tmp_path / "l.db")
    fleet.record_health(tmp_path, None, lg, _result(), gate="pre-push",
                        aramid_version="0.9.0", now=NOW)
    assert fleet.read_rows() == []
    assert capsys.readouterr().err == \
        "aramid: fleet: health row not recorded (over the 2s budget)\n"
    lg.close()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_fleet_rows.py -q -p no:cacheprovider`
Expected: `AttributeError: module 'aramid.fleet' has no attribute 'build_row'` (and siblings).

- [ ] **Step 3: Append the row layer to `src/aramid/fleet.py`**

Add to the imports: `import json`, `import time`, `from aramid import health as health_mod`, `from aramid.fingerprint import normalize_path`. Then:

```python
PUSH_BUDGET_S = 2.0
_monotonic = time.monotonic     # seam for the budget tests


def repo_key(root) -> str:
    """The registry's own key for a repo -- resolved, forward slashes,
    casefolded -- so a row and a registry entry compare equal."""
    return normalize_path(str(Path(root).resolve()))


def build_row(root, h: health_mod.Health, *, aramid_version: str, now: str) -> dict:
    """Spec section 3.1, exactly. Every row carries the full `armed` dict:
    arming is an aramid.toml edit, not a ledger event, so the SEQUENCE of
    rows is the only place a disarm is observable (criterion 6)."""
    return {
        "schema_version": SCHEMA_VERSION,
        "at": now,
        "repo": repo_key(root),
        "name": Path(root).resolve().name,
        "aramid_version": aramid_version,
        "gate": h.gate,
        "run_id": h.run_id,
        "exit_code": h.exit_code,
        "engine_error": h.engine_error,
        "criteria": health_mod.criteria(h),
        "evidence": {
            "skip_streaks": {g: dict(t) for g, t in h.skip_streaks.items()},
            "degraded_consumers": [f.name for f in h.degraded_consumers],
            "stood_down": [f.name for f in h.stood_down],
            "no_work": [f.name for f in h.no_work],
            "resolver_defects": [f"{r}/{t} {v}" for r, t, v in h.resolver_defects],
            "bad_tools": list(h.bad_tools),
            "degraded_block_tier": h.degraded_block_tier,
            "armed": dict(h.armed),
            "open": h.open,
            "blocking": h.blocking,
        },
    }


def append_line(path: Path, obj: dict) -> None:
    """One write of one newline-terminated line in O_APPEND mode: concurrent
    gates in different repos interleave WHOLE lines. O_BINARY on Windows,
    or the C runtime turns the newline into CRLF."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(obj, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def append_row(row: dict, path: Path | None = None) -> None:
    append_line(path if path is not None else health_path(), row)


def _read_jsonl(path: Path, required: tuple[str, ...]) -> list[dict]:
    """Tolerant reader shared by the rows and the notices: unreadable lines
    (a torn trailing write, garbage) are skipped, rows newer than this
    schema are ignored, and each class gets ONE stderr note per read."""
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"aramid: fleet: {path} unreadable ({exc}); treating as empty",
              file=sys.stderr)
        return []
    out, skipped, newer = [], 0, 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        version = obj.get("schema_version") if isinstance(obj, dict) else None
        if not isinstance(version, int) or isinstance(version, bool):
            skipped += 1
            continue
        if version > SCHEMA_VERSION:
            newer += 1
            continue
        if any(not isinstance(obj.get(k), (str, dict)) for k in required):
            skipped += 1
            continue
        out.append(obj)
    if skipped:
        print(f"aramid: fleet: skipped {skipped} unreadable row(s) in {path.name}",
              file=sys.stderr)
    if newer:
        print(f"aramid: fleet: ignored {newer} row(s) newer than schema "
              f"{SCHEMA_VERSION} in {path.name}", file=sys.stderr)
    return out


def read_rows(path: Path | None = None) -> list[dict]:
    return _read_jsonl(path if path is not None else health_path(),
                       required=("at", "repo", "criteria"))


def record_health(root, cfg, ledger, result, *, gate, aramid_version: str, now: str,
                  engine_error: bool = False) -> None:
    """The push seam (spec section 5). Called by `cmd_check` after the report
    is printed. NEVER raises and never touches the exit code: any failure --
    a read-only home, a full disk, a store that is a directory, a ledger
    that will not walk -- is one stderr line. Over budget the row is SKIPPED,
    never written partially: a torn row would read as a repo that went
    quiet, which is a different lie."""
    started = _monotonic()
    try:
        h = health_mod.snapshot(cfg, ledger, result, gate=gate, engine_error=engine_error)
        if _monotonic() - started > PUSH_BUDGET_S:
            print(f"aramid: fleet: health row not recorded "
                  f"(over the {PUSH_BUDGET_S:.0f}s budget)", file=sys.stderr)
            return
        append_row(build_row(root, h, aramid_version=aramid_version, now=now))
    except Exception as exc:
        print(f"aramid: fleet: health row not recorded ({exc})", file=sys.stderr)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/unit/test_fleet_rows.py tests/unit/test_fleet_store.py -q -p no:cacheprovider`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/fleet.py tests/unit/test_fleet_rows.py
python -P -m aramid check --staged
git commit -F <scratchpad>/msg-task4.txt
```

Message: `feat(fleet): health rows -- append-only store and the budgeted, fail-open push`.

---

### Task 5: Push seam in `cmd_check`

**Files:**
- Modify: `src/aramid/commands/check.py:80-87` (imports) and `:224-229` (the print / return and the mid-run `except`)
- Test: `tests/integration/test_check_fleet.py`

**Interfaces:**
- Consumes: `fleet.record_health` (Task 4), `aramid.__version__`.
- Produces: a row per recording `cmd_check` run; an `engine_error: true` row on the mid-run engine-error path; nothing on `record=False`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/integration/test_check_fleet.py
"""`aramid check` pushes its repo's health row after printing its report.
The row is evidence, so a `--no-record` snapshot run writes none; the store
is machine state, so a broken one changes nothing about the gate's answer."""
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import aramid
from aramid import config as config_mod
from aramid import fleet, pipeline
from aramid.commands.check import cmd_check
from aramid.models import Gate
from aramid.runners.base import RunnerResult, ToolState


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path, name="r") -> Path:
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "a.py")
    _git(r, "commit", "-q", "-m", "initial")
    return r


@pytest.fixture
def clean_gate(monkeypatch):
    fake = SimpleNamespace(run=lambda ctx: RunnerResult("gitleaks", ToolState.OK),
                           parse=lambda result, ctx: [])
    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks", fake)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["gitleaks"])


def test_a_recording_run_appends_one_row(tmp_path, clean_gate, capsys):
    root = _repo(tmp_path)
    rc = cmd_check(root, Gate.PRE_COMMIT, "staged", as_json=True)
    report = json.loads(capsys.readouterr().out)
    (row,) = fleet.read_rows()
    assert rc == 0
    assert row["repo"] == fleet.repo_key(root)
    assert row["gate"] == "pre-commit"
    assert row["run_id"] == report["run_id"]
    assert row["exit_code"] == 0
    assert row["aramid_version"] == aramid.__version__
    assert row["criteria"]["dep_audit_ran"] is None      # deps never runs at pre-commit


def test_no_record_writes_no_row(tmp_path, clean_gate):
    root = _repo(tmp_path)
    assert cmd_check(root, Gate.PRE_COMMIT, "staged", record=False) == 0
    assert not fleet.health_path().exists()


def test_an_engine_error_mid_run_records_a_red_row_and_still_exits_3(tmp_path, clean_gate,
                                                                     monkeypatch):
    root = _repo(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("injected")
    monkeypatch.setattr(pipeline, "run_gate", boom)
    assert cmd_check(root, Gate.PRE_COMMIT, "staged") == 3
    (row,) = fleet.read_rows()
    assert row["engine_error"] is True and row["exit_code"] == 3
    assert row["criteria"]["no_self_inflicted_block"] is False


def test_a_broken_store_does_not_change_the_exit_code(tmp_path, clean_gate, capsys):
    root = _repo(tmp_path)
    healthy = cmd_check(root, Gate.PRE_COMMIT, "staged")
    capsys.readouterr()
    fleet.health_path().unlink()
    fleet.health_path().mkdir()                       # a directory where the file goes
    broken = cmd_check(root, Gate.PRE_COMMIT, "staged")
    assert broken == healthy == 0
    assert "aramid: fleet: health row not recorded (" in capsys.readouterr().err


def test_subprocess_gate_exits_identically_with_a_broken_store(tmp_path, checkout_env):
    """Spec section 10, as a real child process: the shim's `aramid check`
    with the store unusable must exit exactly as it does with a healthy one.
    Tools are absent from the isolated tools dir, so both arms degrade the
    same way; only the store differs."""
    root = _repo(tmp_path)

    def run(store: Path):
        env = dict(checkout_env)
        env[fleet.FLEET_DIR_ENV] = str(store)
        return subprocess.run([sys.executable, "-P", "-m", "aramid", "check", "--staged"],
                              cwd=root, env=env, capture_output=True, text=True)

    healthy_store = tmp_path / "healthy"
    broken_store = tmp_path / "broken"
    (broken_store / "fleet_health.jsonl").mkdir(parents=True)
    a = run(healthy_store)
    b = run(broken_store)
    assert a.returncode == b.returncode
    assert (healthy_store / "fleet_health.jsonl").is_file()
    assert "aramid: fleet: health row not recorded (" in b.stderr
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/integration/test_check_fleet.py -q -p no:cacheprovider`
Expected: the first test fails with `ValueError: not enough values to unpack` (no rows written); the engine-error and broken-store tests fail the same way.

- [ ] **Step 3: Wire the seam**

Imports in `check.py`: add `from aramid import __version__` and `from aramid import fleet` beside the existing `from aramid import config as config_mod` block. Then replace the tail of the second `try`:

```python
        output = reporter.render_json(result) if as_json else reporter.render_console(result, ledger)
        print(output)
        # Fleet health row (fleet-readiness spec section 5): this repo's own
        # signals, appended to the machine-level store AFTER the report is
        # printed, so a slow or broken store can never delay or hide the
        # verdict. Fail-open inside `record_health`. A `--no-record` run is a
        # snapshot, not evidence, and writes nothing.
        if record:
            fleet.record_health(root, cfg, ledger, result, gate=gate,
                                aramid_version=__version__, now=_now())
        return exit_code
    except Exception as exc:  # engine error mid-run -> exit 3, never a silent 0.
        print(f"aramid: check: engine error: {exc}", file=sys.stderr)
        # The row says the gate died: criteria all red, audit unknown. The
        # ledger may be the thing that broke; `record_health` tolerates that.
        if record:
            fleet.record_health(root, cfg, ledger, None, gate=gate,
                                aramid_version=__version__, now=_now(), engine_error=True)
        return 3
```

The first `except` (config or ledger failed to open) records nothing: there is no config to read armed flags from and no ledger to snapshot, and it already exits 3 loudly.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/integration/test_check_fleet.py tests/integration/test_check.py -q -p no:cacheprovider`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/check.py tests/integration/test_check_fleet.py
python -P -m aramid check --staged
git commit -F <scratchpad>/msg-task5.txt
```

Message: `feat(check): push a fleet health row after every recording gate run`.

---
### Task 6: The notices channel

**Files:**
- Create: `src/aramid/notices.py`
- Test: `tests/unit/test_notices.py`

**Interfaces:**
- Consumes: `fleet.store_dir()`, `fleet.append_line`, `fleet._read_jsonl` (Task 4), `fleet.SCHEMA_VERSION`.
- Produces: `notices.NOTICES_FILE = "notices.jsonl"`; `notices.KINDS = ("readiness-reached", "readiness-broken", "fleet-defect")`; `notices.notices_path() -> Path`; `notices.notice_id(kind, key) -> str`; `notices.read_events(path=None) -> list[dict]`; `notices.append_event(event, path=None)`; `notices.materialize(events) -> dict[str, dict]` (id -> `{"notice": <event>, "acked": bool, "cleared": bool, "shown": {repo: at}}`); `notices.pending(events=None) -> list[dict]` (notice events, oldest first); `notices.pending_count() -> int | None`; `notices.post(kind, key, *, title, body, evidence, now) -> str | None` (the id, or `None` when a pending or acked notice with that id already exists); `notices.clear(nid, *, reason, now) -> bool`; `notices.ack(nid, *, repo, now) -> bool` (False only for an unknown id; idempotent); `notices.mark_shown(nid, *, repo, surface, now)`; `notices.due(repo, now, repeat_hours, events=None) -> list[dict]`; `notices.render_line(n) -> str`.
- Event shapes (spec section 3.3): notice `{"schema_version": 1, "kind": "notice", "id", "notice_kind", "key", "at", "title", "body", "evidence"}`; shown `{"schema_version": 1, "kind": "shown", "id", "at", "repo", "surface"}`; ack `{"schema_version": 1, "kind": "ack", "id", "at", "repo"}`; cleared `{"schema_version": 1, "kind": "cleared", "id", "at", "reason"}`.
- Line shape: `NOTICE <id> <notice_kind>: <title> -- ack: aramid notices ack <id>`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_notices.py
"""aramid's own channel. Event-sourced like the ledger: nothing is rewritten,
'pending' is materialised, and a condition that re-posts maps to the SAME id
so it is deduplicated by construction."""
import hashlib
import json

from aramid import notices

T0 = "2026-09-03T10:00:00+00:00"
T1 = "2026-09-03T11:00:00+00:00"       # +1h
T2 = "2026-09-04T11:00:00+00:00"       # +25h


def _post(key="streak:x", kind="readiness-broken", now=T0, title="t"):
    return notices.post(kind, key, title=title, body="b", evidence={"k": 1}, now=now)


def test_id_is_the_first_12_hex_of_sha256_kind_colon_key():
    expected = hashlib.sha256(b"readiness-broken:run:abc").hexdigest()[:12]
    assert notices.notice_id("readiness-broken", "run:abc") == expected


def test_post_makes_a_pending_notice_with_the_spec_shape():
    nid = _post(key="run:abc")
    (n,) = notices.pending()
    assert n["id"] == nid
    assert set(n) == {"schema_version", "kind", "id", "notice_kind", "key", "at",
                      "title", "body", "evidence"}
    assert (n["kind"], n["notice_kind"], n["key"]) == ("notice", "readiness-broken", "run:abc")
    assert notices.pending_count() == 1


def test_a_second_post_with_the_same_key_is_deduplicated():
    assert _post(key="run:abc") is not None
    assert _post(key="run:abc") is None
    assert notices.pending_count() == 1
    assert sum(1 for e in notices.read_events() if e["kind"] == "notice") == 1


def test_ack_is_idempotent_and_unknown_id_is_refused():
    nid = _post()
    assert notices.ack(nid, repo="f:/p/a", now=T1) is True
    assert notices.ack(nid, repo="f:/p/b", now=T1) is True
    assert notices.pending() == []
    assert sum(1 for e in notices.read_events() if e["kind"] == "ack") == 1
    assert notices.ack("000000000000", repo="f:/p/a", now=T1) is False


def test_an_acked_condition_is_not_re_posted_while_uncleared():
    nid = _post(key="defect:r:resolver:x", kind="fleet-defect")
    notices.ack(nid, repo="f:/p/a", now=T1)
    assert _post(key="defect:r:resolver:x", kind="fleet-defect", now=T1) is None
    assert notices.pending() == []


def test_clear_then_recurrence_re_posts_under_the_same_id():
    nid = _post(key="defect:r:resolver:x", kind="fleet-defect")
    assert notices.clear(nid, reason="defect absent from latest row", now=T1) is True
    assert notices.pending() == []
    assert notices.clear(nid, reason="again", now=T1) is False
    assert _post(key="defect:r:resolver:x", kind="fleet-defect", now=T2) == nid
    (n,) = notices.pending()
    assert n["at"] == T2


def test_due_respects_repeat_hours_per_repo():
    nid = _post()
    assert [n["id"] for n in notices.due("f:/p/a", T0, 24)] == [nid]
    notices.mark_shown(nid, repo="f:/p/a", surface="session-start", now=T0)
    assert notices.due("f:/p/a", T1, 24) == []
    assert [n["id"] for n in notices.due("f:/p/b", T1, 24)] == [nid]
    assert [n["id"] for n in notices.due("f:/p/a", T2, 24)] == [nid]
    shown = [e for e in notices.read_events() if e["kind"] == "shown"]
    assert shown == [{"schema_version": 1, "kind": "shown", "id": nid, "at": T0,
                      "repo": "f:/p/a", "surface": "session-start"}]


def test_read_events_skips_garbage_with_one_note(capsys):
    p = notices.notices_path()
    p.parent.mkdir(parents=True)
    p.write_text("{oops\n" + json.dumps({"schema_version": 1, "kind": "notice", "id": "a" * 12,
                                          "notice_kind": "fleet-defect", "key": "k",
                                          "at": T0, "title": "t", "body": "b",
                                          "evidence": {}}) + "\n", encoding="utf-8")
    assert len(notices.pending()) == 1
    assert capsys.readouterr().err == \
        "aramid: fleet: skipped 1 unreadable row(s) in notices.jsonl\n"


def test_pending_count_is_none_when_the_store_cannot_be_read(monkeypatch):
    def boom(*a, **k):
        raise OSError("locked")
    monkeypatch.setattr(notices, "read_events", boom)
    assert notices.pending_count() is None


def test_render_line_full_shape():
    nid = _post(key="run:abc", title="Atlas_Data went red at 2026-09-03T10:11:00+00:00 "
                                     "(resolvers_ok: file_departed/mutation BLIND)")
    (n,) = notices.pending()
    assert notices.render_line(n) == (
        f"NOTICE {nid} readiness-broken: Atlas_Data went red at "
        f"2026-09-03T10:11:00+00:00 (resolvers_ok: file_departed/mutation BLIND)"
        f" -- ack: aramid notices ack {nid}")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_notices.py -q -p no:cacheprovider`
Expected: `ModuleNotFoundError: No module named 'aramid.notices'`.

- [ ] **Step 3: Create `src/aramid/notices.py`**

```python
"""notices -- aramid's own channel to the operator (fleet-readiness spec
sections 3.3 and 7). Machine-level, under the fleet store, append-only.

Event-sourced like the ledger: `notice`, `shown`, `ack` and `cleared` events
are only ever appended, and "pending" is materialised from them. A notice's
id is derived from its kind and key, so a condition that is judged again
maps to the SAME id and is deduplicated by construction, and an `ack` in one
repo silences it in every repo -- it followed you; you answered it.
"""
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aramid import fleet

SCHEMA_VERSION = fleet.SCHEMA_VERSION
NOTICES_FILE = "notices.jsonl"
KINDS = ("readiness-reached", "readiness-broken", "fleet-defect")


def notices_path() -> Path:
    return fleet.store_dir() / NOTICES_FILE


def notice_id(kind: str, key: str) -> str:
    return hashlib.sha256(f"{kind}:{key}".encode("utf-8")).hexdigest()[:12]


def _parse(at) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(at))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def read_events(path: Path | None = None) -> list[dict]:
    return fleet._read_jsonl(path if path is not None else notices_path(),
                             required=("kind", "id", "at"))


def append_event(event: dict, path: Path | None = None) -> None:
    fleet.append_line(path if path is not None else notices_path(), event)


def materialize(events: list[dict]) -> dict[str, dict]:
    """id -> {"notice", "acked", "cleared", "shown": {repo: at}}. A `notice`
    event for a known id is a RE-POST (only ever written after a `cleared`,
    see `post`) and starts the record over. Events for unknown ids are
    ignored rather than fatal."""
    out: dict[str, dict] = {}
    for e in events:
        kind, nid = e.get("kind"), str(e.get("id"))
        if kind == "notice":
            out[nid] = {"notice": e, "acked": False, "cleared": False, "shown": {}}
            continue
        rec = out.get(nid)
        if rec is None:
            continue
        if kind == "shown":
            rec["shown"][str(e.get("repo", ""))] = str(e.get("at", ""))
        elif kind == "ack":
            rec["acked"] = True
        elif kind == "cleared":
            rec["cleared"] = True
    return out


def _is_pending(rec: dict) -> bool:
    return not rec["acked"] and not rec["cleared"]


def pending(events: list[dict] | None = None) -> list[dict]:
    recs = materialize(read_events() if events is None else events)
    return sorted((r["notice"] for r in recs.values() if _is_pending(r)),
                  key=lambda n: str(n.get("at", "")))


def pending_count() -> int | None:
    """None when the store cannot be read -- the gate's JSON key has to be
    able to say 'unknown' rather than 'none'."""
    try:
        return len(pending())
    except Exception:
        return None


def post(kind: str, key: str, *, title: str, body: str, evidence: dict,
         now: str) -> str | None:
    """Append a notice unless one with this id is pending OR acked: an ack
    means 'I know', and a condition that persists past it must not nag
    again. Only a `cleared` notice (the condition went away) may re-post,
    because then the condition has genuinely come back."""
    nid = notice_id(kind, key)
    rec = materialize(read_events()).get(nid)
    if rec is not None and not rec["cleared"]:
        return None
    append_event({"schema_version": SCHEMA_VERSION, "kind": "notice", "id": nid,
                  "notice_kind": kind, "key": key, "at": now, "title": title,
                  "body": body, "evidence": evidence})
    return nid


def clear(nid: str, *, reason: str, now: str) -> bool:
    rec = materialize(read_events()).get(nid)
    if rec is None or rec["cleared"]:
        return False
    append_event({"schema_version": SCHEMA_VERSION, "kind": "cleared", "id": nid,
                  "at": now, "reason": reason})
    return True


def ack(nid: str, *, repo: str, now: str) -> bool:
    """Idempotent. False only for an id the channel has never seen."""
    rec = materialize(read_events()).get(nid)
    if rec is None:
        return False
    if not rec["acked"]:
        append_event({"schema_version": SCHEMA_VERSION, "kind": "ack", "id": nid,
                      "at": now, "repo": repo})
    return True


def mark_shown(nid: str, *, repo: str, surface: str, now: str) -> None:
    append_event({"schema_version": SCHEMA_VERSION, "kind": "shown", "id": nid,
                  "at": now, "repo": repo, "surface": surface})


def due(repo: str, now: str, repeat_hours: int, events: list[dict] | None = None) -> list[dict]:
    """Pending notices not shown in `repo` within the last `repeat_hours`."""
    recs = materialize(read_events() if events is None else events)
    now_dt = _parse(now)
    out = []
    for rec in recs.values():
        if not _is_pending(rec):
            continue
        last_dt = _parse(rec["shown"].get(repo)) if repo in rec["shown"] else None
        if (last_dt is not None and now_dt is not None
                and now_dt - last_dt < timedelta(hours=repeat_hours)):
            continue
        out.append(rec["notice"])
    return sorted(out, key=lambda n: str(n.get("at", "")))


def render_line(n: dict) -> str:
    return (f"NOTICE {n['id']} {n['notice_kind']}: {n['title']}"
            f" -- ack: aramid notices ack {n['id']}")
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/unit/test_notices.py -q -p no:cacheprovider`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/notices.py tests/unit/test_notices.py
python -P -m aramid check --staged
git commit -F <scratchpad>/msg-task6.txt
```

Message: `feat(notices): aramid's own append-only notice channel`.

---

### Task 7: The judge -- streak and verdict math

**Files:**
- Modify: `src/aramid/fleet.py` (append after `record_health`)
- Test: `tests/unit/test_fleet_judge.py`

**Interfaces:**
- Consumes: `health.CRITERIA`, `health.row_green`; `registry.load_registry`.
- Produces: `fleet.ROW_WINDOW_DAYS = 180`; `fleet.READY = "ready"`, `fleet.NOT_READY = "not-ready"`, `fleet.INSUFFICIENT = "insufficient-data"`; `fleet.registered_repos(entries=None) -> dict[str, str]` (registry key -> display name); `fleet.judge(rows, registered, policy, now, *, aramid_version="") -> dict`.
- Verdict dict (spec section 3.2, plus `criteria` per repo and `blockers` / `breaking_row` under `fleet`):
  ```
  {"schema_version": 1, "computed_at": now, "aramid_version": ..., "policy": {"min_days", "min_versions"},
   "repos": {<key>: {"name", "rows", "latest_at", "green", "red_criteria", "criteria"}},
   "fleet": {"all_green_now", "streak_started_at", "days_held", "versions_in_streak", "armed_anywhere",
             "disarm_in_streak", "blockers": [...], "breaking_row": {"repo","name","at","run_id","red_criteria","detail"} | None},
   "verdict": ..., "reasons": [...]}
  ```
  `reasons` = per-repo red lines (`"<name>: <crit>, <crit>"`), then `"no rows: <names>"`, then the fleet-level `blockers` in this order: `"streak <d>d < <min_days>d"`, `"versions <n>/<min_versions> in streak"`, `"no repo has an armed consumer"`, `"streak restarted by <name> disarming <flag> at <at>"`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_fleet_judge.py
"""Streak and verdict math, table-driven on fixture rows with explicit
timestamps and versions. No sleeps: `now` is an argument."""
from datetime import datetime, timedelta, timezone

from aramid import fleet, health

R_A, R_B = "f:/projects/a", "f:/projects/b"
REG = {R_A: "a", R_B: "b"}
NOW_DT = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
NOW = NOW_DT.isoformat()
POLICY = fleet.Policy(min_days=14, min_versions=2)


def _at(days_ago: float) -> str:
    return (NOW_DT - timedelta(days=days_ago)).isoformat()


def _row(repo, days_ago, version="0.9.0", *, red=(), armed=None, run_id=None,
         dep=None, defects=()):
    crit = {k: True for k in health.CRITERIA}
    crit["dep_audit_ran"] = dep
    for k in red:
        crit[k] = False
    return {"schema_version": 1, "at": _at(days_ago), "repo": repo,
            "name": repo.rsplit("/", 1)[-1], "aramid_version": version,
            "gate": "pre-push", "run_id": run_id or f"{repo[-1]}-{days_ago}",
            "exit_code": 0, "engine_error": False, "criteria": crit,
            "evidence": {"skip_streaks": {}, "degraded_consumers": [], "stood_down": [],
                         "no_work": [], "resolver_defects": list(defects),
                         "bad_tools": [], "degraded_block_tier": False,
                         "armed": dict(armed or {}), "open": 0, "blocking": 0}}


ARMED = {"semgrep_block_armed": True}


def _ready_rows():
    return [_row(R_A, 20, "0.8.0", armed=ARMED), _row(R_B, 20, "0.8.0"),
            _row(R_A, 10, "0.9.0", armed=ARMED), _row(R_B, 10, "0.9.0")]


def test_ready_when_every_condition_holds():
    v = fleet.judge(_ready_rows(), REG, POLICY, NOW, aramid_version="0.9.0")
    assert v["verdict"] == "ready"
    assert v["reasons"] == []
    assert v["fleet"]["streak_started_at"] == _at(20)
    assert v["fleet"]["days_held"] == 20.0
    assert v["fleet"]["versions_in_streak"] == ["0.8.0", "0.9.0"]
    assert v["fleet"]["armed_anywhere"] is True
    assert v["fleet"]["all_green_now"] is True
    assert v["repos"][R_A] == {"name": "a", "rows": 2, "latest_at": _at(10), "green": True,
                               "red_criteria": [],
                               "criteria": {**{k: True for k in health.CRITERIA},
                                            "dep_audit_ran": None}}
    assert v["schema_version"] == 1 and v["computed_at"] == NOW
    assert v["policy"] == {"min_days": 14, "min_versions": 2}


def test_a_red_row_resets_the_streak_and_names_the_criterion():
    rows = _ready_rows() + [_row(R_A, 1, "0.9.0", red=("dep_audit_ran",), armed=ARMED,
                                 run_id="red-run", dep=False)]
    v = fleet.judge(rows, REG, POLICY, NOW)
    assert v["verdict"] == "not-ready"
    assert v["fleet"]["streak_started_at"] is None and v["fleet"]["days_held"] == 0.0
    assert v["reasons"] == ["a: dep_audit_ran"]
    assert v["repos"][R_A]["red_criteria"] == ["dep_audit_ran"]
    assert v["fleet"]["breaking_row"] == {"repo": R_A, "name": "a", "at": _at(1),
                                          "run_id": "red-run",
                                          "red_criteria": ["dep_audit_ran"],
                                          "detail": "dep_audit_ran: pip-audit did not run"}


def test_streak_restarts_on_the_next_green_row():
    rows = _ready_rows() + [_row(R_A, 5, red=("resolvers_ok",), armed=ARMED,
                                 defects=["gap_addressed/mutation NEVER RAN"]),
                            _row(R_A, 2, armed=ARMED)]
    v = fleet.judge(rows, REG, POLICY, NOW)
    assert v["fleet"]["streak_started_at"] == _at(2)
    assert v["verdict"] == "not-ready"
    assert v["reasons"] == ["streak 2.0d < 14d", "versions 1/2 in streak"]


def test_a_registered_repo_without_rows_is_insufficient_data():
    v = fleet.judge(_ready_rows(), {**REG, "f:/projects/c": "c"}, POLICY, NOW)
    assert v["verdict"] == "insufficient-data"
    assert v["reasons"] == ["no rows: c"]
    assert v["fleet"]["streak_started_at"] is None
    assert v["repos"]["f:/projects/c"] == {"name": "c", "rows": 0, "latest_at": None,
                                           "green": False, "red_criteria": [],
                                           "criteria": {}}


def test_versions_count_only_inside_the_streak():
    rows = [_row(R_A, 30, "0.7.0", armed=ARMED), _row(R_B, 30, "0.7.0", red=("no_skip_streak",)),
            _row(R_A, 20, "0.9.0", armed=ARMED), _row(R_B, 20, "0.9.0")]
    v = fleet.judge(rows, REG, POLICY, NOW)
    assert v["fleet"]["streak_started_at"] == _at(20)
    assert v["fleet"]["versions_in_streak"] == ["0.9.0"]
    assert v["verdict"] == "not-ready"
    assert v["reasons"] == ["versions 1/2 in streak"]


def test_min_days_boundary():
    rows = [_row(R_A, 13.9, "0.8.0", armed=ARMED), _row(R_B, 13.9, "0.8.0"),
            _row(R_A, 1, "0.9.0", armed=ARMED)]
    short = fleet.judge(rows, REG, POLICY, NOW)
    assert short["verdict"] == "not-ready" and short["reasons"] == ["streak 13.9d < 14d"]
    rows[0]["at"] = rows[1]["at"] = _at(14)
    assert fleet.judge(rows, REG, POLICY, NOW)["verdict"] == "ready"


def test_no_armed_consumer_anywhere_blocks_readiness():
    rows = [_row(R_A, 20, "0.8.0"), _row(R_B, 20, "0.8.0"), _row(R_A, 1, "0.9.0")]
    v = fleet.judge(rows, REG, POLICY, NOW)
    assert v["fleet"]["armed_anywhere"] is False
    assert v["verdict"] == "not-ready"
    assert v["reasons"] == ["no repo has an armed consumer"]


def test_a_disarm_inside_the_streak_restarts_it_at_that_row():
    rows = _ready_rows() + [_row(R_A, 3, "0.9.0", armed={"semgrep_block_armed": False},
                                 run_id="disarm"),
                            _row(R_B, 2, "0.9.0", armed=ARMED)]
    v = fleet.judge(rows, REG, POLICY, NOW)
    assert v["fleet"]["streak_started_at"] == _at(3)
    assert v["fleet"]["disarm_in_streak"] is True
    assert v["verdict"] == "not-ready"
    assert v["reasons"] == ["streak 3.0d < 14d", "versions 1/2 in streak",
                            "streak restarted by a disarming semgrep_block_armed at " + _at(3)]


def test_rows_older_than_180_days_and_deregistered_repos_are_ignored():
    rows = _ready_rows() + [_row(R_A, 200, red=("consumers_healthy",)),
                            _row("f:/projects/gone", 1, red=("consumers_healthy",))]
    v = fleet.judge(rows, REG, POLICY, NOW)
    assert v["verdict"] == "ready"
    assert v["repos"][R_A]["rows"] == 2
    assert "f:/projects/gone" not in v["repos"]


def test_no_registered_repos_is_insufficient_data():
    v = fleet.judge([], {}, POLICY, NOW)
    assert v["verdict"] == "insufficient-data"
    assert v["reasons"] == ["no repos registered"]


def test_breaking_row_detail_names_every_red_criterion():
    row = _row(R_A, 1, red=("no_skip_streak", "consumers_healthy", "no_self_inflicted_block"),
               armed=ARMED, run_id="bad")
    row["evidence"].update({"skip_streaks": {"pre-push": {"semgrep": 2}},
                            "stood_down": ["mutation"], "bad_tools": ["gitleaks"]})
    v = fleet.judge(_ready_rows() + [row], REG, POLICY, NOW)
    assert v["fleet"]["breaking_row"]["detail"] == (
        "no_skip_streak: pre-push/semgrep x2; consumers_healthy: mutation; "
        "no_self_inflicted_block: gitleaks")


def test_registered_repos_uses_the_registry_key_and_basename(tmp_path):
    entries = [{"path": str(tmp_path / "Atlas_Data"), "registered_at": "t"}]
    assert fleet.registered_repos(entries) == {
        fleet.repo_key(tmp_path / "Atlas_Data"): "Atlas_Data"}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_fleet_judge.py -q -p no:cacheprovider`
Expected: `AttributeError: module 'aramid.fleet' has no attribute 'judge'`.

- [ ] **Step 3: Append the judge to `src/aramid/fleet.py`**

Add imports: `from collections import defaultdict`, `from datetime import datetime, timedelta, timezone`, `from aramid import registry`.

```python
ROW_WINDOW_DAYS = 180
READY, NOT_READY, INSUFFICIENT = "ready", "not-ready", "insufficient-data"


def _parse(at) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(at))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def registered_repos(entries: list[dict] | None = None) -> dict[str, str]:
    """registry key -> display name for every registered repo. The registry
    stores resolved paths, so `repo_key` on them equals the key a gate run
    in that repo writes."""
    entries = registry.load_registry() if entries is None else entries
    return {repo_key(e["path"]): Path(e["path"]).name for e in entries}


def _red_criteria(crit: dict) -> list[str]:
    return [k for k in health_mod.CRITERIA
            if not (crit.get(k) is True or (k == "dep_audit_ran" and crit.get(k) is None))]


def _red_detail(row: dict) -> str:
    """Why a row is red, per criterion, from its own evidence -- so a notice
    can say `(resolvers_ok: file_departed/mutation BLIND)` instead of
    sending the reader to the store."""
    ev = row.get("evidence", {})
    parts = []
    for k in _red_criteria(row.get("criteria", {})):
        if k == "no_skip_streak":
            what = ", ".join(f"{g}/{t} x{n}" for g, tools in sorted((ev.get("skip_streaks") or {}).items())
                             for t, n in sorted(tools.items()))
        elif k == "consumers_healthy":
            what = ", ".join(sorted(set((ev.get("degraded_consumers") or []) + (ev.get("stood_down") or [])
                                        + (ev.get("no_work") or []))))
        elif k == "resolvers_ok":
            what = ", ".join(ev.get("resolver_defects") or [])
        elif k == "no_self_inflicted_block":
            what = "engine error" if row.get("engine_error") else ", ".join(ev.get("bad_tools") or [])
        else:
            what = "pip-audit did not run"
        parts.append(f"{k}: {what}" if what else k)
    return "; ".join(parts)


def judge(rows: list[dict], registered: dict[str, str], policy: Policy, now: str,
          *, aramid_version: str = "") -> dict:
    """Spec section 6. Walk the registered repos' rows in time order,
    tracking each repo's latest row; the fleet is green at a row when every
    registered repo has a row and its latest is green. The streak starts at
    the row that turned the fleet green and resets on any red row -- or on
    a disarm (criterion 6), which restarts it at the disarming row rather
    than pinning the verdict forever."""
    now_dt = _parse(now) or datetime.now(timezone.utc)
    cutoff = now_dt - timedelta(days=ROW_WINDOW_DAYS)
    live = []
    for r in rows:
        at = _parse(r.get("at"))
        if at is None or at < cutoff or r.get("repo") not in registered:
            continue
        live.append((at, r))
    live.sort(key=lambda p: p[0])

    latest: dict[str, dict] = {}
    counts: dict[str, int] = defaultdict(int)
    streak_start: str | None = None
    versions: set[str] = set()
    disarm: dict | None = None
    for _at, r in live:
        repo = r["repo"]
        prev = latest.get(repo)
        latest[repo] = r
        counts[repo] += 1
        if prev is not None and streak_start is not None:
            before = prev.get("evidence", {}).get("armed") or {}
            after = r.get("evidence", {}).get("armed") or {}
            for flag, was in before.items():
                if was and not after.get(flag, False):
                    disarm = {"name": r.get("name") or repo, "flag": flag, "at": r["at"]}
                    streak_start, versions = None, set()
                    break
        green = all(k in latest and health_mod.row_green(latest[k].get("criteria", {}))
                    for k in registered)
        if green:
            if streak_start is None:
                streak_start, versions = r["at"], set()
            versions.add(str(r.get("aramid_version", "")))
        else:
            streak_start, versions, disarm = None, set(), None

    repos_out: dict[str, dict] = {}
    for key, name in sorted(registered.items(), key=lambda kv: kv[1].casefold()):
        row = latest.get(key)
        if row is None:
            repos_out[key] = {"name": name, "rows": 0, "latest_at": None, "green": False,
                              "red_criteria": [], "criteria": {}}
            continue
        crit = dict(row.get("criteria", {}))
        repos_out[key] = {"name": row.get("name") or name, "rows": counts[key],
                          "latest_at": row["at"], "green": health_mod.row_green(crit),
                          "red_criteria": _red_criteria(crit), "criteria": crit}
    missing = sorted((v["name"] for v in repos_out.values() if v["rows"] == 0), key=str.casefold)
    all_green_now = bool(registered) and not missing and all(v["green"] for v in repos_out.values())
    armed_anywhere = any(any((r.get("evidence", {}).get("armed") or {}).values())
                         for r in latest.values())
    days_held = 0.0
    if streak_start is not None:
        start_dt = _parse(streak_start)
        days_held = max(0.0, (now_dt - start_dt).total_seconds() / 86400.0)
    days_held = round(days_held, 2)

    red_rows = [r for r in latest.values() if not health_mod.row_green(r.get("criteria", {}))]
    breaking = None
    if red_rows:
        b = max(red_rows, key=lambda r: str(r.get("at", "")))
        breaking = {"repo": b["repo"], "name": b.get("name") or b["repo"], "at": b["at"],
                    "run_id": b.get("run_id"), "red_criteria": _red_criteria(b.get("criteria", {})),
                    "detail": _red_detail(b)}

    reasons = [f"{v['name']}: {', '.join(v['red_criteria'])}"
               for v in repos_out.values() if v["red_criteria"]]
    blockers: list[str] = []
    if not registered:
        verdict = INSUFFICIENT
        reasons.append("no repos registered")
    elif missing:
        verdict = INSUFFICIENT
        reasons.append("no rows: " + ", ".join(missing))
    elif not all_green_now:
        verdict = NOT_READY
    else:
        if days_held < policy.min_days:
            blockers.append(f"streak {days_held:.1f}d < {policy.min_days}d")
        if len(versions) < policy.min_versions:
            blockers.append(f"versions {len(versions)}/{policy.min_versions} in streak")
        if not armed_anywhere:
            blockers.append("no repo has an armed consumer")
        verdict = READY if not blockers else NOT_READY
        if disarm is not None:
            blockers.append(f"streak restarted by {disarm['name']} disarming "
                            f"{disarm['flag']} at {disarm['at']}")
    reasons.extend(blockers)

    return {"schema_version": SCHEMA_VERSION, "computed_at": now,
            "aramid_version": aramid_version,
            "policy": {"min_days": policy.min_days, "min_versions": policy.min_versions},
            "repos": repos_out,
            "fleet": {"all_green_now": all_green_now, "streak_started_at": streak_start,
                      "days_held": days_held, "versions_in_streak": sorted(versions),
                      "armed_anywhere": armed_anywhere, "disarm_in_streak": disarm is not None,
                      "blockers": blockers, "breaking_row": breaking},
            "verdict": verdict, "reasons": reasons}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/unit/test_fleet_judge.py -q -p no:cacheprovider`
Expected: PASS. If `days_held` rounding makes the boundary test flaky, keep `round(..., 2)` and compare `>=` against `min_days` exactly as written; do not widen the margin.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/fleet.py tests/unit/test_fleet_judge.py
python -P -m aramid check --staged
git commit -F <scratchpad>/msg-task7.txt
```

Message: `feat(fleet): the readiness judge -- streak, versions, arming, verdict`.

---
### Task 8: `run_judgement` -- verdict I/O, transitions, defect notices, compaction, budget

**Files:**
- Modify: `src/aramid/fleet.py` (append after `judge`)
- Test: `tests/unit/test_fleet_judgement.py`

**Interfaces:**
- Consumes: `judge`, `read_rows`, `load_policy`, `registered_repos` (Tasks 4, 7); `notices.post`, `notices.pending`, `notices.clear` (Task 6).
- Produces: `fleet.JUDGE_BUDGET_S = 30.0`; `fleet.COMPACT_EVERY_H = 24`; `fleet.read_verdict(path=None) -> dict | None`; `fleet.write_verdict(v, path=None)`; `fleet.run_judgement(now, *, aramid_version, entries=None, policy=None) -> dict | None`.
- Notice keys and titles:
  - `readiness-reached`, key `streak:<streak_started_at>`, title `1.0 readiness reached -- streak since <start> (<days>d, versions <v1>, <v2>) across <n> repos`.
  - `readiness-broken`, key `run:<run_id of breaking row>` (or `at:<now>` when there is no breaking row, e.g. a repo was added), title `<name> went red at <at> (<detail>)` (or `fleet readiness lost -- <reasons joined by "; ">`).
  - `fleet-defect`, key `defect:<repo key>:<kind>:<name>` with kind in `skip`, `consumer`, `resolver`; title `<name>: <kind> <target> on the last <defect_rows> gate runs`.
- Compaction: rows older than 180 days removed by tmp + `os.replace`, at most once per 24 h, recorded as `compacted_at` in the verdict file.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_fleet_judgement.py
"""The drain-time orchestration: judge, write the verdict atomically, post
exactly one notice per transition or persistent defect, clear what recovers,
compact old rows once a day, and never raise."""
import json
from datetime import datetime, timedelta, timezone

from aramid import fleet, health, notices

NOW_DT = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
NOW = NOW_DT.isoformat()
LATER = (NOW_DT + timedelta(hours=1)).isoformat()
# tests/unit is not a package, so the row helper is repeated here rather
# than imported from test_fleet_judge.py. Keep the two copies identical.
R_A, R_B = "f:/projects/a", "f:/projects/b"
ARMED = {"semgrep_block_armed": True}


def _at(days_ago: float) -> str:
    return (NOW_DT - timedelta(days=days_ago)).isoformat()


def _row(repo, days_ago, version="0.9.0", *, red=(), armed=None, run_id=None,
         dep=None, defects=()):
    crit = {k: True for k in health.CRITERIA}
    crit["dep_audit_ran"] = dep
    for k in red:
        crit[k] = False
    return {"schema_version": 1, "at": _at(days_ago), "repo": repo,
            "name": repo.rsplit("/", 1)[-1], "aramid_version": version,
            "gate": "pre-push", "run_id": run_id or f"{repo[-1]}-{days_ago}",
            "exit_code": 0, "engine_error": False, "criteria": crit,
            "evidence": {"skip_streaks": {}, "degraded_consumers": [], "stood_down": [],
                         "no_work": [], "resolver_defects": list(defects),
                         "bad_tools": [], "degraded_block_tier": False,
                         "armed": dict(armed or {}), "open": 0, "blocking": 0}}
ENTRIES = [{"path": "F:/projects/a", "registered_at": "t"},
           {"path": "F:/projects/b", "registered_at": "t"}]


def _seed(rows):
    for r in rows:
        fleet.append_row(r)


def _ready_rows():
    return [_row(R_A, 20, "0.8.0", armed=ARMED), _row(R_B, 20, "0.8.0"),
            _row(R_A, 10, "0.9.0", armed=ARMED), _row(R_B, 10, "0.9.0")]


def _registered():
    return {fleet.repo_key(e["path"]): "a" if e["path"].endswith("a") else "b"
            for e in ENTRIES}


def _judge(now=NOW):
    # `registered_repos` resolves paths; the fixture rows use the same keys
    # `repo_key` produces for these entries on this machine.
    return fleet.run_judgement(now, aramid_version="0.9.0", entries=ENTRIES)


def _entries_rows(rows):
    keys = list(_registered())
    for r in rows:
        r["repo"] = keys[0] if r["repo"] == R_A else keys[1]
    return rows


def test_first_judgement_writes_the_verdict_file_atomically():
    _seed(_entries_rows(_ready_rows()))
    v = _judge()
    assert v["verdict"] == "ready"
    on_disk = json.loads(fleet.verdict_path().read_text(encoding="utf-8"))
    assert on_disk["verdict"] == "ready" and on_disk["compacted_at"] == NOW
    assert not fleet.verdict_path().with_name("fleet_verdict.json.tmp").exists()
    assert fleet.read_verdict() == on_disk


def test_reaching_readiness_posts_one_notice_and_only_once():
    _seed(_entries_rows(_ready_rows()))
    _judge()
    _judge(LATER)
    (n,) = notices.pending()
    assert n["notice_kind"] == "readiness-reached"
    assert n["key"] == "streak:" + _ready_rows()[0]["at"]
    assert n["title"] == ("1.0 readiness reached -- streak since " + _ready_rows()[0]["at"]
                          + " (20d, versions 0.8.0, 0.9.0) across 2 repos")


def test_losing_readiness_posts_readiness_broken_keyed_on_the_breaking_run():
    _seed(_entries_rows(_ready_rows()))
    _judge()
    red = _row(R_A, 0.5, "0.9.0", red=("resolvers_ok",), armed=ARMED, run_id="red-run",
               defects=["file_departed/mutation BLIND"])
    _seed(_entries_rows([red]))
    v = _judge(LATER)
    assert v["verdict"] == "not-ready"
    kinds = sorted(n["notice_kind"] for n in notices.pending())
    assert kinds == ["readiness-broken", "readiness-reached"]
    broken = next(n for n in notices.pending() if n["notice_kind"] == "readiness-broken")
    assert broken["key"] == "run:red-run"
    assert broken["title"] == (f"a went red at {red['at']} "
                               "(resolvers_ok: file_departed/mutation BLIND)")


def test_persistent_defect_posts_one_notice_and_clears_on_recovery():
    rows = [_row(R_A, d, armed=ARMED, defects=["gap_addressed/mutation NEVER RAN"],
                 red=("resolvers_ok",)) for d in (4, 3, 2)]
    rows += [_row(R_B, 3)]
    _seed(_entries_rows(rows))
    _judge()
    defects = [n for n in notices.pending() if n["notice_kind"] == "fleet-defect"]
    assert len(defects) == 1
    key_a = list(_registered())[0]
    assert defects[0]["key"] == f"defect:{key_a}:resolver:gap_addressed/mutation"
    assert defects[0]["title"] == "a: resolver gap_addressed/mutation on the last 3 gate runs"
    _judge(LATER)                                    # still present: no second notice
    assert len([n for n in notices.pending() if n["notice_kind"] == "fleet-defect"]) == 1
    _seed(_entries_rows([_row(R_A, 0.1, armed=ARMED)]))   # recovered
    _judge(LATER)
    assert [n for n in notices.pending() if n["notice_kind"] == "fleet-defect"] == []
    cleared = [e for e in notices.read_events() if e["kind"] == "cleared"]
    assert cleared[0]["reason"] == "defect absent from latest row"


def test_two_rows_of_a_defect_are_not_yet_a_notice():
    rows = [_row(R_A, d, armed=ARMED, defects=["gap_addressed/mutation NEVER RAN"],
                 red=("resolvers_ok",)) for d in (3, 2)] + [_row(R_B, 3)]
    _seed(_entries_rows(rows))
    _judge()
    assert notices.pending() == []


def test_compaction_drops_rows_older_than_180_days_once_a_day():
    _seed(_entries_rows(_ready_rows() + [_row(R_A, 200, armed=ARMED)]))
    assert len(fleet.read_rows()) == 5
    _judge()
    assert len(fleet.read_rows()) == 4
    _seed(_entries_rows([_row(R_A, 199, armed=ARMED)]))
    _judge(LATER)                                    # within 24h: not rewritten
    assert len(fleet.read_rows()) == 5
    assert fleet.read_verdict()["compacted_at"] == NOW


def test_over_budget_reports_and_writes_no_verdict(monkeypatch, capsys):
    _seed(_entries_rows(_ready_rows()))
    ticks = iter([0.0, 31.0, 31.0, 31.0])
    monkeypatch.setattr(fleet, "_monotonic", lambda: next(ticks))
    assert _judge() is None
    assert not fleet.verdict_path().exists()
    assert notices.pending() == []
    assert capsys.readouterr().err == \
        "aramid: fleet: judgement over the 30s budget; verdict not written\n"


def test_a_corrupt_verdict_file_reads_as_none_and_is_replaced():
    fleet.verdict_path().parent.mkdir(parents=True)
    fleet.verdict_path().write_text("{not json", encoding="utf-8")
    assert fleet.read_verdict() is None
    _seed(_entries_rows(_ready_rows()))
    assert _judge()["verdict"] == "ready"
    assert fleet.read_verdict()["verdict"] == "ready"


def test_an_unwritable_verdict_path_fails_open(capsys):
    fleet.verdict_path().mkdir(parents=True)         # a directory where the file goes
    _seed(_entries_rows(_ready_rows()))
    assert _judge() is None
    assert capsys.readouterr().err.startswith("aramid: fleet: judgement skipped (")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_fleet_judgement.py -q -p no:cacheprovider`
Expected: `AttributeError: module 'aramid.fleet' has no attribute 'run_judgement'`.

- [ ] **Step 3: Append the orchestration to `src/aramid/fleet.py`**

```python
JUDGE_BUDGET_S = 30.0
COMPACT_EVERY_H = 24


def read_verdict(path: Path | None = None) -> dict | None:
    p = path if path is not None else verdict_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        return None
    return data


def write_verdict(verdict: dict, path: Path | None = None) -> None:
    """tmp + os.replace, the autolearn precedent: a torn write can never
    corrupt the previous verdict."""
    p = path if path is not None else verdict_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(verdict, indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, p)


def _defects_of(row: dict) -> list[tuple[str, str]]:
    """(kind, target) pairs a row carries -- the defects a fleet-defect notice
    is about. `no_work` is deliberately not one: it is cost, not a broken
    mechanism (spec section 6)."""
    ev = row.get("evidence", {})
    out = []
    for gate, tools in sorted((ev.get("skip_streaks") or {}).items()):
        for tool in sorted(tools):
            out.append(("skip", f"{gate}/{tool}"))
    for name in sorted(set((ev.get("degraded_consumers") or []) + (ev.get("stood_down") or []))):
        out.append(("consumer", name))
    for entry in ev.get("resolver_defects") or []:
        out.append(("resolver", str(entry).split(" ")[0]))
    return out


def _post_transitions(previous: dict | None, verdict: dict, now: str) -> None:
    from aramid import notices
    prev_v = previous.get("verdict") if previous else None
    new_v = verdict["verdict"]
    info = verdict["fleet"]
    if new_v == READY and prev_v != READY:
        start = info["streak_started_at"]
        names = sorted(v["name"] for v in verdict["repos"].values())
        versions = ", ".join(info["versions_in_streak"])
        notices.post("readiness-reached", f"streak:{start}",
                     title=(f"1.0 readiness reached -- streak since {start} "
                            f"({info['days_held']:.0f}d, versions {versions}) across "
                            f"{len(names)} repos"),
                     body=("Every registered repo has been green on every criterion since "
                           f"{start}: {', '.join(names)}. `aramid fleet` prints the matrix. "
                           "RELEASING.md's \"The 1.0 gate\" names the manual criterion "
                           "(API freeze) still to check before tagging 1.0.0."),
                     evidence={"streak_started_at": start, "days_held": info["days_held"],
                               "versions": info["versions_in_streak"], "repos": names},
                     now=now)
    elif prev_v == READY and new_v != READY:
        br = info.get("breaking_row")
        if br:
            key, title = f"run:{br['run_id']}", f"{br['name']} went red at {br['at']} ({br['detail']})"
        else:
            key, title = f"at:{now}", "fleet readiness lost -- " + "; ".join(verdict["reasons"])
        notices.post("readiness-broken", key, title=title,
                     body=(f"1.0 readiness was READY and is now {new_v.upper()}: "
                           + "; ".join(verdict["reasons"])
                           + ". The streak restarts from the next row on which every "
                             "registered repo is green."),
                     evidence={"breaking_row": br, "reasons": verdict["reasons"]}, now=now)


def _post_defects(rows: list[dict], registered: dict[str, str], policy: Policy,
                  now: str) -> None:
    from aramid import notices
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for r in sorted(rows, key=lambda r: str(r.get("at", ""))):
        if r.get("repo") in registered:
            by_repo[r["repo"]].append(r)
    pending = {n["id"]: n for n in notices.pending() if n.get("notice_kind") == "fleet-defect"}
    for repo, seq in by_repo.items():
        name = seq[-1].get("name") or registered[repo]
        latest = set(_defects_of(seq[-1]))
        window = seq[-policy.defect_rows:]
        persistent = (set.intersection(*(set(_defects_of(r)) for r in window))
                      if len(window) >= policy.defect_rows else set())
        for kind, target in sorted(persistent):
            notices.post("fleet-defect", f"defect:{repo}:{kind}:{target}",
                         title=f"{name}: {kind} {target} on the last {policy.defect_rows} gate runs",
                         body=(f"{name} has carried the same {kind} defect ({target}) on its last "
                               f"{policy.defect_rows} consecutive gate runs. Run `aramid status` "
                               f"in that repo for the line and the remedy; this notice clears "
                               "itself on the first row without it."),
                         evidence={"repo": repo, "name": name, "kind": kind, "target": target,
                                   "rows": policy.defect_rows}, now=now)
        for n in pending.values():
            ev = n.get("evidence", {})
            if ev.get("repo") == repo and (ev.get("kind"), ev.get("target")) not in latest:
                notices.clear(n["id"], reason="defect absent from latest row", now=now)


def _maybe_compact(rows: list[dict], previous: dict | None, now: str) -> str | None:
    """Rewrite the store without rows older than ROW_WINDOW_DAYS, at most
    once per COMPACT_EVERY_H, tmp + replace, under the drain lock the caller
    holds. A gate appending between the read and the replace loses its row;
    accepted for a once-a-day rewrite. On Windows a concurrently open file
    makes os.replace raise; that is reported and skipped, never fatal."""
    last = (previous or {}).get("compacted_at")
    now_dt, last_dt = _parse(now), _parse(last) if last else None
    if last_dt is not None and now_dt is not None and now_dt - last_dt < timedelta(hours=COMPACT_EVERY_H):
        return last
    cutoff = now_dt - timedelta(days=ROW_WINDOW_DAYS)
    keep = [r for r in rows if (_parse(r.get("at")) or now_dt) >= cutoff]
    if len(keep) != len(rows) or not health_path().exists():
        try:
            p = health_path()
            tmp = p.with_name(p.name + ".tmp")
            tmp.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in keep),
                           encoding="utf-8")
            os.replace(tmp, p)
        except OSError as exc:
            print(f"aramid: fleet: compaction skipped ({exc})", file=sys.stderr)
            return last
    return now


def run_judgement(now: str, *, aramid_version: str, entries: list[dict] | None = None,
                  policy: Policy | None = None) -> dict | None:
    """The drain's seam (spec section 6). Reads ONLY the store; never a
    ledger. Never raises; over budget it reports and writes nothing."""
    started = _monotonic()
    try:
        policy = policy or load_policy()
        registered = registered_repos(entries)
        previous = read_verdict()
        rows = read_rows()
        verdict = judge(rows, registered, policy, now, aramid_version=aramid_version)
        if _monotonic() - started > JUDGE_BUDGET_S:
            print(f"aramid: fleet: judgement over the {JUDGE_BUDGET_S:.0f}s budget; "
                  "verdict not written", file=sys.stderr)
            return None
        _post_transitions(previous, verdict, now)
        _post_defects(rows, registered, policy, now)
        verdict["compacted_at"] = _maybe_compact(rows, previous, now)
        write_verdict(verdict)
        return verdict
    except Exception as exc:
        print(f"aramid: fleet: judgement skipped ({exc})", file=sys.stderr)
        return None
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/unit/test_fleet_judgement.py tests/unit/test_fleet_judge.py tests/unit/test_notices.py -q -p no:cacheprovider`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/fleet.py tests/unit/test_fleet_judgement.py
python -P -m aramid check --staged
git commit -F <scratchpad>/msg-task8.txt
```

Message: `feat(fleet): drain-time judgement -- verdict file, transitions, defect notices, compaction`.

---

### Task 9: Judge seam in `cmd_drain` and the drain integration test

**Files:**
- Modify: `src/aramid/commands/drain.py:20-27` (imports) and the block after the autolearn rollup (`:268-283`)
- Test: `tests/integration/test_drain_fleet.py`

**Interfaces:**
- Consumes: `fleet.run_judgement` (Task 8), `aramid.__version__`.
- Produces: after every non-dry-run drain, `fleet_verdict.json` exists and transitions post notices.

- [ ] **Step 1: Write the failing test**

```python
# tests/integration/test_drain_fleet.py
"""Spec section 10, drain integration: two temp repos, a temp registry and
store; after `cmd_drain` the verdict exists, and a seeded green -> red
sequence across two drains yields readiness-reached then readiness-broken.
The drain never opens either repo's ledger for this -- only the rows."""
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aramid import fleet, health, notices, registry
from aramid.commands import drain as drain_mod
from aramid.commands.drain import cmd_drain

NOW_DT = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
NOW = NOW_DT.isoformat()
LATER = (NOW_DT + timedelta(hours=4)).isoformat()


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path, name) -> Path:
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "README.md").write_text("hi\n", encoding="utf-8")
    _git(r, "add", "README.md")
    _git(r, "commit", "-q", "-m", "benign")
    return r


@pytest.fixture
def seam(tmp_path, monkeypatch):
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: tmp_path / "central" / "drain.lock")
    monkeypatch.setattr(drain_mod, "CONSUMERS", {})


def _row(root, days_ago, version, *, red=(), armed=None, run_id="r"):
    crit = {k: True for k in health.CRITERIA}
    crit["dep_audit_ran"] = None
    for k in red:
        crit[k] = False
    return {"schema_version": 1, "at": (NOW_DT - timedelta(days=days_ago)).isoformat(),
            "repo": fleet.repo_key(root), "name": root.name, "aramid_version": version,
            "gate": "pre-push", "run_id": run_id, "exit_code": 0, "engine_error": False,
            "criteria": crit,
            "evidence": {"skip_streaks": {}, "degraded_consumers": [], "stood_down": [],
                         "no_work": [], "resolver_defects": [], "bad_tools": [],
                         "degraded_block_tier": False, "armed": dict(armed or {}),
                         "open": 0, "blocking": 0}}


def test_drain_judges_the_fleet_and_posts_transitions(tmp_path, seam):
    a, b = _repo(tmp_path, "a"), _repo(tmp_path, "b")
    registry.register(a, "t0")
    registry.register(b, "t0")
    armed = {"semgrep_block_armed": True}
    for row in (_row(a, 20, "0.8.0", armed=armed), _row(b, 20, "0.8.0"),
                _row(a, 10, "0.9.0", armed=armed), _row(b, 10, "0.9.0")):
        fleet.append_row(row)

    assert cmd_drain([], clock=lambda: NOW) == 0
    verdict = fleet.read_verdict()
    assert verdict is not None and verdict["verdict"] == "ready"
    assert [n["notice_kind"] for n in notices.pending()] == ["readiness-reached"]

    fleet.append_row(_row(a, 0.5, "0.9.0", red=("consumers_healthy",), armed=armed,
                          run_id="broke"))
    assert cmd_drain([], clock=lambda: LATER) == 0
    assert fleet.read_verdict()["verdict"] == "not-ready"
    kinds = sorted(n["notice_kind"] for n in notices.pending())
    assert kinds == ["readiness-broken", "readiness-reached"]


def test_a_broken_store_never_fails_the_drain(tmp_path, seam, capsys):
    a = _repo(tmp_path, "a")
    registry.register(a, "t0")
    fleet.verdict_path().mkdir(parents=True)          # unwritable verdict
    assert cmd_drain([], clock=lambda: NOW) == 0
    assert "aramid: fleet: judgement skipped (" in capsys.readouterr().err
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/integration/test_drain_fleet.py -q -p no:cacheprovider`
Expected: `assert verdict is not None` fails (no judgement runs yet).

- [ ] **Step 3: Wire the seam in `drain.py`**

Add imports `from aramid import __version__` and `from aramid import fleet`. After the autolearn rollup loop and before `print(f"aramid drain: {drained} item(s) drained, ...")`:

```python
        # Fleet judgement (fleet-readiness spec section 6): judge every
        # registered repo's health rows, write the verdict, post notices.
        # Reads only ~/.aramid/fleet_health.jsonl -- never another repo's
        # ledger -- and fails open: a broken store never fails the drain.
        try:
            fleet.run_judgement(clock(), aramid_version=__version__)
        except Exception as exc:
            print(f"aramid drain: fleet judgement skipped: {exc}", file=sys.stderr)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/integration/test_drain_fleet.py tests/integration/test_drain.py -q -p no:cacheprovider`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/drain.py tests/integration/test_drain_fleet.py
python -P -m aramid check --staged
git commit -F <scratchpad>/msg-task9.txt
```

Message: `feat(drain): judge the fleet after every drain`.

---
### Task 10: Delivery -- the readiness line and notices in the session-start hook and `aramid status`

**Files:**
- Modify: `src/aramid/fleet.py` (append `readiness_line`, `delivery_lines`)
- Modify: `src/aramid/commands/agent_hook.py:139-165` (`_session_context`)
- Modify: `src/aramid/commands/status.py` (`cmd_status`, after `_scheduled_drain_line()`)
- Test: `tests/integration/test_agent_hook_fleet.py`, `tests/integration/test_status_fleet.py`

**Interfaces:**
- Consumes: `read_verdict`, `load_policy`, `repo_key` (Tasks 1, 4, 8); `notices.due`, `notices.mark_shown`, `notices.render_line` (Task 6).
- Produces: `fleet.readiness_line(verdict: dict | None) -> str`; `fleet.delivery_lines(root, *, surface: str, now: str, policy=None) -> list[str]` (readiness line first, then one line per due notice; each shown notice gets a `shown` event; `[]` on any error).
- Line shapes (spec section 8):
  - `fleet: no verdict yet -- first drain after promotion computes it`
  - `fleet: 1.0 readiness NOT READY -- 4/5 repos green, streak 0d, versions 0/2; red: aramid (dep_audit_ran); no repo has an armed consumer`
  - `fleet: 1.0 readiness READY -- 5/5 repos green, streak 21d, versions 2/2`
  - `fleet: 1.0 readiness INSUFFICIENT DATA -- 3/5 repos green, streak 0d, versions 0/2; no rows: atlas_data, graphite`
  - `NOTICE <id> <kind>: <title> -- ack: aramid notices ack <id>`
  - The hook prefixes every line with `aramid: `; `status` prints them bare, after `scheduled drain:`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/integration/test_agent_hook_fleet.py
"""The session-start hook is where a notice reaches the operator in the repo
they are working in. Full-line assertions; `shown` events respect
repeat_hours; a broken channel costs the fleet lines and nothing else."""
import subprocess
import sys
from pathlib import Path

from aramid import fleet, notices
from aramid.commands import agent_hook, doctor, init

NOW = "2026-09-20T12:00:00+00:00"


def _git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _fake_present(root):
    return {name: doctor.ToolStatus(name, True, "1.0")
            for name in ("gitleaks", "semgrep", "ruff", "pip-audit")} | {
        "interpreter": doctor.ToolStatus("interpreter", True, sys.executable)}


def _onboarded(tmp_path, monkeypatch) -> Path:
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "app.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "app.py")
    _git(r, "commit", "-q", "-m", "seed")
    assert init.cmd_init(r) == 0
    return r


def _verdict(**over):
    base = {"schema_version": 1, "computed_at": NOW, "aramid_version": "0.9.0",
            "policy": {"min_days": 14, "min_versions": 2},
            "repos": {"f:/p/aramid": {"name": "aramid", "rows": 41, "latest_at": NOW,
                                      "green": False, "red_criteria": ["dep_audit_ran"],
                                      "criteria": {}},
                      "f:/p/graphite": {"name": "graphite", "rows": 3, "latest_at": NOW,
                                        "green": True, "red_criteria": [], "criteria": {}}},
            "fleet": {"all_green_now": False, "streak_started_at": None, "days_held": 0.0,
                      "versions_in_streak": [], "armed_anywhere": False,
                      "disarm_in_streak": False,
                      "blockers": ["no repo has an armed consumer"], "breaking_row": None},
            "verdict": "not-ready",
            "reasons": ["aramid: dep_audit_ran", "no repo has an armed consumer"]}
    base.update(over)
    return base


def _lines(r, capsys):
    capsys.readouterr()
    assert agent_hook.cmd_agent_hook("session-start", root=r) == 0
    return capsys.readouterr().out.splitlines()


def test_no_verdict_yet_line_sits_before_the_commands_line(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    lines = _lines(r, capsys)
    assert lines[-2] == "aramid: fleet: no verdict yet -- first drain after promotion computes it"
    assert lines[-1].startswith("aramid: commands:")


def test_not_ready_line_full_shape(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    fleet.write_verdict(_verdict())
    assert ("aramid: fleet: 1.0 readiness NOT READY -- 1/2 repos green, streak 0d, "
            "versions 0/2; red: aramid (dep_audit_ran); no repo has an armed consumer"
            ) in _lines(r, capsys)


def test_a_due_notice_is_shown_once_per_repeat_window(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)
    fleet.write_verdict(_verdict())
    nid = notices.post("readiness-broken", "run:x",
                       title="Atlas_Data went red at 2026-09-03T10:11:00+00:00 "
                             "(resolvers_ok: file_departed/mutation BLIND)",
                       body="b", evidence={}, now=NOW)
    expected = (f"aramid: NOTICE {nid} readiness-broken: Atlas_Data went red at "
                f"2026-09-03T10:11:00+00:00 (resolvers_ok: file_departed/mutation BLIND)"
                f" -- ack: aramid notices ack {nid}")
    assert expected in _lines(r, capsys)
    shown = [e for e in notices.read_events() if e["kind"] == "shown"]
    assert len(shown) == 1 and shown[0]["surface"] == "session-start"
    assert shown[0]["repo"] == fleet.repo_key(r)
    assert expected not in _lines(r, capsys)         # within repeat_hours: not repeated
    assert any(ln.startswith("aramid: fleet: 1.0 readiness") for ln in _lines(r, capsys))


def test_a_channel_that_is_a_directory_still_prints_the_verdict_line(tmp_path, monkeypatch,
                                                                     capsys):
    # The tolerant reader turns an unreadable notices file into "no events"
    # plus one stderr note; the readiness line survives, the block is whole.
    r = _onboarded(tmp_path, monkeypatch)
    notices.notices_path().mkdir(parents=True)
    lines = _lines(r, capsys)
    assert "aramid: fleet: no verdict yet -- first drain after promotion computes it" in lines
    assert not any("NOTICE" in ln for ln in lines)


def test_an_internal_fleet_error_costs_only_the_fleet_lines(tmp_path, monkeypatch, capsys):
    r = _onboarded(tmp_path, monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("injected")
    monkeypatch.setattr(fleet, "read_verdict", boom)
    lines = _lines(r, capsys)
    assert lines[0].startswith("aramid: this repo is GATED")
    assert lines[-1].startswith("aramid: commands:")
    assert not any("fleet" in ln or "NOTICE" in ln for ln in lines)
```

```python
# tests/integration/test_status_fleet.py
"""`aramid status` carries the same two line shapes without the prefix,
after `scheduled drain:`."""
import subprocess

import pytest

from aramid import fleet, notices
from aramid.commands import schedule as schedule_mod
from aramid.commands.status import cmd_status

NOW = "2026-09-20T12:00:00+00:00"


def _verdict(**over):
    # tests/integration is not a package: the fixture verdict is repeated
    # from test_agent_hook_fleet.py. Keep the copies identical.
    base = {"schema_version": 1, "computed_at": NOW, "aramid_version": "0.9.0",
            "policy": {"min_days": 14, "min_versions": 2},
            "repos": {"f:/p/aramid": {"name": "aramid", "rows": 41, "latest_at": NOW,
                                      "green": False, "red_criteria": ["dep_audit_ran"],
                                      "criteria": {}},
                      "f:/p/graphite": {"name": "graphite", "rows": 3, "latest_at": NOW,
                                        "green": True, "red_criteria": [], "criteria": {}}},
            "fleet": {"all_green_now": False, "streak_started_at": None, "days_held": 0.0,
                      "versions_in_streak": [], "armed_anywhere": False,
                      "disarm_in_streak": False,
                      "blockers": ["no repo has an armed consumer"], "breaking_row": None},
            "verdict": "not-ready",
            "reasons": ["aramid: dep_audit_ran", "no repo has an armed consumer"]}
    base.update(over)
    return base


@pytest.fixture(autouse=True)
def _no_real_schtasks(monkeypatch):
    real_run = subprocess.run

    def fake_run(argv, *a, **k):
        if argv and argv[0] == "schtasks":
            class _R:
                returncode = 1
                stdout = ""
                stderr = ""
            return _R()
        return real_run(argv, *a, **k)
    monkeypatch.setattr(schedule_mod.subprocess, "run", fake_run)


def _repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, check=True)
    (r / "aramid.toml").write_text("schema_version = 1\nsemgrep_block_armed = true\n",
                                   encoding="utf-8")
    return r


def _out(root, capsys):
    capsys.readouterr()
    assert cmd_status(root) == 0
    return capsys.readouterr().out.splitlines()


def test_status_fleet_block_follows_scheduled_drain(tmp_path, capsys):
    root = _repo(tmp_path)
    lines = _out(root, capsys)
    i = next(i for i, ln in enumerate(lines) if ln.startswith("scheduled drain:"))
    assert lines[i + 1] == "fleet: no verdict yet -- first drain after promotion computes it"


def test_status_prints_the_verdict_and_a_due_notice_bare(tmp_path, capsys):
    root = _repo(tmp_path)
    fleet.write_verdict(_verdict())
    nid = notices.post("fleet-defect", "defect:f:/p/aramid:resolver:gap_addressed/mutation",
                       title="aramid: resolver gap_addressed/mutation on the last 3 gate runs",
                       body="b", evidence={}, now=NOW)
    lines = _out(root, capsys)
    assert ("fleet: 1.0 readiness NOT READY -- 1/2 repos green, streak 0d, versions 0/2; "
            "red: aramid (dep_audit_ran); no repo has an armed consumer") in lines
    assert (f"NOTICE {nid} fleet-defect: aramid: resolver gap_addressed/mutation on the "
            f"last 3 gate runs -- ack: aramid notices ack {nid}") in lines
    assert [e["surface"] for e in notices.read_events() if e["kind"] == "shown"] == ["status"]


def test_an_acked_notice_is_gone_from_status(tmp_path, capsys):
    root = _repo(tmp_path)
    nid = notices.post("fleet-defect", "k", title="t", body="b", evidence={}, now=NOW)
    notices.ack(nid, repo="elsewhere", now=NOW)
    assert not any("NOTICE" in ln for ln in _out(root, capsys))
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/integration/test_agent_hook_fleet.py tests/integration/test_status_fleet.py -q -p no:cacheprovider`
Expected: `AttributeError: module 'aramid.fleet' has no attribute 'write_verdict'` is NOT expected (Task 8 added it); the failures are the missing `fleet:` lines in the hook and status output.

- [ ] **Step 3: Append the delivery helpers to `src/aramid/fleet.py`**

```python
_LABELS = {READY: "READY", NOT_READY: "NOT READY", INSUFFICIENT: "INSUFFICIENT DATA"}


def readiness_line(verdict: dict | None) -> str:
    """Spec section 8's one-line verdict; the same string on every surface."""
    if verdict is None:
        return "fleet: no verdict yet -- first drain after promotion computes it"
    repos = verdict.get("repos", {})
    info = verdict.get("fleet", {})
    green = sum(1 for v in repos.values() if v.get("green"))
    label = _LABELS.get(verdict.get("verdict"), str(verdict.get("verdict")).upper())
    line = (f"fleet: 1.0 readiness {label} -- {green}/{len(repos)} repos green, "
            f"streak {float(info.get('days_held', 0.0)):.0f}d, "
            f"versions {len(info.get('versions_in_streak', []))}/"
            f"{verdict.get('policy', {}).get('min_versions', 2)}")
    tail = []
    red = [f"{v['name']} ({', '.join(v['red_criteria'])})"
           for v in repos.values() if v.get("red_criteria")]
    if red:
        tail.append("red: " + ", ".join(red))
    missing = sorted((v["name"] for v in repos.values() if not v.get("rows")), key=str.casefold)
    if missing:
        tail.append("no rows: " + ", ".join(missing))
    tail.extend(info.get("blockers", []))
    return line + ("; " + "; ".join(tail) if tail else "")


def delivery_lines(root, *, surface: str, now: str, policy: Policy | None = None) -> list[str]:
    """The readiness line plus every notice due in this repo (spec section
    7): shown at most once per `repeat_hours` per repo, each display recorded
    as a `shown` event. Fail-open: any error yields NO lines -- the hook's
    own contract is a block built fully or not at all."""
    try:
        from aramid import notices as notices_mod
        policy = policy or load_policy()
        lines = [readiness_line(read_verdict())]
        repo = repo_key(root)
        for n in notices_mod.due(repo, now, policy.repeat_hours):
            lines.append(notices_mod.render_line(n))
            notices_mod.mark_shown(n["id"], repo=repo, surface=surface, now=now)
        return lines
    except Exception:
        return []
```

- [ ] **Step 4: Wire the hook and `status`**

In `agent_hook._session_context`, after the `_bake_lines` extend and before the `commands:` line:

```python
        from datetime import datetime, timezone

        from aramid import fleet
        lines.extend("aramid: " + line for line in fleet.delivery_lines(
            repo, surface="session-start", now=datetime.now(timezone.utc).isoformat()))
```

In `status.cmd_status`, after `lines.append(_scheduled_drain_line())`:

```python
        # --- fleet health (fleet-readiness spec section 8) ---
        from aramid import fleet
        lines.extend(fleet.delivery_lines(root, surface="status",
                                          now=datetime.now(timezone.utc).isoformat()))
```

(`status.py` already imports `datetime` and `timezone`.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/integration/test_agent_hook_fleet.py tests/integration/test_status_fleet.py tests/integration/test_agent_hook.py tests/integration/test_status.py -q -p no:cacheprovider`
Expected: PASS, including the pre-existing `test_session_start_prints_posture_in_onboarded_repo` (the commands line is still last).

- [ ] **Step 6: Commit**

```bash
git add src/aramid/fleet.py src/aramid/commands/agent_hook.py src/aramid/commands/status.py tests/integration/test_agent_hook_fleet.py tests/integration/test_status_fleet.py
python -P -m aramid check --staged
git commit -F <scratchpad>/msg-task10.txt
```

Message: `feat(fleet): deliver the verdict and due notices in the session-start hook and status`.

---

### Task 11: Gate console trailer and the JSON key

**Files:**
- Modify: `src/aramid/pipeline.py` (`GateResult`, after `stacks`)
- Modify: `src/aramid/reporter.py` (`render_console` tail, `render_json` payload)
- Modify: `src/aramid/commands/check.py` (before rendering)
- Test: `tests/unit/test_reporter_fleet.py`; extend `tests/integration/test_check_fleet.py`

**Interfaces:**
- Consumes: `notices.pending_count()`, `fleet.load_policy()`.
- Produces: `GateResult.fleet_notices_pending: int | None = None`, `GateResult.fleet_trailer: bool = False`; console trailer (last line, only when `fleet_trailer` and the count is non-zero): `aramid: <n> fleet notice(s) pending -- see \`aramid notices\``; JSON key `"fleet_notices_pending"` always present (`int` or `null`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_reporter_fleet.py
"""The gate's own output is the cheapest delivery surface: a count, never a
`shown` event. The JSON key is always present so a consumer can tell 'none'
from 'unknown' from 'too old to say'."""
import json

from aramid import reporter
from aramid.ledger import Ledger
from aramid.pipeline import GateResult


def _result(**kw):
    base = dict(exit_code=0, findings=[], degraded=[], new_ids=[], stale_overrides=[],
                run_id="r1")
    base.update(kw)
    return GateResult(**base)


def test_trailer_is_the_last_console_line(tmp_path):
    ledger = Ledger(tmp_path / "l.db")
    out = reporter.render_console(_result(fleet_notices_pending=2, fleet_trailer=True), ledger)
    assert out.splitlines()[-1] == "aramid: 2 fleet notice(s) pending -- see `aramid notices`"
    ledger.close()


def test_no_trailer_when_zero_unknown_or_switched_off(tmp_path):
    ledger = Ledger(tmp_path / "l.db")
    for kw in ({"fleet_notices_pending": 0, "fleet_trailer": True},
               {"fleet_notices_pending": None, "fleet_trailer": True},
               {"fleet_notices_pending": 3, "fleet_trailer": False},
               {}):
        assert "fleet notice" not in reporter.render_console(_result(**kw), ledger)
    ledger.close()


def test_json_key_is_always_present():
    assert json.loads(reporter.render_json(_result()))["fleet_notices_pending"] is None
    assert json.loads(reporter.render_json(_result(fleet_notices_pending=0)))[
        "fleet_notices_pending"] == 0
    assert json.loads(reporter.render_json(_result(fleet_notices_pending=2, fleet_trailer=False)))[
        "fleet_notices_pending"] == 2
```

Append to `tests/integration/test_check_fleet.py`:

```python
from aramid import notices


def test_gate_output_carries_the_pending_count(tmp_path, clean_gate, capsys):
    root = _repo(tmp_path)
    notices.post("fleet-defect", "k", title="t", body="b", evidence={}, now="2026-09-20T12:00:00+00:00")
    assert cmd_check(root, Gate.PRE_COMMIT, "staged") == 0
    assert capsys.readouterr().out.splitlines()[-1] == \
        "aramid: 1 fleet notice(s) pending -- see `aramid notices`"
    assert cmd_check(root, Gate.PRE_COMMIT, "staged", as_json=True) == 0
    assert json.loads(capsys.readouterr().out)["fleet_notices_pending"] == 1


def test_gate_trailer_policy_off_keeps_the_json_key(tmp_path, clean_gate, capsys):
    root = _repo(tmp_path)
    fleet.policy_path().parent.mkdir(parents=True, exist_ok=True)
    fleet.policy_path().write_text("[notices]\ngate_trailer = false\n", encoding="utf-8")
    notices.post("fleet-defect", "k", title="t", body="b", evidence={}, now="2026-09-20T12:00:00+00:00")
    assert cmd_check(root, Gate.PRE_COMMIT, "staged") == 0
    assert "fleet notice" not in capsys.readouterr().out
    assert cmd_check(root, Gate.PRE_COMMIT, "staged", as_json=True) == 0
    assert json.loads(capsys.readouterr().out)["fleet_notices_pending"] == 1
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_reporter_fleet.py tests/integration/test_check_fleet.py -q -p no:cacheprovider`
Expected: `TypeError: GateResult.__init__() got an unexpected keyword argument 'fleet_notices_pending'`.

- [ ] **Step 3: Implement**

`pipeline.GateResult`, after `stacks`:

```python
    # Fleet notices pending on this machine when the report was rendered
    # (fleet-readiness spec section 8): 0 when none, None when the channel
    # could not be read. Set by commands/check.py, which owns the read; the
    # reporter stays pure formatting. `fleet_trailer` carries the operator's
    # `[notices].gate_trailer` policy the same way, so the console line can
    # be switched off without touching the JSON key, which is always present.
    fleet_notices_pending: int | None = None
    fleet_trailer: bool = False
```

`reporter.render_console`, after the stale-override loop and before `return "\n".join(lines)`:

```python
    # A count only, never a `shown` event: the gate is the cheapest surface
    # and must stay so. The full lines live in the session-start hook and
    # `aramid status`.
    pending = getattr(result, "fleet_notices_pending", None)
    if getattr(result, "fleet_trailer", False) and pending:
        lines.append(f"aramid: {pending} fleet notice(s) pending -- see `aramid notices`")
```

`reporter.render_json`, add to `payload` after `"recorded"`:

```python
        # Always present: an int is a real count (0 = none pending), null
        # means the notices store could not be read. Absent means an aramid
        # too old to have a fleet.
        "fleet_notices_pending": getattr(result, "fleet_notices_pending", None),
```

`commands/check.py`, after the `if exit_code != result.exit_code:` block and before `output = ...`:

```python
        # The notice COUNT rides the report (fleet-readiness spec section 8);
        # read here, not in the reporter, which touches no filesystem.
        from aramid import notices as notices_mod
        result = dataclasses.replace(result, fleet_notices_pending=notices_mod.pending_count(),
                                     fleet_trailer=fleet.load_policy().gate_trailer)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/unit/test_reporter_fleet.py tests/unit/test_reporter.py tests/integration/test_check_fleet.py tests/integration/test_check.py -q -p no:cacheprovider`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/pipeline.py src/aramid/reporter.py src/aramid/commands/check.py tests/unit/test_reporter_fleet.py tests/integration/test_check_fleet.py
python -P -m aramid check --staged
git commit -F <scratchpad>/msg-task11.txt
```

Message: `feat(check): fleet notice count in the gate's console trailer and JSON`.

---
### Task 12: `aramid fleet` and `aramid notices`

**Files:**
- Create: `src/aramid/commands/fleet_cmd.py`
- Modify: `src/aramid/fleet.py` (append `render_report`)
- Modify: `src/aramid/cli.py` (import, two subparsers, two dispatch branches)
- Test: `tests/integration/test_fleet_cmd.py`

**Interfaces:**
- Consumes: `fleet.read_verdict`, `fleet.load_policy`, `fleet.repo_key`; `notices.pending`, `notices.materialize`, `notices.read_events`, `notices.ack`.
- Produces: `fleet.render_report(verdict: dict | None, policy: Policy) -> str`; `fleet_cmd.cmd_fleet(as_json: bool = False) -> int` (always 0); `fleet_cmd.cmd_notices(action: str, notice_id: str | None, root) -> int` (0; 3 for an unknown id); CLI `aramid fleet [--json]`, `aramid notices [list|show <id>|ack <id>]`.
- Report shape (`aramid fleet`), columns `repo`, `rows`, `latest`, then `skip`, `consumers`, `resolvers`, `self-block`, `dep-audit` with cells `ok` / `RED` / `-`:

```
fleet health -- 1.0 readiness (policy: 14 days, 2 versions)

  repo      rows  latest                     skip        consumers   resolvers   self-block  dep-audit
  aramid      41  2026-09-20T12:00:00+00:00  ok          ok          ok          ok          RED
  graphite     0  (no rows)                  -           -           -           -           -

  streak: none (fleet not green)
  armed anywhere: no

verdict: not-ready
  - aramid: dep_audit_ran
  - no repo has an armed consumer
```

- [ ] **Step 1: Write the failing tests**

```python
# tests/integration/test_fleet_cmd.py
"""`aramid fleet` is a report (exit 0 always); `aramid notices` is the ack
surface (exit 3 only for an unknown id, with the pending ids listed)."""
import json

import pytest

from aramid import cli, fleet, notices
from aramid.commands.fleet_cmd import cmd_fleet, cmd_notices

NOW = "2026-09-20T12:00:00+00:00"


def _verdict(**over):
    # tests/integration is not a package: the fixture verdict is repeated
    # from test_agent_hook_fleet.py. Keep the copies identical.
    base = {"schema_version": 1, "computed_at": NOW, "aramid_version": "0.9.0",
            "policy": {"min_days": 14, "min_versions": 2},
            "repos": {"f:/p/aramid": {"name": "aramid", "rows": 41, "latest_at": NOW,
                                      "green": False, "red_criteria": ["dep_audit_ran"],
                                      "criteria": {}},
                      "f:/p/graphite": {"name": "graphite", "rows": 3, "latest_at": NOW,
                                        "green": True, "red_criteria": [], "criteria": {}}},
            "fleet": {"all_green_now": False, "streak_started_at": None, "days_held": 0.0,
                      "versions_in_streak": [], "armed_anywhere": False,
                      "disarm_in_streak": False,
                      "blockers": ["no repo has an armed consumer"], "breaking_row": None},
            "verdict": "not-ready",
            "reasons": ["aramid: dep_audit_ran", "no repo has an armed consumer"]}
    base.update(over)
    return base


def _full_verdict():
    v = _verdict()
    v["repos"]["f:/p/aramid"]["criteria"] = {"no_skip_streak": True, "consumers_healthy": True,
                                             "resolvers_ok": True,
                                             "no_self_inflicted_block": True,
                                             "dep_audit_ran": False}
    v["repos"]["f:/p/graphite"] = {"name": "graphite", "rows": 0, "latest_at": None,
                                   "green": False, "red_criteria": [], "criteria": {}}
    return v


def test_fleet_report_full_lines(capsys):
    fleet.write_verdict(_full_verdict())
    assert cmd_fleet() == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "fleet health -- 1.0 readiness (policy: 14 days, 2 versions)"
    assert lines[2] == ("  repo      rows  latest                     skip        consumers   "
                        "resolvers   self-block  dep-audit")
    assert lines[3] == ("  aramid      41  2026-09-20T12:00:00+00:00  ok          ok          "
                        "ok          ok          RED")
    assert lines[4] == ("  graphite     0  (no rows)                  -           -           "
                        "-           -           -")
    assert lines[6] == "  streak: none (fleet not green)"
    assert lines[7] == "  armed anywhere: no"
    assert lines[9] == "verdict: not-ready"
    assert lines[10:] == ["  - aramid: dep_audit_ran", "  - no repo has an armed consumer"]


def test_fleet_report_without_a_verdict(capsys):
    assert cmd_fleet() == 0
    assert capsys.readouterr().out.splitlines()[2] == \
        "  no verdict yet -- first drain after promotion computes it"


def test_fleet_json_prints_the_verdict_verbatim(capsys):
    fleet.write_verdict(_full_verdict())
    assert cmd_fleet(as_json=True) == 0
    assert json.loads(capsys.readouterr().out) == fleet.read_verdict()
    fleet.verdict_path().unlink()
    assert cmd_fleet(as_json=True) == 0
    assert json.loads(capsys.readouterr().out) is None


def test_notices_list_show_ack(tmp_path, capsys):
    nid = notices.post("fleet-defect", "k", title="aramid: resolver x on the last 3 gate runs",
                       body="the body", evidence={"repo": "f:/p/aramid"}, now=NOW)
    assert cmd_notices("list", None, tmp_path) == 0
    assert capsys.readouterr().out == f"{nid} fleet-defect aramid: resolver x on the last 3 gate runs\n"
    assert cmd_notices("show", nid, tmp_path) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0] == f"{nid} fleet-defect ({NOW})"
    assert "the body" in out and '"repo": "f:/p/aramid"' in out
    assert cmd_notices("ack", nid, tmp_path) == 0
    assert capsys.readouterr().out == f"acked {nid}\n"
    assert notices.pending() == []
    acks = [e for e in notices.read_events() if e["kind"] == "ack"]
    assert acks[0]["repo"] == fleet.repo_key(tmp_path)
    assert cmd_notices("ack", nid, tmp_path) == 0            # idempotent
    assert cmd_notices("list", None, tmp_path) == 0
    assert capsys.readouterr().out == "no pending fleet notices\n"


def test_notices_unknown_id_exits_3_and_lists_pending(tmp_path, capsys):
    nid = notices.post("fleet-defect", "k", title="t", body="b", evidence={}, now=NOW)
    assert cmd_notices("ack", "000000000000", tmp_path) == 3
    assert capsys.readouterr().err == \
        f"aramid: notices: unknown id '000000000000'; pending: {nid}\n"
    assert cmd_notices("show", "000000000000", tmp_path) == 3


@pytest.mark.parametrize("argv", [["fleet"], ["fleet", "--json"], ["notices"],
                                  ["notices", "list"]])
def test_cli_wires_fleet_and_notices(argv, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(argv) == 0
    capsys.readouterr()


def test_cli_notices_ack_dispatch(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    nid = notices.post("fleet-defect", "k", title="t", body="b", evidence={}, now=NOW)
    assert cli.main(["notices", "ack", nid]) == 0
    assert notices.pending() == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/integration/test_fleet_cmd.py -q -p no:cacheprovider`
Expected: `ModuleNotFoundError: No module named 'aramid.commands.fleet_cmd'`.

- [ ] **Step 3: Append `render_report` to `src/aramid/fleet.py`**

```python
_COLUMNS = (("no_skip_streak", "skip"), ("consumers_healthy", "consumers"),
            ("resolvers_ok", "resolvers"), ("no_self_inflicted_block", "self-block"),
            ("dep_audit_ran", "dep-audit"))


def render_report(verdict: dict | None, policy: Policy) -> str:
    """`aramid fleet`: the repo x criteria matrix, the streak, the verdict
    with its reasons. `ok` / `RED` / `-` (not applicable, or no rows)."""
    out = [f"fleet health -- 1.0 readiness (policy: {policy.min_days} days, "
           f"{policy.min_versions} versions)", ""]
    if verdict is None:
        out.append("  no verdict yet -- first drain after promotion computes it")
        return "\n".join(out)
    repos = list(verdict.get("repos", {}).values())
    width = max([len(v["name"]) for v in repos] + [4])
    cells_header = "  ".join(f"{label:<10}" for _k, label in _COLUMNS)
    out.append(f"  {'repo':<{width}}  {'rows':>4}  {'latest':<25}  {cells_header}".rstrip())
    for v in repos:
        if not v.get("rows"):
            latest, cells = "(no rows)", ["-"] * len(_COLUMNS)
        else:
            latest = str(v.get("latest_at"))
            crit = v.get("criteria", {})
            cells = ["-" if crit.get(k) is None else ("ok" if crit.get(k) is True else "RED")
                     for k, _label in _COLUMNS]
        out.append((f"  {v['name']:<{width}}  {v['rows']:>4}  {latest:<25}  "
                    + "  ".join(f"{c:<10}" for c in cells)).rstrip())
    info = verdict.get("fleet", {})
    out.append("")
    if info.get("streak_started_at"):
        versions = ", ".join(info.get("versions_in_streak", [])) or "none"
        out.append(f"  streak: since {info['streak_started_at']} "
                   f"({float(info.get('days_held', 0.0)):.1f}d, versions: {versions})")
    else:
        out.append("  streak: none (fleet not green)")
    out.append(f"  armed anywhere: {'yes' if info.get('armed_anywhere') else 'no'}")
    out.append("")
    out.append(f"verdict: {verdict.get('verdict')}")
    out.extend(f"  - {r}" for r in verdict.get("reasons", []))
    return "\n".join(out)
```

- [ ] **Step 4: Create `src/aramid/commands/fleet_cmd.py`**

```python
"""fleet / notices -- the operator's view of the machine-level fleet store
(fleet-readiness spec section 8). `fleet` is a report: exit 0 always, it
has nothing to block. `notices` lists, shows and acks aramid's own notices;
exit 3 only for an id the channel has never seen, with the pending ids
listed so the typo is one line away from the fix.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from aramid import fleet, notices


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def cmd_fleet(as_json: bool = False) -> int:
    verdict = fleet.read_verdict()
    if as_json:
        print(json.dumps(verdict, indent=2, sort_keys=True))
        return 0
    print(fleet.render_report(verdict, fleet.load_policy()))
    return 0


def _unknown(notice_id) -> int:
    ids = ", ".join(n["id"] for n in notices.pending()) or "none"
    print(f"aramid: notices: unknown id {notice_id!r}; pending: {ids}", file=sys.stderr)
    return 3


def cmd_notices(action: str, notice_id: str | None, root) -> int:
    action = action or "list"
    if action == "list":
        pend = notices.pending()
        if not pend:
            print("no pending fleet notices")
        for n in pend:
            print(f"{n['id']} {n['notice_kind']} {n['title']}")
        return 0
    if action == "show":
        rec = notices.materialize(notices.read_events()).get(notice_id or "")
        if rec is None:
            return _unknown(notice_id)
        n = rec["notice"]
        state = "acked" if rec["acked"] else "cleared" if rec["cleared"] else "pending"
        print(f"{n['id']} {n['notice_kind']} ({n['at']})")
        print(n["title"])
        print()
        print(n["body"])
        print()
        print(f"state: {state}")
        print("evidence: " + json.dumps(n.get("evidence", {}), sort_keys=True))
        return 0
    if action == "ack":
        if notices.ack(notice_id or "", repo=fleet.repo_key(Path(root)), now=_now()):
            print(f"acked {notice_id}")
            return 0
        return _unknown(notice_id)
    print("aramid: notices: a subcommand is required (list|show|ack)", file=sys.stderr)
    return 3
```

- [ ] **Step 5: Wire `cli.py`**

Import: `from aramid.commands.fleet_cmd import cmd_fleet, cmd_notices` (alphabetically after `drain`). Subparsers, after `p_res` (`resolvers`):

```python
    p_fleet = sub.add_parser("fleet",
                             help="fleet health across every registered repo and the "
                                  "1.0 readiness verdict (machine-level; read-only)")
    p_fleet.add_argument("--json", action="store_true")

    p_notices = sub.add_parser("notices",
                               help="aramid's own notices: list (default), show <id>, "
                                    "ack <id> (an ack anywhere silences it everywhere)")
    notices_sub = p_notices.add_subparsers(dest="notices_command")
    notices_sub.add_parser("list")
    p_nshow = notices_sub.add_parser("show")
    p_nshow.add_argument("id")
    p_nack = notices_sub.add_parser("ack")
    p_nack.add_argument("id")
```

Dispatch, after the `resolvers` branch:

```python
    if args.command == "fleet":
        return cmd_fleet(as_json=args.json)

    if args.command == "notices":
        return cmd_notices(args.notices_command or "list", getattr(args, "id", None), root)
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m pytest tests/integration/test_fleet_cmd.py tests/integration/test_cli_dispatch.py -q -p no:cacheprovider`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/aramid/commands/fleet_cmd.py src/aramid/fleet.py src/aramid/cli.py tests/integration/test_fleet_cmd.py
python -P -m aramid check --staged
git commit -F <scratchpad>/msg-task12.txt
```

Message: `feat(cli): aramid fleet and aramid notices`.

---

### Task 13: Documentation and the 1.0 gate

**Files:**
- Modify: `docs/user-guide.md` (the `aramid status` paragraph at line ~248; a new subsection after "Installing the schedule", before `## 8. Drain Consumers`)
- Modify: `RELEASING.md` (new section after the "What the release workflow guarantees" table, before "## Promoting a release to the live tool")
- Modify: `MAINTAINERS.md` (item 5 of "What a successor needs")
- Modify: `CHANGELOG.md` (`## [Unreleased]`)
- Test: `tests/unit/test_fleet_docs.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_fleet_docs.py
"""The 1.0 gate is a documented procedure, not folklore: RELEASING.md names
it, MAINTAINERS.md points at it, the user guide explains the surfaces, and
the changelog records the feature. Guards, like tests/unit/test_repo_governance.py."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_releasing_has_the_1_0_gate():
    text = _read("RELEASING.md")
    assert "## The 1.0 gate" in text
    assert "`aramid fleet`" in text and "ready" in text
    assert "API freeze" in text


def test_maintainers_points_at_the_gate():
    assert "The 1.0 gate" in _read("MAINTAINERS.md")


def test_user_guide_documents_every_surface():
    text = _read("docs/user-guide.md")
    for needle in ("### Fleet health, 1.0 readiness and notices", "aramid fleet",
                   "aramid notices ack", "fleet_health.jsonl", "fleet.toml",
                   "ARAMID_FLEET_DIR"):
        assert needle in text, needle


def test_changelog_records_the_feature():
    unreleased = _read("CHANGELOG.md").split("## [Unreleased]", 1)[1].split("## [0.8.1]", 1)[0]
    assert "aramid fleet" in unreleased and "aramid notices" in unreleased
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/unit/test_fleet_docs.py -q -p no:cacheprovider`
Expected: four failures on the missing text.

- [ ] **Step 3: Write the documentation**

`docs/user-guide.md`, extend the `aramid status` paragraph's final sentence: replace `whether scheduled drain is installed.` with `whether scheduled drain is installed; the fleet 1.0-readiness verdict and any fleet notice due in this repo (see [Fleet health](#fleet-health-10-readiness-and-notices)).`

New subsection, inserted after the "Installing the schedule" block and before `## 8. Drain Consumers`:

```markdown
### Fleet health, 1.0 readiness and notices

aramid has no telemetry and never phones home, so the question "is aramid ready to be called 1.0?" is answered on your machine, from the repos it gates. Every recording gate run appends one row for its own repo to `~/.aramid/fleet_health.jsonl` -- which tools ran, whether a consumer is degraded or stood down, whether a resolver is graded `NEVER RAN`/`BLIND`, whether a BLOCK-tier tool failed, whether pip-audit ran on a Python repo, and every `*_armed` flag. The drain then judges every registered repo's rows (`~/.aramid/fleet_verdict.json`) and posts notices to aramid's own channel (`~/.aramid/notices.jsonl`). Nothing is written into any repo; no process reads another repo's ledger; `aramid uninstall` leaves the store alone.

```powershell
aramid fleet             # repo x criteria matrix, streak, verdict with reasons
aramid fleet --json      # the verdict file verbatim
aramid notices           # pending notices, one per line
aramid notices show <id>
aramid notices ack <id>  # acking anywhere silences it everywhere
```

The verdict is `ready` only when every registered repo's latest row is green on every criterion, that has held for at least 14 days and across at least 2 aramid versions, and at least one repo has an armed consumer with no disarm inside the streak. A registered repo with no rows makes it `insufficient-data`; anything else is `not-ready` with the red repos and criteria named. `pip-audit` on a pyproject-only Python repo reads red on purpose: the gate does not audit those dependencies yet, and 1.0 waits for that.

Where you see it: the Claude Code session-start hook prints the verdict and any notice due in this repo (`aramid: fleet: ...`, `aramid: NOTICE <id> ...`); `aramid status` prints the same lines; a gate run ends with `aramid: N fleet notice(s) pending -- see `aramid notices`` and `check --json` carries `fleet_notices_pending`. A notice is repeated in a given repo at most once a day until acked; `readiness-reached` and `readiness-broken` mark transitions, and a `fleet-defect` notice fires when the same defect sits on three consecutive rows of one repo and clears itself when it goes.

Policy lives in `~/.aramid/fleet.toml` (optional; defaults shown):

```toml
schema_version = 1
[readiness]
min_days = 14
min_versions = 2
[notices]
repeat_hours = 24
defect_rows = 3
gate_trailer = true
```

Everything is fail-open: a missing, corrupt or unwritable store costs one stderr line and never changes a gate's, the drain's, or the hook's exit code. The push is budgeted at 2 s and the judgement at 30 s; over budget, the row or verdict is skipped and said so. The store directory can be redirected with the `ARAMID_FLEET_DIR` environment variable (the test suite does this so it never touches yours).
```

`RELEASING.md`, new section after the guarantees table:

```markdown
## The 1.0 gate

A 1.0.0 tag needs two things the release workflow cannot check:

1. **`aramid fleet` reads `ready`** on the maintainer's machine: every registered repo green on every criterion, held for at least 14 days across at least 2 releases, with an armed consumer somewhere and no disarm in the streak (fleet-readiness spec, `docs/superpowers/specs/2026-09-02-aramid-fleet-readiness-design.md`). The verdict is recomputed by every scheduled drain; the session-start hook and `aramid status` show it, and `readiness-reached` arrives as a notice.
2. **API freeze** (the manual criterion): the two most recent releases carry no `Changed` or `Removed` entry against the declared compatibility surface -- the CLI names and flags, the exit codes, `check --json` keys, the ledger statuses, and `aramid.toml` keys. Judged by reading `CHANGELOG.md` at release time; not automated.

Until both hold, the next release is `0.x`. Cutting 1.0.0 on a `not-ready` verdict is a decision to make in the changelog, not silently.
```

`MAINTAINERS.md`, append to item 5: ` \`RELEASING.md\`'s "The 1.0 gate" section says when a 1.0 may be cut; \`aramid fleet\` is the evidence.`

`CHANGELOG.md`, under `## [Unreleased]`:

```markdown
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
```

(Drop the `stacks` bullet if the reviewer prefers; it is internal.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/unit/test_fleet_docs.py tests/unit/test_repo_governance.py tests/unit/test_aramid_md_template_sync.py -q -p no:cacheprovider`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add docs/user-guide.md RELEASING.md MAINTAINERS.md CHANGELOG.md tests/unit/test_fleet_docs.py
python -P -m aramid check --staged
git commit -F <scratchpad>/msg-task13.txt
```

Message: `docs: fleet health, the notices channel, and the 1.0 gate`.

---

### Task 14: Whole-suite gate, push, CI

No new code. This is the operator-side close, run by the controller, not a subagent (memory: the full suite takes about 25 minutes and the pre-push gate re-runs it).

- [ ] **Step 1: Ruff and the unit+integration suite, backgrounded to a log**

```bash
python -m ruff check src tests
python -m pytest tests/unit tests/integration -q -p no:cacheprovider > <scratchpad>/suite.log 2>&1; echo rc=$? >> <scratchpad>/suite.log
```

Run the second line in the background and read the log when it finishes; the exit code lives in the log's last line, never in the task's own status (memory: bg task output file comes back empty; `rc=$?` after a pipe lies). No tree edits while it runs. Expected: `rc=0`. Any failure is fixed under TDD in the task that owns the file, then this step repeats.

- [ ] **Step 2: The pre-push gate, once, by hand**

```bash
python -P -m aramid check --gate pre-push
python -P -m aramid ledger filter --status open
```

Expected: exit 0 or 2 (degraded only by tools this machine lacks); every open finding read, and any WARN the drain files against `src/aramid/fleet.py`, `health.py`, `notices.py` or `commands/fleet_cmd.py` either fixed with a test or overridden with `aramid override <id> --reason "..."` (an equivalent mutant on a budget constant is the expected shape).

- [ ] **Step 3: Sanity on the real store, read-only**

```bash
python -P -m aramid fleet
python -P -m aramid notices
```

Expected (the checkout, not the wheel, via `pythonpath`): `no verdict yet` on both -- the live store is written by the PROMOTED wheel on the next release, not by this checkout. If a row or verdict appears here, a test escaped the `ARAMID_FLEET_DIR` fixture; find it before pushing.

- [ ] **Step 4: Push, in the background, then watch CI**

```bash
gh run list --limit 3
git push origin main > <scratchpad>/push.log 2>&1; echo rc=$? >> <scratchpad>/push.log
```

Background the push (the hook runs the suite again, ~25 min); no tree edits meanwhile. Then `gh run list --limit 3` again and `gh run watch <id>` until the seven `ci (...)` legs are green. Re-run flakes go through `gh run rerun --failed`; a real red is fixed under TDD and re-pushed.

- [ ] **Step 5: Hand back**

Report: the commits pushed, the CI run id and its seven legs, the open-ledger count, and that the store on this machine stays empty until the next release is cut and promoted (spec section 11: first rows on each registered repo's next gate run after promotion; first verdict on the next scheduled drain; expected first reading `not-ready` with `aramid: dep_audit_ran` and `no repo has an armed consumer`). Cutting the release (`0.9.0`, a minor) is the operator's call and follows `RELEASING.md`.

---

## Self-review notes (already applied)

- **Spec coverage:** section 3 (files, schema, policy) -> Tasks 1, 4, 6, 8; section 4 (criteria) -> Task 3; section 5 (push) -> Tasks 4, 5; section 6 (judge, transitions, defects) -> Tasks 7, 8, 9; section 7 (channel semantics) -> Task 6; section 8 (surfaces) -> Tasks 10, 11, 12; section 9 (invariants) -> tested in Tasks 4, 5, 8, 9, 10; section 10 (testing plan) -> each bullet has a named test above; section 11 (rollout, docs) -> Tasks 13, 14; section 12 (out of scope) -> nothing here touches `init`, a consumer's tracked files, or the network.
- **Type consistency:** `record_health(root, cfg, ledger, result, *, gate, aramid_version, now, engine_error=False)` is called with that keyword set in Tasks 5 and the tests of Task 4; `snapshot(cfg, ledger, result=None, *, gate=None, engine_error=False)` in Tasks 3, 4; `judge(rows, registered: dict, policy, now, *, aramid_version="")` in Tasks 7, 8; `run_judgement(now, *, aramid_version, entries=None, policy=None)` in Tasks 8, 9; `delivery_lines(root, *, surface, now, policy=None)` in Task 10; `notices.post(kind, key, *, title, body, evidence, now)` in Tasks 6, 8, 10, 11, 12; `cmd_notices(action, notice_id, root)` in Task 12 and `cli.py`.
- **No cross-test imports.** `tests/`, `tests/unit/` and `tests/integration/` carry no `__init__.py` (checked 2026-09-03), so a `from tests.unit.x import ...` would fail at collection. Every test file above is self-contained; the row helper (`_row`) and the fixture verdict (`_verdict`) are repeated where needed with a comment saying so.
- **Placeholder scan:** no TBD/TODO/"similar to Task N"; every code step shows the code.
