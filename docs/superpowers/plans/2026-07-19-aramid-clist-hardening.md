# C-list Hardening Bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three verified Phase 1/2a residuals — subprocess decode crashes, the override-reason materialization gap, and the unbounded post-commit triage hook.

**Architecture:** Three independent, localized fixes on one branch: (1) add explicit `encoding=`/`errors=` to every remaining `text=True` subprocess site, split by what the child emits (UTF-8 vs Windows OEM codepage); (2) fold the `finding_overridden` payload's `reason` into `Ledger._materialize` state; (3) arm a daemon `threading.Timer` watchdog in `cmd_triage` when the post-commit shim passes `--budget 15`, `os._exit(3)` on expiry (shim maps any exit to 0 — fail-open).

**Tech Stack:** Python 3.14 stdlib only (`subprocess`, `threading`, `os`). No new dependencies. Spec: `docs/superpowers/specs/2026-07-19-aramid-clist-hardening-design.md`.

## Global Constraints

- Branch: `feat/clist-hardening` off `main` (create in Task 1, Step 1). One commit per task.
- Tests run via `python -m pytest` (semgrep/ruff/pytest live in `%APPDATA%\Python\Python314\Scripts`, not on PATH).
- Shims are byte-rendered with `\n` line endings ONLY and written via `write_bytes` — never introduce a text-mode write or a `\r`.
- Invariant 1 (spec §2): gate behavior unchanged — no change to verdict logic, exit-code mapping, or pre-commit/pre-push shims.
- Invariant 2: the post-commit path can never block or noisy-fail a commit — watchdog exits 3, shim maps it to 0.
- Invariant 3: ledger event stream untouched — Task 2 changes materialization only; no event shape, append, or compaction change.
- Ruff: no NEW findings vs the branch base (`python -m ruff check src tests`; baseline count on `main` before starting).
- Full suite green at the end: `python -m pytest -q` (687 passing at branch base).

---

### Task 1: Subprocess encoding sweep

Eight `text=True`-without-`encoding=` call sites across six files. UTF-8 emitters
(git, scanner tools, `--version` probes) get `encoding="utf-8", errors="replace"`
mirroring `gitutil._run`. OEM emitters (`tasklist`, `schtasks` — Windows tools
that emit the console/ANSI codepage, NOT UTF-8) get `errors="replace"` ONLY,
keeping the locale codec: their consumers are ASCII-only (`str(pid)` containment,
returncode checks, verbatim print), which decodes identically under any candidate
codec — the change removes only the crash mode.

**Files:**
- Modify: `src/aramid/hooks.py:65-66` (`_git_config`)
- Modify: `src/aramid/runners/base.py:93-95` (`run_subprocess` Popen)
- Modify: `src/aramid/commands/doctor.py:149-150` (`--version` probe)
- Modify: `src/aramid/commands/drain.py:46-47` (`tasklist`)
- Modify: `src/aramid/commands/schedule.py:82,86,88` (`schtasks` ×3)
- Modify: `src/aramid/commands/status.py:242` (`schtasks` query)
- Test: `tests/unit/test_runner_base.py`, `tests/unit/test_hooks.py`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: nothing other tasks rely on (behavior-only hardening).

**Honest-coverage note (goes in the commit message too):** the two new tests
discriminate the UTF-8 group's fix through Python's real subprocess decode path
(the identical mechanism at all eight sites). The OEM-group and doctor sites get
no dedicated test: a fake `tasklist`/`schtasks` can't be injected (fixed argv,
CreateProcess resolves `.exe` only, no seam), and a real one can't be made to
emit non-ASCII deterministically. Their change is the same one-argument pattern,
verified by review inspection.

- [ ] **Step 1: Create the branch**

```bash
git checkout -b feat/clist-hardening
python -m ruff check src tests | tail -1   # record the baseline finding count
```

- [ ] **Step 2: Write the two failing tests**

Append to `tests/unit/test_runner_base.py`:

```python
def test_invalid_utf8_output_never_raises(tmp_path):
    # A scanner emitting a byte that is invalid UTF-8 AND undefined in cp1252
    # (0x81) must yield replaced text, not a UnicodeDecodeError crash. Before
    # the encoding="utf-8", errors="replace" fix, text=True decoded with the
    # locale codec strictly -> this raised out of run_subprocess on cp1252
    # hosts (the target platform and CI's windows-latest).
    code = "import sys; sys.stdout.buffer.write(b'pre\\x81post')"
    r = run_subprocess([sys.executable, "-c", code], tmp_path, 10)
    assert r.state is ToolState.OK
    assert "pre" in r.raw and "post" in r.raw
    assert "�" in r.raw  # replaced, never raised
```

Append to `tests/unit/test_hooks.py` (uses the file's existing `_repo` helper):

```python
def test_hooks_dir_decodes_utf8_hooks_path(tmp_path):
    # git emits config values as UTF-8 regardless of host locale. Without
    # encoding="utf-8" in _git_config, cp1252 hosts mojibake a non-ASCII
    # core.hooksPath ("café" -> "cafÃ©") and hooks_dir resolves a wrong dir.
    r = _repo(tmp_path)
    with (r / ".git" / "config").open("a", encoding="utf-8") as f:
        f.write("[core]\n\thooksPath = hooks-café\n")
    assert hooks_dir(r) == (r / "hooks-café").resolve()
```

- [ ] **Step 3: Run both tests to verify they fail**

```
python -m pytest tests/unit/test_runner_base.py::test_invalid_utf8_output_never_raises tests/unit/test_hooks.py::test_hooks_dir_decodes_utf8_hooks_path -q
```

Expected: 2 FAILED — the runner test with `UnicodeDecodeError` (raised inside
`proc.communicate`), the hooks test with an assertion mismatch on the mojibaked
path. (If the runner test PASSES, the host locale is not cp1252 — stop and
check `python -c "import locale; print(locale.getpreferredencoding())"`; this
plan assumes the project's documented cp1252 host.)

- [ ] **Step 4: Apply the eight-site fix**

`src/aramid/hooks.py` — in `_git_config`:

```python
        cp = subprocess.run(["git", "config", key], cwd=str(root),  # noqa: S603,S607
                             capture_output=True, text=True,
                             encoding="utf-8", errors="replace")
```

`src/aramid/runners/base.py` — in `run_subprocess`:

```python
    proc = subprocess.Popen(argv, cwd=str(cwd), stdout=subprocess.PIPE,  # noqa: S603
                            stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace",
                            env={**os.environ, **(env or {})}, **kwargs)
```

`src/aramid/commands/doctor.py` — in the probe:

```python
        cp = subprocess.run([str(exe), "--version"], capture_output=True, text=True,  # noqa: S603
                             encoding="utf-8", errors="replace",
                             timeout=15, env=env)
```

`src/aramid/commands/drain.py` — in `_pid_alive` (locale codec KEPT deliberately;
add a comment so a future sweep doesn't "fix" it to UTF-8):

```python
        # errors="replace" only -- tasklist emits the console/ANSI codepage,
        # NOT UTF-8; the str(pid) containment check below is pure ASCII, which
        # decodes identically under any locale codec. Forcing UTF-8 here would
        # trade one mojibake for another; "replace" removes only the crash mode.
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],  # noqa: S603,S607
                             capture_output=True, text=True, errors="replace")
```

`src/aramid/commands/schedule.py` — all three `schtasks` sites (same
one-argument change; add the group comment once, above the first):

```python
            try:
                # errors="replace" on all schtasks reads -- schtasks emits the
                # console/ANSI codepage, not UTF-8 (see drain._pid_alive).
                cp = subprocess.run(_create_argv(xml_path), capture_output=True, text=True,
                                    errors="replace")
            finally:
                xml_path.unlink(missing_ok=True)
        elif action == "remove":
            cp = subprocess.run(_delete_argv(), capture_output=True, text=True,
                                errors="replace")
        elif action == "status":
            cp = subprocess.run(_query_argv(), capture_output=True, text=True,
                                errors="replace")
```

`src/aramid/commands/status.py` — in `_scheduled_drain_line`:

```python
        cp = subprocess.run(_query_argv(), capture_output=True, text=True,
                            errors="replace")
```

- [ ] **Step 5: Run the two tests to verify they pass, then the affected suites**

```
python -m pytest tests/unit/test_runner_base.py tests/unit/test_hooks.py -q
python -m pytest tests/unit/test_schedule.py tests/integration/test_drain.py tests/integration/test_status.py tests/integration/test_doctor.py -q
```

Expected: all PASS (the second command proves no call-site behavior change).

- [ ] **Step 6: Ruff + commit**

```bash
python -m ruff check src tests   # no NEW findings vs the Step-1 baseline
git add -A
git commit -m "fix(encoding): complete the text=True-without-encoding sweep (8 sites, 6 files)

UTF-8 emitters (git config, scanner Popen, doctor probes) get
encoding=utf-8+errors=replace mirroring gitutil._run; tasklist/schtasks
sites get errors=replace only (OEM codepage emitters, ASCII-only
consumers). Discriminating tests cover the UTF-8 group through the real
subprocess decode path; OEM/doctor sites are the same one-arg pattern,
review-verified (no injectable seam for a fake tasklist)."
```

---

### Task 2: Override-reason materialization

`Ledger._materialize` folds a `finding_overridden` event into `status` only,
dropping the payload's `reason` — so `pipeline._overrides_from_ledger` always
builds `OverrideRecord(reason="")`. One-line fold; `compact()` already keeps the
latest `FINDING_OVERRIDDEN` row whole, so the reason survives compaction.

**Files:**
- Modify: `src/aramid/ledger.py:33-35` (`_materialize`)
- Modify: `src/aramid/commands/override.py:30-39` (delete the stale KNOWN-GAP docstring paragraph)
- Test: `tests/unit/test_ledger_state.py`, `tests/unit/test_ledger_compact.py`, `tests/unit/test_pipeline.py`

**Interfaces:**
- Consumes: `Ledger.open_findings() -> dict` (existing), `Event(EventType.FINDING_OVERRIDDEN, run_id, at, finding_id=..., payload={"reason": ...})` (existing shape, unchanged).
- Produces: materialized override records now carry `rec["reason"]`; `pipeline._overrides_from_ledger` (unchanged code) starts returning real `OverrideRecord.reason`.

- [ ] **Step 1: Write the three failing tests**

Append to `tests/unit/test_ledger_state.py` (uses the file's existing `_f` helper;
add the imports shown):

```python
import uuid

from aramid.models import Event, EventType


def test_override_reason_materializes(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1", "t", "pre-push", {"ruff"}, {"a.py"}, [_f("id1")])
    led.append(Event(EventType.FINDING_OVERRIDDEN, uuid.uuid4().hex, "t2",
                     finding_id="id1", payload={"reason": "vendored test fixture"}))
    rec = led.open_findings()["id1"]
    assert rec["status"] == "overridden"
    assert rec["reason"] == "vendored test fixture"


def test_override_without_reason_key_materializes_empty(tmp_path):
    # Old events appended before --reason was mandatory may lack the key.
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1", "t", "pre-push", {"ruff"}, {"a.py"}, [_f("id1")])
    led.append(Event(EventType.FINDING_OVERRIDDEN, uuid.uuid4().hex, "t2",
                     finding_id="id1", payload={}))
    assert led.open_findings()["id1"]["reason"] == ""


def test_redetect_after_override_clears_reason(tmp_path):
    # A re-detect rebuilds state from the detect payload -- the finding is
    # open again and the old override (and its reason) is history.
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1", "t", "pre-push", {"ruff"}, {"a.py"}, [_f("id1")])
    led.append(Event(EventType.FINDING_OVERRIDDEN, uuid.uuid4().hex, "t2",
                     finding_id="id1", payload={"reason": "was overridden"}))
    led.record_run("r2", "t3", "pre-push", {"ruff"}, {"a.py"}, [_f("id1")])
    rec = led.open_findings()["id1"]
    assert rec["status"] == "open"
    assert "reason" not in rec
```

Append to `tests/unit/test_ledger_compact.py` (match its existing imports; add
any of `Event`/`EventType`/`uuid` it lacks, and reuse its finding helper if one
exists — otherwise inline a `Finding` as `test_ledger_state._f` does):

```python
def test_compact_preserves_override_reason(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1", "t", "pre-push", {"ruff"}, {"a.py"}, [_f("id1")])
    led.append(Event(EventType.FINDING_OVERRIDDEN, uuid.uuid4().hex, "t2",
                     finding_id="id1", payload={"reason": "keep me"}))
    led.compact()
    rec = led.open_findings()["id1"]
    assert rec["status"] == "overridden"
    assert rec["reason"] == "keep me"
```

Append to `tests/unit/test_pipeline.py` (match its existing imports; the
function under test is `aramid.pipeline._overrides_from_ledger`):

```python
def test_overrides_from_ledger_carries_reason(tmp_path):
    from aramid.pipeline import _overrides_from_ledger
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1", "t", "pre-push", {"ruff"}, {"a.py"}, [_f("id1")])
    led.append(Event(EventType.FINDING_OVERRIDDEN, uuid.uuid4().hex, "t2",
                     finding_id="id1", payload={"reason": "audit trail"}))
    records = _overrides_from_ledger(led)
    assert len(records) == 1
    assert records[0].id == "id1"
    assert records[0].reason == "audit trail"
```

(If `test_pipeline.py` / `test_ledger_compact.py` lack an `_f`-style
Finding helper, add this local one at the top of the new test block rather than
importing across test modules:)

```python
from aramid.models import Finding, Gate, Severity, Verdict

def _f(fid, tool="ruff", file="a.py"):
    return Finding(fid, tool, "S102", "high", Severity.HIGH, Verdict.WARN,
                   file, 1, "m", "e", Gate.PRE_PUSH)
```

- [ ] **Step 2: Run the new tests to verify they fail**

```
python -m pytest tests/unit/test_ledger_state.py tests/unit/test_ledger_compact.py::test_compact_preserves_override_reason tests/unit/test_pipeline.py::test_overrides_from_ledger_carries_reason -q
```

Expected: the reason-asserting tests FAIL with `KeyError: 'reason'` (state) /
`assert '' == 'audit trail'` (pipeline). `test_redetect_after_override_clears_reason`
may already PASS (it locks existing re-detect semantics) — that is fine.

- [ ] **Step 3: Implement the one-line fold**

`src/aramid/ledger.py`, in `_materialize`:

```python
        elif e.type.value == "finding_overridden":
            if e.finding_id in state:
                state[e.finding_id]["status"] = "overridden"
                state[e.finding_id]["reason"] = e.payload.get("reason", "")
```

- [ ] **Step 4: Delete the stale KNOWN-GAP paragraph**

`src/aramid/commands/override.py` docstring: remove the entire paragraph that
begins `KNOWN GAP (pre-existing, already flagged in .superpowers/sdd/progress.md's`
and ends `...outside M7's "thin CLI wrapper" scope.` (lines 30-39). The rest of
the docstring is untouched.

- [ ] **Step 5: Run the tests to verify they pass, plus the neighbors**

```
python -m pytest tests/unit/test_ledger_state.py tests/unit/test_ledger_compact.py tests/unit/test_pipeline.py tests/integration/test_override.py tests/integration/test_ledger_cmd.py -q
```

Expected: all PASS (neighbors prove no materialization regression).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "fix(ledger): materialize finding_overridden reason into state

_materialize now folds payload['reason'] alongside status='overridden',
so pipeline._overrides_from_ledger (unchanged) carries the real reason
into OverrideRecord for audit display. compact() already keeps the
latest FINDING_OVERRIDDEN row whole -- round-trip test locks it.
Removes override.py's now-stale KNOWN-GAP docstring paragraph."
```

---

### Task 3: Triage watchdog (`--budget`)

The post-commit shim swallows output/exit but has no wall-clock bound — a hung
`aramid triage HEAD` hangs `git commit` forever. The shim now passes
`--budget 15`; `cmd_triage` arms a daemon `threading.Timer` FIRST (before repo
resolution, config load, ledger open — every hang class is downstream of it)
that stderr-logs, flushes, and `os._exit(3)`s. The shim maps any exit to 0 and
SQLite is in WAL mode (crash-safe), so the kill is fail-open; the drain
catch-up sweep recovers the lost enqueue. Manual `aramid triage` (no flag)
stays unbounded. Decisions on record (supersede Phase 2a spec §6): budget 15s
not 2s; no log file.

**Files:**
- Modify: `src/aramid/hooks.py:151,153` (`render_triage_shim` — both interpreter branches)
- Modify: `src/aramid/commands/triage_cmd.py` (watchdog + signature)
- Modify: `src/aramid/cli.py:66-67,163-164` (`--budget` flag + dispatch)
- Modify: `README.md` (~line 76, shim-regeneration note)
- Test: `tests/unit/test_hooks.py`, `tests/integration/test_triage_cmd.py`, `tests/integration/test_cli_dispatch.py`

**Interfaces:**
- Consumes: `render_triage_shim(interpreter) -> bytes` (existing), `cmd_triage(root, rev)` (existing).
- Produces: `cmd_triage(root, rev: str = "HEAD", budget: float | None = None) -> int`; shim line `-m aramid triage HEAD --budget 15`; CLI flag `--budget` (float, default None).

- [ ] **Step 1: Write the failing tests**

In `tests/unit/test_hooks.py`, STRENGTHEN the existing assertion inside
`test_install_writes_post_commit_shim_fail_open` (do not add a new test):

```python
    assert "-m aramid triage HEAD --budget 15" in text
```

(replacing the existing `assert "-m aramid triage HEAD" in text` line).

Append to `tests/integration/test_triage_cmd.py` (add imports shown):

```python
import threading
import time
from types import SimpleNamespace

import aramid.commands.triage_cmd as triage_mod
from aramid import gitutil


def test_watchdog_kills_hung_triage(tmp_path, monkeypatch):
    # Inject a hang BEFORE repo resolution; the watchdog (armed first) must
    # fire. os._exit is monkeypatched module-locally to a recorder -- the
    # real one would kill pytest.
    exits = []
    monkeypatch.setattr(triage_mod, "os", SimpleNamespace(_exit=lambda c: exits.append(c)))

    def slow_repo_root(p):
        time.sleep(1.5)
        raise gitutil.NotARepo(str(p))

    monkeypatch.setattr(triage_mod.gitutil, "repo_root", slow_repo_root)
    rc = cmd_triage(tmp_path, "HEAD", budget=0.2)
    assert exits == [3], "watchdog must have fired during the injected hang"
    assert rc == 3  # the (faked-survival) body still returns its own error


def test_watchdog_cancelled_on_fast_run(tmp_path, monkeypatch):
    exits = []
    monkeypatch.setattr(triage_mod, "os", SimpleNamespace(_exit=lambda c: exits.append(c)))
    r = _repo(tmp_path)
    _commit(r, "docs/note.md", "hello\n", "docs")
    assert cmd_triage(r, "HEAD", budget=30) == 0
    assert exits == []


def test_no_budget_arms_no_timer(tmp_path, monkeypatch):
    created = []
    monkeypatch.setattr(triage_mod, "threading",
                         SimpleNamespace(Timer=lambda *a, **kw: created.append(a)))
    r = _repo(tmp_path)
    _commit(r, "docs/note.md", "hello\n", "docs")
    assert cmd_triage(r, "HEAD") == 0
    assert created == []
```

Append to `tests/integration/test_cli_dispatch.py` (follows the file's
monkeypatch-dispatch convention):

```python
def test_triage_dispatch_maps_budget(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "cmd_triage",
                         lambda root, rev="HEAD", budget=None: calls.append((rev, budget)) or 0)
    assert cli.main(["triage", "--budget", "15"]) == 0
    assert calls == [("HEAD", 15.0)]


def test_triage_dispatch_defaults_no_budget(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "cmd_triage",
                         lambda root, rev="HEAD", budget=None: calls.append((rev, budget)) or 0)
    assert cli.main(["triage", "abc123"]) == 0
    assert calls == [("abc123", None)]
```

- [ ] **Step 2: Run the new/changed tests to verify they fail**

```
python -m pytest tests/unit/test_hooks.py::test_install_writes_post_commit_shim_fail_open tests/integration/test_triage_cmd.py tests/integration/test_cli_dispatch.py::test_triage_dispatch_maps_budget tests/integration/test_cli_dispatch.py::test_triage_dispatch_defaults_no_budget -q
```

Expected: shim test FAILS (`--budget 15` absent); watchdog tests FAIL
(`TypeError: cmd_triage() got an unexpected keyword argument 'budget'`);
dispatch tests FAIL (argparse: unrecognized `--budget` → SystemExit remapped
to 3, or TypeError).

- [ ] **Step 3: Implement**

`src/aramid/hooks.py` — `render_triage_shim`, both invocation lines:

```python
        '    "$INTERP" -m aramid triage HEAD --budget 15 >/dev/null 2>&1 || true',
        "elif command -v py >/dev/null 2>&1; then",
        "    py -3 -m aramid triage HEAD --budget 15 >/dev/null 2>&1 || true",
```

`src/aramid/commands/triage_cmd.py` — full new file body (imports gain `os` and
`threading`; docstring gains the watchdog paragraph; the existing body is
UNCHANGED inside the new try/finally):

```python
"""aramid triage <rev> -- score one commit (or A..B range) and enqueue.

Called by the post-commit shim with HEAD (which additionally maps ANY
exit to 0 -- fail-open lives in the shim, spec section 6); usable
manually. Engine errors return 3 per the Phase 1 exit-code contract.

Watchdog (C-list hardening, supersedes Phase 2a spec section 6's "2s
self-timeout"): the shim passes --budget 15; when set, a daemon Timer is
armed BEFORE repo resolution / config load / ledger open, so every hang
class (wedged git subprocess, config read, sqlite, filesystem) is
downstream of it. On expiry it stderr-logs, flushes, and os._exit(3)s --
the shim maps that to 0 (fail-open), SQLite WAL is crash-safe against
the hard exit, and the drain catch-up sweep re-derives the lost enqueue.
Manual `aramid triage` without the flag stays unbounded.
"""
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from aramid import config as config_mod
from aramid import gitutil, triage
from aramid.ledger import Ledger


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _watchdog_kill(budget: float) -> None:
    print(f"aramid: triage: watchdog: exceeded {budget}s -- killing", file=sys.stderr)
    try:
        sys.stderr.flush()
        sys.stdout.flush()
    except Exception:
        pass
    os._exit(3)


def cmd_triage(root, rev: str = "HEAD", budget: float | None = None) -> int:
    timer = None
    if budget is not None:
        timer = threading.Timer(budget, _watchdog_kill, args=(budget,))
        timer.daemon = True
        timer.start()
    try:
        try:
            try:
                repo = gitutil.repo_root(Path(root).resolve())
            except gitutil.NotARepo:
                print("aramid: triage: not a git repository", file=sys.stderr)
                return 3
            if ".." in rev:
                base_rev, head_rev = rev.split("..", 1)
                base = gitutil.rev_sha(repo, base_rev)
                head = gitutil.rev_sha(repo, head_rev)
                if base is None or head is None:
                    print(f"aramid: triage: cannot resolve range {rev!r}", file=sys.stderr)
                    return 3
            else:
                head = gitutil.rev_sha(repo, rev)
                if head is None:
                    print(f"aramid: triage: cannot resolve rev {rev!r}", file=sys.stderr)
                    return 3
                base = gitutil.first_parent(repo, head)
            cfg = config_mod.load_config(repo)
            ledger = Ledger(repo / ".aramid" / "ledger.db")
            try:
                result, queued = triage.run_triage(repo, cfg, ledger, base, head, _now())
            finally:
                ledger.close()
            state = "queued" if queued else "below threshold"
            print(f"aramid triage: {head[:7]} score {result.score} ({state}); "
                  f"{'; '.join(result.reasons) or 'no signals'}")
            return 0
        except Exception as exc:  # engine error tier -- the hook maps this to 0 anyway
            print(f"aramid: triage: engine error: {exc}", file=sys.stderr)
            return 3
    finally:
        if timer is not None:
            timer.cancel()
```

`src/aramid/cli.py` — parser:

```python
    p_triage = sub.add_parser("triage", help="score a commit (or range) and enqueue if risky")
    p_triage.add_argument("rev", nargs="?", default="HEAD")
    p_triage.add_argument("--budget", type=float, default=None,
                          help="wall-clock watchdog in seconds; on expiry triage "
                               "self-kills with exit 3 (used by the post-commit shim)")
```

dispatch:

```python
    if args.command == "triage":
        return cmd_triage(root, args.rev, budget=args.budget)
```

`README.md` — append one sentence to the paragraph ending `...Task Scheduler
task \`aramid-drain\`).` (~line 76):

```
The post-commit hook self-kills after 15s (`--budget`), so a wedged triage can
never hang `git commit`; shims installed before this feature pick it up on the
next `aramid init` (idempotent shim regeneration).
```

- [ ] **Step 4: Run the tests to verify they pass**

```
python -m pytest tests/unit/test_hooks.py tests/integration/test_triage_cmd.py tests/integration/test_cli_dispatch.py -q
```

Expected: all PASS. Note `test_cli_dispatches_triage` (existing, subprocess)
and the e2e hook tests now exercise the real no-flag/flag paths respectively.

- [ ] **Step 5: Run the post-commit e2e suite (real git dispatch through the new shim)**

```
python -m pytest tests/e2e -q
```

Expected: PASS — the installed shim now carries `--budget 15` end-to-end and the
watchdog's normal cancel path runs live.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(triage): 15s watchdog via shim-passed --budget

Post-commit shim invokes 'aramid triage HEAD --budget 15'; cmd_triage
arms a daemon Timer FIRST (before repo/config/ledger -- every hang class
is downstream) that stderr-logs, flushes, and os._exit(3)s on expiry.
Shim maps any exit to 0 (fail-open), WAL is crash-safe, drain catch-up
recovers the lost enqueue. Manual triage without the flag is unbounded.
Supersedes Phase 2a spec section 6 (2s + log file) per design decision."
```

---

### Final gate (controller, not a task)

```bash
python -m ruff check src tests    # count == Task 1 Step-1 baseline
python -m pytest -q               # full suite green (687 base + new)
```

Then: whole-branch review, push + CI, `superpowers:finishing-a-development-branch`.
