# Aramid Release-Hardening Bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close three release-correctness residuals: the gitleaks `protect`→`git` staged-argv drift (+ real tests), a first-release `aramid rebaseline` command (+ churn doc + semgrep `rfind` nit), and self-dogfood config/doc honesty.

**Architecture:** Small edits confined to `runners/gitleaks.py`, a new `commands/rebaseline.py` + `cli.py` wiring, `runners/semgrep.py` one-liner, a committed root `aramid.toml`, and README prose. New tests: gitleaks argv unit, gitleaks live skip-if-absent integration, offline `_fix_gitleaks` download, rebaseline unit, semgrep `rfind` unit. Gate path behavior unchanged except the behavior-equivalent gitleaks argv.

**Tech Stack:** Python stdlib. Tests via `python -m pytest` (Windows: tools live in `%APPDATA%\Python\Python314\Scripts`, never bare `pytest`).

**Spec:** `docs/superpowers/specs/2026-07-20-aramid-release-hardening-design.md`

## Global Constraints

- Branch: `feat/release-hardening` off main @ 8ee652b. Never implement on main.
- Gate path unchanged except the intended gitleaks staged argv (behavior-equivalent on the pinned/CI gitleaks). No change to `pipeline.py`, `policy.py`, other runners, or hooks.
- Ruff parity: `python -m ruff check .` must equal the baseline measured at branch creation (expected 43). Every task matches it.
- Full suite green before merge: `python -m pytest -q` (766 base + new).
- Commit trailer on every commit: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` (omitted from inline commands below for brevity — always add it).
- gitleaks facts (verified vs v8.21.2 source `cmd/git.go`; CI installs 8.28.0 via `gacts/gitleaks@v1`): `gitleaks git` supports `--staged`; `--report-format`/`--report-path` are root flags usable on `git`; `protect` is deprecated (hidden in `--help`) but functional on 8.19–8.28; exit codes 0=clean, 1=leaks/error, 126=unknown flag.
- CI REALITY (supersedes spec §2 "add a CI step"): `.github/workflows/aramid.yml:32-36` ALREADY installs gitleaks on PATH, so the live test runs in CI with no workflow change. Leave that step as-is (hard, not `continue-on-error`): the existing `check --all --strict` dogfood step already hard-requires gitleaks, so softening the install would not decouple CI anyway. See Task 2 note.

---

### Task 1: gitleaks staged argv `protect`→`git`

**Files:**
- Modify: `src/aramid/runners/gitleaks.py:53-56` (staged branch of `_build_argv`), comments at `:47` and `:88`
- Test: `tests/unit/test_runner_gitleaks.py:37-44` (rewrite `test_staged_argv_uses_protect_staged`)

**Interfaces:**
- Produces: `_build_argv(ctx, report_path)` staged-mode (`ctx.rng is None`) returns `["gitleaks", "git", "--staged", "--report-format", "json", "--report-path", <p>]`. History mode unchanged.

- [ ] **Step 0: Create branch, record ruff baseline**

```bash
git checkout -b feat/release-hardening
python -m ruff check . 2>&1 | tail -1   # expect "Found 43 errors." — record it
```

- [ ] **Step 1: Rewrite the staged-argv unit test (red)**

In `tests/unit/test_runner_gitleaks.py`, replace `test_staged_argv_uses_protect_staged` (lines 37-44) with:

```python
def test_staged_argv_uses_git_staged(tmp_path):
    # protect is deprecated in gitleaks 8.19+ (removed in a future major ->
    # unknown-command -> CRASHED -> pre-commit fail-open lets secrets pass).
    # git --staged is the non-deprecated equivalent (verified vs v8.21.2
    # cmd/git.go), and matches the history path's `gitleaks git`.
    ctx = RunContext(root=tmp_path)
    report_path = tmp_path / "report.json"
    argv = gitleaks._build_argv(ctx, report_path)
    assert argv[:3] == ["gitleaks", "git", "--staged"]
    assert "protect" not in argv
    assert "--report-format" in argv and "json" in argv
    assert "--report-path" in argv and str(report_path) in argv
    assert "-" not in argv  # never pass "-" as a report-path sentinel
```

- [ ] **Step 2: Run it (red)**

Run: `python -m pytest tests/unit/test_runner_gitleaks.py::test_staged_argv_uses_git_staged -v`
Expected: FAIL — current argv[:3] is `["gitleaks", "protect", "--staged"]`.

- [ ] **Step 3: Fix the argv + comments**

`src/aramid/runners/gitleaks.py`, replace the staged return (lines 53-56):

```python
    return [
        "gitleaks", "git", "--staged",
        "--report-format", "json", "--report-path", str(report_path),
    ]
```

At `:47` change the comment `back to `protect --staged`.` → `back to `git --staged`.`. At `:88` change `the `protect` / `--staged` path scans the working tree/index` → `the `git --staged` path scans the working tree/index`.

- [ ] **Step 4: Run gitleaks unit tests (green)**

Run: `python -m pytest tests/unit/test_runner_gitleaks.py -v`
Expected: all PASS (the `FULL_HISTORY_RNG` test at :57 already asserts `"protect" not in argv` — still true).

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .   # == baseline
git add src/aramid/runners/gitleaks.py tests/unit/test_runner_gitleaks.py
git commit -m "fix(gitleaks): staged mode uses `git --staged`, not deprecated `protect` (fail-open guard)"
```

---

### Task 2: live skip-if-absent gitleaks integration test

**Files:**
- Create: `tests/integration/test_gitleaks_live.py`

**Interfaces:**
- Consumes: `gitleaks.run(ctx)` / `gitleaks.parse(result, ctx)`; `RunContext(root, rng=...)`; `ToolState`.

**CI note (no workflow change):** `.github/workflows/aramid.yml:32-36` already puts gitleaks 8.28.0 on PATH, so `shutil.which("gitleaks")` is truthy in CI and this test EXECUTES there; locally (no gitleaks) it SKIPS. That is the intended teeth. Do NOT add a new install step and do NOT mark the existing one `continue-on-error` — the `check --all --strict` dogfood step (`:46-47`) already hard-requires gitleaks, so CI cannot be decoupled from gitleaks provisioning regardless. (Observation, out of scope: CI pins 8.28.0 while `doctor.py:59` pins 8.21.2 for its own download — a version drift to reconcile in a later cleanup, not here.)

- [ ] **Step 1: Write the live test (skips locally)**

Create `tests/integration/test_gitleaks_live.py`:

```python
"""Live, skip-if-absent coverage for the gitleaks BLOCK-tier secrets gate.
Every other gitleaks test is fixture/monkeypatch-only; this one drives the
REAL binary end-to-end so argv/exit-contract drift (e.g. the deprecated
`protect` subcommand) is actually caught. Skips cleanly where gitleaks is
absent (local dev); runs in CI, which provisions gitleaks on PATH."""
import shutil
import subprocess
from pathlib import Path

import pytest

from aramid.runners import gitleaks
from aramid.runners.base import RunContext, ToolState

_GITLEAKS = shutil.which("gitleaks")
_SKIP = "gitleaks binary not on PATH (installed in CI, skipped in local dev)"

# A syntactically valid AWS access-key id (AKIA + 16 upper-alnum) that is NOT
# the canonical ...EXAMPLE key, to dodge any example-key allowlisting.
_SECRET = "AKIAZ7PB4XQK9WORNC2D"


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "readme.txt").write_text("clean\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "clean base")
    return r


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
def test_live_staged_secret_is_found(tmp_path):
    r = _repo(tmp_path)
    (r / "config.py").write_text(f'AWS_KEY = "{_SECRET}"\n', encoding="utf-8")
    _git(r, "add", "config.py")               # staged, not committed
    ctx = RunContext(root=r)                    # rng is None -> staged mode
    result = gitleaks.run(ctx)
    assert result.state is ToolState.OK, result.stderr
    findings = gitleaks.parse(result, ctx)
    assert any(_SECRET in (f.secret or "") for f in findings), \
        "real gitleaks git --staged must flag the staged AWS key"


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
def test_live_history_secret_is_found(tmp_path):
    r = _repo(tmp_path)
    (r / "config.py").write_text(f'AWS_KEY = "{_SECRET}"\n', encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "leak")
    ctx = RunContext(root=r, rng="")            # "" -> full-history scan
    result = gitleaks.run(ctx)
    assert result.state is ToolState.OK, result.stderr
    findings = gitleaks.parse(result, ctx)
    assert any(_SECRET in (f.secret or "") for f in findings)


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
def test_live_clean_tree_no_findings_and_exit_ok(tmp_path):
    r = _repo(tmp_path)
    (r / "notes.txt").write_text("nothing secret here\n", encoding="utf-8")
    _git(r, "add", "notes.txt")
    ctx = RunContext(root=r)
    result = gitleaks.run(ctx)
    # exit 0 (clean) stays OK; the {0,1} contract is honored by the real binary
    assert result.state is ToolState.OK, result.stderr
    assert gitleaks.parse(result, ctx) == []
```

- [ ] **Step 2: Run locally (must skip, not fail)**

Run: `python -m pytest tests/integration/test_gitleaks_live.py -v`
Expected: 3 SKIPPED (gitleaks absent locally). If gitleaks IS on your PATH, they must PASS.

- [ ] **Step 3: Ruff + commit**

```bash
python -m ruff check .
git add tests/integration/test_gitleaks_live.py
git commit -m "test(gitleaks): live skip-if-absent staged/history/clean coverage against the real binary"
```

---

### Task 3: offline `_fix_gitleaks` download test

**Files:**
- Create: `tests/integration/test_doctor_fix_gitleaks.py`

**Interfaces:**
- Consumes: `doctor._fix_gitleaks()`, `doctor._gitleaks_platform_key()`, `doctor._exe_name(name)`, `doctor._tools_dir()`, `doctor.GITLEAKS_SHA256`, `doctor.GITLEAKS_VERSION`.

- [ ] **Step 1: Write the offline test (red)**

Create `tests/integration/test_doctor_fix_gitleaks.py`:

```python
"""Offline coverage for doctor._fix_gitleaks download/checksum/extract path,
which is network-touching and never exercised elsewhere (all other doctor
tests monkeypatch the prober). We feed a synthetic archive through a
monkeypatched urlopen + injected checksum -- no network, runs everywhere."""
import hashlib
import io
import tarfile
import zipfile

import pytest

from aramid.commands import doctor


class _FakeResp:
    def __init__(self, data):
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._data


def _archive_for(platform_key, exe_name, payload=b"#!/fake gitleaks\n"):
    """Build the archive shape _fix_gitleaks expects for this platform:
    a zip (windows keys) or tar.gz (others) whose single member is exe_name."""
    buf = io.BytesIO()
    if "windows" in platform_key:
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(exe_name, payload)
    else:
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo(name=exe_name)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


@pytest.fixture
def _wired(tmp_path, monkeypatch):
    key = doctor._gitleaks_platform_key()
    if key is None:
        pytest.skip("no gitleaks platform key for this OS/arch")
    exe = doctor._exe_name("gitleaks")
    data = _archive_for(key, exe)
    monkeypatch.setattr(doctor, "_tools_dir", lambda: tmp_path / "tools")
    monkeypatch.setattr(doctor.urllib.request, "urlopen",
                        lambda url, timeout=60: _FakeResp(data))
    return key, exe, data, tmp_path


def test_fix_gitleaks_extracts_on_matching_checksum(_wired, monkeypatch):
    key, exe, data, tmp_path = _wired
    monkeypatch.setitem(doctor.GITLEAKS_SHA256, key, hashlib.sha256(data).hexdigest())
    assert doctor._fix_gitleaks() is True
    assert (tmp_path / "tools" / exe).exists()


def test_fix_gitleaks_rejects_on_bad_checksum(_wired, monkeypatch):
    key, exe, data, tmp_path = _wired
    monkeypatch.setitem(doctor.GITLEAKS_SHA256, key, "00" * 32)  # wrong sha
    assert doctor._fix_gitleaks() is False
    assert not (tmp_path / "tools" / exe).exists()
```

- [ ] **Step 2: Run it (red first, then green after confirming imports)**

Run: `python -m pytest tests/integration/test_doctor_fix_gitleaks.py -v`
Expected: PASS if `doctor` exposes `urllib`, `_gitleaks_platform_key`, `_exe_name`, `_tools_dir`, `GITLEAKS_SHA256`. If `doctor.urllib` is not importable as an attribute (it imports `urllib.request` at module top — verify with `python -c "from aramid.commands import doctor; print(doctor.urllib.request.urlopen)"`), monkeypatch `doctor.urllib.request.urlopen` is correct; if the module does `import urllib.request`, `doctor.urllib` resolves. Adjust the monkeypatch target to the actual import form if needed (e.g. `monkeypatch.setattr("urllib.request.urlopen", ...)`).

- [ ] **Step 3: Ruff + commit**

```bash
python -m ruff check .
git add tests/integration/test_doctor_fix_gitleaks.py
git commit -m "test(doctor): offline _fix_gitleaks download/checksum/extract coverage"
```

---

### Task 4: `aramid rebaseline` command + churn doc

**Files:**
- Create: `src/aramid/commands/rebaseline.py`
- Modify: `src/aramid/cli.py` (subparser + dispatch + import)
- Modify: `README.md` (new "Upgrading / re-baselining" subsection)
- Test: `tests/integration/test_rebaseline.py`

**Interfaces:**
- Produces: `cmd_rebaseline(root: Path, *, yes: bool = False) -> int` — returns 3 (no `--yes`, nothing written), 0 (rewrote baseline).

- [ ] **Step 1: Write the failing tests**

Create `tests/integration/test_rebaseline.py`:

```python
import subprocess
from pathlib import Path

from aramid import config as config_mod
from aramid.commands.rebaseline import cmd_rebaseline
from aramid.ledger import Ledger
from aramid.models import EventType


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    return r


def _baseline_snapshot_count(r):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        return sum(1 for e in led.events() if e.type is EventType.BASELINE_SNAPSHOT)
    finally:
        led.close()


def test_rebaseline_without_yes_refuses_and_writes_nothing(tmp_path, monkeypatch, capsys):
    r = _repo(tmp_path, monkeypatch)
    rc = cmd_rebaseline(r, yes=False)
    assert rc == 3
    assert _baseline_snapshot_count(r) == 0
    out = capsys.readouterr().out.lower()
    assert "--yes" in out  # tells the user how to actually do it


def test_rebaseline_with_yes_writes_a_baseline_snapshot(tmp_path, monkeypatch):
    r = _repo(tmp_path, monkeypatch)
    rc = cmd_rebaseline(r, yes=True)
    assert rc == 0
    assert _baseline_snapshot_count(r) == 1


def test_rebaseline_with_yes_overwrites_prior_baseline_latest_wins(tmp_path, monkeypatch):
    r = _repo(tmp_path, monkeypatch)
    assert cmd_rebaseline(r, yes=True) == 0
    assert cmd_rebaseline(r, yes=True) == 0
    # baseline_ids is latest-wins; two snapshots exist but the accepted set is
    # the newest one (proving re-baseline supersedes, not appends-to).
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        assert _baseline_snapshot_count(r) == 2
        snaps = [e for e in led.events() if e.type is EventType.BASELINE_SNAPSHOT]
        assert led.baseline_ids() == set(snaps[-1].payload.get("ids", []))
    finally:
        led.close()
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/integration/test_rebaseline.py -v`
Expected: FAIL — `ModuleNotFoundError: aramid.commands.rebaseline`.

- [ ] **Step 3: Implement the command**

Create `src/aramid/commands/rebaseline.py`:

```python
"""`aramid rebaseline`: re-snapshot the current findings as the accepted
ratchet baseline. First-release recovery for fingerprint churn -- when an
aramid upgrade changes rule/path normalization, grandfathered findings
re-fingerprint and the ratchet re-escalates them as new BLOCKs; rebaseline
re-accepts the current set. Destructive to grandfathering, so it refuses
without an explicit --yes (no interactive prompt: safe in hooks/CI)."""
import datetime as _dt
from pathlib import Path

from aramid import config as config_mod
from aramid.ledger import Ledger
from aramid.models import Gate
from aramid.pipeline import run_gate


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def cmd_rebaseline(root: Path, *, yes: bool = False) -> int:
    cfg = config_mod.load_config(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        old = len(ledger.baseline_ids())
        if not yes:
            print(f"aramid: rebaseline: would discard the current baseline "
                  f"({old} grandfathered finding(s)) and re-snapshot the current "
                  f"gate result. This drops ratchet grandfathering. Re-run with "
                  f"--yes to proceed.")
            return 3
        result = run_gate(root, Gate.ALL, "all", cfg, ledger)
        new_ids = {f.id for f in result.findings}
        ledger.write_baseline(result.run_id, _now(), new_ids)
        print(f"aramid: rebaseline: baseline rewritten ({old} -> {len(new_ids)} "
              f"finding(s) accepted).")
        return 0
    finally:
        ledger.close()
```

- [ ] **Step 4: Wire into cli.py**

In `src/aramid/cli.py`, add the import near the other command imports (match existing style, e.g. alongside `from aramid.commands.uninstall import cmd_uninstall`):

```python
from aramid.commands.rebaseline import cmd_rebaseline
```

Add the subparser after the `schedule` parser block (after line 118):

```python
    p_rebaseline = sub.add_parser("rebaseline",
                                  help="re-snapshot current findings as the ratchet baseline (after a fingerprint-affecting upgrade)")
    p_rebaseline.add_argument("path", nargs="?", default=".")
    p_rebaseline.add_argument("--yes", action="store_true",
                              help="required: confirms discarding current ratchet grandfathering")
```

Add the dispatch branch before the final `print(f"aramid: unknown command...")` (after the `schedule` branch, line 214):

```python
    if args.command == "rebaseline":
        return cmd_rebaseline(Path(args.path), yes=args.yes)
```

- [ ] **Step 5: Run tests (green)**

Run: `python -m pytest tests/integration/test_rebaseline.py -v` and `python -m pytest tests -k "cli or dispatch" -q`
Expected: rebaseline tests PASS; CLI dispatch tests unaffected.

- [ ] **Step 6: Add the churn/upgrade README doc**

In `README.md`, add a subsection (place it after the exit-code/roadmap material, before the Phase 2a section, so it reads as operational guidance). Insert:

```markdown
### Upgrading / re-baselining

A finding's identity is `sha256(tool + rule + normalized-path + sha256(normalized-line) + occurrence-index)`. Rule-id and path normalization feed that hash, so an aramid upgrade that changes them re-fingerprints already-accepted findings — the ratchet then sees them as new and can escalate them to BLOCK. After such an upgrade, run:

    aramid rebaseline --yes

to re-snapshot the current findings as the accepted baseline. This discards prior ratchet grandfathering (that is the point), so review the gate output first. Without `--yes` the command only reports what it would discard and exits non-zero.
```

- [ ] **Step 7: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/commands/rebaseline.py src/aramid/cli.py tests/integration/test_rebaseline.py README.md
git commit -m "feat(cli): aramid rebaseline command + fingerprint-churn upgrade doc"
```

---

### Task 5: semgrep `_canonical_rule_id` leftmost→rightmost

**Files:**
- Modify: `src/aramid/runners/semgrep.py:67-70`
- Test: `tests/unit/test_runner_semgrep.py` (add one test; if that file doesn't exist, use the semgrep test file that does — find via `python -m pytest tests -k semgrep --collect-only -q`)

**Interfaces:**
- Produces: `_canonical_rule_id(check_id)` uses `rfind` (rightmost prefix occurrence).

- [ ] **Step 1: Write the failing test**

Add to the semgrep runner unit test file:

```python
def test_canonical_rule_id_uses_rightmost_prefix_occurrence():
    from aramid.runners.semgrep import _canonical_rule_id, _CANONICAL_RULE_PREFIX
    # A checkout path that itself embeds the literal prefix must not truncate
    # the id early -- the REAL canonical id is the rightmost occurrence.
    cid = f"/src/{_CANONICAL_RULE_PREFIX}junk/config/{_CANONICAL_RULE_PREFIX}sqli"
    assert _canonical_rule_id(cid) == f"{_CANONICAL_RULE_PREFIX}sqli"
```

- [ ] **Step 2: Run it (red)**

Run: `python -m pytest tests -k "canonical_rule_id_uses_rightmost" -v`
Expected: FAIL — leftmost `.find` returns the first (junk) occurrence.

- [ ] **Step 3: Implement**

`src/aramid/runners/semgrep.py`, in `_canonical_rule_id` change the loop body (lines 67-70):

```python
    for prefix in (_CANONICAL_RULE_PREFIX, _PACK_RULE_PREFIX):
        idx = check_id.rfind(prefix)
        if idx != -1:
            return check_id[idx:]
    return check_id
```

Update the docstring "Finds the LEFTMOST occurrence" → "Finds the RIGHTMOST occurrence" (and the `:56` "LEFTMOST" wording).

- [ ] **Step 4: Run semgrep tests (green)**

Run: `python -m pytest tests -k semgrep -q`
Expected: all PASS (normal single-occurrence ids identical under `find`/`rfind`).

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/runners/semgrep.py tests/unit/test_runner_semgrep.py
git commit -m "fix(semgrep): canonical rule-id uses rightmost prefix (robust to checkout paths embedding the literal)"
```

---

### Task 6: self-dogfood config + honest README + final gate

**Files:**
- Create: `aramid.toml` (repo root)
- Modify: `README.md:71-72` and `:80` (honest framing)

- [ ] **Step 1: Commit a neutral root `aramid.toml`**

Create `aramid.toml` at the repo root:

```toml
# aramid dogfoods itself: this is the config a maintainer's `aramid init .`
# would write. Kept to schema_version only -- equal to built-in defaults, so
# aramid's own CI gate (`aramid check --all --strict --json`) is unchanged.
schema_version = 1
```

Verify neutrality: `python -m aramid check --all --json > /tmp/after.json 2>&1 || true` and confirm it runs the same selection as before (no config-driven behavior change; a bare `schema_version` sets no overrides). The full suite + CI dogfood are the durable guard.

- [ ] **Step 2: Fix the README claims**

In `README.md`, replace lines 71-72 (currently "the code has landed and is dogfooded here, though it is not yet wired into this repo's own hooks or drain schedule."):

```markdown
Phase 2 starts with a zero-token chassis — the code has landed, and this repo
carries its config (`aramid.toml`). The triage hook and scheduled drain are a
per-clone local step (`.git/hooks` is not version-controlled): run `aramid init .`
to install the post-commit triage shim and `aramid schedule install` to register
the drain job.
```

Replace the `:80` parenthetical (currently "The regression attack pack (`.aramid-rules/regression.yml`, committed) replays..."):

```markdown
The regression attack pack (`.aramid-rules/regression.yml`) replays rules
compiled from resolved findings — `aramid pack compile` writes it, and an
adopting repo commits it (this repo has none yet: no findings resolved). It
reintroduces a rotated secret or banned dependency as a pre-push block.
```

- [ ] **Step 3: Full-suite + ruff gate**

Run: `python -m pytest -q`
Expected: 766 base + ~13 new (3 gitleaks-live [skip locally], 2 offline-fix, 3 rebaseline, 1 argv, 1 semgrep, plus any collateral), all green/skipped.
Run: `python -m ruff check .` — must equal the recorded baseline.

- [ ] **Step 4: Commit**

```bash
git add aramid.toml README.md
git commit -m "chore(dogfood): commit aramid.toml; correct README hooks/pack claims"
```

After Task 6: whole-branch review (sonnet subagent per project convention), fix wave if needed, then superpowers:finishing-a-development-branch.

---

## Self-Review notes (author)

- **Spec §2 (gitleaks)** → Tasks 1 (argv+unit), 2 (live), 3 (offline). CI: no change needed (already provisioned) — documented in Task 2, supersedes spec's "add a step".
- **Spec §3 (rebaseline + doc + semgrep nit)** → Tasks 4 (command+doc), 5 (semgrep rfind).
- **Spec §4 (self-dogfood)** → Task 6.
- **Invariants:** gate path only changes gitleaks argv (Task 1, behavior-equivalent); rebaseline additive (Task 4); aramid.toml neutral (Task 6 Step 1); semgrep rfind strict-improvement (Task 5). All covered.
- **Type consistency:** `cmd_rebaseline(root, *, yes)` signature identical in impl (Task 4 Step 3), cli dispatch (Step 4), tests (Step 1). `_build_argv(ctx, report_path)` unchanged arity.
