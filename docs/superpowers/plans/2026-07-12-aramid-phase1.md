# Aramid Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the deterministic security/quality gate engine `aramid` — a Python CLI that runs industry-standard checkers at git pre-commit/pre-push and normalizes their output into one severity-tiered findings model backed by a SQLite event ledger.

**Architecture:** A standalone Python package invoked as `python -m aramid`, installed editable into one interpreter, activated per-repo via `aramid init`. Six layers — detectors, runners (one adapter per tool), normalizer, policy, ledger, reporter — orchestrated by a pipeline that a git-hook shim calls. Zero LLM. The findings schema, ledger, and exit-code contract are the shared currency for later phases.

**Tech Stack:** Python 3.14, stdlib `argparse`/`sqlite3`/`subprocess`/`hashlib`/`tomllib`; `tomli-w` for writing TOML; external checkers gitleaks, semgrep, ruff, eslint, tsc, mypy, pip-audit, npm/pnpm/yarn audit, pytest; pytest for aramid's own tests. Host is Windows 11 (Git for Windows sh hooks, PowerShell).

## Global Constraints

- **Spec of record:** `docs/superpowers/specs/2026-07-12-aramid-phase1-design.md`. Every task implements part of it; re-read the cited section before starting a task.
- **Python floor:** 3.11+ (uses `tomllib`); target/dev on 3.14.
- **Package name / module:** distribution `aramid`, import `aramid`, entry `python -m aramid`.
- **Windows-first correctness:** all file writes that become shell scripts use binary mode with explicit `\n`; never rely on bare `python` in a hook; never `git add -A` in this repo (graphite daemon drops artifacts — use explicit paths).
- **State dirs:** per-repo state in `.aramid/` (gitignored); user config `~/.aramid/config.toml`; salt `.aramid/salt`; ledger `.aramid/ledger.db`; tool cache `.aramid/cache/`; logs `.aramid/logs/`.
- **Ignore paths (built-in, always):** `.aramid/`, `graph-out/`, `.graphite*`, `.cache/`, `node_modules/`, `.venv/`, `__pycache__/`, `.git/` — aramid never scans or fingerprints these (graphite coexistence, §8b).
- **Exit codes:** `0` pass · `1` blocking · `2` pass-but-degraded (WARN-tier skip) · `3` engine/config error. Shim maps: pre-commit `{2,3}→0`; pre-push `2→0`, `{1,3}` block. `--strict` treats `{2,3}` as failure.
- **Fingerprint (frozen):** `sha256( tool + "\x1f" + rule + "\x1f" + norm_path + "\x1f" + sha256(ws_normalized_line) + "\x1f" + str(occurrence_index) )`. Line number is NEVER an input. Line content comes from the git object being scanned, not the worktree.
- **Secret hygiene:** raw secret material never persisted anywhere. Store `first2…last2` preview + `sha256(salt + match)`.
- **TDD:** every task writes the failing test first, watches it fail, implements minimally, watches it pass, commits. Conventional-commit messages.
- **Never** skip hooks with `--no-verify` in aramid's own commits, and never weaken a gate to make a test pass.

---

## File structure

```
aramid/
  pyproject.toml
  src/aramid/
    __init__.py            # __version__
    __main__.py            # python -m aramid -> cli.main()
    cli.py                 # argparse tree, dispatch
    models.py              # enums + Finding + Event dataclasses
    fingerprint.py         # frozen fingerprint algorithm
    redact.py              # secret preview + salted hash, salt load/create
    gitutil.py             # repo root, blob reads, range resolution, changed files
    detectors.py           # stack / package-manager / tests / nested-git / scope
    config.py              # layered config (defaults + user + repo toml)
    ledger.py              # SQLite event store + materialized state + baseline/ratchet
    normalizer.py          # raw tool output -> list[Finding]
    policy.py              # severity->verdict, block-list, override/suppression, escalation
    pipeline.py            # run a gate: select, run concurrently, budget, verdict, events
    reporter.py            # console + json, exit-code selection
    hooks.py               # shim gen, chaining, core.hooksPath, install/uninstall
    runners/
      __init__.py          # registry
      base.py              # Runner protocol, run_subprocess (tree-kill/timeout), RunnerResult, ToolState
      gitleaks.py
      ruff.py
      semgrep.py
      eslint.py
      typecheck.py         # tsc + mypy
      deps.py              # pip-audit / npm|pnpm|yarn audit (+ cache)
      tests.py             # pytest / npm test
    commands/
      __init__.py
      init.py              # + discover
      check.py
      doctor.py
      status.py
      ledger_cmd.py        # list/show/filter/mark-rotated
      override.py
      arm.py
      update_rules.py
      uninstall.py
    data/
      block_rules.toml     # curated BLOCK-tier rule-ID list (ruff-S + semgrep)
      defaults.toml        # built-in default config
      rules/semgrep/owasp.yml  # vendored OWASP ruleset (pinned)
      ARAMID.md.tmpl       # per-repo doc template
  tests/
    unit/  integration/  e2e/  fixtures/
```

---

## Milestone M0 — Project scaffold

### Task 0.1: Package skeleton, version, owned toolchain

**Files:**
- Create: `pyproject.toml`, `src/aramid/__init__.py`, `src/aramid/__main__.py`, `src/aramid/cli.py`
- Test: `tests/unit/test_version.py`

**Interfaces:**
- Produces: `aramid.__version__: str`; `aramid.cli.main(argv: list[str] | None = None) -> int`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_version.py
import subprocess, sys

def test_version_flag_prints_semver():
    out = subprocess.run([sys.executable, "-m", "aramid", "--version"],
                         capture_output=True, text=True)
    assert out.returncode == 0
    assert out.stdout.strip().startswith("aramid ")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_version.py -v`
Expected: FAIL (No module named aramid).

- [ ] **Step 3: Write minimal implementation**

```toml
# pyproject.toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "aramid"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["tomli-w>=1.0", "pip-audit>=2.7", "ruff>=0.6", "semgrep>=1.100"]

[project.scripts]
aramid = "aramid.cli:main"

[tool.setuptools.packages.find]
where = ["src"]
```

```python
# src/aramid/__init__.py
__version__ = "0.1.0"
```

```python
# src/aramid/__main__.py
import sys
from aramid.cli import main
sys.exit(main())
```

```python
# src/aramid/cli.py
import argparse, sys
from aramid import __version__

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aramid")
    p.add_argument("--version", action="store_true")
    p.add_argument("command", nargs="?")
    return p

def main(argv: list[str] | None = None) -> int:
    args, _ = build_parser().parse_known_args(argv)
    if args.version:
        print(f"aramid {__version__}")
        return 0
    print("aramid: no command", file=sys.stderr)
    return 3
```

- [ ] **Step 4: Verify pass**

Run: `pip install -e . && pytest tests/unit/test_version.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/aramid tests/unit/test_version.py
git commit -m "feat: package skeleton with version command and owned toolchain deps"
```

---

## Milestone M1 — Core data model, fingerprint, redaction

### Task 1.1: Data model (enums, Finding, Event)

**Files:**
- Create: `src/aramid/models.py`
- Test: `tests/unit/test_models.py`

**Interfaces:**
- Produces:
  - `class Severity(StrEnum)`: `INFO, LOW, MEDIUM, HIGH, CRITICAL`
  - `class Verdict(StrEnum)`: `BLOCK, WARN, INFO`
  - `class Status(StrEnum)`: `OPEN, FIXED, OVERRIDDEN, HISTORICAL, ROTATED`
  - `class Gate(StrEnum)`: `PRE_COMMIT, PRE_PUSH, ALL`
  - `class Source(StrEnum)`: `DETERMINISTIC, LLM`
  - `class EventType(StrEnum)`: `RUN_STARTED, RUN_FINISHED, FINDING_DETECTED, FINDING_RESOLVED, FINDING_OVERRIDDEN, FINDING_ROTATED, INFRASTRUCTURE_BYPASS, BASELINE_SNAPSHOT`
  - `@dataclass(frozen=True) class Finding`: `id, tool, rule, severity_raw:str, severity:Severity, verdict:Verdict, file:str, line:int, message:str, evidence:str, gate:Gate, source:Source=DETERMINISTIC, historical:bool=False`
  - `@dataclass(frozen=True) class Event`: `type:EventType, run_id:str, at:str, finding_id:str|None=None, payload:dict=field(default_factory=dict)`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_models.py
from aramid.models import Finding, Verdict, Severity, Gate, Source

def test_finding_is_frozen_and_defaults_deterministic():
    f = Finding(id="x", tool="ruff", rule="S102", severity_raw="high",
                severity=Severity.HIGH, verdict=Verdict.BLOCK, file="a.py",
                line=3, message="exec used", evidence="exec(x)", gate=Gate.PRE_COMMIT)
    assert f.source is Source.DETERMINISTIC
    assert f.historical is False
    import dataclasses
    try:
        f.line = 9  # frozen
        assert False
    except dataclasses.FrozenInstanceError:
        pass
```

- [ ] **Step 2: Run test — expect FAIL** (`No module named aramid.models`).

- [ ] **Step 3: Implement**

```python
# src/aramid/models.py
from dataclasses import dataclass, field
from enum import StrEnum

class Severity(StrEnum):
    INFO="info"; LOW="low"; MEDIUM="medium"; HIGH="high"; CRITICAL="critical"
class Verdict(StrEnum):
    BLOCK="block"; WARN="warn"; INFO="info"
class Status(StrEnum):
    OPEN="open"; FIXED="fixed"; OVERRIDDEN="overridden"; HISTORICAL="historical"; ROTATED="rotated"
class Gate(StrEnum):
    PRE_COMMIT="pre-commit"; PRE_PUSH="pre-push"; ALL="all"
class Source(StrEnum):
    DETERMINISTIC="deterministic"; LLM="llm"
class EventType(StrEnum):
    RUN_STARTED="run_started"; RUN_FINISHED="run_finished"
    FINDING_DETECTED="finding_detected"; FINDING_RESOLVED="finding_resolved"
    FINDING_OVERRIDDEN="finding_overridden"; FINDING_ROTATED="finding_rotated"
    INFRASTRUCTURE_BYPASS="infrastructure_bypass"; BASELINE_SNAPSHOT="baseline_snapshot"

@dataclass(frozen=True)
class Finding:
    id: str; tool: str; rule: str; severity_raw: str; severity: Severity
    verdict: Verdict; file: str; line: int; message: str; evidence: str
    gate: Gate; source: Source = Source.DETERMINISTIC; historical: bool = False

@dataclass(frozen=True)
class Event:
    type: EventType; run_id: str; at: str
    finding_id: str | None = None; payload: dict = field(default_factory=dict)
```

- [ ] **Step 4: Verify pass** — `pytest tests/unit/test_models.py -v` → PASS.
- [ ] **Step 5: Commit** — `git add src/aramid/models.py tests/unit/test_models.py && git commit -m "feat: core data model — Finding, Event, and enums"`

### Task 1.2: Fingerprint algorithm

**Files:**
- Create: `src/aramid/fingerprint.py`
- Test: `tests/unit/test_fingerprint.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `normalize_path(path: str) -> str` (forward slashes, casefold)
  - `normalize_line(line: str) -> str` (collapse runs of whitespace to single space, strip)
  - `compute_fingerprint(tool: str, rule: str, path: str, line_content: str, occurrence_index: int) -> str`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_fingerprint.py
from aramid.fingerprint import compute_fingerprint, normalize_line

def test_id_stable_across_line_shift_and_crlf():
    a = compute_fingerprint("ruff","S102","src/a.py","    exec(x)\n",0)
    b = compute_fingerprint("ruff","S102","src/a.py","    exec(x)\r\n",0)   # CRLF
    c = compute_fingerprint("ruff","S102","SRC/A.PY","exec(x)",0)           # ws+case
    assert a == b == c

def test_occurrence_index_disambiguates_identical_lines():
    assert compute_fingerprint("ruff","S102","a.py","exec(x)",0) != \
           compute_fingerprint("ruff","S102","a.py","exec(x)",1)

def test_editing_line_changes_id():
    assert compute_fingerprint("ruff","S102","a.py","exec(x)",0) != \
           compute_fingerprint("ruff","S102","a.py","exec(y)",0)
```

- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement**

```python
# src/aramid/fingerprint.py
import hashlib, re
_WS = re.compile(r"\s+")

def normalize_path(path: str) -> str:
    return path.replace("\\", "/").casefold()

def normalize_line(line: str) -> str:
    return _WS.sub(" ", line).strip()

def compute_fingerprint(tool, rule, path, line_content, occurrence_index) -> str:
    line_hash = hashlib.sha256(normalize_line(line_content).encode()).hexdigest()
    key = "\x1f".join([tool, rule, normalize_path(path), line_hash, str(occurrence_index)])
    return hashlib.sha256(key.encode()).hexdigest()
```

- [ ] **Step 4: Verify pass.**
- [ ] **Step 5: Commit** — `git commit -m "feat: frozen fingerprint algorithm with drift/CRLF/occurrence tests"`

### Task 1.3: Secret redaction + per-repo salt

**Files:**
- Create: `src/aramid/redact.py`
- Test: `tests/unit/test_redact.py`

**Interfaces:**
- Produces:
  - `load_or_create_salt(aramid_dir: Path) -> bytes` (reads `<aramid_dir>/salt`, else creates 32 random bytes, 0600 where supported)
  - `redact(secret: str, salt: bytes) -> tuple[str, str]` returns `(preview, hashed)` where preview is `f"{s[:2]}…{s[-2:]}"` for len≥5 else `"…"`, hashed is `sha256(salt+secret).hexdigest()`
  - `scrub(text: str, secrets: list[str]) -> str` replaces every raw secret occurrence in `text` with its preview (for stderr logs)

- [ ] **Step 1: Failing test**

```python
# tests/unit/test_redact.py
from pathlib import Path
from aramid.redact import load_or_create_salt, redact, scrub

def test_salt_is_stable(tmp_path: Path):
    s1 = load_or_create_salt(tmp_path); s2 = load_or_create_salt(tmp_path)
    assert s1 == s2 and len(s1) == 32

def test_redact_hides_body_but_is_stable(tmp_path):
    salt = load_or_create_salt(tmp_path)
    p, h = redact("AKIAABCDEFGH1234", salt)
    assert p == "AK…34" and "ABCDEFGH" not in p
    assert redact("AKIAABCDEFGH1234", salt)[1] == h

def test_scrub_removes_raw_secret_from_logs(tmp_path):
    salt = load_or_create_salt(tmp_path)
    assert "SEKRET" not in scrub("leaked=SEKRETvalue", ["SEKRETvalue"])
```

- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement**

```python
# src/aramid/redact.py
import hashlib, os
from pathlib import Path

def load_or_create_salt(aramid_dir: Path) -> bytes:
    f = aramid_dir / "salt"
    if f.exists():
        return f.read_bytes()
    aramid_dir.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(32)
    f.write_bytes(salt)
    try: os.chmod(f, 0o600)
    except OSError: pass
    return salt

def redact(secret: str, salt: bytes) -> tuple[str, str]:
    preview = f"{secret[:2]}…{secret[-2:]}" if len(secret) >= 5 else "…"
    return preview, hashlib.sha256(salt + secret.encode()).hexdigest()

def scrub(text: str, secrets: list[str]) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, f"{s[:2]}…{s[-2:]}" if len(s) >= 5 else "…")
    return text
```

- [ ] **Step 4: Verify pass. Step 5: Commit** — `git commit -m "feat: secret redaction and per-repo salt"`

---

## Milestone M2 — Git utilities and detectors

### Task 2.1: Git helpers

**Files:**
- Create: `src/aramid/gitutil.py`
- Test: `tests/unit/test_gitutil.py` (uses a real temp git repo)

**Interfaces:**
- Produces:
  - `repo_root(path: Path) -> Path` (`git rev-parse --show-toplevel`; raises `NotARepo` if none)
  - `class NotARepo(Exception)`
  - `read_blob(root: Path, ref: str, rel_path: str) -> str` (`git show <ref>:<rel_path>`; `ref=":"` means index; returns "" if missing)
  - `resolve_range(root: Path) -> str | None` (chain: `@{u}..HEAD`; else `merge-base(origin/HEAD,HEAD)..HEAD`; else `None` meaning "all reachable from HEAD")
  - `range_commits(root: Path, rng: str | None) -> list[str]`
  - `staged_files(root: Path) -> list[str]`; `changed_files(root: Path, rng: str | None) -> list[str]`
  - `newest_commit_touching(root: Path, rng: str | None, rel_path: str) -> str` (returns `":"` when rng is None-for-index contexts; else the newest sha in range that modified the file, else `HEAD`)

- [ ] **Step 1: Failing test** (helper builds a repo)

```python
# tests/unit/test_gitutil.py
import subprocess
from pathlib import Path
from aramid import gitutil

def _git(root, *a): subprocess.run(["git", *a], cwd=root, check=True,
                                   capture_output=True, text=True)

def _repo(tmp_path) -> Path:
    r = tmp_path / "r"; r.mkdir(); _git(r, "init", "-b", "main")
    _git(r, "config", "user.email", "t@t"); _git(r, "config", "user.name", "t")
    return r

def test_repo_root_and_blob(tmp_path):
    r = _repo(tmp_path)
    (r / "a.py").write_text("print(1)\n")
    _git(r, "add", "a.py"); _git(r, "commit", "-m", "x")
    assert gitutil.repo_root(r / ".") == r.resolve()
    assert gitutil.read_blob(r, "HEAD", "a.py") == "print(1)\n"

def test_not_a_repo_raises(tmp_path):
    import pytest
    with pytest.raises(gitutil.NotARepo):
        gitutil.repo_root(tmp_path)
```

- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** (subprocess wrappers; `resolve_range` tries each rev-parse and swallows `CalledProcessError`)

```python
# src/aramid/gitutil.py
import subprocess
from pathlib import Path

class NotARepo(Exception): ...

def _run(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(root), capture_output=True, text=True)

def repo_root(path: Path) -> Path:
    cp = _run(path, "rev-parse", "--show-toplevel")
    if cp.returncode != 0:
        raise NotARepo(str(path))
    return Path(cp.stdout.strip()).resolve()

def read_blob(root: Path, ref: str, rel_path: str) -> str:
    spec = f"{ref}:{rel_path}" if ref != ":" else f":{rel_path}"
    cp = _run(root, "show", spec)
    return cp.stdout if cp.returncode == 0 else ""

def resolve_range(root: Path):
    if _run(root, "rev-parse", "@{u}").returncode == 0:
        return "@{u}..HEAD"
    head = _run(root, "symbolic-ref", "refs/remotes/origin/HEAD")
    if head.returncode == 0:
        base = head.stdout.strip()
        mb = _run(root, "merge-base", base, "HEAD")
        if mb.returncode == 0:
            return f"{mb.stdout.strip()}..HEAD"
    return None

def range_commits(root: Path, rng):
    spec = rng if rng else "HEAD"
    cp = _run(root, "rev-list", spec)
    return [l for l in cp.stdout.splitlines() if l] if cp.returncode == 0 else []

def staged_files(root: Path):
    cp = _run(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR")
    return [l for l in cp.stdout.splitlines() if l]

def changed_files(root: Path, rng):
    spec = rng if rng else "HEAD"
    cp = _run(root, "diff", "--name-only", "--diff-filter=ACMR", spec)
    return [l for l in cp.stdout.splitlines() if l]

def newest_commit_touching(root: Path, rng, rel_path):
    spec = rng if rng else "HEAD"
    cp = _run(root, "log", "-1", "--format=%H", spec, "--", rel_path)
    return cp.stdout.strip() or "HEAD"
```

- [ ] **Step 4: Verify pass. Step 5: Commit** — `git commit -m "feat: git helpers — root, blob reads, range resolution"`

### Task 2.2: Detectors (stack, package manager, tests, topology)

**Files:**
- Create: `src/aramid/detectors.py`
- Test: `tests/unit/test_detectors.py`

**Interfaces:**
- Produces:
  - `detect_stacks(root: Path, scope: Path) -> set[str]` (subset of `{"python","js"}` by presence of `*.py`/`pyproject.toml` and `package.json`)
  - `detect_package_manager(root: Path) -> str | None` (`package-lock.json`→"npm", `pnpm-lock.yaml`→"pnpm", `yarn.lock`→"yarn", else None)
  - `detect_tests(root: Path) -> set[str]` (`{"pytest"}` if `tests/`/`test_*.py`; `{"npm"}` if package.json has a `test` script)
  - `nested_git_dirs(root: Path) -> list[Path]` (immediate-and-deeper `.git` dirs below root, excluding root's own)

- [ ] **Step 1: Failing test**

```python
# tests/unit/test_detectors.py
from pathlib import Path
from aramid import detectors

def test_stack_and_pm(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_path / "package.json").write_text('{"scripts":{"test":"vitest"}}')
    (tmp_path / "pnpm-lock.yaml").write_text("")
    assert detectors.detect_stacks(tmp_path, tmp_path) == {"python", "js"}
    assert detectors.detect_package_manager(tmp_path) == "pnpm"
    assert "npm" in detectors.detect_tests(tmp_path)
```

- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement**

```python
# src/aramid/detectors.py
import json
from pathlib import Path

def detect_stacks(root: Path, scope: Path) -> set[str]:
    s = set()
    if (root / "pyproject.toml").exists() or any(scope.rglob("*.py")): s.add("python")
    if (root / "package.json").exists(): s.add("js")
    return s

def detect_package_manager(root: Path):
    for f, name in (("package-lock.json","npm"),("pnpm-lock.yaml","pnpm"),("yarn.lock","yarn")):
        if (root / f).exists(): return name
    return None

def detect_tests(root: Path) -> set[str]:
    out = set()
    if (root / "tests").exists() or any(root.rglob("test_*.py")): out.add("pytest")
    pj = root / "package.json"
    if pj.exists():
        try:
            if "test" in json.loads(pj.read_text()).get("scripts", {}): out.add("npm")
        except (ValueError, OSError): pass
    return out

def nested_git_dirs(root: Path) -> list[Path]:
    return [p.parent for p in root.rglob(".git")
            if p.parent.resolve() != root.resolve() and "node_modules" not in p.parts]
```

- [ ] **Step 4: Verify pass. Step 5: Commit** — `git commit -m "feat: detectors — stack, package manager, tests, nested repos"`

---

## Milestone M3 — Ledger (SQLite event store)

### Task 3.1: Event store schema + append/read

**Files:**
- Create: `src/aramid/ledger.py`
- Test: `tests/unit/test_ledger_events.py`

**Interfaces:**
- Consumes: `models.Event, EventType`.
- Produces:
  - `class Ledger` with `__init__(self, db_path: Path)`, `append(self, event: Event) -> None`, `events(self) -> list[Event]`, `close(self)`
  - Table `events(seq INTEGER PK AUTOINCREMENT, type TEXT, run_id TEXT, at TEXT, finding_id TEXT, payload TEXT)` — `payload` is JSON.
  - Uses `PRAGMA journal_mode=WAL` for concurrent hook+manual writes.

- [ ] **Step 1: Failing test**

```python
# tests/unit/test_ledger_events.py
from aramid.ledger import Ledger
from aramid.models import Event, EventType

def test_append_and_read_roundtrip(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.append(Event(EventType.RUN_STARTED, "run1", "2026-07-12T00:00:00Z",
                     payload={"gate": "pre-commit"}))
    got = led.events()
    assert len(got) == 1 and got[0].run_id == "run1"
    assert got[0].payload["gate"] == "pre-commit"
    led.close()
```

- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement**

```python
# src/aramid/ledger.py
import json, sqlite3
from pathlib import Path
from aramid.models import Event, EventType

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL, run_id TEXT NOT NULL, at TEXT NOT NULL,
  finding_id TEXT, payload TEXT NOT NULL DEFAULT '{}');
"""

class Ledger:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._c = sqlite3.connect(str(db_path))
        self._c.execute("PRAGMA journal_mode=WAL")
        self._c.executescript(_SCHEMA)
        self._c.commit()

    def append(self, event: Event) -> None:
        self._c.execute(
            "INSERT INTO events(type,run_id,at,finding_id,payload) VALUES(?,?,?,?,?)",
            (str(event.type), event.run_id, event.at, event.finding_id,
             json.dumps(event.payload)))
        self._c.commit()

    def events(self) -> list[Event]:
        rows = self._c.execute(
            "SELECT type,run_id,at,finding_id,payload FROM events ORDER BY seq").fetchall()
        return [Event(EventType(t), r, a, fid, json.loads(p)) for t, r, a, fid, p in rows]

    def close(self): self._c.close()
```

- [ ] **Step 4: Verify pass. Step 5: Commit** — `git commit -m "feat: SQLite event ledger — append and read"`

### Task 3.2: Materialized finding state with scope-aware resolution

**Files:**
- Modify: `src/aramid/ledger.py`
- Test: `tests/unit/test_ledger_state.py`

**Interfaces:**
- Produces on `Ledger`:
  - `record_run(self, run_id, at, gate, scope_tools: set[str], scope_files: set[str], findings: list[Finding]) -> list[str]` — appends `RUN_STARTED`, one `FINDING_DETECTED` per finding not already open, one `FINDING_RESOLVED` for each previously-open finding whose (tool,file) was in this run's scope but is now absent, and `RUN_FINISHED`. Returns the list of NEW finding ids (not previously seen — for the ratchet).
  - `open_findings(self) -> dict[str, dict]` — materialized current state: id → {status, tool, file, historical, ...} by replaying events.
  - Resolution rule: a finding transitions OPEN→FIXED only if `finding.tool in scope_tools and finding.file in scope_files`.

- [ ] **Step 1: Failing test**

```python
# tests/unit/test_ledger_state.py
from aramid.ledger import Ledger
from aramid.models import Finding, Severity, Verdict, Gate

def _f(fid, tool="ruff", file="a.py"):
    return Finding(fid, tool, "S102", "high", Severity.HIGH, Verdict.WARN,
                   file, 1, "m", "e", Gate.PRE_PUSH)

def test_absent_finding_resolved_only_when_in_scope(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1","t","pre-push",{"ruff"},{"a.py"},[_f("id1")])
    assert led.open_findings()["id1"]["status"] == "open"
    # next run scopes a.py+ruff, finding gone -> resolved
    led.record_run("r2","t",{"ruff"} and "pre-push",{"ruff"},{"a.py"},[])
    assert led.open_findings()["id1"]["status"] == "fixed"

def test_out_of_scope_absence_does_not_resolve(tmp_path):
    led = Ledger(tmp_path / "l.db")
    led.record_run("r1","t","pre-push",{"ruff"},{"a.py"},[_f("id1", file="a.py")])
    led.record_run("r2","t","pre-push",{"ruff"},{"b.py"},[])   # a.py not scanned
    assert led.open_findings()["id1"]["status"] == "open"

def test_new_ids_returned_for_ratchet(tmp_path):
    led = Ledger(tmp_path / "l.db")
    new = led.record_run("r1","t","pre-push",{"ruff"},{"a.py"},[_f("id1")])
    assert new == ["id1"]
    again = led.record_run("r2","t","pre-push",{"ruff"},{"a.py"},[_f("id1")])
    assert again == []   # already seen
```

- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** `record_run` + `open_findings` by replaying events into a dict, applying the scope rule. (Store tool/file/historical in the `FINDING_DETECTED` payload so resolution can check scope.)

```python
# append to src/aramid/ledger.py
from aramid.models import Finding

def _detect_payload(f: Finding) -> dict:
    return {"tool": f.tool, "file": f.file, "rule": f.rule, "verdict": str(f.verdict),
            "severity": str(f.severity), "line": f.line, "message": f.message,
            "evidence": f.evidence, "historical": f.historical}

class _LedgerStateMixin:  # merged into Ledger below
    pass

def _materialize(events):
    state: dict[str, dict] = {}
    seen: set[str] = set()
    for e in events:
        if e.type.value == "finding_detected":
            seen.add(e.finding_id)
            state[e.finding_id] = {**e.payload,
                                   "status": "historical" if e.payload.get("historical") else "open"}
        elif e.type.value == "finding_resolved":
            if e.finding_id in state: state[e.finding_id]["status"] = "fixed"
        elif e.type.value == "finding_overridden":
            if e.finding_id in state: state[e.finding_id]["status"] = "overridden"
        elif e.type.value == "finding_rotated":
            if e.finding_id in state: state[e.finding_id]["status"] = "rotated"
    return state, seen
```

Then add methods to `Ledger`:

```python
    def open_findings(self) -> dict:
        state, _ = _materialize(self.events())
        return state

    def record_run(self, run_id, at, gate, scope_tools, scope_files, findings):
        from aramid.models import Event, EventType
        state, seen = _materialize(self.events())
        present = {f.id for f in findings}
        self.append(Event(EventType.RUN_STARTED, run_id, at,
                          payload={"gate": gate, "tools": sorted(scope_tools)}))
        new_ids = []
        for f in findings:
            if f.id not in state or state[f.id]["status"] in ("fixed",):
                self.append(Event(EventType.FINDING_DETECTED, run_id, at,
                                  finding_id=f.id, payload=_detect_payload(f)))
            if f.id not in seen: new_ids.append(f.id)
        for fid, rec in state.items():
            if rec["status"] == "open" and fid not in present \
               and rec.get("tool") in scope_tools and rec.get("file") in scope_files:
                self.append(Event(EventType.FINDING_RESOLVED, run_id, at, finding_id=fid))
        self.append(Event(EventType.RUN_FINISHED, run_id, at,
                          payload={"blocking": sum(1 for f in findings if str(f.verdict)=="block")}))
        return new_ids
```

- [ ] **Step 4: Verify pass. Step 5: Commit** — `git commit -m "feat: materialized ledger state with scope-aware resolution and ratchet ids"`

### Task 3.3: Baseline snapshot + ratchet query

**Files:**
- Modify: `src/aramid/ledger.py`
- Test: `tests/unit/test_ledger_baseline.py`

**Interfaces:**
- Produces on `Ledger`:
  - `has_baseline(self) -> bool`
  - `write_baseline(self, run_id, at, fingerprints: set[str]) -> None` (appends `BASELINE_SNAPSHOT` with `payload={"ids": [...]}`)
  - `baseline_ids(self) -> set[str]`
  - `is_new(self, finding_id: str) -> bool` (not in baseline AND not previously detected)

- [ ] **Step 1: Failing test**

```python
# tests/unit/test_ledger_baseline.py
from aramid.ledger import Ledger

def test_baseline_suppresses_legacy_from_new(tmp_path):
    led = Ledger(tmp_path / "l.db")
    assert not led.has_baseline()
    led.write_baseline("r0", "t", {"legacy1", "legacy2"})
    assert led.has_baseline() and led.baseline_ids() == {"legacy1", "legacy2"}
    assert led.is_new("legacy1") is False
    assert led.is_new("fresh") is True
```

- [ ] **Step 2–5:** implement (query events for `BASELINE_SNAPSHOT`; `is_new` = id not in baseline_ids and id not in `seen` from `_materialize`), verify, commit `feat: ledger baseline snapshot and ratchet query`.

### Task 3.4: `compact`

**Files:** Modify `src/aramid/ledger.py`; Test `tests/unit/test_ledger_compact.py`.
**Interfaces:** `Ledger.compact(self) -> int` rewrites the DB keeping only the latest state-defining events (all `BASELINE_SNAPSHOT`, and the terminal event per finding), returns rows removed. Test: append 100 redundant detect/resolve pairs, compact, assert `open_findings()` unchanged and row count dropped. Commit `feat: ledger compaction`.

---

## Milestone M4 — Runners

### Task 4.1: Runner base — subprocess with tree-kill + timeout

**Files:**
- Create: `src/aramid/runners/__init__.py`, `src/aramid/runners/base.py`
- Test: `tests/unit/test_runner_base.py`

**Interfaces:**
- Produces:
  - `class ToolState(StrEnum)`: `OK, MISSING, CRASHED, TIMEOUT`
  - `@dataclass class RunnerResult`: `tool:str, state:ToolState, raw:str, stderr:str, duration_s:float`
  - `run_subprocess(argv: list[str], cwd: Path, timeout_s: float, env: dict|None=None) -> RunnerResult` — resolves argv[0]; if missing → `MISSING`; spawns in a new process group; on timeout kills the whole tree (`taskkill /T /F /PID` on Windows, `os.killpg` elsewhere) → `TIMEOUT`; non-zero-but-produced-output is not itself a crash (checkers exit non-zero when they find issues) — `CRASHED` only when the tool errors without parseable output (decided per-runner).
  - `class Runner(Protocol)`: `name: str`; `applies(self, ctx) -> bool`; `run(self, ctx) -> RunnerResult`.

- [ ] **Step 1: Failing test**

```python
# tests/unit/test_runner_base.py
import sys
from pathlib import Path
from aramid.runners.base import run_subprocess, ToolState

def test_missing_binary_is_missing(tmp_path):
    r = run_subprocess(["definitely-not-a-real-binary-xyz"], tmp_path, 5)
    assert r.state is ToolState.MISSING

def test_ok_captures_stdout(tmp_path):
    r = run_subprocess([sys.executable, "-c", "print('hi')"], tmp_path, 10)
    assert r.state is ToolState.OK and "hi" in r.raw

def test_timeout_kills(tmp_path):
    r = run_subprocess([sys.executable, "-c", "import time;time.sleep(30)"], tmp_path, 1)
    assert r.state is ToolState.TIMEOUT
```

- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** (use `shutil.which` for MISSING; `subprocess.Popen` with `creationflags=CREATE_NEW_PROCESS_GROUP` on Windows / `start_new_session=True` elsewhere; on `TimeoutExpired` call `taskkill` or `killpg`).

```python
# src/aramid/runners/base.py
import os, shutil, subprocess, sys, time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

class ToolState(StrEnum):
    OK="ok"; MISSING="missing"; CRASHED="crashed"; TIMEOUT="timeout"

@dataclass
class RunnerResult:
    tool: str; state: ToolState; raw: str = ""; stderr: str = ""; duration_s: float = 0.0

_WIN = sys.platform == "win32"

def _kill_tree(proc: subprocess.Popen):
    try:
        if _WIN:
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                           capture_output=True)
        else:
            os.killpg(os.getpgid(proc.pid), 9)
    except Exception:
        proc.kill()

def run_subprocess(argv, cwd: Path, timeout_s: float, env=None) -> RunnerResult:
    tool = Path(argv[0]).name
    if shutil.which(argv[0]) is None and not Path(argv[0]).exists():
        return RunnerResult(tool, ToolState.MISSING)
    kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if _WIN \
             else {"start_new_session": True}
    start = time.monotonic()
    proc = subprocess.Popen(argv, cwd=str(cwd), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True,
                            env={**os.environ, **(env or {})}, **kwargs)
    try:
        out, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_tree(proc); proc.communicate()
        return RunnerResult(tool, ToolState.TIMEOUT, duration_s=time.monotonic()-start)
    return RunnerResult(tool, ToolState.OK, out, err, time.monotonic()-start)

class Runner(Protocol):
    name: str
    def applies(self, ctx) -> bool: ...
    def run(self, ctx) -> RunnerResult: ...
```

- [ ] **Step 4: Verify pass. Step 5: Commit** — `git commit -m "feat: runner base with process-tree kill and timeout"`

### Task 4.2–4.8: Tool adapters

Each adapter is a small module exposing `run(ctx) -> RunnerResult` plus a `parse(result, ctx) -> list[RawFinding]` used by the normalizer (Task 4.9). `RawFinding` is `@dataclass(tool, rule, severity_raw, file, line, message, secret:str|None)` defined in `normalizer.py` (Task 4.9). Implement each with real argv and a JSON-output parse; test each against a **captured fixture** of the tool's real output stored in `tests/fixtures/<tool>.json` (no live tool needed in unit tests).

- **Task 4.2 gitleaks** — `runners/gitleaks.py`. Staged: `gitleaks protect --staged --report-format json --report-path -`. Range/history: `gitleaks git --log-opts "<rng>" --report-format json`. Parse JSON array → RawFinding per leak with `secret=item["Secret"]`, `rule=item["RuleID"]`, `file=item["File"]`, `line=item["StartLine"]`. Test: fixture with one leak → one RawFinding whose `secret` is set. Commit `feat: gitleaks adapter`.
- **Task 4.3 ruff** — `runners/ruff.py`. `ruff check --output-format json --force-exclude -- <files>`. Parse → RawFinding(`rule=item["code"]`, `file`, `line=item["location"]["row"]`, `message`). Commit `feat: ruff adapter`.
- **Task 4.4 semgrep** — `runners/semgrep.py`. `semgrep --config <vendored owasp.yml> --json --metrics=off --quiet -- <files>`. Parse `results[]` → RawFinding(`rule=item["check_id"]`, severity from `extra.severity`, `file=item["path"]`, `line=item["start"]["line"]`). Commit `feat: semgrep adapter (offline vendored rules)`.
- **Task 4.5 eslint** — `runners/eslint.py`. Resolve `<root>/node_modules/.bin/eslint(.cmd on Windows)`; MISSING (skip) if absent — never global. `eslint -f json <files>`. Parse `[].messages[]` → RawFinding(`rule=ruleId`, `file`, `line`). Commit `feat: eslint adapter (repo-local)`.
- **Task 4.6 typecheck** — `runners/typecheck.py`. tsc: `node_modules/.bin/tsc --noEmit` when `tsconfig.json` exists (parse `file(line,col): error TSxxxx` text). mypy: only when `[tool.mypy]` or `mypy.ini` present; `mypy --no-error-summary --show-column-numbers`. Commit `feat: tsc and mypy adapters`.
- **Task 4.7 deps** — `runners/deps.py`. Python: `pip-audit -r <requirements*.txt> -f json` (skip+note if none); severity from OSV data, absent→WARN. JS: dispatch by `detect_package_manager` → `npm audit --json` / `pnpm audit --json` / `yarn npm audit --json`. **Cache**: `.aramid/cache/deps-<sha256(lockfile bytes)>.json` with a 24h TTL; pre-push consults cache, `check --all` refreshes. Commit `feat: dependency audit adapter with lockfile-keyed cache`.
- **Task 4.8 tests** — `runners/tests.py`. pytest: `pytest -q`. npm: `npm test`. Non-zero exit → a single RawFinding(rule="tests-failed") that maps to BLOCK. Commit `feat: test-suite runner`.

### Task 4.9: Normalizer — RawFinding → Finding with fingerprint

**Files:**
- Create: `src/aramid/normalizer.py`
- Test: `tests/unit/test_normalizer.py`

**Interfaces:**
- Consumes: adapters' `parse()`, `gitutil`, `fingerprint`, `redact`, `policy.classify` (Task 5.1).
- Produces:
  - `@dataclass class RawFinding`: `tool, rule, severity_raw, file, line, message, secret:str|None=None`
  - `normalize(raws: list[RawFinding], root: Path, ref_for: Callable[[str], str], salt: bytes, gate: Gate, classify) -> list[Finding]` — for each raw: read the flagged line from the correct git object (`ref_for(file)` returns `":"`, a sha, or `HEAD`), compute occurrence index among identical (tool,rule,file,normalized-line) raws, build the fingerprint, redact `secret` into evidence if present (else use the message), and call `classify(tool, rule, severity_raw, gate)` to get `(severity, verdict)`.

- [ ] **Step 1: Failing test**

```python
# tests/unit/test_normalizer.py
from pathlib import Path
from aramid.normalizer import RawFinding, normalize
from aramid.models import Gate, Verdict

def _classify(tool, rule, sev, gate): 
    from aramid.models import Severity, Verdict
    return (Severity.HIGH, Verdict.BLOCK)

def test_two_identical_lines_get_distinct_ids(tmp_path):
    raws = [RawFinding("ruff","S102","high","a.py",3,"exec"),
            RawFinding("ruff","S102","high","a.py",7,"exec")]
    ref_for = lambda f: "HEAD"
    # line content identical for both -> occurrence index disambiguates
    out = normalize(raws, tmp_path, lambda f: "STUB", b"salt", Gate.PRE_COMMIT, _classify)
    # patch: normalize reads via injected reader in real impl; here assert 2 unique ids
    assert len({f.id for f in out}) == 2

def test_secret_is_redacted_into_evidence(tmp_path):
    raws = [RawFinding("gitleaks","aws","high","a.py",1,"leak",secret="AKIA12345678")]
    out = normalize(raws, tmp_path, lambda f: "HEAD", b"salt", Gate.PRE_COMMIT, _classify)
    assert "AKIA12345678" not in out[0].evidence and "…" in out[0].evidence
```

> Implementation note: `normalize` reads line content via `gitutil.read_blob(root, ref_for(file), file)` split by lines at `raw.line-1`; inject a reader in tests by monkeypatching `gitutil.read_blob`. Occurrence index = count of prior raws in the list with the same `(tool,rule,file, normalized flagged-line)`.

- [ ] **Step 2–5:** implement, verify, commit `feat: normalizer — RawFinding to fingerprinted Finding with redaction`.

---

## Milestone M5 — Policy, config, pipeline, reporter

### Task 5.1: Policy — classify + block-list + overrides + escalation

**Files:**
- Create: `src/aramid/policy.py`, `src/aramid/data/block_rules.toml`
- Test: `tests/unit/test_policy.py`

**Interfaces:**
- Produces:
  - `load_block_rules() -> dict` (reads packaged `data/block_rules.toml`: `[ruff] block = ["S102","S105",...]`, `[semgrep] block = ["owasp.sqli.*",...]`, `[deps] block_severity = "critical"`)
  - `classify(tool, rule, severity_raw, gate, cfg) -> tuple[Severity, Verdict]` — secrets always BLOCK; block-list rules BLOCK; `tests-failed` BLOCK; deps at/above `block_severity` BLOCK else WARN; everything else WARN. During bake (`cfg.semgrep_block_armed is False`) semgrep BLOCKs demote to WARN.
  - `apply_overrides(findings, overrides: set[str], suppressions: set[str], seen_ledger) -> list[Finding]` — WARN override ids and BLOCK suppression ids get verdict downgraded to INFO; a stale override (id not matching any current finding) is ignored (finding re-fires).
  - `escalate_degraded(verdict_exit: int, degraded_block_tier: bool, gate: Gate) -> int` — at pre-push, degraded BLOCK-tier forces exit 1.

- [ ] **Step 1: Failing test**

```python
# tests/unit/test_policy.py
from aramid import policy
from aramid.models import Gate, Verdict, Severity

def test_secret_always_blocks():
    _, v = policy.classify("gitleaks","aws-key","high",Gate.PRE_COMMIT, _cfg(armed=True))
    assert v is Verdict.BLOCK

def test_bake_demotes_semgrep_block():
    _, v = policy.classify("semgrep","owasp.sqli","error",Gate.PRE_PUSH, _cfg(armed=False))
    assert v is Verdict.WARN
    _, v2 = policy.classify("semgrep","owasp.sqli","error",Gate.PRE_PUSH, _cfg(armed=True))
    assert v2 is Verdict.BLOCK

def _cfg(armed): 
    from types import SimpleNamespace
    return SimpleNamespace(semgrep_block_armed=armed,
                           block_rules=policy.load_block_rules())
```

> `data/block_rules.toml` seed (implementation-owned, criteria in spec §3): `[ruff]\nblock=["S102","S105","S106","S107","S608","S301","S302"]\n[semgrep]\nblock=["owasp-top-ten.*","*sqli*","*deserialization*","*command-injection*"]\n[deps]\nblock_severity="critical"` — semgrep uses fnmatch.

- [ ] **Step 2–5:** implement, verify, commit `feat: policy — classify, block-list, overrides, degraded escalation`.

### Task 5.2: Config — layered load

**Files:**
- Create: `src/aramid/config.py`, `src/aramid/data/defaults.toml`
- Test: `tests/unit/test_config.py`

**Interfaces:**
- Produces:
  - `@dataclass class Config`: `schema_version:int, semgrep_block_armed:bool, bake_started:str|None, cve_block_severity:str, ignore_paths:list[str], test_command:str|None, scope_subpath:str|None, timeouts:dict, block_rules:dict`
  - `load_config(root: Path) -> Config` — deep-merge `data/defaults.toml` ← `~/.aramid/config.toml` ← `<root>/aramid.toml`; built-in `ignore_paths` from Global Constraints are always unioned in.
  - `render_repo_stub(stack, pkg_mgr) -> str` — the near-empty per-repo TOML init writes (only `schema_version`, `semgrep_block_armed=false`, `bake_started`).

- [ ] **Step 1: Failing test**: user config raises `cve_block_severity`, repo toml overrides `test_command`; assert both land and built-in ignore paths present. **Steps 2–5:** implement with `tomllib`/`tomli_w`, verify, commit `feat: layered configuration`.

### Task 5.3: Pipeline — run a gate

**Files:**
- Create: `src/aramid/pipeline.py`
- Test: `tests/unit/test_pipeline.py`

**Interfaces:**
- Consumes: detectors, runners registry, normalizer, policy, ledger, config, gitutil, redact.
- Produces:
  - `@dataclass class GateResult`: `exit_code:int, findings:list[Finding], degraded:list[str], new_ids:list[str], run_id:str`
  - `run_gate(root: Path, gate: Gate, mode: str, cfg: Config, ledger: Ledger, accept_degraded: str|None) -> GateResult` — selects applicable runners for the gate+stack; runs them concurrently under the gate wall-clock budget (`ThreadPoolExecutor`, `timeouts["pre_commit"|"pre_push"]`); collects `RunnerResult`s; records degraded (MISSING/CRASHED/TIMEOUT) tools; parses+normalizes; applies overrides/suppressions; records the run in the ledger; computes exit code: `1` if any BLOCK finding; else if degraded BLOCK-tier tool and gate is pre-push and not `accept_degraded` → `1` (write `INFRASTRUCTURE_BYPASS` only if accepted); else `2` if any degradation; else `0`. Enforces the no-new-warnings ratchet at pre-push (new WARN ids in `new_ids` → BLOCK unless overridden).
  - `run_id` generated from ledger seq + counter (NO `Date.now`/random reliance for determinism in tests: accept an injected `clock: Callable[[], str]` and `run_id: str` param with defaults).

- [ ] **Step 1: Failing test** (inject two fake runners — one clean, one returning a BLOCK RawFinding — assert exit 1; then all-clean assert exit 0; then a MISSING BLOCK-tier tool at pre-push assert exit 1, and with `accept_degraded="reason"` assert exit 2 + an INFRASTRUCTURE_BYPASS event). **Steps 2–5:** implement, verify, commit `feat: gate pipeline with concurrency, budget, ratchet, degraded escalation`.

### Task 5.4: Reporter — console + json + exit mapping

**Files:**
- Create: `src/aramid/reporter.py`
- Test: `tests/unit/test_reporter.py`

**Interfaces:**
- Produces:
  - `render_console(result: GateResult, ledger: Ledger) -> str` — NEW findings first; legacy collapsed to `"(+N baseline findings)"`; each secret finding appends the rotation warning; degraded tools listed as skips; aging line from ledger.
  - `render_json(result: GateResult) -> str` — machine output: `{exit_code, findings:[...], degraded:[...], new_ids:[...]}` with redacted evidence only.
- Test: a GateResult with 1 new BLOCK + 2 baseline WARN renders NEW first, shows `(+2 baseline`, and a secret finding shows "rotate". Commit `feat: reporter — console and json output`.

---

## Milestone M6 — Hooks and init

### Task 6.1: Hook shim generation, chaining, install/uninstall

**Files:**
- Create: `src/aramid/hooks.py`
- Test: `tests/unit/test_hooks.py`, `tests/e2e/test_hook_fires.py`

**Interfaces:**
- Produces:
  - `hooks_dir(root: Path) -> Path` — respects `git config core.hooksPath`, else `<root>/.git/hooks`.
  - `render_shim(gate: Gate, interpreter: Path) -> bytes` — sh script, **bytes with `\n`**, header marker `# >>> aramid managed >>>`, execs `"<interp /c form, quoted>" -m aramid check --gate <gate>` with `command -v py && py -3` fallback, and applies the §3 exit-code mapping (pre-commit `{2,3}→0`; pre-push passthrough) and forwards `ARAMID_ACCEPT_DEGRADED`.
  - `install(root, interpreter) -> None` — for each gate: if a foreign hook exists, rename to `<hook>.aramid-chained` and have the shim exec it first; write shim in binary mode; `chmod +x` where supported. Idempotent (marker-detected — regenerate own, never double-chain).
  - `uninstall(root) -> None` — remove aramid shims, restore any `.aramid-chained` originals.
  - `win_sh_path(p: Path) -> str` — `C:\x` → `/c/x`.

- [ ] **Step 1: Failing unit test** for `render_shim` (contains marker, `\n` only, baked interpreter path quoted) and `win_sh_path`. **Step: e2e** creates a temp repo, `install`, makes a commit that stages a fake secret, asserts the commit is **blocked** (hook fired through real git dispatch), then `uninstall` and assert commit succeeds. **Steps 2–5:** implement, verify (`pytest tests/unit/test_hooks.py tests/e2e/test_hook_fires.py -v`), commit `feat: git hook shims with chaining and Windows-correct exec`.

### Task 6.2: `init` (+ discover)

**Files:**
- Create: `src/aramid/commands/__init__.py`, `src/aramid/commands/init.py`, `src/aramid/data/ARAMID.md.tmpl`
- Test: `tests/integration/test_init.py`

**Interfaces:**
- Consumes: gitutil, detectors, config, hooks, doctor (Task 6.3), ledger, runners/gitleaks.
- Produces: `cmd_init(target: Path, discover: bool=False) -> int` —
  1. `repo_root` (refuse non-repos → exit 3 with message);
  2. compute scope subpath if target ≠ root; record nested `.git` exclusions;
  3. run `doctor` — **refuse to arm hooks** (exit 3) if any BLOCK-tier tool (gitleaks/semgrep) is missing, telling the user to run `aramid doctor`;
  4. write `aramid.toml` stub (only if absent; never overwrite user keys), `ARAMID.md` (always regenerate, marker-tagged), and gitignore entries for `.aramid/`, `graph-out/`, `.graphite*`, `.cache/` (append if missing);
  5. `install` hooks;
  6. full-history gitleaks scan → record hits as `FINDING_DETECTED historical=true`;
  7. `write_baseline` from a `check --all` fingerprint set;
  8. validate the hook fires via a scratch commit in a throwaway index (or a documented dry `git commit --dry-run` through the shim);
  9. print summary. `--discover` walks `<target>` (marker-based, skips ignore paths) and runs the above per repo.

- [ ] **Step 1: Failing integration test**: init a temp git repo with a `.py` containing `exec()`; assert `aramid.toml`, `ARAMID.md`, `.gitignore` entries, `.git/hooks/pre-commit` (with marker) all created, ledger has a baseline, and a second `init` (idempotent) doesn't duplicate gitignore lines or clobber a user-edited `aramid.toml` key. **Steps 2–5:** implement, verify, commit `feat: init command with doctor gate, history scan, baseline, idempotent re-init`.

### Task 6.3: `doctor`

**Files:**
- Create: `src/aramid/commands/doctor.py`
- Test: `tests/integration/test_doctor.py`

**Interfaces:**
- Produces: `cmd_doctor(root: Path, fix: bool=False) -> int` — probes each tool (`--version`) and the recorded shim interpreter; reports OK/missing/version; when `fix`, `pip install` the owned toolchain into the current interpreter and download a pinned gitleaks release binary into `~/.aramid/tools/` (verify sha256). Returns 0 if all BLOCK-tier tools present, else 2.
- Test (no network): monkeypatch the prober to report gitleaks missing → `cmd_doctor` returns 2 and message names gitleaks. Commit `feat: doctor — toolchain probe and repair`.

---

## Milestone M7 — Remaining CLI commands + wiring

### Task 7.1: `check`

**Files:** Create `src/aramid/commands/check.py`; Test `tests/integration/test_check.py`.
**Interfaces:** `cmd_check(root, gate, mode, strict, as_json, accept_degraded) -> int` — load config, open ledger (auto-baseline + non-blocking if `not ledger.has_baseline()` — fresh-clone rule), `run_gate`, render, return exit code (with `--strict` mapping `{2,3}` per §3; env `ARAMID_ACCEPT_DEGRADED` read here). Test: seeded-secret repo → `cmd_check(pre_commit)` returns 1; clean repo returns 0; fresh ledger first run auto-baselines and returns 0/2 not 1. Commit `feat: check command`.

### Task 7.2: `status`
Create `src/aramid/commands/status.py`; Test `tests/integration/test_status.py`. `cmd_status(root)` prints last run, open counts, NEW-since-baseline, aging (>30d), per-tool skip streaks, unrotated historical secrets, and `"bake in progress, day N"` when unarmed. Commit `feat: status command`.

### Task 7.3: `ledger` (list/show/filter/mark-rotated)
Create `src/aramid/commands/ledger_cmd.py`; Test `tests/integration/test_ledger_cmd.py`. `mark-rotated <id> --reason` appends `FINDING_ROTATED`; requires the id be `historical`. Commit `feat: ledger command with mark-rotated`.

### Task 7.4: `override`, `arm`, `update_rules`, `uninstall`
Create the four command modules; Tests in `tests/integration/`. `override <id> --reason` (WARN only; BLOCK ids error, directing to `.aramid-suppressions.toml`); `arm` sets `semgrep_block_armed=true` in `aramid.toml`; `update_rules` refreshes vendored semgrep rules from a pinned source into `data/rules/semgrep/`; `uninstall <path>` calls `hooks.uninstall` + removes ARAMID.md/gitignore entries (keeps ledger). Commit `feat: override, arm, update-rules, uninstall commands`.

### Task 7.5: CLI dispatch
Modify `src/aramid/cli.py` to build the full subcommand tree and dispatch to `commands.*`; each maps its exit int to `main`'s return. Test `tests/integration/test_cli_dispatch.py`: `python -m aramid check --help` exits 0; unknown command exits 3. Commit `feat: full CLI dispatch tree`.

---

## Milestone M8 — Integration, E2E, dogfood

### Task 8.1: Seeded-violations integration suite
Create `tests/integration/test_gates_end_to_end.py` + `tests/fixtures/seeded_repo/` builder. Assert: fake AWS key → pre-commit exit 1; SQLi pattern → pre-push semgrep WARN during bake, BLOCK after `arm`; vulnerable pinned dep → dep WARN/BLOCK per severity; failing test → pre-push exit 1; clean → 0. Commit `test: end-to-end gate behavior on seeded violations`.

### Task 8.2: Windows E2E hook + chaining + uninstall
Create `tests/e2e/test_windows_hooks.py` (skip if not win32): real `git commit`/`git push` (to a bare local remote), assert hooks fire through git dispatch, a pre-existing foreign hook still runs (chaining), and `uninstall` reverses everything. Commit `test: Windows E2E hooks, chaining, uninstall`.

### Task 8.3: Dogfood + CI
Run `python -m aramid init F:\Projects\aramid`; fix anything it flags; add `.github/workflows/aramid.yml` running `python -m aramid check --all --strict --json` on push. Commit `chore: dogfood aramid on itself + CI gate`.

---

## Self-review checklist (run before execution)

1. **Spec coverage:** map each spec section (§2 architecture→M0–M7; §3 gates/policy/exit codes→M4/M5; §4 finding/fingerprint→M1; §5 ledger→M3; §6 secret hygiene/suppression→1.3/5.1/7.3–7.4; §7 config→5.2; §8 init/topology/bake→6.2/7.4; §8b graphite coexistence→Global Constraints ignore paths + 6.2 gitignore; §9 testing→M8). Every section has a task.
2. **Placeholder scan:** no "TBD"/"similar to"/"add error handling" — each step carries real code or a concrete adapter spec (argv + parse + fixture test).
3. **Type consistency:** `Finding`/`Event`/`Verdict`/`ToolState`/`RunnerResult`/`GateResult`/`Config` names are defined once (Tasks 1.1, 4.1, 5.2, 5.3) and referenced verbatim thereafter.
