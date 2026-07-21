# TDD-Enforcement Gate — Sub-project 1a (Code-Without-Test Signal + Teeth) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a synchronous, git-fact "code-without-test" signal to Aramid's pre-push gate that warns (default) and can BLOCK once armed, riding all existing gate machinery.

**Architecture:** A pure git-diff producer (`tdd.scan`) emits a WARN-tier `RawFinding` per changed production `.py` file when the push adds no new test lines. It joins `run_gate`'s normal finding stream before `normalize()`, so `policy.classify` (a new `tool=="tdd"` branch gated on `tdd_block_armed`), the fingerprint, the ratchet, overrides, the ledger, and `_has_genuine_block` all apply unchanged. Disarmed findings are ratchet-exempt (pure advisory); armed findings return BLOCK from `classify` (genuine, survive the fresh-clone downgrade). The block rests only on git facts; a graph-annotation seam ships as an inert no-op stub.

**Tech Stack:** Python 3.14 (Windows-first), pytest, ruff, tomllib/tomli_w, git via `subprocess`.

**Spec:** `docs/superpowers/specs/2026-07-21-aramid-tdd-enforcement-gate-design.md`

## Global Constraints

- **Windows:** run tools as `python -m pytest` / `python -m ruff`, never bare.
- **ruff baseline = 43** findings; do not increase it.
- **Fail-open:** `tdd.scan` MUST NOT raise into `run_gate` — any exception yields zero findings.
- **Block rests only on git-diff facts.** Absence/corruption/staleness of `graph-out/graph.json` MUST NEVER change a verdict.
- **No edits to `check.py`, no ledger-schema change, no consumer change.** Arming routes through `policy.classify` so `_has_genuine_block` handles armed `tdd` findings by construction.
- **Signal runs at `Gate.PRE_PUSH` only** in this sub-project.
- **Commits:** end every commit message with the trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Never use backticks in `-m` messages (shell expands them). Never `--no-verify`.
- **Scope:** `mutation_block_armed` and arming the existing mutation findings are **sub-project 1b, not here.**

---

### Task 1: Config plumbing — `tdd_block_armed` + `[tdd]` section

**Files:**
- Modify: `src/aramid/data/defaults.toml`
- Modify: `src/aramid/config.py:30-48` (Config dataclass), `src/aramid/config.py:96-113` (load_config return)
- Test: `tests/unit/test_config.py`

**Interfaces:**
- Produces: `Config.tdd_block_armed: bool` (default `False`) and `Config.tdd: dict` (default `{}`; carries `{"enabled": True}` from defaults). Consumed by Task 2 (`classify`) and Task 3 (`scan`).

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_config.py`:

```python
def test_tdd_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "no-user.toml")
    cfg = config.load_config(tmp_path)
    assert cfg.tdd_block_armed is False
    assert cfg.tdd.get("enabled") is True


def test_tdd_block_armed_from_repo_toml(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "no-user.toml")
    (tmp_path / "aramid.toml").write_text("tdd_block_armed = true\n", encoding="utf-8")
    cfg = config.load_config(tmp_path)
    assert cfg.tdd_block_armed is True
```

(Ensure `from aramid import config` is imported at the top of the test file — it already is.)

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_config.py::test_tdd_defaults -v`
Expected: FAIL with `AttributeError: 'Config' object has no attribute 'tdd_block_armed'`.

- [ ] **Step 3: Add the config fields and defaults**

In `src/aramid/data/defaults.toml`, add the root key near `semgrep_block_armed` (top of file):

```toml
tdd_block_armed = false
```

And add a new section (place it beside the other sections, e.g. after `[mutation]`):

```toml
[tdd]
enabled = true
```

In `src/aramid/config.py`, add two fields to the `Config` dataclass, in the defaulted group after `dast` (dataclass rule: defaulted fields must follow non-defaulted ones):

```python
    dast: dict = field(default_factory=dict)
    tdd_block_armed: bool = False
    tdd: dict = field(default_factory=dict)
```

In `load_config`, add to the `Config(...)` return call (after the `dast=` line):

```python
        dast=merged.get("dast", {}),
        tdd_block_armed=merged.get("tdd_block_armed", False),
        tdd=merged.get("tdd", {}),
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_config.py -v`
Expected: PASS (both new tests, plus the existing suite still green).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/data/defaults.toml src/aramid/config.py tests/unit/test_config.py
git commit -m "feat(tdd): add tdd_block_armed + [tdd] config" -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `policy.classify` — the `tdd` verdict branch

**Files:**
- Modify: `src/aramid/policy.py:93-94` (insert after the `llm-review` branch)
- Test: `tests/unit/test_policy.py`

**Interfaces:**
- Consumes: `Config.tdd_block_armed` (Task 1).
- Produces: `classify("tdd", "code-without-test", "medium", gate, cfg)` → `(Severity.MEDIUM, Verdict.BLOCK)` when armed, `(Severity.MEDIUM, Verdict.WARN)` when disarmed. Relied on by Task 4 (wiring) and `check._has_genuine_block` (unchanged).

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_policy.py`:

```python
from types import SimpleNamespace
from aramid import policy
from aramid.models import Gate, Severity, Verdict


def _tdd_cfg(armed: bool):
    # classify reads cfg.block_rules early, then the tool branch; a minimal
    # namespace with the attributes classify touches is enough.
    return SimpleNamespace(block_rules={}, semgrep_block_armed=False,
                           pack={}, tdd_block_armed=armed)


def test_tdd_disarmed_is_warn():
    sev, verdict = policy.classify("tdd", "code-without-test", "medium",
                                   Gate.PRE_PUSH, _tdd_cfg(armed=False))
    assert sev is Severity.MEDIUM
    assert verdict is Verdict.WARN


def test_tdd_armed_is_block():
    _sev, verdict = policy.classify("tdd", "code-without-test", "medium",
                                    Gate.PRE_PUSH, _tdd_cfg(armed=True))
    assert verdict is Verdict.BLOCK
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_policy.py::test_tdd_armed_is_block -v`
Expected: FAIL — `classify` falls through to the final `return severity, Verdict.WARN`, so the armed case returns WARN, not BLOCK.

- [ ] **Step 3: Add the classify branch**

In `src/aramid/policy.py`, insert immediately after the `llm-review` branch (after line 94, before the `ruff_block` line):

```python
    if tool == "llm-review":
        return severity, Verdict.WARN

    # TDD gate (1a): the git-fact code-without-test signal. WARN during the
    # bake; BLOCK once the repo opts in via `tdd_block_armed` -- routing the
    # verdict through classify (not a gate-only computation like llm-review)
    # means _has_genuine_block treats an armed tdd BLOCK as genuine with no
    # check.py change, and it survives the fresh-clone downgrade.
    if tool == "tdd":
        armed = getattr(cfg, "tdd_block_armed", False)
        return severity, Verdict.BLOCK if armed else Verdict.WARN
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_policy.py -v`
Expected: PASS (new tests + existing suite green).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/policy.py tests/unit/test_policy.py
git commit -m "feat(tdd): classify tdd findings, armed via tdd_block_armed" -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: `tdd.py` producer + `gitutil.is_test_file`

**Files:**
- Modify: `src/aramid/gitutil.py` (add `is_test_file`)
- Create: `src/aramid/tdd.py`
- Test: `tests/unit/test_tdd.py` (create)

**Interfaces:**
- Consumes: `gitutil.diff_new_lines(root, base, head) -> dict[str, set[int]]`; `RunContext(root, files, rng, ...)`; `Config.tdd` (Task 1).
- Produces:
  - `gitutil.is_test_file(rel: str) -> bool`
  - `tdd.scan(ctx: RunContext, cfg) -> list[RawFinding]` — findings with `tool="tdd"`, `rule="code-without-test"`, `severity_raw="medium"`, `line=0`. Consumed by Task 4.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_tdd.py`:

```python
from pathlib import Path
from types import SimpleNamespace

from aramid import gitutil, tdd
from aramid.runners.base import RunContext


def _ctx(files, rng="base..head", root=Path("/x")):
    return RunContext(root=root, files=files, rng=rng)


def _cfg(enabled=True):
    return SimpleNamespace(tdd={"enabled": enabled})


def test_is_test_file():
    assert gitutil.is_test_file("tests/test_foo.py") is True
    assert gitutil.is_test_file("pkg/tests/thing.py") is True
    assert gitutil.is_test_file("pkg/test_foo.py") is True
    assert gitutil.is_test_file("pkg/foo_test.py") is True
    assert gitutil.is_test_file("src/aramid/foo.py") is False


def test_prod_change_no_test_flags(monkeypatch):
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda root, b, h: {"src/foo.py": {1, 2}})
    findings = tdd.scan(_ctx(["src/foo.py"]), _cfg())
    assert [f.file for f in findings] == ["src/foo.py"]
    f = findings[0]
    assert (f.tool, f.rule, f.severity_raw, f.line) == ("tdd", "code-without-test", "medium", 0)


def test_prod_change_with_new_test_lines_is_clean(monkeypatch):
    monkeypatch.setattr(gitutil, "diff_new_lines",
                        lambda root, b, h: {"src/foo.py": {1}, "tests/test_foo.py": {5, 6}})
    findings = tdd.scan(_ctx(["src/foo.py", "tests/test_foo.py"]), _cfg())
    assert findings == []


def test_test_only_change_is_clean(monkeypatch):
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda root, b, h: {"tests/test_foo.py": {5}})
    findings = tdd.scan(_ctx(["tests/test_foo.py"]), _cfg())
    assert findings == []


def test_prod_change_with_test_deletion_only_flags(monkeypatch):
    # test file changed but gained NO new lines (pure deletion) -> not "tested"
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda root, b, h: {"src/foo.py": {1}})
    findings = tdd.scan(_ctx(["src/foo.py", "tests/test_foo.py"]), _cfg())
    assert [f.file for f in findings] == ["src/foo.py"]


def test_disabled_returns_nothing(monkeypatch):
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda root, b, h: {"src/foo.py": {1}})
    findings = tdd.scan(_ctx(["src/foo.py"]), _cfg(enabled=False))
    assert findings == []


def test_scan_is_fail_open(monkeypatch):
    def boom(root, b, h):
        raise RuntimeError("git exploded")
    monkeypatch.setattr(gitutil, "diff_new_lines", boom)
    assert tdd.scan(_ctx(["src/foo.py"]), _cfg()) == []


def test_graph_advisory_note_is_inert(tmp_path):
    # No-op stub: no graph -> empty note, never raises.
    assert tdd._graph_advisory_note(tmp_path, "src/foo.py") == ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_tdd.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'aramid.tdd'` and `AttributeError: module 'aramid.gitutil' has no attribute 'is_test_file'`.

- [ ] **Step 3: Add `is_test_file` to gitutil**

In `src/aramid/gitutil.py`, add (near the other path helpers):

```python
def is_test_file(rel: str) -> bool:
    """True for pytest-style test files (canonical helper; the mutation/fuzz/
    js_mutation consumers keep their own local copies, left untouched)."""
    p = rel.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    if p.startswith("tests/") or "/tests/" in p:
        return True
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))
```

- [ ] **Step 4: Create the producer**

Create `src/aramid/tdd.py`:

```python
"""tdd -- synchronous 'code-without-test' producer for the pre-push gate
(design 1a sections 3-4). Pure git-diff analysis: one WARN-tier RawFinding per
changed production .py file when the range adds no new test lines. No
subprocess; never raises into run_gate (fail-open); the block rests only on
git facts. The graph note is an inert no-op stub that lights up once Graphite
is decision-grade."""
from pathlib import Path

from aramid import gitutil
from aramid.normalizer import RawFinding

RULE = "code-without-test"
_TOOL = "tdd"
_MESSAGE = "code changed with no new test in this range"


def _split_range(rng):
    """Derive (base, head) for gitutil.diff_new_lines from run_gate's `rng`.
    `rng` is a git range string like '@{u}..HEAD'; the FULL_HISTORY_RNG
    sentinel (empty string / None, new-repo first push) maps to (None, 'HEAD'),
    which diff_new_lines reads via its base=None `git show` path."""
    if not rng:
        return None, "HEAD"
    base, sep, head = rng.partition("..")
    if not sep:
        return None, "HEAD"
    return (base or None), (head or "HEAD")


def _graph_advisory_note(root: Path, rel: str) -> str:
    """No-op advisory stub (design 1a section 9). Returns "" today; a future
    sub-project promotes this to a fail-open read of graph-out/graph.json once
    Graphite resolution is decision-grade. Must never raise and never affect a
    verdict."""
    return ""


def scan(ctx, cfg) -> list[RawFinding]:
    """Return code-without-test RawFindings for the pre-push range. `ctx.files`
    is the already-changed, already-ignore-filtered file set. Fail-open: any
    error yields no findings (never blocks a push, never crashes the gate)."""
    try:
        if not getattr(cfg, "tdd", {}).get("enabled", True):
            return []
        prod = [f for f in ctx.files
                if f.endswith(".py") and not gitutil.is_test_file(f)]
        if not prod:
            return []
        base, head = _split_range(ctx.rng)
        new_lines = gitutil.diff_new_lines(ctx.root, base, head)
        has_new_test_lines = any(
            lines and gitutil.is_test_file(path)
            for path, lines in new_lines.items())
        if has_new_test_lines:
            return []
        out = []
        for rel in prod:
            note = _graph_advisory_note(ctx.root, rel)
            message = f"{_MESSAGE} ({note})" if note else _MESSAGE
            out.append(RawFinding(tool=_TOOL, rule=RULE, severity_raw="medium",
                                  file=rel, line=0, message=message))
        return out
    except Exception:
        return []
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_tdd.py -v`
Expected: PASS (all 8 tests).

- [ ] **Step 6: Commit**

```bash
git add src/aramid/gitutil.py src/aramid/tdd.py tests/unit/test_tdd.py
git commit -m "feat(tdd): code-without-test producer + gitutil.is_test_file" -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Wire `tdd.scan` into `run_gate` + ratchet exemption

**Files:**
- Modify: `src/aramid/pipeline.py:38` (import), `src/aramid/pipeline.py:270-272` (append producer output), `src/aramid/pipeline.py:300-307` (ratchet exemption)
- Test: `tests/unit/test_pipeline.py`

**Interfaces:**
- Consumes: `tdd.scan(ctx, cfg)` (Task 3), `classify` tdd branch (Task 2).
- Produces: at `Gate.PRE_PUSH`, tdd findings appear in `GateResult.findings`; disarmed → WARN and non-blocking (ratchet-exempt); armed → BLOCK (exit 1).

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_pipeline.py` (helpers `_repo`, `_cfg`, `_ledger` already exist there):

```python
from aramid import tdd  # noqa: E402  (module-level import at top of file is fine too)


def test_tdd_disarmed_warns_and_is_ratchet_exempt(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)

    raw = RawFinding(tool="tdd", rule="code-without-test", severity_raw="medium",
                     file="a.py", line=0, message="code changed with no new test in this range")
    monkeypatch.setattr(pipeline.tdd, "scan", lambda ctx, cfg: [raw])
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, [])

    result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-tdd-w")

    tdd_findings = [f for f in result.findings if f.tool == "tdd"]
    assert len(tdd_findings) == 1
    assert tdd_findings[0].verdict is Verdict.WARN          # not escalated
    assert result.exit_code == 0                            # ratchet-exempt: does NOT block
    ledger.close()


def test_tdd_armed_blocks(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    cfg.tdd_block_armed = True
    ledger = _ledger(tmp_path)

    raw = RawFinding(tool="tdd", rule="code-without-test", severity_raw="medium",
                     file="a.py", line=0, message="code changed with no new test in this range")
    monkeypatch.setattr(pipeline.tdd, "scan", lambda ctx, cfg: [raw])
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, [])

    result = pipeline.run_gate(root, Gate.PRE_PUSH, "range", cfg, ledger, run_id="run-tdd-a")

    tdd_findings = [f for f in result.findings if f.tool == "tdd"]
    assert tdd_findings[0].verdict is Verdict.BLOCK
    assert result.exit_code == 1
    ledger.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_pipeline.py::test_tdd_disarmed_warns_and_is_ratchet_exempt -v`
Expected: FAIL — before wiring, `pipeline.tdd` does not exist (AttributeError on monkeypatch) and/or the finding never appears / the ratchet escalates the new WARN to BLOCK (`exit_code == 1`, not 0).

- [ ] **Step 3: Wire the producer and exempt it from the ratchet**

In `src/aramid/pipeline.py`, add `tdd` to the aramid imports (line 28-30 group):

```python
from aramid import config as config_mod
from aramid import gitutil, policy, redact, tdd
from aramid import review as review_mod
```

After the runner parse loop that builds `all_raws` (right after line 272, before `raw_secrets = ...`), add:

```python
    # TDD gate (1a): synchronous git-fact code-without-test producer. PRE_PUSH
    # only; joins the raw stream so classify/fingerprint/ratchet/overrides all
    # apply. Fail-open inside tdd.scan -- never raises here.
    if gate is Gate.PRE_PUSH:
        all_raws.extend(tdd.scan(ctx, cfg))
```

In the pre-push ratchet comprehension (lines 300-307), add the `tdd` exemption so a disarmed WARN is never auto-escalated:

```python
    if gate is Gate.PRE_PUSH:
        findings = [
            replace(f, verdict=Verdict.BLOCK)
            if (f.id in new_ids and f.verdict is Verdict.WARN
                and f.rule != deps.DEPS_SHAPE_DRIFT_RULE
                and f.tool != "tdd")
            else f
            for f in findings
        ]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_pipeline.py -v`
Expected: PASS (both new tests + existing pipeline suite green).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/pipeline.py tests/unit/test_pipeline.py
git commit -m "feat(tdd): wire code-without-test producer into pre-push gate; ratchet-exempt when disarmed" -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: `aramid arm --tdd`

**Files:**
- Modify: `src/aramid/commands/arm.py` (add `_TDD_KEY_RE`, `tdd` param + branch)
- Modify: `src/aramid/cli.py:110-112` (arm flag), `src/aramid/cli.py:211-212` (dispatch)
- Test: `tests/unit/test_arm.py`, `tests/unit/test_cli.py` (or wherever arm/cli tests live)

**Interfaces:**
- Consumes: `Config.tdd_block_armed` semantics (Task 1).
- Produces: `cmd_arm(root, tdd=True)` writes `tdd_block_armed = true` to `aramid.toml`; `aramid arm --tdd` dispatches to it.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_arm.py` (mirror the existing semgrep/llm arm tests in that file):

```python
def test_arm_tdd_writes_root_key(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\nsemgrep_block_armed = false\n\n[llm]\nllm_block_armed = false\n",
                    encoding="utf-8")
    rc = cmd_arm(tmp_path, tdd=True)
    assert rc == 0
    text = toml.read_text(encoding="utf-8")
    assert "tdd_block_armed = true" in text
    # root key must land BEFORE the first section header, not inside [llm]
    assert text.index("tdd_block_armed = true") < text.index("[llm]")


def test_arm_tdd_idempotent(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("tdd_block_armed = false\n", encoding="utf-8")
    cmd_arm(tmp_path, tdd=True)
    cmd_arm(tmp_path, tdd=True)
    text = toml.read_text(encoding="utf-8")
    assert text.count("tdd_block_armed") == 1
    assert "tdd_block_armed = true" in text
```

Add a dispatch test to the CLI test module (mirror the existing `arm --llm` dispatch test):

```python
def test_cli_arm_tdd_dispatches(monkeypatch, tmp_path):
    called = {}
    monkeypatch.setattr(cli, "cmd_arm", lambda root, **kw: called.update(kw) or 0)
    cli.main(["arm", "--tdd"])
    assert called.get("tdd") is True
```

(Adjust `cli.main` / import names to match the existing CLI test's conventions.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_arm.py::test_arm_tdd_writes_root_key -v`
Expected: FAIL — `cmd_arm() got an unexpected keyword argument 'tdd'`.

- [ ] **Step 3: Implement `--tdd` in the command**

In `src/aramid/commands/arm.py`, add the key regex next to `_KEY_RE` (line 26-27):

```python
_TDD_KEY_RE = re.compile(
    r"(?m)^tdd_block_armed[^\S\n]*=[^\S\n]*[^\s#]+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
```

Change the `cmd_arm` signature (line 76) to accept `tdd`:

```python
def cmd_arm(root, llm: bool = False, autolearn: bool = False, tdd: bool = False) -> int:
```

Add a `tdd` branch immediately after the `if llm:` block (after line 107, before the semgrep default), mirroring the semgrep root-key insertion:

```python
    if tdd:
        if _TDD_KEY_RE.search(text):
            new_text = _armed_sub(_TDD_KEY_RE, "tdd_block_armed = true", text)
        else:
            m = _NEXT_SECTION_RE.search(text)
            if m:
                new_text = (text[:m.start()] + "tdd_block_armed = true\n" + text[m.start():])
            else:
                prefix = "" if not text or text.endswith("\n") else "\n"
                new_text = text + prefix + "tdd_block_armed = true\n"
        toml_path.write_text(new_text, encoding="utf-8")
        print(f"aramid: arm: tdd_block_armed=true written to {toml_path}")
        print("aramid: arm: TDD bake ended -- code-without-test findings now BLOCK at pre-push.")
        return 0
```

- [ ] **Step 4: Wire the CLI flag and dispatch**

In `src/aramid/cli.py`, add the flag to the `arm_which` mutually-exclusive group (after line 112):

```python
    arm_which.add_argument("--tdd", action="store_true")
```

Update the dispatch (line 212):

```python
    if args.command == "arm":
        return cmd_arm(root, llm=args.llm, autolearn=args.autolearn, tdd=args.tdd)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_arm.py tests/unit/test_cli.py -v`
Expected: PASS (new tests + existing arm/cli suite green).

- [ ] **Step 6: Commit**

```bash
git add src/aramid/commands/arm.py src/aramid/cli.py tests/unit/test_arm.py tests/unit/test_cli.py
git commit -m "feat(tdd): aramid arm --tdd ends the code-without-test bake" -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Real-git integration + full-suite + ruff verification

**Files:**
- Test: `tests/integration/test_tdd_gate.py` (create)

**Interfaces:**
- Consumes: `tdd.scan` with a REAL `RunContext` over a REAL `resolve_range` (exercises `_split_range` + `diff_new_lines` against git, which the Task-3 unit tests monkeypatch away).

- [ ] **Step 1: Write the failing integration tests**

Create `tests/integration/test_tdd_gate.py`:

```python
import subprocess
from pathlib import Path
from types import SimpleNamespace

from aramid import gitutil, tdd
from aramid.runners.base import RunContext


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo_with_upstream(tmp_path) -> Path:
    bare = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(bare)], check=True, capture_output=True, text=True)
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "src").mkdir()
    (r / "tests").mkdir()
    (r / "src" / "foo.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
    (r / "tests" / "test_foo.py").write_text("def test_foo():\n    assert True\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "initial")
    _git(r, "remote", "add", "origin", str(bare))
    _git(r, "push", "-u", "origin", "main")
    return r


def _scan(r):
    rng = gitutil.resolve_range(r)
    files = gitutil.changed_files(r, rng)
    ctx = RunContext(root=r, files=files, rng=rng)
    return tdd.scan(ctx, SimpleNamespace(tdd={"enabled": True}))


def test_real_prod_change_without_test_flags(tmp_path):
    r = _repo_with_upstream(tmp_path)
    (r / "src" / "foo.py").write_text("def foo():\n    return 2\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "change foo, no test")
    findings = _scan(r)
    assert [f.file for f in findings] == ["src/foo.py"]


def test_real_prod_change_with_test_is_clean(tmp_path):
    r = _repo_with_upstream(tmp_path)
    (r / "src" / "foo.py").write_text("def foo():\n    return 2\n", encoding="utf-8")
    (r / "tests" / "test_foo.py").write_text(
        "def test_foo():\n    assert True\n\ndef test_foo_two():\n    assert True\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "change foo with a new test")
    findings = _scan(r)
    assert findings == []
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `python -m pytest tests/integration/test_tdd_gate.py -v`
Expected: PASS (both). If either fails, the producer's real-git path (`_split_range` / `diff_new_lines` over `@{u}..HEAD`) needs fixing — the unit tests monkeypatch this away, so this is the load-bearing real-git check.

- [ ] **Step 3: Run the full suite**

Run: `python -m pytest`
Expected: all green (existing count + the new tdd tests; no regressions).

- [ ] **Step 4: Check ruff stayed at baseline**

Run: `python -m ruff check src/aramid | tail -1`
Expected: total findings **≤ 43** (the baseline). Fix any new lint the tdd files introduced (unused imports, line length) until at or below baseline.

- [ ] **Step 5: Commit**

```bash
git add tests/integration/test_tdd_gate.py
git commit -m "test(tdd): real-git integration for code-without-test scan over a live range" -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- §3 detection rule → Task 3 (producer) + Task 6 (real-git). Whole-range test presence, `line=0` stable fingerprint, diff-scoping all exercised.
- §4 architecture (tdd.py, classify branch, ratchet exempt, config, arm) → Tasks 1-5.
- §6 enforcement semantics (disarmed advisory/ratchet-exempt; armed BLOCK; fresh-clone survival is by-construction via classify + unchanged `_has_genuine_block`) → Tasks 2, 4.
- §9 graph no-op stub → Task 3 (`_graph_advisory_note`).
- §10 fail-open → Task 3 (`test_scan_is_fail_open`).
- §11 test list → covered across Tasks 1-6 (the fresh-clone downgrade path is covered structurally: armed tdd is genuine-by-classify, which `_has_genuine_block` already tests; no new check.py test is needed since check.py is unchanged).
- §12 invariants (no check.py/ledger/consumer change; ruff ≤ 43) → enforced by construction + Task 6 Step 4.

**Placeholder scan:** No TBD/TODO; every code step shows complete code.

**Type consistency:** `tdd.scan(ctx, cfg)` signature is consistent across Tasks 3, 4, 6; `is_test_file` name consistent (gitutil) across Tasks 3, 6; `tdd_block_armed` / `cfg.tdd` names consistent across Tasks 1, 2, 4; `cmd_arm(..., tdd=...)` consistent across Task 5.

**Note for the executor:** in Task 5, adjust the CLI dispatch test's import/entrypoint names (`cli.main`, `cli.cmd_arm`) to match the existing CLI test module's conventions — the pattern (monkeypatch `cmd_arm`, assert the `tdd` kwarg) is what matters.
