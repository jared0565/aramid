"""integration: seeded-violations end-to-end suite (Task 8.1).

Drives `aramid.pipeline.run_gate` / `aramid.commands.check.cmd_check` against
REAL temp git repos, mixing:
  - LIVE real-tool subprocesses: semgrep, ruff, pip-audit, pytest (all
    installed in this machine's per-user Scripts dir, not on PATH by
    default -- `_find_tool`/`live_tools_path_env` below prepend it, mirroring
    the discovery pattern in tests/integration/test_semgrep_rules.py).
  - a FIXTURE gitleaks runner (monkeypatched into `pipeline.RUNNERS`) --
    gitleaks itself is not installed on this machine and there is no network
    to fetch it, so every gitleaks-shaped assertion here goes through a fake
    double, exactly like tests/integration/test_check.py's own `_fake`
    pattern. Every other selected runner for a given gate is left live.

Each seeded violation gets its own temp repo (via `_init_repo`) so tests are
independent and order-agnostic.
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from aramid import config as config_mod
from aramid import pipeline
from aramid.commands.arm import cmd_arm
from aramid.commands.check import cmd_check
from aramid.ledger import Ledger
from aramid.models import Gate
from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState

# --------------------------------------------------- live-tool discovery ----
# Same search strategy as test_semgrep_rules.py's `_find_semgrep`, generalized
# to the other console-script tools this suite drives live (ruff, pip-audit,
# pytest): shutil.which, next to sys.executable, and next to every
# site-packages dir on sys.path -- these tools install into the interpreter's
# *user-site* Scripts dir on this machine, which is not on PATH by default.


def _find_tool(name: str) -> Path | None:
    candidates: list[Path] = []
    which = shutil.which(name)
    if which:
        candidates.append(Path(which))
    exe_dir = Path(sys.executable).parent
    candidates.append(exe_dir / "Scripts" / f"{name}.exe")
    candidates.append(exe_dir / name)
    for entry in sys.path:
        p = Path(entry)
        if p.name == "site-packages":
            candidates.append(p.parent / "Scripts" / f"{name}.exe")
            candidates.append(p.parent / "bin" / name)
    for c in candidates:
        if c.exists():
            return c
    return None


_SEMGREP_BIN = _find_tool("semgrep")
_RUFF_BIN = _find_tool("ruff")
_PIP_AUDIT_BIN = _find_tool("pip-audit")
_PYTEST_BIN = _find_tool("pytest")

_LIVE_DIRS = list(dict.fromkeys(
    b.parent for b in (_SEMGREP_BIN, _RUFF_BIN, _PIP_AUDIT_BIN, _PYTEST_BIN) if b))

_SKIP_SEMGREP = "semgrep console-script not found (see test_semgrep_rules.py discovery pattern)"
_SKIP_RUFF = "ruff console-script not found (see test_semgrep_rules.py discovery pattern)"
_SKIP_PIP_AUDIT = "pip-audit console-script not found (see test_semgrep_rules.py discovery pattern)"
_SKIP_PYTEST = "pytest console-script not found (see test_semgrep_rules.py discovery pattern)"


@pytest.fixture
def live_tools_path_env(monkeypatch):
    """Prepend every discovered live-tool directory to PATH -- needed both
    for `aramid.runners.base.run_subprocess`'s own `shutil.which` gate and
    (semgrep specifically) because semgrep.exe shells out to a sibling
    pysemgrep process by bare name."""
    for d in _LIVE_DIRS:
        monkeypatch.setenv("PATH", str(d) + os.pathsep + os.environ.get("PATH", ""))


# --------------------------------------------------------- repo builder -----

def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(root), check=True, capture_output=True, text=True)


def _init_repo(tmp_path: Path, name: str = "repo") -> Path:
    """git init + user config + one seed commit, so `staged`/`range`/`all`
    file-discovery modes all have a real HEAD to diff against."""
    root = tmp_path / name
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")
    (root / "README.md").write_text("seed\n", encoding="utf-8")
    _git(root, "add", "README.md")
    _git(root, "commit", "-q", "-m", "initial")
    return root


def _no_user_config(tmp_path: Path, monkeypatch) -> None:
    """Never let a test read a real ~/.aramid/config.toml off this machine."""
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user-config.toml")


def _write_aramid_toml(root: Path, *, armed: bool) -> None:
    (root / "aramid.toml").write_text(
        "# aramid repo config -- detected stack: python\n"
        "schema_version = 1\n"
        f"semgrep_block_armed = {'true' if armed else 'false'}\n"
        'bake_started = "2026-01-01"\n',
        encoding="utf-8")


# ------------------------------------------------------ gitleaks fixture ----
# gitleaks is not installed and there is no network on this machine -- every
# gitleaks assertion below goes through this fake double instead.

def _fake_runner(run_result: RunnerResult, raws: list[RawFinding] | None = None):
    return SimpleNamespace(run=lambda ctx: run_result, parse=lambda result, ctx: raws or [])


def _gitleaks_clean():
    return _fake_runner(RunnerResult("gitleaks", ToolState.OK))


def _gitleaks_secret(file: str = "secret.py", secret: str = "AKIAFAKEFAKEFAKEFAKE"):
    raw = RawFinding(tool="gitleaks", rule="aws-access-token", severity_raw="high",
                      file=file, line=1, message="Identified a fake AWS access token",
                      secret=secret)
    return _fake_runner(RunnerResult("gitleaks", ToolState.OK), raws=[raw])


# ============================================================ (a) SQLi ======
# semgrep, LIVE. WARN during bake (semgrep_block_armed=false), BLOCK after
# `arm`. The 3-run shape below is deliberate, not incidental: pipeline.py's
# no-new-warnings ratchet unconditionally escalates a brand-new WARN finding
# to BLOCK on its very first sighting (`run_gate`'s own PRE_PUSH branch), and
# cmd_check's fresh-clone rule only downgrades the resulting *exit code* --
# it does not rewrite `result.findings` back to their pre-ratchet verdict.
# So the JSON body's `findings[].verdict` on run 1 would still read "block"
# even though the process exit code is 0/2 -- an artifact of the ratchet,
# not the thing this test is trying to prove. Run 2 (identical commit state,
# finding no longer "new") is what actually exercises steady-state WARN.

_SQLI_SRC = (
    'def get_user(cursor, user):\n'
    '    return cursor.execute("SELECT * FROM t WHERE x=" + user)\n'
)


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_SEMGREP)
def test_seeded_sqli_semgrep_warn_during_bake_then_block_after_arm(
        tmp_path, monkeypatch, live_tools_path_env):
    root = _init_repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_aramid_toml(root, armed=False)

    (root / "vuln.py").write_text(_SQLI_SRC, encoding="utf-8")
    _git(root, "add", "vuln.py", "aramid.toml")
    _git(root, "commit", "-q", "-m", "add vulnerable query")

    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks", _gitleaks_clean())

    # Run 1: fresh ledger -- establishes the baseline; the ratchet's own
    # escalation of this brand-new WARN finding gets downgraded right back
    # by cmd_check's fresh-clone rule (not a genuine block).
    rc1 = cmd_check(root, Gate.PRE_PUSH, "all")
    assert rc1 in (0, 2)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    assert ledger.has_baseline()
    ledger.close()

    # Run 2: identical commit state -- the finding is no longer "new", so
    # the ratchet does not touch it. This is the genuine, steady-state,
    # unarmed verdict: WARN, non-blocking.
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc2 = cmd_check(root, Gate.PRE_PUSH, "all", as_json=True)
    assert rc2 == 0
    payload = json.loads(buf.getvalue())
    sqli = [f for f in payload["findings"] if "sqli" in f["rule"]]
    assert sqli, payload["findings"]
    assert all(f["verdict"] == "warn" for f in sqli), sqli
    assert all(f["tool"] == "semgrep" for f in sqli), sqli

    # arm: semgrep_block_armed -> true (real `aramid arm` command).
    assert cmd_arm(root) == 0

    # Run 3: same finding, now classified BLOCK directly (armed, not via
    # the ratchet) -- must block the push.
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc3 = cmd_check(root, Gate.PRE_PUSH, "all", as_json=True)
    assert rc3 == 1
    payload = json.loads(buf.getvalue())
    sqli = [f for f in payload["findings"] if "sqli" in f["rule"]]
    assert sqli, payload["findings"]
    assert all(f["verdict"] == "block" for f in sqli), sqli


# ================================= (a2) Task 81b: owasp-top-ten.* pattern ===
# semgrep, LIVE. Regression test for the BLOCK-tier bug found via
# integration testing with the real semgrep binary: LIVE `check_id` is
# prefixed with the `--config` file's directory path
# (e.g. "F.Projects.aramid.src.aramid.rules.owasp-top-ten.a03-injection.
# python-sqli-string-concat"), so block_rules.toml's `owasp-top-ten.*`
# fnmatch pattern NEVER matched live output -- only the substring globs
# (`*sqli*`, `*deserialization*`, `*command-injection*`) happened to still
# fire, which is why test (a) above (using the FULL, unmodified
# block_rules.toml) already blocked before this fix and proves nothing
# about the `owasp-top-ten.*` pattern specifically.
#
# This test isolates the `[semgrep] block` list down to ONLY
# `owasp-top-ten.*` (no substring globs) via aramid.toml's `block_rules`
# override layer (aramid.config.load_config deep-merges `block_rules` from
# repo aramid.toml over the packaged defaults -- see test_config.py's own
# `[block_rules.deps]` override). With the substring globs removed, a BLOCK
# verdict here can ONLY be explained by aramid.runners.semgrep.parse()
# normalizing the live, prefixed check_id back to its canonical
# "owasp-top-ten...." form before classification -- pre-fix this test's
# assertions fail (verdict stays WARN, rc != 1, and the reported `rule`
# still carries semgrep's raw path prefix); post-fix it passes.

def _write_aramid_toml_owasp_pattern_isolated(root: Path) -> None:
    (root / "aramid.toml").write_text(
        "# aramid repo config -- detected stack: python\n"
        "schema_version = 1\n"
        "semgrep_block_armed = true\n"
        'bake_started = "2026-01-01"\n'
        "\n"
        "[block_rules.semgrep]\n"
        'block = ["owasp-top-ten.*"]\n',
        encoding="utf-8")


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_SEMGREP)
def test_seeded_sqli_blocks_via_owasp_top_ten_wildcard_pattern_only(
        tmp_path, monkeypatch, live_tools_path_env):
    root = _init_repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    _write_aramid_toml_owasp_pattern_isolated(root)

    (root / "vuln.py").write_text(_SQLI_SRC, encoding="utf-8")
    _git(root, "add", "vuln.py", "aramid.toml")
    _git(root, "commit", "-q", "-m", "add vulnerable query")

    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks", _gitleaks_clean())

    # semgrep_block_armed=true from the very first run, and the finding is
    # genuinely BLOCK-classified (not merely ratchet-escalated), so
    # cmd_check's fresh-clone rule does not downgrade it -- a single run
    # suffices here (unlike test (a) above, which needs 3 runs to isolate
    # the ratchet's own first-sighting escalation from the armed verdict).
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cmd_check(root, Gate.PRE_PUSH, "all", as_json=True)

    assert rc == 1
    payload = json.loads(buf.getvalue())
    sqli = [f for f in payload["findings"] if "sqli" in f["rule"]]
    assert sqli, payload["findings"]
    assert all(f["verdict"] == "block" for f in sqli), sqli
    # The reported rule id itself must be the canonical vendored form, not
    # semgrep's raw, config-path-prefixed check_id.
    assert all(f["rule"].startswith("owasp-top-ten.") for f in sqli), sqli


# ======================================================= (b) ruff S102 ======
# ruff, LIVE. exec(x) -> S102 (in block_rules.toml's ruff block-list) ->
# BLOCK directly at pre-commit (ruff carries no armed/bake gate, unlike
# semgrep -- policy.classify blocks on rule-id membership alone). Pre-commit
# has no ratchet escalation at all, so a single run is enough.

_EXEC_SRC = "def run_it(x):\n    exec(x)\n"


@pytest.mark.skipif(_RUFF_BIN is None, reason=_SKIP_RUFF)
def test_seeded_ruff_exec_s102_blocks_pre_commit(tmp_path, monkeypatch, live_tools_path_env):
    root = _init_repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)

    (root / "danger.py").write_text(_EXEC_SRC, encoding="utf-8")
    _git(root, "add", "danger.py")  # staged, not committed -- pre-commit scans staged files

    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks", _gitleaks_clean())

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cmd_check(root, Gate.PRE_COMMIT, "staged", as_json=True)

    assert rc == 1
    payload = json.loads(buf.getvalue())
    s102 = [f for f in payload["findings"] if f["rule"] == "S102"]
    assert s102, payload["findings"]
    assert all(f["tool"] == "ruff" and f["verdict"] == "block" for f in s102), s102


# ============================================== (c) vulnerable dependency ===
# pip-audit, LIVE (network to the OSV database is available in this
# environment -- verified manually: `pip-audit -r requirements.txt -f json`
# against `requests==2.6.0` returns 6 real CVE/PYSEC/GHSA advisories). Per
# runners/deps.py's own documented behavior, pip-audit's JSON carries no
# severity field at all, so aramid hard-codes "low" -> below the "critical"
# deps block threshold (block_rules.toml) -> WARN, never BLOCK. Same 2-run
# shape as the semgrep test, for the same reason (steady-state, not
# ratchet-escalated, verdict).

_VULNERABLE_REQUIREMENTS = "requests==2.6.0\n"


@pytest.mark.skipif(_SEMGREP_BIN is None or _PIP_AUDIT_BIN is None,
                     reason=_SKIP_SEMGREP + " / " + _SKIP_PIP_AUDIT)
def test_seeded_vulnerable_dependency_pip_audit_warns(tmp_path, monkeypatch, live_tools_path_env):
    root = _init_repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)

    (root / "requirements.txt").write_text(_VULNERABLE_REQUIREMENTS, encoding="utf-8")
    _git(root, "add", "requirements.txt")
    _git(root, "commit", "-q", "-m", "pin vulnerable dependency")

    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks", _gitleaks_clean())

    rc1 = cmd_check(root, Gate.PRE_PUSH, "all")  # fresh-ledger baseline run
    assert rc1 in (0, 2)

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc2 = cmd_check(root, Gate.PRE_PUSH, "all", as_json=True)
    assert rc2 == 0
    payload = json.loads(buf.getvalue())
    pip_findings = [f for f in payload["findings"] if f["tool"] == "pip-audit"]
    assert pip_findings, payload["findings"]
    assert all(f["verdict"] == "warn" for f in pip_findings), pip_findings


# ==================================================== (d) failing test ======
# pytest, LIVE (via the tests/ runner adapter). A non-zero pytest exit ->
# a single collapsed "tests-failed" RawFinding, which policy.classify blocks
# unconditionally (no armed/bake gate, no ratchet interaction -- it's
# already Verdict.BLOCK straight out of classify, so a single run is enough,
# same as the ruff case).

_FAILING_TEST_SRC = "def test_always_fails():\n    assert False\n"


@pytest.mark.skipif(_SEMGREP_BIN is None or _PYTEST_BIN is None,
                     reason=_SKIP_SEMGREP + " / " + _SKIP_PYTEST)
def test_seeded_failing_test_blocks_pre_push(tmp_path, monkeypatch, live_tools_path_env):
    root = _init_repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)

    tests_dir = root / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_x.py").write_text(_FAILING_TEST_SRC, encoding="utf-8")
    _git(root, "add", "tests/test_x.py")
    _git(root, "commit", "-q", "-m", "add failing test")

    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks", _gitleaks_clean())

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cmd_check(root, Gate.PRE_PUSH, "all", as_json=True)

    assert rc == 1
    payload = json.loads(buf.getvalue())
    tf = [f for f in payload["findings"] if f["rule"] == "tests-failed"]
    assert tf, payload["findings"]
    assert all(f["verdict"] == "block" for f in tf), tf


# ========================================================= (e) fake key =====
# gitleaks -- FIXTURE (not installed, no network). Unconditional BLOCK, no
# armed/bake gate, no ratchet interaction: single run at pre-commit suffices.

@pytest.mark.skipif(_RUFF_BIN is None, reason=_SKIP_RUFF)  # pre-commit also selects ruff
def test_seeded_fake_aws_key_gitleaks_blocks(tmp_path, monkeypatch, live_tools_path_env):
    root = _init_repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)

    (root / "secret.py").write_text("AWS_KEY = 'not a real key, just text'\n", encoding="utf-8")
    _git(root, "add", "secret.py")

    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks", _gitleaks_secret(file="secret.py"))

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cmd_check(root, Gate.PRE_COMMIT, "staged", as_json=True)

    assert rc == 1
    payload = json.loads(buf.getvalue())
    leaks = [f for f in payload["findings"] if f["tool"] == "gitleaks"]
    assert leaks, payload["findings"]
    assert all(f["verdict"] == "block" for f in leaks), leaks


# ============================================================ (f) clean =====
# semgrep LIVE + ruff not involved (pre-push gate) + gitleaks FIXTURE-clean.
# Nothing seeded -> exit 0.

_CLEAN_SRC = (
    'import hashlib\n\n\n'
    'def get_user(cursor, user):\n'
    '    return cursor.execute("SELECT * FROM t WHERE x=%s", (user,))\n\n\n'
    'def strong_hash(x):\n'
    '    return hashlib.sha256(x).hexdigest()\n'
)


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_SEMGREP)
def test_clean_repo_exits_zero(tmp_path, monkeypatch, live_tools_path_env):
    root = _init_repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)

    (root / "clean.py").write_text(_CLEAN_SRC, encoding="utf-8")
    _git(root, "add", "clean.py")
    _git(root, "commit", "-q", "-m", "clean code")

    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks", _gitleaks_clean())

    rc = cmd_check(root, Gate.PRE_PUSH, "all")

    assert rc == 0


# ============================================ (g) graphite exclusion (§8b) ==
# Hard requirement: a fake secret under graph-out/ and a SAST-triggering
# pattern under .graphite_cache/ must produce ZERO findings and ZERO ledger
# `finding_detected` events, in all three file-discovery modes, and BOTH
# filter passes (pipeline.py's own docstring) must independently hold:
#   1. pre-runner file filter (`config.filter_paths` on the discovered file
#      set, before any runner runs) -- proven here directly (white-box) by
#      calling `pipeline._discover_files` + `config.filter_paths` exactly as
#      `run_gate` itself does, and asserting the ignored paths are dropped
#      while an unrelated staged file (`benign.py`) survives -- this also
#      rules out a "ctx.files ends up empty -> semgrep falls back to
#      scanning its whole cwd" false pass (verified manually: semgrep given
#      an EMPTY explicit target list after `--` does NOT skip the scan, it
#      scans the cwd -- so a non-empty, correctly-scoped file list matters).
#   2. post-parse RawFinding filter -- proven end-to-end via a gitleaks
#      FIXTURE that (like the real tool, which scans by git-log range/
#      --staged rather than by ctx.files) reports a finding for the ignored
#      graph-out/ path regardless of what ctx.files contains; run_gate must
#      still drop it before fingerprinting/the ledger.

_GRAPHITE_CACHE_SQLI_SRC = _SQLI_SRC
_BENIGN_SRC = "x = 1\n"
_IGNORED_PREFIXES = ("graph-out/", ".graphite_cache/")


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_SEMGREP)
@pytest.mark.parametrize("mode", ["staged", "range", "all"])
def test_graphite_artifacts_excluded_from_findings_and_ledger(
        tmp_path, monkeypatch, live_tools_path_env, mode):
    root = _init_repo(tmp_path)
    _no_user_config(tmp_path, monkeypatch)

    (root / "graph-out").mkdir()
    (root / "graph-out" / "leak.json").write_text('{"key": "fake"}\n', encoding="utf-8")
    (root / ".graphite_cache").mkdir()
    (root / ".graphite_cache" / "x.py").write_text(_GRAPHITE_CACHE_SQLI_SRC, encoding="utf-8")
    (root / "benign.py").write_text(_BENIGN_SRC, encoding="utf-8")
    _git(root, "add", "graph-out/leak.json", ".graphite_cache/x.py", "benign.py")
    # deliberately left staged, NOT committed -- git's index already makes
    # these paths visible to staged (diff --cached), range (falls back to
    # diff HEAD, no upstream configured), and all (ls-files) alike.

    cfg = config_mod.load_config(root)

    # --- filter pass 1: pre-runner file-set filter -------------------------
    raw_files, _rng = pipeline._discover_files(root, mode)
    filtered = config_mod.filter_paths(raw_files, cfg)
    assert "graph-out/leak.json" not in filtered
    assert ".graphite_cache/x.py" not in filtered
    assert "benign.py" in filtered  # proves the filter is scoped, not wholesale

    # --- filter pass 2: post-parse RawFinding filter ------------------------
    secret_raw = RawFinding(tool="gitleaks", rule="generic-api-key", severity_raw="high",
                             file="graph-out/leak.json", line=1, message="found a key",
                             secret="AKIAFAKEFAKEFAKEFAKE")
    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks",
                         _fake_runner(RunnerResult("gitleaks", ToolState.OK), raws=[secret_raw]))

    ledger = Ledger(root / ".aramid" / "ledger.db")
    result = pipeline.run_gate(root, Gate.PRE_PUSH, mode, cfg, ledger, run_id=f"run-{mode}")

    assert not any(f.file.startswith(_IGNORED_PREFIXES) for f in result.findings), result.findings

    detected = [e for e in ledger.events() if e.type.value == "finding_detected"]
    assert not any(e.payload.get("file", "").startswith(_IGNORED_PREFIXES) for e in detected), \
        detected
    ledger.close()
