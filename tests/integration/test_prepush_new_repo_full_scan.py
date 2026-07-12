"""integration: MUST-FIX 1 (`.superpowers/sdd/final-review.md`) -- the FIRST
push of a brand-new repo (no `@{u}`, no `origin/HEAD` -- i.e.
`gitutil.resolve_range` genuinely returns `None`) must scan EVERYTHING, per
spec §3: "no remote refs at all -- first push of a new repo -- scan every
commit reachable from HEAD. Never exit 3 merely because a branch is new."

Pre-fix, `pipeline._discover_files`'s "range" mode fed a bare `rng=None`
straight through to `gitutil.changed_files` (`git diff --name-only HEAD`,
empty on a clean working tree -- silently under-scanning every file-scoped
pre-push tool) and to `gitleaks._build_argv` (`if ctx.rng:` treated `None`
as "use `protect --staged`", which only ever sees the currently-staged
diff -- empty here too, so a plain committed secret sails through). The fix
(pipeline.py's `FULL_HISTORY_RNG` sentinel, `_discover_files`, and
`gitleaks._build_argv`'s `is not None` check) makes range mode fall back to
the full tracked file set plus a full-history gitleaks scan specifically
when -- and only when -- `resolve_range()` returns `None`.

(a) proves the file-set half using REAL, LIVE ruff -- this environment has
    no gitleaks binary (fixture-only throughout), but ruff is installed in
    the interpreter's per-user Scripts dir (same discovery pattern as
    test_gates_end_to_end.py's `_find_tool`). ruff is not normally part of
    the pre-push runner matrix (`GATE_RUNNER_KEYS`); it is added here via
    monkeypatch purely to observe `ctx.files` as a stand-in for the
    file-scoped pre-push tools the review calls out (semgrep/eslint/
    typecheck), none of which can run live in this environment. The
    load-bearing assertion is the *captured* `ctx.files` the real
    `ruff.run()` actually received -- NOT the process exit code -- because
    ruff's own CLI defaults an empty explicit path list to scanning its cwd
    (verified manually against the real binary: `ruff check ... --` with
    zero trailing paths still finds violations in cwd), which would mask
    the bug for this specific tool's exit code and give a false "it already
    worked" reading. The `ctx.files` capture is what actually pins the fix.
(b) proves the gitleaks-argv half via a FIXTURE gitleaks double (no real
    binary anywhere in this suite) that captures the `ctx.rng` value the
    real pipeline hands it -- pinning that it is `pipeline.FULL_HISTORY_RNG`
    ("") and not `None`, which is exactly the distinction
    `gitleaks._build_argv` (see test_runner_gitleaks.py) now keys off to
    route to a full-history scan instead of `protect --staged`.
(c) confirms the ordinary upstream-configured case is unaffected: with a
    real `@{u}` established (push to a local bare "origin"), range mode
    still returns the actual diff range and only the newly-committed file,
    never falling back to the full tracked set.
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
from aramid import gitutil, pipeline
from aramid.commands.check import cmd_check
from aramid.models import Gate
from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState

# --------------------------------------------------- live-tool discovery ----
# Same search strategy as test_gates_end_to_end.py's `_find_tool`: ruff
# installs into the interpreter's per-user Scripts dir on this machine,
# which is not on PATH by default.


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


_RUFF_BIN = _find_tool("ruff")
_SKIP_RUFF = "ruff console-script not found (see test_gates_end_to_end.py discovery pattern)"


@pytest.fixture
def live_ruff_path_env(monkeypatch):
    if _RUFF_BIN:
        monkeypatch.setenv("PATH", str(_RUFF_BIN.parent) + os.pathsep + os.environ.get("PATH", ""))


# --------------------------------------------------------- repo builder -----

def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(root), check=True, capture_output=True, text=True)


def _new_repo_no_upstream(tmp_path: Path, name: str = "repo") -> Path:
    """git init + one seed commit, deliberately with NO `git remote add`
    and NO push -- the exact state of a brand-new repo about to be pushed
    for the very first time, before `@{u}`/`origin/HEAD` exist."""
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


def _gitleaks_clean_fixture():
    return SimpleNamespace(run=lambda ctx: RunnerResult("gitleaks", ToolState.OK),
                            parse=lambda result, ctx: [])


# ================================================== (a) file-set half =======

@pytest.mark.skipif(_RUFF_BIN is None, reason=_SKIP_RUFF)
def test_new_repo_no_upstream_prepush_hands_ruff_the_full_tracked_set(
        tmp_path, monkeypatch, live_ruff_path_env):
    root = _new_repo_no_upstream(tmp_path)
    _no_user_config(tmp_path, monkeypatch)

    # Committed, NOT staged -- the working tree exactly matches HEAD, so the
    # pre-fix `changed_files(root, None)` (git diff --name-only HEAD) path
    # returns nothing here. That emptiness is precisely the bug.
    (root / "danger.py").write_text("def run_it(x):\n    exec(x)\n", encoding="utf-8")
    _git(root, "add", "danger.py")
    _git(root, "commit", "-q", "-m", "add exec violation")

    assert gitutil.resolve_range(root) is None  # sanity: genuinely no upstream/origin

    # gitleaks: clean fixture -- this test is only about the file-set half.
    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks", _gitleaks_clean_fixture())
    # ruff is not normally a pre-push runner (GATE_RUNNER_KEYS) -- added
    # here (the REAL module, spied) specifically to observe ctx.files.
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["gitleaks", "ruff"])

    captured_files: list = []
    real_ruff_run = pipeline.RUNNERS["ruff"].run

    def spy_run(ctx):
        captured_files.append(list(ctx.files))
        return real_ruff_run(ctx)

    monkeypatch.setattr(pipeline.RUNNERS["ruff"], "run", spy_run)

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cmd_check(root, Gate.PRE_PUSH, "range", as_json=True)

    assert captured_files, "ruff.run() was never invoked"
    assert "danger.py" in captured_files[0], (
        "ctx.files was missing danger.py -- pre-push under-scanned a brand-new repo's "
        f"first push (MUST-FIX 1). captured ctx.files={captured_files!r}")

    assert rc == 1
    payload = json.loads(buf.getvalue())
    s102 = [f for f in payload["findings"] if f["rule"] == "S102"]
    assert s102, payload["findings"]
    assert all(f["tool"] == "ruff" and f["verdict"] == "block" for f in s102), s102


# ================================================ (b) gitleaks-argv half ====

def test_new_repo_no_upstream_prepush_gitleaks_receives_full_history_sentinel(
        tmp_path, monkeypatch):
    root = _new_repo_no_upstream(tmp_path)
    _no_user_config(tmp_path, monkeypatch)

    # A secret committed in a PLAIN commit, nothing currently staged -- the
    # exact scenario `gitleaks protect --staged` can never catch (spec §3's
    # own stated reason gitleaks runs at pre-push: "catches add-then-
    # remove"). gitleaks itself is not installed on this machine (fixture
    # throughout this suite) -- the fake below captures the `ctx.rng` the
    # real pipeline hands it, which is exactly what `_build_argv` (see
    # test_runner_gitleaks.py) branches on to decide `protect --staged` vs
    # a full-history `git log` scan.
    (root / "secret.py").write_text("AWS_KEY = 'AKIAFAKEFAKEFAKEFAKE'\n", encoding="utf-8")
    _git(root, "add", "secret.py")
    _git(root, "commit", "-q", "-m", "accidentally commit a secret")

    assert gitutil.resolve_range(root) is None  # sanity: genuinely no upstream/origin

    captured_rng: list = []
    secret_raw = RawFinding(tool="gitleaks", rule="aws-access-token", severity_raw="high",
                             file="secret.py", line=1,
                             message="Identified a fake AWS access token",
                             secret="AKIAFAKEFAKEFAKEFAKE")

    def fake_run(ctx):
        captured_rng.append(ctx.rng)
        return RunnerResult("gitleaks", ToolState.OK)

    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks",
                         SimpleNamespace(run=fake_run, parse=lambda result, ctx: [secret_raw]))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["gitleaks"])

    rc = cmd_check(root, Gate.PRE_PUSH, "range")

    assert captured_rng == [pipeline.FULL_HISTORY_RNG], (
        "gitleaks must receive the full-history sentinel (\"\"), not None -- None builds "
        "'protect --staged', which silently scans nothing on a brand-new repo's first push "
        f"(MUST-FIX 1). captured ctx.rng={captured_rng!r}")
    assert rc == 1, "a real secret in the very first commit must BLOCK the first push"


# ============================================== (c) normal case unaffected ==

def test_prepush_range_mode_with_real_upstream_still_scans_only_the_range(tmp_path):
    """Regression guard: the None -> "full history" fallback must ONLY
    trigger when `resolve_range()` genuinely returns `None`. Once a real
    upstream exists, range mode must keep scanning only the actual diff
    range, never silently widening to the whole tracked set."""
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)],
                    check=True, capture_output=True, text=True)

    root = _new_repo_no_upstream(tmp_path)
    _git(root, "remote", "add", "origin", str(origin))
    _git(root, "push", "-q", "-u", "origin", "main")

    # A second, NOT-YET-PUSHED commit -- this is the only file that should
    # appear in the range-mode file set once @{u} is established.
    (root / "new_file.py").write_text("y = 2\n", encoding="utf-8")
    _git(root, "add", "new_file.py")
    _git(root, "commit", "-q", "-m", "second commit, not pushed")

    rng = gitutil.resolve_range(root)
    assert rng == "@{u}..HEAD"  # a real range resolved, not None

    files, returned_rng = pipeline._discover_files(root, "range")

    assert returned_rng == rng
    assert returned_rng != pipeline.FULL_HISTORY_RNG
    assert files == ["new_file.py"]     # only the unpushed commit's change
    assert "README.md" not in files     # already-pushed content excluded
