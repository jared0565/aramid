"""integration: FN-38 -- a tool's own inline marker that hides a BLOCK-tier hit
is reported, through the real gate, with the REAL tool.

Spec section 6: for each tool a bare control (the tool's own BLOCK fires and no
`inline-suppressed-block`) and a marked arm (no tool BLOCK, exactly one
`inline-suppressed-block` naming the tool, rule and line). The runner list is
the real one; every runner but the tool under test is swapped for a clean
double, so the only thing that can produce a finding is that tool and its
second pass. Each tool skips where its binary is absent (CI provisions all
three).
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
from aramid.commands.check import cmd_check
from aramid.models import Gate
from aramid.runners import inline
from aramid.runners.base import RunnerResult, ToolState


def _find_tool(name: str) -> Path | None:
    # Same search as test_prepush_gate_runs_ruff.py: ruff and semgrep install
    # into the interpreter's per-user Scripts dir here, which is not on PATH.
    candidates: list[Path] = []
    which = shutil.which(name)
    if which:
        candidates.append(Path(which))
    exe_dir = Path(sys.executable).parent
    candidates += [exe_dir / "Scripts" / f"{name}.exe", exe_dir / name]
    for entry in sys.path:
        p = Path(entry)
        if p.name == "site-packages":
            candidates += [p.parent / "Scripts" / f"{name}.exe", p.parent / "bin" / name]
    return next((c for c in candidates if c.exists()), None)


_BINS = {name: _find_tool(name) for name in ("ruff", "semgrep", "gitleaks")}
_TOKEN = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"


@pytest.fixture
def real(monkeypatch, tmp_path):
    """`real("ruff")`: put that binary on PATH, make every other gate runner a
    clean double, and keep the user's config out."""
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")

    def _use(tool: str) -> None:
        if _BINS[tool] is None:
            pytest.skip(f"{tool} binary not found")
        monkeypatch.setenv("PATH", str(_BINS[tool].parent) + os.pathsep + os.environ["PATH"])
        for key in {k for keys in pipeline.GATE_RUNNER_KEYS.values() for k in keys}:
            if key != tool:
                monkeypatch.setitem(pipeline.RUNNERS, key, SimpleNamespace(
                    run=lambda ctx, _k=key: _clean(_k),
                    parse=lambda result, ctx: []))
    return _use


def _clean(key: str) -> RunnerResult:
    # Shaped like the real runner: ruff, gitleaks and semgrep carry their inline
    # pass whenever they run OK.
    own = RunnerResult(key, ToolState.OK)
    if key not in inline.LABELS:
        return own
    return inline.bundle(own, RunnerResult(inline.LABELS[key], ToolState.OK,
                                           examined=frozenset()))


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(root), check=True, capture_output=True, text=True)


def _repo(tmp_path: Path, files: dict[str, str], *, origin: bool = False) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "seed")
    if origin:
        bare = tmp_path / "origin.git"
        subprocess.run(["git", "init", "-q", "--bare", str(bare)],
                       check=True, capture_output=True, text=True)
        _git(root, "remote", "add", "origin", str(bare))
        _git(root, "push", "-q", "-u", "origin", "main")
    return root


def _gate(root: Path, gate=Gate.PRE_COMMIT, mode="all", strict=False) -> tuple[int, dict]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cmd_check(root, gate, mode, strict=strict, as_json=True)
    return rc, json.loads(buf.getvalue())


def _by(payload: dict, tool: str) -> list[dict]:
    return [f for f in payload["findings"] if f["tool"] == tool]


def _assert_one_inline(payload: dict, label: str, tool: str, rule: str, line: int) -> dict:
    [hit] = _by(payload, label)
    assert hit["rule"] == inline.RULE and hit["verdict"] == "warn", hit
    assert hit["line"] == line, hit
    assert tool in hit["message"] and rule in hit["message"], hit["message"]
    return hit


# ------------------------------------------------------------------- ruff ---

_CRED_LINE = 'password = "hunter2-very-secret"'


def test_ruff_control_blocks_and_reports_no_marker(tmp_path, real):
    real("ruff")
    root = _repo(tmp_path, {"creds.py": _CRED_LINE + "\n"})
    rc, payload = _gate(root)
    assert rc == 1, payload
    assert [f["rule"] for f in _by(payload, "ruff")] == ["S105"]
    assert _by(payload, inline.RUFF) == []
    assert inline.RUFF in payload["tools_ran"]


def test_a_noqa_comment_is_reported_and_no_longer_hides_silently(tmp_path, real):
    real("ruff")
    root = _repo(tmp_path, {"creds.py": f"X = 1\n{_CRED_LINE}  # noqa: S105\n"})
    rc, payload = _gate(root)
    assert rc == 0, payload
    assert _by(payload, "ruff") == []
    hit = _assert_one_inline(payload, inline.RUFF, "ruff", "S105", 2)
    assert "`# noqa`" in hit["message"]


def test_a_per_file_ignores_entry_is_reported(tmp_path, real):
    real("ruff")
    root = _repo(tmp_path, {
        "pyproject.toml": '[tool.ruff.lint]\nper-file-ignores = {"tests/*" = ["S105"]}\n',
        "tests/helper.py": _CRED_LINE + "\n"})
    rc, payload = _gate(root)
    assert rc == 0, payload
    hit = _assert_one_inline(payload, inline.RUFF, "ruff", "S105", 1)
    assert hit["file"] == "tests/helper.py" and "per-file-ignores" in hit["message"]


def test_a_file_the_repo_excludes_is_never_reported_as_hidden(tmp_path, real):
    real("ruff")
    root = _repo(tmp_path, {
        "pyproject.toml": '[tool.ruff]\nextend-exclude = ["vendored"]\n',
        "vendored/creds.py": _CRED_LINE + "\n"})
    rc, payload = _gate(root)
    assert rc == 0, payload
    assert _by(payload, "ruff") == _by(payload, inline.RUFF) == []


def test_a_block_rules_code_this_ruff_does_not_know_never_degrades_the_pass(tmp_path, real):
    # A typo in a repo's additions reaches ruff's `--select`, where ruff exits 2.
    # Degraded on every run, `--strict` would refuse every push.
    real("ruff")
    root = _repo(tmp_path, {
        "aramid.toml": '[block_rules.ruff]\nblock = ["S102", "S105", "S106", "S107", '
                       '"S608", "S301", "S302", "S9999"]\n',
        "creds.py": f"{_CRED_LINE}  # noqa: S105\n"})
    rc, payload = _gate(root, strict=True)
    assert rc == 0, payload
    assert payload["degraded"] == [], payload["degraded_reasons"]
    _assert_one_inline(payload, inline.RUFF, "ruff", "S105", 1)

def test_a_noqa_on_a_warn_tier_rule_reports_nothing(tmp_path, real):
    real("ruff")
    root = _repo(tmp_path, {"mod.py": "import os  # noqa: F401\n"})
    rc, payload = _gate(root)
    assert rc == 0, payload
    assert _by(payload, inline.RUFF) == []


def test_existing_markers_never_refuse_the_first_strict_push_after_upgrading(tmp_path, real):
    # Day one: the marker predates the upgrade, so its finding is NEW to this
    # ledger at the push. Ratchet-escalated, the push would be refused for a
    # marker nobody added in it.
    real("ruff")
    root = _repo(tmp_path, {"seed.py": "X = 1\n"}, origin=True)
    (root / "creds.py").write_text(f"{_CRED_LINE}  # noqa: S105\n", encoding="utf-8")
    _git(root, "add", "creds.py")
    _git(root, "commit", "-q", "-m", "a marker, committed before aramid saw it")

    rc, payload = _gate(root, gate=Gate.PRE_PUSH, mode="range", strict=True)

    assert rc == 0, payload
    hit = _assert_one_inline(payload, inline.RUFF, "ruff", "S105", 1)
    assert not hit.get("escalated_by_ratchet"), hit


# ---------------------------------------------------------------- semgrep ---

_SQL = ("def lookup(cur, name):\n"
        "    cur.execute(\"SELECT * FROM t WHERE n = '\" + name + \"'\"){marker}\n")


def _semgrep_repo(tmp_path, marker: str, armed: bool) -> Path:
    return _repo(tmp_path, {
        "aramid.toml": f"semgrep_block_armed = {'true' if armed else 'false'}\n",
        "q.py": _SQL.format(marker=marker)})


def _push_all(root: Path) -> tuple[int, dict]:
    # semgrep runs only at pre-push: CI's second step, `--gate pre-push --all`.
    return _gate(root, gate=Gate.PRE_PUSH, mode="all")


def test_semgrep_control_blocks_and_reports_no_marker(tmp_path, real):
    real("semgrep")
    rc, payload = _push_all(_semgrep_repo(tmp_path, "", armed=True))
    assert rc == 1, payload
    assert [f["verdict"] for f in _by(payload, "semgrep")] == ["block"]
    assert _by(payload, inline.SEMGREP) == []


def test_a_nosemgrep_comment_is_reported_and_no_longer_hides_silently(tmp_path, real):
    real("semgrep")
    rc, payload = _push_all(_semgrep_repo(tmp_path, "  # nosemgrep", armed=True))
    assert rc == 0, payload
    assert _by(payload, "semgrep") == []
    hit = _assert_one_inline(payload, inline.SEMGREP, "semgrep",
                             "owasp-top-ten.a03-injection", 2)
    assert "`# nosemgrep`" in hit["message"]


def test_a_nosemgrep_comment_during_the_bake_reports_nothing(tmp_path, real):
    # Disarmed, the hit it hides would not have blocked either.
    real("semgrep")
    rc, payload = _push_all(_semgrep_repo(tmp_path, "  # nosemgrep", armed=False))
    assert rc == 0, payload
    assert _by(payload, "semgrep") == _by(payload, inline.SEMGREP) == []


# --------------------------------------------------------------- gitleaks ---

def test_gitleaks_control_blocks_and_reports_no_marker(tmp_path, real):
    real("gitleaks")
    root = _repo(tmp_path, {"cfg.txt": f"token: {_TOKEN}\n"})
    rc, payload = _gate(root)
    assert rc == 1, payload
    assert [f["verdict"] for f in _by(payload, "gitleaks")] == ["block"]
    assert _by(payload, inline.GITLEAKS) == []


def test_a_gitleaks_allow_comment_is_reported_without_quoting_the_secret(tmp_path, real):
    real("gitleaks")
    root = _repo(tmp_path, {"cfg.txt": f"note\ntoken: {_TOKEN}  # gitleaks:allow\n"})
    rc, payload = _gate(root)
    assert rc == 0, payload
    assert _by(payload, "gitleaks") == []
    hit = _assert_one_inline(payload, inline.GITLEAKS, "gitleaks", "github-pat", 2)
    assert _TOKEN not in json.dumps(payload)
    logs = root / ".aramid" / "logs"
    assert not any(_TOKEN in p.read_text(encoding="utf-8") for p in logs.glob("*.log"))
    assert hit["file"] == "cfg.txt"


def test_a_gitleaks_allow_comment_in_the_pushed_range_is_reported(tmp_path, real):
    real("gitleaks")
    root = _repo(tmp_path, {"seed.txt": "clean\n"}, origin=True)
    (root / "cfg.txt").write_text(f"token: {_TOKEN}  # gitleaks:allow\n", encoding="utf-8")
    _git(root, "add", "cfg.txt")
    _git(root, "commit", "-q", "-m", "allowed token")

    rc, payload = _gate(root, gate=Gate.PRE_PUSH, mode="range", strict=True)

    assert rc == 0, payload
    _assert_one_inline(payload, inline.GITLEAKS, "gitleaks", "github-pat", 1)
