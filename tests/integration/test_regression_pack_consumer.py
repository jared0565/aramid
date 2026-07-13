"""Fixture-driven consumer tests + THE reintroduction e2e (spec section 7):
resolve a finding -> compile pack rule -> reintroduce the pattern ->
the gate blocks. Live-semgrep parts reuse test_semgrep_rules.py's
discovery/skip pattern (copied verbatim -- see that module's docstring for
why semgrep needs PATH-fixture discovery on Windows dev machines)."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from aramid import pack, queue
from aramid.consumers import regression_pack
from aramid.consumers.base import CONSUMERS, DrainContext
from aramid.ledger import Ledger
from aramid.runners.base import RunnerResult, ToolState


def test_consumer_registered():
    assert CONSUMERS.get("regression_pack") is regression_pack


def _item(head="deadbee"):
    return queue.QueueItem(id="i1", base=None, head=head, score=50, reasons=("r",),
                           state="queued", created_at="t", updated_at="t")


def test_no_pack_file_is_ok_noop(tmp_path):
    ctx = DrainContext(root=tmp_path, cfg=None, ledger=None, clock=lambda: "t")
    res = regression_pack.consume(_item(), ctx)
    assert res.state == "ok" and res.findings == [] and "no pack" in res.note


def test_consume_parses_semgrep_output(tmp_path, monkeypatch):
    (tmp_path / pack.RULES_REL_PATH).parent.mkdir(parents=True)
    (tmp_path / pack.RULES_REL_PATH).write_text("rules: []\n", encoding="utf-8")
    # the changed-path filter requires the file to actually exist under root
    # (consume() drops paths that don't -- deleted/renamed-away files can't
    # be scanned); run_subprocess itself is faked below, so content is moot.
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "prod.env").write_text("x\n", encoding="utf-8")
    payload = {"results": [{"check_id": "x.aramid-regression.block.deadbeef",
                            "path": "cfg/prod.env", "start": {"line": 3},
                            "extra": {"severity": "ERROR", "message": "reintroduction"}}]}
    monkeypatch.setattr(regression_pack, "_changed_paths", lambda root, item: ["cfg/prod.env"])
    monkeypatch.setattr(
        regression_pack, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="semgrep", state=ToolState.OK, raw=json.dumps(payload)))
    ctx = DrainContext(root=tmp_path, cfg=None, ledger=None, clock=lambda: "t")
    res = regression_pack.consume(_item(), ctx)
    assert res.state == "ok"
    assert res.findings[0].rule == "aramid-regression.block.deadbeef"
    assert res.cost == 0.0


# --- live semgrep discovery, copied verbatim from test_semgrep_rules.py -----

def _find_semgrep() -> Path | None:
    candidates: list[Path] = []
    which = shutil.which("semgrep")
    if which:
        candidates.append(Path(which))
    exe_dir = Path(sys.executable).parent
    candidates.append(exe_dir / "Scripts" / "semgrep.exe")
    candidates.append(exe_dir / "semgrep")
    for entry in sys.path:
        p = Path(entry)
        if p.name == "site-packages":
            candidates.append(p.parent / "Scripts" / "semgrep.exe")
            candidates.append(p.parent / "bin" / "semgrep")
    for c in candidates:
        if c.exists():
            return c
    return None


_SEMGREP_BIN = _find_semgrep()
_SKIP_REASON = (
    "semgrep console-script not found via shutil.which, next to sys.executable, "
    "or next to any sys.path site-packages dir -- cannot exercise a live scan "
    "in this environment."
)


@pytest.fixture
def semgrep_path_env(monkeypatch):
    """Prepend the discovered semgrep's directory to PATH.

    Needed for two independent reasons: (1) `aramid.runners.base.run_subprocess`
    gates on `shutil.which(argv[0])` before it will even attempt to run
    "semgrep", and (2) the semgrep.exe console script itself shells out to a
    sibling `pysemgrep` process by bare name -- if that directory isn't on
    PATH, semgrep.exe fails with "executing pysemgrep failed" even when
    invoked by its own full path.
    """
    assert _SEMGREP_BIN is not None
    monkeypatch.setenv("PATH", str(_SEMGREP_BIN.parent) + os.pathsep + os.environ.get("PATH", ""))


# --- THE reintroduction e2e --------------------------------------------------

def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _make_git_repo(tmp_path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")
    return root


@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_reintroduction_blocks_at_gate_live(tmp_path, semgrep_path_env):
    """resolve -> compile -> reintroduce -> BLOCK, through the real pipeline."""
    import uuid
    from aramid import config as config_mod
    from aramid import pipeline
    from aramid.models import Event, EventType, Gate, Verdict

    root = _make_git_repo(tmp_path)
    # 1. seed a rotated gitleaks finding whose evidence anchors are known
    led = Ledger(root / ".aramid" / "ledger.db")
    fid = "e" * 64
    led.append(Event(EventType.FINDING_DETECTED, uuid.uuid4().hex, "t", finding_id=fid,
                     payload={"tool": "gitleaks", "rule": "generic-api-key",
                              "file": "cfg.env", "verdict": "block",
                              "severity": "critical", "line": 1, "message": "key",
                              "evidence": "AK…LE (sha256:x)", "historical": False}))
    led.append(Event(EventType.FINDING_ROTATED, uuid.uuid4().hex, "t", finding_id=fid))
    led.close()
    # 2. compile the pack
    from aramid.commands.pack_cmd import cmd_pack_compile
    assert cmd_pack_compile(root) == 0
    # 3. reintroduce a matching value and commit it
    (root / "cfg.env").write_text("AKSOMETHINGSECRETLE\n", encoding="utf-8")
    _git(root, "add", "cfg.env")
    _git(root, "commit", "-m", "reintroduce")
    # 4. the ALL gate must now block via the pack rule
    cfg = config_mod.load_config(root)
    led = Ledger(root / ".aramid" / "ledger.db")
    try:
        result = pipeline.run_gate(root, Gate.ALL, "all", cfg, led)
        pack_blocks = [f for f in result.findings
                       if f.rule.startswith("aramid-regression.block.")
                       and f.verdict is Verdict.BLOCK]
        assert pack_blocks, [f"{f.rule}:{f.verdict}" for f in result.findings]
    finally:
        led.close()
