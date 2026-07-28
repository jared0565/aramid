"""T-8 end-to-end: a repo whose stack detection strands a ruff finding,
proven through the real pipeline -- not hand-appended ledger events."""
import subprocess
from pathlib import Path

from aramid import cli, config as config_mod, pipeline
from aramid.commands.status import cmd_status
from aramid.ledger import Ledger
from aramid.models import Gate
from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "app.py").write_text("import os\n", encoding="utf-8")  # F401-shaped
    _git(r, "add", "app.py")
    _git(r, "commit", "-q", "-m", "initial")
    return r


def test_ghost_ruff_finding_surfaces_retires_and_resurrects(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    monkeypatch.chdir(root)  # cli.main resolves root from Path.cwd()
    cfg = config_mod.load_config(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")

    # 1. Seed the ghost: a real ruff finding, run while python IS the stack.
    fake_ruff_raw = [RawFinding(tool="ruff", rule="F401", severity_raw="low",
                                file="app.py", line=1, message="unused import")]
    monkeypatch.setitem(
        pipeline.RUNNERS, "ruff",
        type("F", (), {"run": staticmethod(lambda ctx: RunnerResult("ruff", ToolState.OK, raw="")),
                       "parse": staticmethod(lambda result, ctx: fake_ruff_raw)})())
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["gitleaks", "ruff"])

    result1 = pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger, run_id="run-seed")
    fid = next(f.id for f in result1.findings if f.tool == "ruff")

    # 2. Detection strands it: remove app.py so python is no longer detected
    #    (a real repo would lose it via a detector-fix branch, per spec's
    #    motivating pawscout case -- this fixture forces the same end state
    #    directly rather than re-deriving a detector regression).
    (root / "app.py").unlink()
    _git(root, "rm", "--cached", "-q", "app.py")
    _git(root, "commit", "-q", "-m", "remove python file")

    # 3. status names it as a candidate.
    rc = cmd_status(root)
    out = capsys.readouterr().out
    assert rc == 0
    assert "unreachable candidates:" in out
    assert fid in out
    assert f"aramid ledger mark-unreachable {fid} --reason ..." in out

    # 4. Retire it.
    rc = cli.main(["ledger", "mark-unreachable", fid, "--reason", "no python stack anymore"])
    assert rc == 0
    capsys.readouterr()

    # 5. It leaves the open count and the candidate nag.
    rc = cmd_status(root)
    out = capsys.readouterr().out
    assert "unreachable: 1" in out
    assert "unreachable candidates" not in out
    assert ledger.open_findings()[fid]["status"] == "unreachable"

    # 6. Restore detection, re-run the gate, prove it comes back open.
    (root / "app.py").write_text("import os\n", encoding="utf-8")
    _git(root, "add", "app.py")
    _git(root, "commit", "-q", "-m", "restore python file")
    cfg2 = config_mod.load_config(root)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["gitleaks", "ruff"])
    pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg2, ledger, run_id="run-restore")

    assert ledger.open_findings()[fid]["status"] == "open"
    ledger.close()
