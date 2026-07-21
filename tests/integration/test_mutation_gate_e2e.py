"""End-to-end (real git, real @{u}..HEAD range, real cmd_check): a seeded
surviving-mutant ledger finding warns while baking, blocks when armed, and
resolves when the pushed range adds the mapped test -- the whole 1b chain
through the exit code. Real subprocess RUNNERS are isolated out
(GATE_RUNNER_KEYS -> []) so the exit code reflects ONLY the mutation ledger
gate, never a stray lint/tests-failed BLOCK from the fixture repo -- exactly as
tests/unit/test_llm_gate.py::test_pipeline_pre_push_integration does. The git
range that drives auto_resolve_mutation stays fully real.
"""
import subprocess

from aramid import pipeline
from aramid.commands.check import cmd_check
from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Source, Verdict

NOW = "2026-07-21T12:00:00+00:00"


def _no_runners(monkeypatch):
    monkeypatch.setattr(pipeline, "GATE_RUNNER_KEYS",
                        {**pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH: []})


def _run(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   capture_output=True, text=True)


def _repo_with_upstream(tmp_path):
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    r = tmp_path / "repo"
    r.mkdir()
    _run(r, "init", "-q", "-b", "main")
    _run(r, "config", "user.email", "t@t")
    _run(r, "config", "user.name", "t")
    (r / "src").mkdir()
    (r / "src" / "widget.py").write_text("def add(a, b):\n    return a + b\n",
                                         encoding="utf-8")
    _run(r, "add", ".")
    _run(r, "commit", "-q", "-m", "c1")
    _run(r, "remote", "add", "origin", str(remote))
    _run(r, "push", "-q", "-u", "origin", "main")
    return r


def _seed_survivor(r):
    """Seed an OPEN mutation finding on src/widget.py (module stem 'widget')."""
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        f = Finding(id="w" * 64, tool="mutation", rule="flip_arith",
                    severity_raw="medium", severity=Severity.MEDIUM,
                    verdict=Verdict.WARN, file="src/widget.py", line=2,
                    message="mutant survived: a - b", evidence="",
                    gate=Gate.ALL, source=Source.DETERMINISTIC)
        led.record_run("r0", NOW, "drain", set(), set(), [f])
    finally:
        led.close()


def _commit_unrelated(r):
    (r / "src" / "other.py").write_text("y = 2\n", encoding="utf-8")
    _run(r, "add", ".")
    _run(r, "commit", "-q", "-m", "unrelated change")


def _arm_mutation(r):
    (r / "aramid.toml").write_text(
        "schema_version = 1\n\n[mutation]\nmutation_block_armed = true\n",
        encoding="utf-8")


def test_e2e_baking_warns_armed_blocks_then_resolves(tmp_path, monkeypatch):
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _seed_survivor(r)

    # An unrelated commit puts something in the @{u}..HEAD range WITHOUT
    # touching widget.py or a mapped test -> the survivor is not resolved.
    _commit_unrelated(r)

    # Baking (no arm config): warns, does not block.
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc != 1

    # Armed: the survivor blocks.
    _arm_mutation(r)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc == 1

    # Add the mapped test in the pushed range -> resolves before the block
    # check -> no longer blocks.
    (r / "tests").mkdir()
    (r / "tests" / "test_widget.py").write_text(
        "from src.widget import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n",
        encoding="utf-8")
    _run(r, "add", ".")
    _run(r, "commit", "-q", "-m", "add widget test")
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc != 1


def test_e2e_armed_block_survives_fresh_ledger(tmp_path, monkeypatch):
    """A fresh ledger (no baseline) with an armed survivor still blocks -- the
    fresh-clone downgrade does NOT fire because _has_genuine_block sees the
    armed mutation BLOCK as genuine (via the classify branch)."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _arm_mutation(r)
    _seed_survivor(r)
    _commit_unrelated(r)
    # has_baseline() is False here -> cmd_check takes the fresh path, writes a
    # baseline, and must NOT downgrade the armed BLOCK.
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc == 1
