"""End-to-end (real git, real @{u}..HEAD range, real cmd_check): a seeded
transition regression in CONSUMER_RUN_FINISHED history warns while baking,
blocks when [mutation].score_block_armed, is EPHEMERALLY suppressed when the
pushed range adds the mapped test, is NOT suppressed under mode "all", and
survives a fresh-ledger baseline (the classify branch makes
_has_genuine_block see the armed BLOCK as genuine). Mirrors
test_mutation_gate_e2e.py: GATE_RUNNER_KEYS emptied so the exit code
reflects only the gate producers, never a stray lint/tests-failed BLOCK."""
import subprocess

from aramid import pipeline
from aramid.commands.check import cmd_check
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Gate

NOW = "2026-07-24T12:00:00+00:00"
FP = "deadbeef"


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


def _crf(idx, killed_s1, survived_s1, killed_fps, survivor_fps):
    return Event(EventType.CONSUMER_RUN_FINISHED, f"r{idx}", NOW, payload={
        "consumer": "mutation", "item_id": "q",
        "mutation_scores": {"schema": 1, "targets": {"src/widget.py::add": {
            "generated": killed_s1 + survived_s1, "killed_s1": killed_s1,
            "survived_s1": survived_s1, "timeouts": 0, "errors": 0,
            "fully_mutated": True, "killed_fps": list(killed_fps),
            "survivor_fps": list(survivor_fps)}}}})


def _seed_transition(r):
    """Baseline kills FP; current run confirms FP as a survivor."""
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.append(_crf(0, 2, 0, [FP, "other"], []))
        led.append(_crf(1, 1, 1, ["other"], [FP]))
    finally:
        led.close()


def _arm_score(r):
    (r / "aramid.toml").write_text(
        "schema_version = 1\n\n[mutation]\nscore_block_armed = true\n",
        encoding="utf-8")


def _commit_unrelated(r):
    (r / "src" / "other.py").write_text("y = 2\n", encoding="utf-8")
    _run(r, "add", ".")
    _run(r, "commit", "-q", "-m", "unrelated change")


def _commit_mapped_test(r):
    (r / "tests").mkdir(exist_ok=True)
    (r / "tests" / "test_widget.py").write_text(
        "from src.widget import add\n\n\ndef test_add():\n"
        "    assert add(1, 2) == 3\n",
        encoding="utf-8")
    _run(r, "add", ".")
    _run(r, "commit", "-q", "-m", "add widget test")


def test_e2e_baking_warns_armed_blocks_mapped_test_suppresses(tmp_path,
                                                              monkeypatch):
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _seed_transition(r)
    _commit_unrelated(r)          # something in @{u}..HEAD, no mapped test

    # Baking: the transition WARNs, never blocks.
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc != 1

    # Armed: the transition blocks.
    _arm_score(r)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc == 1

    # Mapped test in the pushed range -> ephemeral suppression, no block.
    _commit_mapped_test(r)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc != 1


def test_e2e_mode_all_never_suppresses(tmp_path, monkeypatch):
    """Under mode "all" the pipeline passes changed_files=None -- the mapped
    test sitting in the tree must NOT suppress (only a range push does)."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _seed_transition(r)
    _arm_score(r)
    _commit_mapped_test(r)        # mapped test exists and is in the range

    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc != 1                # range mode: suppressed

    rc = cmd_check(r, Gate.PRE_PUSH, "all")
    assert rc == 1                # all mode: no suppression -> blocks


def test_e2e_armed_block_survives_fresh_baseline(tmp_path, monkeypatch):
    """A fresh ledger (no baseline snapshot) with an armed transition still
    blocks -- the fresh-clone downgrade does NOT fire because
    _has_genuine_block sees the armed mutation-score BLOCK as genuine via
    the classify branch."""
    _no_runners(monkeypatch)
    r = _repo_with_upstream(tmp_path)
    _arm_score(r)
    _seed_transition(r)
    _commit_unrelated(r)
    rc = cmd_check(r, Gate.PRE_PUSH, "range")
    assert rc == 1
