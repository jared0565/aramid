"""Integration: the mutation consumer against real git worktrees + real
pytest on tiny fixture repos. Budgets are tightened via aramid.toml so each
scenario runs a handful of pytest invocations, not hundreds.

Fixture-design note: the mutated function must have NO equivalent mutants
for its operator set, or the strong-suite test cannot pass. A clamp-style
function is the classic trap (x > 10 -> x >= 10 is behaviorally identical
at the clamp point). is_adult(age >= 18) is boundary-observable: cmp-flip
(>= -> >) and int-bound (18 -> 19) BOTH flip is_adult(18) -- killable by
any test that pins the boundary. (Real repos WILL produce occasionally-
equivalent mutants; that inherent noise is why 2c-1 is WARN-only.)"""
import subprocess

import pytest

from aramid import config as config_mod
from aramid.consumers import mutation as mut_consumer
from aramid.consumers.base import DrainContext
from aramid.ledger import Ledger
from aramid.queue import QueueItem


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _sha(root) -> str:
    cp = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                         capture_output=True, text=True)
    return cp.stdout.strip()


ADULT = ("def is_adult(age):\n"
         "    if age >= 18:\n"
         "        return True\n"
         "    return False\n")
WEAK_TEST = ("from calc import is_adult\n"
             "def test_type():\n"
             "    assert isinstance(is_adult(5), bool)\n")
STRONG_TEST = ("from calc import is_adult\n"
               "def test_boundary():\n"
               "    assert is_adult(18) is True\n"
               "    assert is_adult(17) is False\n"
               "    assert is_adult(19) is True\n")


def _repo(tmp_path, test_body, extra_files=()):
    r = tmp_path / "r"
    (r / "tests").mkdir(parents=True)
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[mutation]\nmax_mutants = 3\nconfirm_cap = 3\n"
        "wall_budget_s = 300\nmutant_timeout_s = 60\n", encoding="utf-8")
    (r / "conftest.py").write_text("import sys, pathlib\n"
                                   "sys.path.insert(0, str(pathlib.Path(__file__).parent))\n",
                                   encoding="utf-8")
    (r / "calc.py").write_text("def is_adult(age):\n    return False\n",
                               encoding="utf-8")
    (r / "tests" / "test_calc.py").write_text(test_body, encoding="utf-8")
    for name, content in extra_files:
        (r / name).write_text(content, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    (r / "calc.py").write_text(ADULT, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "feature")
    return r, base, _sha(r)


def _consume(r, base, head, monkeypatch, tmp_path):
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    item = QueueItem(id="q1", base=base, head=head, score=55, reasons=("t",),
                     state="queued", created_at="t", updated_at="t")
    try:
        return mut_consumer.consume(item, DrainContext(root=r, cfg=cfg,
                                                        ledger=led, clock=lambda: "t"))
    finally:
        led.close()


def _no_worktrees(r):
    cp = subprocess.run(["git", "worktree", "list"], cwd=r, check=True,
                         capture_output=True, text=True)
    return len([ln for ln in cp.stdout.splitlines() if ln.strip()]) == 1


def test_weak_suite_survivor_confirmed_and_reported(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings, "a survivor must be reported against a weak suite"
    f = res.findings[0]
    assert f.tool == "mutation" and f.file == "calc.py"
    assert "mutant survived" in f.message
    assert res.extra["confirmed"] >= 1
    assert _no_worktrees(r), "throwaway worktree must be removed"


def test_strong_suite_kills_no_findings(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, STRONG_TEST)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings == []
    assert res.extra["killed"] >= 1
    assert _no_worktrees(r)


def test_stage2_rescue_prevents_false_survivor(tmp_path, monkeypatch):
    # Stage-1 selection runs tests/test_calc.py (weak). A DIFFERENT test file
    # -- never selected by the test_<module>.py heuristic -- pins the boundary
    # and kills every mutant at the full-suite confirmation, so no finding
    # may be reported.
    other = ("from calc import is_adult\n"
             "def test_cross_file_boundary():\n"
             "    assert is_adult(18) is True\n"
             "    assert is_adult(17) is False\n")
    r, base, head = _repo(tmp_path, WEAK_TEST,
                          extra_files=[("tests/test_other.py", other)])
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings == [], "full-suite confirmation must kill what stage 1 missed"
    assert res.extra["killed"] >= 1


def test_no_pytest_stack_skips_ok_with_loud_note(tmp_path, monkeypatch):
    # JS-only / test-less repo: PERMANENT structural absence must be an OK
    # skip with a loud note (the 2c-1b seam), NOT degraded -- the drain
    # refuses to mark items drained while any consumer is degraded, so
    # degraded here would pin queue items forever on non-Python repos
    # (caught live by test_llm_review's no-providers drain e2e).
    import shutil as _shutil
    r, base, head = _repo(tmp_path, WEAK_TEST)
    _shutil.rmtree(r / "tests")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "drop tests")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings == []
    assert "no python test stack" in res.note


def test_baseline_red_degrades_no_findings(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, "def test_always_fails():\n    assert False\n")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "degraded"
    assert "baseline" in res.note
    assert res.findings == []
    assert _no_worktrees(r)


def test_no_python_files_is_ok_noop(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    (r / "notes.md").write_text("hi\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "docs")
    res = _consume(r, head, _sha(r), monkeypatch, tmp_path)
    assert res.state == "ok" and res.findings == []
    assert "no python files" in res.note


def test_budget_truncation_visible(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[mutation]\nmax_mutants = 1\nconfirm_cap = 1\n",
        encoding="utf-8")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.extra["truncated"] is True
    assert "truncated" in res.note


def test_worktree_removed_on_midloop_exception(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, WEAK_TEST)
    monkeypatch.setattr(mut_consumer.mutation, "generate_mutants",
                         lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        _consume(r, base, head, monkeypatch, tmp_path)
    assert _no_worktrees(r), "finally must remove the worktree even on a crash"


def test_drain_e2e_records_mutation_run(tmp_path, monkeypatch):
    from aramid import registry
    from aramid.commands import drain as drain_mod
    from aramid.commands.drain import cmd_drain
    from aramid.models import EventType
    from aramid import queue as queue_mod

    r, base, head = _repo(tmp_path, WEAK_TEST)
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "repos.toml")
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: tmp_path / "drain.lock")
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    registry.register(r, "2026-07-20T10:00:00+00:00")
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        queue_mod.enqueue(led, "2026-07-20T10:00:00+00:00", base, head, 55, ["seed"])
    finally:
        led.close()

    rc = cmd_drain([str(r)])
    assert rc in (0, 2)  # 2 allowed: llm consumer may degrade w/o providers

    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        events = led.events()
        runs = [e for e in events if e.type is EventType.CONSUMER_RUN_FINISHED
                and e.payload.get("consumer") == "mutation"]
        assert runs, "drain must have run the mutation consumer"
        assert "confirmed" in runs[-1].payload  # extra payload merged
        state = led.open_findings()
        assert any(rec.get("tool") == "mutation" for rec in state.values()), \
            "confirmed survivor must land in the ledger as a finding"
    finally:
        led.close()


def test_mutation_findings_classify_warn_never_block(tmp_path, monkeypatch):
    from aramid.models import Gate
    from aramid import policy
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(tmp_path)
    severity, verdict = policy.classify("mutation", "cmp-flip", "medium",
                                        Gate.ALL, cfg=cfg)
    assert str(verdict) != "block"
    assert not any("mutation" in key for key in cfg.block_rules), \
        "block_rules must have no mutation entry (spec invariant 3)"
