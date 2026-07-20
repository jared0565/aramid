"""Integration: the fuzz consumer against real git worktrees + the real
driver subprocess on tiny fixture repos."""
import subprocess

import pytest

from aramid import config as config_mod
from aramid.consumers import fuzz as fuzz_consumer
from aramid.consumers.base import DrainContext
from aramid.ledger import Ledger
from aramid.queue import QueueItem


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _sha(root) -> str:
    cp = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                         capture_output=True, text=True)
    return cp.stdout.strip()


BUGGY = ("def head(xs: list[int]) -> int:\n"
         "    return xs[0]\n")            # IndexError on []
CONTRACT = ("def validate(a: int) -> int:\n"
            "    if a < 0:\n"
            "        raise ValueError('neg')\n"
            "    return a\n")
SCARY = ("def delete_everything(target: str) -> None:\n"
         "    return None\n")


def _repo(tmp_path, body, filename="lib.py", extra_toml=""):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[fuzz]\nmax_functions = 5\ncases_per_function = 40\n"
        "wall_budget_s = 200\nbatch_timeout_s = 90\n" + extra_toml, encoding="utf-8")
    (r / filename).write_text("def placeholder() -> None:\n    return None\n",
                              encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    (r / filename).write_text(body, encoding="utf-8")
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
        return fuzz_consumer.consume(item, DrainContext(root=r, cfg=cfg,
                                                        ledger=led, clock=lambda: "t"))
    finally:
        led.close()


def _no_worktrees(r):
    cp = subprocess.run(["git", "worktree", "list"], cwd=r, check=True,
                         capture_output=True, text=True)
    return len([ln for ln in cp.stdout.splitlines() if ln.strip()]) == 1


def test_deep_crash_reported(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, BUGGY)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings, "IndexError crash must be reported"
    f = res.findings[0]
    assert f.tool == "fuzz" and f.file == "lib.py"
    assert f.rule == "crash-indexerror"
    assert "raised IndexError" in f.message
    assert res.extra["crashes"] >= 1
    assert _no_worktrees(r)


def test_contract_exception_not_reported(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, CONTRACT)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings == []
    assert res.extra["contract_exceptions"] >= 1
    assert _no_worktrees(r)


def test_scary_name_skipped(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, SCARY)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.extra["skipped_name"] >= 1
    assert res.extra["functions_fuzzed"] == 0


def test_unhinted_function_fuzzes_zero_cases_ok(tmp_path, monkeypatch):
    # An unhinted function is a candidate by AST but the driver's
    # supported_params finds it unfuzzable -> zero cases run, zero findings,
    # OK (never DEGRADED). functions_seen counts it; cases_run stays 0.
    r, base, head = _repo(tmp_path, "def f(a):\n    return a\n")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings == []
    assert res.extra["cases_run"] == 0
    assert res.extra["functions_seen"] >= 1


def test_no_python_files_ok_noop(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, BUGGY)
    (r / "notes.md").write_text("hi\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "docs")
    res = _consume(r, head, _sha(r), monkeypatch, tmp_path)
    assert res.state == "ok" and res.findings == []
    assert "no python files" in res.note


def test_truncation_visible(tmp_path, monkeypatch):
    body = BUGGY + "\ndef head2(xs: list[int]) -> int:\n    return xs[0]\n"
    r, base, head = _repo(tmp_path, body, extra_toml="")
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[fuzz]\nmax_functions = 1\ncases_per_function = 20\n",
        encoding="utf-8")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.extra["truncated"] is True
    assert "truncated" in res.note


def test_worktree_removed_on_midloop_exception(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, BUGGY)
    monkeypatch.setattr(fuzz_consumer.gitutil, "diff_new_lines",
                        lambda *a, **kw: {"lib.py": {1}})
    monkeypatch.setattr(fuzz_consumer, "_candidate_functions",
                        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        _consume(r, base, head, monkeypatch, tmp_path)
    assert _no_worktrees(r)


def test_fuzz_findings_classify_warn_never_block(tmp_path, monkeypatch):
    from aramid.models import Gate
    from aramid import policy
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(tmp_path)
    _sev, verdict = policy.classify("fuzz", "crash-indexerror", "medium",
                                    Gate.ALL, cfg=cfg)
    assert str(verdict) != "block"
    assert not any("fuzz" in key for key in cfg.block_rules)


def test_determinism_same_findings_twice(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, BUGGY)
    a = _consume(r, base, head, monkeypatch, tmp_path)
    b = _consume(r, base, head, monkeypatch, tmp_path)
    assert [(f.rule, f.file, f.line) for f in a.findings] == \
           [(f.rule, f.file, f.line) for f in b.findings]


def test_drain_e2e_records_fuzz_run(tmp_path, monkeypatch):
    from aramid import registry
    from aramid.commands import drain as drain_mod
    from aramid.commands.drain import cmd_drain
    from aramid.models import EventType
    from aramid import queue as queue_mod

    r, base, head = _repo(tmp_path, BUGGY)
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
    assert rc in (0, 2)

    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        runs = [e for e in led.events()
                if e.type is EventType.CONSUMER_RUN_FINISHED
                and e.payload.get("consumer") == "fuzz"]
        assert runs, "drain must have run the fuzz consumer"
        assert "crashes" in runs[-1].payload   # extra payload merged
        state = led.open_findings()
        assert any(rec.get("tool") == "fuzz" for rec in state.values()), \
            "deep-crash finding must land in the ledger"
    finally:
        led.close()
