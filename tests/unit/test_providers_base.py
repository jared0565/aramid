import sys
from types import SimpleNamespace

from aramid.providers import base


def _cfg(order):
    return SimpleNamespace(llm={"provider_order": order})


def test_chain_respects_order_and_availability(monkeypatch):
    a = SimpleNamespace(NAME="a", available=lambda cfg: True)
    b = SimpleNamespace(NAME="b", available=lambda cfg: False)
    c = SimpleNamespace(NAME="c", available=lambda cfg: True)
    monkeypatch.setattr(base, "PROVIDERS", {"a": a, "b": b, "c": c})
    got = base.chain(_cfg(["c", "b", "a"]))
    assert [p.NAME for p in got] == ["c", "a"]


def test_chain_unknown_name_skipped(monkeypatch):
    a = SimpleNamespace(NAME="a", available=lambda cfg: True)
    monkeypatch.setattr(base, "PROVIDERS", {"a": a})
    assert [p.NAME for p in base.chain(_cfg(["ghost", "a"]))] == ["a"]


def test_chain_available_raises_counts_as_unavailable(monkeypatch):
    def boom(cfg):
        raise RuntimeError("probe exploded")
    a = SimpleNamespace(NAME="a", available=boom)
    monkeypatch.setattr(base, "PROVIDERS", {"a": a})
    assert base.chain(_cfg(["a"])) == []       # fail-open: skip, never crash


def test_run_provider_subprocess_pipes_prompt_utf8():
    rc, out, err = base.run_provider_subprocess(
        [sys.executable, "-c", "import sys; print(sys.stdin.read())"],
        "héllo prompt", timeout_s=30.0)
    assert rc == 0
    assert "héllo prompt" in out


def test_run_provider_subprocess_timeout_returns_none():
    got = base.run_provider_subprocess(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        "x", timeout_s=1.0)
    assert got is None


def test_tree_kill_uses_taskkill_on_windows_with_a_30s_timeout_and_nothing_elsewhere(monkeypatch):
    """The provider ladder's own tree kill: the Windows branch only. Faked
    at the subprocess so the branch runs on every CI leg (the ratchet's
    count must not depend on the leg it runs on); off Windows the
    function is a no-op, the runner's killpg path being the one that
    reaps a provider there."""
    calls = []
    monkeypatch.setattr(base.sys, "platform", "win32")
    monkeypatch.setattr(base.subprocess, "run",
                        lambda argv, **kw: calls.append((argv, kw.get("timeout"))))
    base._tree_kill(4242)
    assert calls == [(["taskkill", "/PID", "4242", "/T", "/F"], 30)]
    monkeypatch.setattr(base.sys, "platform", "linux")
    base._tree_kill(4242)
    assert len(calls) == 1
