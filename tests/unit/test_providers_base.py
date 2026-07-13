import subprocess
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
