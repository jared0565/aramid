import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from aramid import gitutil, queue
from aramid.commands import triage_cmd as triage_mod
from aramid.commands.triage_cmd import cmd_triage
from aramid.ledger import Ledger


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    return r


def _commit(root, name, content, msg):
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(content, encoding="utf-8")
    _git(root, "add", name)
    _git(root, "commit", "-m", msg)


def test_triage_head_scores_risky_commit_and_enqueues(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "src/auth/login.py", "def f(x):\n    exec(x)\n", "risky")
    assert cmd_triage(r, "HEAD") == 0
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        item = queue.queued_item(queue.materialize_queue(led.events()))
        assert item is not None
        assert item.score >= 40
        assert queue.last_triaged_head(led) is not None
    finally:
        led.close()


def test_triage_benign_commit_records_without_enqueue(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "docs/note.md", "hello\n", "docs")
    # novelty alone (+20) stays under min_score 40
    assert cmd_triage(r, "HEAD") == 0
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        assert queue.queued_item(queue.materialize_queue(led.events())) is None
        assert queue.last_triaged_head(led) is not None
    finally:
        led.close()


def test_triage_bad_rev_is_engine_error(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x=1\n", "c")
    assert cmd_triage(r, "no-such-rev") == 3


def test_triage_outside_repo_is_engine_error(tmp_path):
    assert cmd_triage(tmp_path / "empty", "HEAD") == 3


def test_watchdog_kills_hung_triage(tmp_path, monkeypatch):
    # Inject a hang BEFORE repo resolution; the watchdog (armed first) must
    # fire. os._exit is monkeypatched module-locally to a recorder -- the
    # real one would kill pytest.
    exits = []
    monkeypatch.setattr(triage_mod, "os", SimpleNamespace(_exit=lambda c: exits.append(c)))

    def slow_repo_root(p):
        time.sleep(1.5)
        raise gitutil.NotARepo(str(p))

    monkeypatch.setattr(triage_mod.gitutil, "repo_root", slow_repo_root)
    rc = cmd_triage(tmp_path, "HEAD", budget=0.2)
    assert exits == [3], "watchdog must have fired during the injected hang"
    assert rc == 3  # the (faked-survival) body still returns its own error


def test_watchdog_cancelled_on_fast_run(tmp_path, monkeypatch):
    exits = []
    monkeypatch.setattr(triage_mod, "os", SimpleNamespace(_exit=lambda c: exits.append(c)))
    r = _repo(tmp_path)
    _commit(r, "docs/note.md", "hello\n", "docs")
    assert cmd_triage(r, "HEAD", budget=30) == 0
    assert exits == []


def test_no_budget_arms_no_timer(tmp_path, monkeypatch):
    created = []
    monkeypatch.setattr(triage_mod, "threading",
                         SimpleNamespace(Timer=lambda *a, **kw: created.append(a)))
    r = _repo(tmp_path)
    _commit(r, "docs/note.md", "hello\n", "docs")
    assert cmd_triage(r, "HEAD") == 0
    assert created == []


def test_cli_dispatches_triage(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "src/auth/login.py", "def f(x):\n    exec(x)\n", "risky")
    out = subprocess.run([sys.executable, "-m", "aramid", "triage"],
                         cwd=r, capture_output=True, text=True)
    assert out.returncode == 0
    assert "triage" in (out.stdout + out.stderr).lower()
