"""Re-scan before closing (OPERATOR 2026-10-25), live: a staged or range
gitleaks scan reads a patch -- the lines the commit or push adds -- so a secret
on a line the change leaves alone is never reported, and the gate wrote its
open row `fixed` while the secret sat in the file. The row now stays open until
a scan of the whole file, as committed, no longer finds it. Skips where
gitleaks is absent (local dev); runs in CI, which provisions gitleaks on PATH.

Every arm asserts the first gate's own row first: it carries the label its
channel gives it (the tool's own, or the inline label for a hit a marker or a
repo file hid), so an open row is never one that was never written.

The secret-shaped value is built at run time, so this file holds none."""
import secrets
import shutil
import string
import subprocess

import pytest

from aramid import config, pipeline
from aramid.ledger import Ledger
from aramid.models import EventType, Gate
from aramid.runners import gitleaks, inline
from aramid.runners.base import RunnerResult, ToolState

_GITLEAKS = shutil.which("gitleaks")
_SKIP = "gitleaks binary not on PATH (installed in CI, skipped in local dev)"

_ALLOW = "[extend]\nuseDefault = true\n\n[allowlist]\ndescription = \"t\"\npaths = ['''cfg\\.py''']\n"
# The repo's own rule, and no other: a row only it finds.
_CUSTOM = "title = \"t\"\n\n[[rules]]\nid = \"acme-key\"\nregex = '''acme_[a-z0-9]{24}'''\n"
_CHANNELS = ["none", "allow-comment", "ignore-file", "config-file", "custom-rule"]
_OWN = ("none", "custom-rule")


def _git(root, *a):
    return subprocess.run(["git", *a], cwd=root, check=True, capture_output=True,
                          text=True).stdout.strip()


def _token(channel):
    if channel == "custom-rule":
        alnum = string.ascii_lowercase + string.digits
        return "acme_" + "".join(secrets.choice(alnum) for _ in range(24))
    alnum = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alnum) for _ in range(36))


@pytest.fixture(autouse=True)
def _gitleaks_only(monkeypatch):
    monkeypatch.delenv("GITLEAKS_CONFIG", raising=False)
    monkeypatch.delenv("GITLEAKS_CONFIG_TOML", raising=False)
    monkeypatch.delenv("GIT_INDEX_FILE", raising=False)
    for gate in (Gate.PRE_COMMIT, Gate.PRE_PUSH):
        monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, gate, ["gitleaks"])


def _gate(r, ledger, gate, mode, run_id):
    return pipeline.run_gate(r, gate, mode, config.load_config(r), ledger, run_id=run_id)


def _repo(tmp_path, channel):
    """A secret on line 2 of cfg.py, whose first staged gate writes its row,
    then committed and pushed to a bare upstream: (repo, ledger, row id)."""
    empty = tmp_path / "no-hooks"
    empty.mkdir()
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "-q", "--bare", f"--template={empty}", str(remote))
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main", f"--template={empty}")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    _git(r, "config", "core.hooksPath", str(empty))
    _git(r, "remote", "add", "origin", str(remote))
    # Three gitleaks runs in a staged gate (own, inline, files) under load do
    # not fit pre-commit's 5 s, and a skipped pass writes no inline row.
    (r / "aramid.toml").write_text("schema_version = 1\n\n[timeouts]\npre_commit = 120\n",
                                   encoding="utf-8")
    (r / "other.py").write_text("C = 1\n", encoding="utf-8")
    if channel == "ignore-file":
        (r / ".gitleaksignore").write_text("cfg.py:github-pat:2\n", encoding="utf-8")
    if channel in ("config-file", "custom-rule"):
        (r / ".gitleaks.toml").write_text(_ALLOW if channel == "config-file" else _CUSTOM,
                                          encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    marker = "  # gitleaks:allow" if channel == "allow-comment" else ""
    (r / "cfg.py").write_text(f'A = 1\nTOKEN = "{_token(channel)}"{marker}\nB = 2\n',
                              encoding="utf-8")
    _git(r, "add", "cfg.py")
    ledger = Ledger(tmp_path / "l.db")
    first = _gate(r, ledger, Gate.PRE_COMMIT, "staged", "leak")
    rows = [(f.id, f.tool, f.rule) for f in first.findings if f.file == "cfg.py"]
    assert [(tool, rule) for _, tool, rule in rows] == [
        (gitleaks.NAME, "acme-key") if channel == "custom-rule"
        else (gitleaks.NAME, "github-pat") if channel in _OWN
        else (inline.GITLEAKS, inline.RULE)], first.degraded_reasons
    _git(r, "commit", "-q", "-m", "leak")
    _git(r, "push", "-q", "-u", "origin", "main")
    return r, ledger, rows[0][0]


def _change(r, mode, path, text):
    (r / path).write_text(text, encoding="utf-8")
    _git(r, "add", path)
    if mode == "range":
        _git(r, "commit", "-q", "-m", "change")


def _run(r, ledger, mode, run_id="change"):
    if mode == "staged":
        return _gate(r, ledger, Gate.PRE_COMMIT, "staged", run_id)
    return _gate(r, ledger, Gate.PRE_PUSH, "range", run_id)


def _status(ledger, fid):
    return ledger.open_findings()[fid]["status"]


def _events(ledger, run_id, fid):
    return [e.type for e in ledger.events() if e.run_id == run_id and e.finding_id == fid]


def _finished(ledger, run_id):
    return next(e.payload for e in ledger.events()
                if e.run_id == run_id and e.type is EventType.RUN_FINISHED)


def _edit_after_the_secret(r):
    text = (r / "cfg.py").read_text(encoding="utf-8")
    return text.replace("B = 2\n", "B = 3\n")


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
@pytest.mark.parametrize("mode", ["staged", "range"])
@pytest.mark.parametrize("channel", _CHANNELS)
def test_a_patch_scan_leaves_open_the_row_of_a_secret_it_did_not_touch(tmp_path, channel, mode):
    r, ledger, fid = _repo(tmp_path, channel)
    _change(r, mode, "cfg.py", _edit_after_the_secret(r))
    res = _run(r, ledger, mode)
    assert _status(ledger, fid) == "open"
    # Present, not detected: the run writes nothing about the row, and a
    # secret the change did not add blocks nothing.
    assert _events(ledger, "change", fid) == []
    assert res.exit_code == 0 and _finished(ledger, "change")["blocking"] == 0


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
@pytest.mark.parametrize("mode", ["staged", "range"])
def test_a_patch_scan_closes_the_row_once_the_secret_is_gone(tmp_path, mode):
    r, ledger, fid = _repo(tmp_path, "none")
    _change(r, mode, "cfg.py", "A = 1\nTOKEN = None\nB = 2\n")
    _run(r, ledger, mode)
    assert _status(ledger, fid) == "fixed"


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
@pytest.mark.parametrize("mode, staged_too", [("staged", False), ("range", False),
                                              ("range", True)])
def test_what_ships_decides_never_the_working_tree(tmp_path, mode, staged_too):
    """The commit or push still carries the secret; only the disk -- and for
    a push, the index too -- has lost it. What ships is what the row is about."""
    r, ledger, fid = _repo(tmp_path, "none")
    _change(r, mode, "cfg.py", _edit_after_the_secret(r))
    (r / "cfg.py").write_text("A = 1\nTOKEN = None\nB = 3\n", encoding="utf-8")
    if staged_too:
        _git(r, "add", "cfg.py")
    _run(r, ledger, mode)
    assert _status(ledger, fid) == "open"


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
def test_an_edit_to_another_file_leaves_the_row_alone(tmp_path):
    r, ledger, fid = _repo(tmp_path, "none")
    _change(r, "staged", "other.py", "C = 2\n")
    _run(r, ledger, "staged")
    assert _status(ledger, fid) == "open" and _events(ledger, "change", fid) == []


@pytest.mark.skipif(_GITLEAKS is None, reason=_SKIP)
@pytest.mark.parametrize("failure", ["crashed", "inline-skipped"])
def test_a_rescan_that_cannot_vouch_for_a_label_keeps_its_rows_open(tmp_path, monkeypatch,
                                                                     failure):
    """The gate's own scan of the patch runs as ever; only the whole-file scan,
    the one `full_tree` run here, fails. No answer is not "gone", and a failed
    check of whether a row may close degrades nothing and blocks nothing."""
    r, ledger, fid = _repo(tmp_path, "none" if failure == "crashed" else "allow-comment")
    real = gitleaks.run

    def failing(ctx):
        if not ctx.full_tree:
            return real(ctx)
        if failure == "crashed":
            return RunnerResult(gitleaks.NAME, ToolState.CRASHED, stderr="injected")
        own = real(ctx)
        own.sub_results = (own.sub_results[0], inline.skipped(inline.GITLEAKS))
        return own

    monkeypatch.setattr(gitleaks, "run", failing)
    _change(r, "staged", "cfg.py", _edit_after_the_secret(r))
    res = _run(r, ledger, "staged")
    assert _status(ledger, fid) == "open"
    finished = _finished(ledger, "change")
    assert res.exit_code == 0 and finished["blocking"] == 0
    assert not {gitleaks.NAME, inline.GITLEAKS} & set(finished["degraded"])
