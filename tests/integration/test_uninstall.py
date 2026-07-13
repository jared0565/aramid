"""integration: `aramid uninstall <path>` -- reverses exactly what `init`
installed (hooks, ARAMID.md, gitignore entries). The ledger (.aramid/) is
KEPT by default.
"""
import subprocess
import sys
from pathlib import Path

from aramid import hooks
from aramid.commands import doctor, init
from aramid.commands.uninstall import cmd_uninstall
from aramid.ledger import Ledger


def _git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _repo(tmp_path, name="repo") -> Path:
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "a.py")
    _git(r, "commit", "-q", "-m", "seed")
    return r


def _fake_present(root):
    return {
        "gitleaks": doctor.ToolStatus("gitleaks", True, "8.21.2"),
        "semgrep": doctor.ToolStatus("semgrep", True, "1.100.0"),
        "ruff": doctor.ToolStatus("ruff", True, "0.6.0"),
        "pip-audit": doctor.ToolStatus("pip-audit", True, "2.7.0"),
        "interpreter": doctor.ToolStatus("interpreter", True, sys.executable),
    }


def test_uninstall_removes_hooks_aramid_md_and_gitignore_entries_keeps_ledger(
        tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0

    assert (r / "ARAMID.md").exists()
    assert (r / ".git" / "hooks" / "pre-commit").exists()
    assert (r / ".aramid" / "ledger.db").exists()

    rc = cmd_uninstall(r)

    assert rc == 0
    assert not (r / "ARAMID.md").exists()
    assert not (r / ".git" / "hooks" / "pre-commit").exists()
    assert not (r / ".git" / "hooks" / "pre-push").exists()

    gitignore_text = (r / ".gitignore").read_text(encoding="utf-8")
    for entry in init.GITIGNORE_ENTRIES:
        assert entry not in gitignore_text.splitlines()

    # ledger kept by default -- finding/security history is not discarded.
    assert (r / ".aramid" / "ledger.db").exists()
    ledger = Ledger(r / ".aramid" / "ledger.db")
    try:
        assert ledger.has_baseline()
    finally:
        ledger.close()


def test_uninstall_preserves_other_gitignore_lines(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)
    assert init.cmd_init(r) == 0

    gitignore_path = r / ".gitignore"
    text = gitignore_path.read_text(encoding="utf-8")
    gitignore_path.write_text(text + "my-own-entry.log\n", encoding="utf-8")

    rc = cmd_uninstall(r)

    assert rc == 0
    gitignore_text = gitignore_path.read_text(encoding="utf-8")
    assert "my-own-entry.log" in gitignore_text


def test_uninstall_refuses_non_repo(tmp_path, capsys):
    not_repo = tmp_path / "not-a-repo"
    not_repo.mkdir()

    rc = cmd_uninstall(not_repo)
    err = capsys.readouterr().err

    assert rc == 3
    assert "git repository" in err


def test_uninstall_on_never_initted_repo_is_a_safe_no_op(tmp_path):
    r = tmp_path / "bare"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")

    rc = cmd_uninstall(r)

    assert rc == 0


def test_uninstall_deregisters_repo_from_central_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", _fake_present)
    r = _repo(tmp_path)

    from aramid import registry
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "central" / "repos.toml")

    assert init.cmd_init(r) == 0
    assert any(Path(e["path"]).resolve() == r.resolve() for e in registry.load_registry())

    rc = cmd_uninstall(r)

    assert rc == 0
    assert not any(Path(e["path"]).resolve() == r.resolve() for e in registry.load_registry())
