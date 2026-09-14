"""The two helpers `aramid hooks` decides with, called directly: the global
git-config read (an unset key and an empty value both read as None) and
the "is this templateDir ours" comparison, resolved and, when the
filesystem refuses to resolve, textual -- the generator mutants on both
that tests/integration reached and the unit suite never did."""
from pathlib import Path

from aramid.commands import hooks_template as ht


class _CP:
    def __init__(self, returncode=0, stdout=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, ""


def test_git_config_get_reads_a_value_and_treats_unset_or_empty_as_none(monkeypatch):
    seen = []

    def run(argv, **kw):
        seen.append(argv)
        return _CP(0, "  ~/.aramid/git-template\n")
    monkeypatch.setattr(ht.subprocess, "run", run)
    assert ht._git_config_get("init.templateDir") == "~/.aramid/git-template"
    assert seen == [["git", "config", "--global", "--get", "init.templateDir"]]

    monkeypatch.setattr(ht.subprocess, "run", lambda argv, **kw: _CP(1, ""))
    assert ht._git_config_get("init.templateDir") is None, "git exits 1 for an unset key"
    monkeypatch.setattr(ht.subprocess, "run", lambda argv, **kw: _CP(0, "\n"))
    assert ht._git_config_get("init.templateDir") is None, "set to nothing is nothing"

    def absent(argv, **kw):
        raise OSError("git not found")
    monkeypatch.setattr(ht.subprocess, "run", absent)
    assert ht._git_config_get("init.templateDir") is None


def test_same_path_compares_resolved_paths_and_falls_back_to_text(tmp_path, monkeypatch):
    ours = tmp_path / "git-template"
    ours.mkdir()
    assert ht._same_path(None, ours) is False
    assert ht._same_path("", ours) is False
    assert ht._same_path(str(ours), ours) is True
    assert ht._same_path(str(tmp_path / "sub" / ".." / "git-template"), ours) is True
    assert ht._same_path(str(tmp_path / "other"), ours) is False

    def refuse(self, *a, **kw):
        raise OSError("cannot resolve")
    monkeypatch.setattr(Path, "resolve", refuse)
    assert ht._same_path(str(ours), ours) is True, "unresolvable: the text decides"
    assert ht._same_path(str(ours) + "x", ours) is False
