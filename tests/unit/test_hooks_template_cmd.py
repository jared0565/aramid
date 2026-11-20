"""The two helpers `aramid hooks` decides with, called directly: the global
git-config read (an unset key and an empty value both read as None) and
the "is this templateDir ours" comparison, resolved and, when the
filesystem refuses to resolve, textual -- the generator mutants on both
that tests/integration reached and the unit suite never did."""
from pathlib import Path
from types import SimpleNamespace

from aramid import toolpath
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
    assert seen == [toolpath.launchable(
        ["git", "config", "--global", "--get", "init.templateDir"])]

    monkeypatch.setattr(ht.subprocess, "run", lambda argv, **kw: _CP(1, ""))
    assert ht._git_config_get("init.templateDir") is None, "git exits 1 for an unset key"
    monkeypatch.setattr(ht.subprocess, "run", lambda argv, **kw: _CP(0, "\n"))
    assert ht._git_config_get("init.templateDir") is None, "set to nothing is nothing"

    def absent(argv, **kw):
        raise OSError("git not found")
    monkeypatch.setattr(ht.subprocess, "run", absent)
    assert ht._git_config_get("init.templateDir") is None


CONFIG = ht.CONFIG_KEY


def _decoding_run(stdout=b"", stderr=b"", rc=0):
    """A `subprocess.run` that decodes its canned BYTES the way the real one
    does with text=True on a Windows cp1252 locale: with the `encoding` and
    `errors` it was handed, else cp1252 and strict. A strict decode that
    fails raises UnicodeDecodeError out of the call, as CPython's does."""
    def run(argv, **kw):
        enc, err = kw.get("encoding") or "cp1252", kw.get("errors") or "strict"
        return SimpleNamespace(returncode=rc, stdout=stdout.decode(enc, err),
                               stderr=stderr.decode(enc, err))
    return run


def test_git_config_is_read_as_utf8_on_any_locale(monkeypatch):
    """git writes UTF-8 whatever the host locale. Decoded in cp1252, a
    templateDir under a profile such as `aːron` (U+02D0, `CB 90`) raised
    UnicodeDecodeError out of `aramid hooks template status`; one that did
    decode came back garbled, so `remove` could not recognise the directory
    as ours. set and unset decode git's stderr too, and one naming that path
    raised the same way."""
    value = "C:/Users/aːron/.aramid/git-template"
    monkeypatch.setattr(ht.subprocess, "run", _decoding_run((value + "\n").encode("utf-8")))
    assert ht._git_config_get(CONFIG) == value

    locked = f"error: could not lock config file {value}/../.gitconfig\n".encode("utf-8")
    monkeypatch.setattr(ht.subprocess, "run", _decoding_run(stderr=locked, rc=255))
    ht._git_config_set(CONFIG, value)      # neither raises
    ht._git_config_unset(CONFIG)


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
