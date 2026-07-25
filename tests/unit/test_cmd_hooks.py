"""`aramid hooks install|remove|status` -- the machine-wide git template.

Every test injects `template_root` and monkeypatches the three git-config
helpers, so the real `~/.aramid/git-template` and the developer's real global
git config are never touched by the suite.
"""
from aramid.commands import hooks_template as ht

KEY = "init.templateDir"


class _FakeGit:
    """Stands in for the user's global git config."""

    def __init__(self, initial=None):
        self.store = {} if initial is None else dict(initial)

    def install(self, monkeypatch):
        monkeypatch.setattr(ht, "_git_config_get", lambda k: self.store.get(k))
        monkeypatch.setattr(ht, "_git_config_set",
                            lambda k, v: self.store.__setitem__(k, v))
        monkeypatch.setattr(ht, "_git_config_unset", lambda k: self.store.pop(k, None))
        return self


def test_install_writes_shims_and_points_global_config_at_them(tmp_path, monkeypatch):
    git = _FakeGit().install(monkeypatch)
    tpl = tmp_path / "tpl"

    rc = ht.cmd_hooks("install", template_root=tpl)

    assert rc == 0
    assert (tpl / "hooks" / "pre-commit").exists()
    assert (tpl / "hooks" / "pre-push").exists()
    assert git.store[KEY] == str(tpl)


def test_install_refuses_to_clobber_a_foreign_template_dir(tmp_path, monkeypatch, capsys):
    """A user who already uses init.templateDir for their own hooks must not
    lose it silently -- git supports exactly one, so overwriting is
    destructive and unrecoverable from aramid's side."""
    git = _FakeGit({KEY: "C:/my/own/template"}).install(monkeypatch)
    tpl = tmp_path / "tpl"

    rc = ht.cmd_hooks("install", template_root=tpl)
    err = capsys.readouterr().err

    assert rc == 2
    assert git.store[KEY] == "C:/my/own/template", "clobbered the user's setting"
    assert "C:/my/own/template" in err, "must name what is already configured"


def test_install_is_idempotent_when_already_pointing_at_ours(tmp_path, monkeypatch):
    """Re-running install regenerates the shims in place -- the configured
    value is ours, so it is not 'foreign' and must not trip the refusal."""
    tpl = tmp_path / "tpl"
    git = _FakeGit({KEY: str(tpl)}).install(monkeypatch)

    assert ht.cmd_hooks("install", template_root=tpl) == 0
    assert git.store[KEY] == str(tpl)
    assert (tpl / "hooks" / "pre-commit").exists()


def test_remove_unsets_config_only_when_it_points_at_ours(tmp_path, monkeypatch):
    tpl = tmp_path / "tpl"
    git = _FakeGit({KEY: str(tpl)}).install(monkeypatch)

    assert ht.cmd_hooks("remove", template_root=tpl) == 0
    assert KEY not in git.store


def test_remove_leaves_a_foreign_template_dir_alone(tmp_path, monkeypatch):
    """Counterfactual for the test above: remove must key on WHOSE dir it is,
    not merely on the key being set."""
    git = _FakeGit({KEY: "C:/my/own/template"}).install(monkeypatch)

    rc = ht.cmd_hooks("remove", template_root=tmp_path / "tpl")

    assert rc == 0
    assert git.store[KEY] == "C:/my/own/template"


def test_status_distinguishes_installed_from_absent(tmp_path, monkeypatch, capsys):
    tpl = tmp_path / "tpl"

    _FakeGit().install(monkeypatch)
    ht.cmd_hooks("status", template_root=tpl)
    assert "not installed" in capsys.readouterr().out.lower()

    _FakeGit({KEY: str(tpl)}).install(monkeypatch)
    ht.cmd_hooks("install", template_root=tpl)
    ht.cmd_hooks("status", template_root=tpl)
    assert "installed" in capsys.readouterr().out.lower()


def test_status_warns_that_existing_repos_are_unaffected(tmp_path, monkeypatch, capsys):
    """git copies template hooks at init/clone time ONLY. Reporting "installed"
    without saying so would imply machine-wide coverage aramid does not have."""
    tpl = tmp_path / "tpl"
    _FakeGit({KEY: str(tpl)}).install(monkeypatch)
    ht.cmd_hooks("install", template_root=tpl)
    ht.cmd_hooks("status", template_root=tpl)

    out = capsys.readouterr().out.lower()
    assert "new" in out and ("clone" in out or "init" in out)


def test_unknown_action_is_rejected(tmp_path, monkeypatch):
    _FakeGit().install(monkeypatch)
    assert ht.cmd_hooks("frobnicate", template_root=tmp_path / "tpl") == 2
