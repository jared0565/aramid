"""[timeouts].stall_s is read once per command and handed to the launcher."""
from types import SimpleNamespace

from aramid import config as config_mod
from aramid.runners import base


def _cfg(**timeouts):
    return SimpleNamespace(timeouts=timeouts)


def test_default_is_three_hundred():
    assert config_mod.stall_window_s(_cfg()) == 300.0


def test_an_explicit_value_is_used():
    assert config_mod.stall_window_s(_cfg(stall_s=45)) == 45.0


def test_zero_is_kept_and_means_off():
    assert config_mod.stall_window_s(_cfg(stall_s=0)) == 0.0


def test_a_non_number_falls_back_to_the_default():
    assert config_mod.stall_window_s(_cfg(stall_s="soon")) == 300.0
    assert config_mod.stall_window_s(_cfg(stall_s=True)) == 300.0


def test_defaults_toml_declares_stall_s(tmp_path):
    cfg = config_mod.load_config(tmp_path)
    assert cfg.timeouts["stall_s"] == 300


def test_cmd_check_sets_the_window_from_config(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(base, "set_stall_window", seen.append)
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n[timeouts]\nstall_s = 42\n",
                                          encoding="utf-8")
    from aramid.commands import check
    check.apply_stall_window(config_mod.load_config(tmp_path))
    assert seen == [42.0]
