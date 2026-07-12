"""integration: `aramid arm` -- ends the per-repo WARN-only semgrep bake by
setting semgrep_block_armed = true in aramid.toml (design doc section 8).
"""
from pathlib import Path

from aramid import config as config_mod
from aramid.commands.arm import cmd_arm


def _no_user_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user-config.toml")


def test_arm_sets_semgrep_block_armed_true(tmp_path, monkeypatch):
    root: Path = tmp_path
    _no_user_config(tmp_path, monkeypatch)
    (root / "aramid.toml").write_text(
        '# aramid repo config -- detected stack: python\n'
        'schema_version = 1\n'
        'semgrep_block_armed = false\n'
        'bake_started = "2026-06-01"\n',
        encoding="utf-8")

    rc = cmd_arm(root)

    assert rc == 0
    cfg = config_mod.load_config(root)
    assert cfg.semgrep_block_armed is True
    # bake_started and the header comment survive untouched.
    text = (root / "aramid.toml").read_text(encoding="utf-8")
    assert "bake_started" in text
    assert "detected stack" in text


def test_arm_missing_config_errors(tmp_path, capsys):
    root: Path = tmp_path
    rc = cmd_arm(root)
    err = capsys.readouterr().err

    assert rc == 3
    assert "aramid.toml" in err


def test_arm_is_idempotent(tmp_path, monkeypatch):
    root: Path = tmp_path
    _no_user_config(tmp_path, monkeypatch)
    (root / "aramid.toml").write_text(
        'schema_version = 1\nsemgrep_block_armed = false\n', encoding="utf-8")

    assert cmd_arm(root) == 0
    assert cmd_arm(root) == 0

    cfg = config_mod.load_config(root)
    assert cfg.semgrep_block_armed is True
