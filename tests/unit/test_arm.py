from pathlib import Path

from aramid import config as config_mod
from aramid.commands.arm import _arm_llm_text, cmd_arm


def test_arm_llm_rewrites_existing_key():
    text = "[llm]\nenabled = true\nllm_block_armed = false\n"
    out = _arm_llm_text(text)
    assert "llm_block_armed = true" in out and "llm_block_armed = false" not in out
    assert "enabled = true" in out                       # rest preserved


def test_arm_llm_inserts_into_existing_section():
    text = "schema_version = 1\n[llm]\nenabled = true\n[pack]\nenabled = true\n"
    out = _arm_llm_text(text)
    llm_at = out.index("[llm]")
    pack_at = out.index("[pack]")
    key_at = out.index("llm_block_armed = true")
    assert llm_at < key_at < pack_at                     # key landed inside [llm]


def test_arm_llm_appends_section_when_missing():
    out = _arm_llm_text("schema_version = 1\n")
    assert out.endswith("[llm]\nllm_block_armed = true\n")


def test_cmd_arm_llm_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user-config.toml")
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")
    assert cmd_arm(tmp_path, llm=True) == 0
    cfg = config_mod.load_config(tmp_path)
    assert cfg.llm["llm_block_armed"] is True
    assert cfg.semgrep_block_armed is False              # untouched


def test_cmd_arm_plain_still_arms_semgrep(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user-config.toml")
    (tmp_path / "aramid.toml").write_text("semgrep_block_armed = false\n", encoding="utf-8")
    assert cmd_arm(tmp_path) == 0
    assert config_mod.load_config(tmp_path).semgrep_block_armed is True


def test_cmd_arm_missing_toml_errors(tmp_path):
    assert cmd_arm(tmp_path, llm=True) == 3
