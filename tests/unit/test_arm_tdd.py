"""arm --tdd: ends the code-without-test bake by setting tdd_block_armed =
true at ROOT scope in aramid.toml -- mirrors the semgrep _KEY_RE root-key
insertion path (NOT a section-scoped key like _LLM_KEY_RE/_AL_KEY_RE),
since tdd_block_armed lives at the top level next to semgrep_block_armed
(Task 1's Config.tdd_block_armed)."""
import tomllib

from aramid import config as config_mod
from aramid.commands.arm import cmd_arm


def test_arm_tdd_writes_root_key(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user-config.toml")
    toml = tmp_path / "aramid.toml"
    toml.write_text(
        "schema_version = 1\nsemgrep_block_armed = false\n\n[llm]\nllm_block_armed = false\n",
        encoding="utf-8")

    rc = cmd_arm(tmp_path, tdd=True)

    assert rc == 0
    text = toml.read_text(encoding="utf-8")
    assert "tdd_block_armed = true" in text
    # root key must land BEFORE the first section header, not inside [llm]
    assert text.index("tdd_block_armed = true") < text.index("[llm]")
    cfg = config_mod.load_config(tmp_path)
    assert cfg.tdd_block_armed is True
    assert cfg.semgrep_block_armed is False               # untouched
    assert cfg.llm["llm_block_armed"] is False             # untouched


def test_arm_tdd_idempotent(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("tdd_block_armed = false\n", encoding="utf-8")

    cmd_arm(tmp_path, tdd=True)
    cmd_arm(tmp_path, tdd=True)

    text = toml.read_text(encoding="utf-8")
    assert text.count("tdd_block_armed") == 1
    assert "tdd_block_armed = true" in text
    tomllib.loads(text)          # must not raise (no duplicate-key corruption)


def test_arm_tdd_appends_at_eof_when_no_sections(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\n", encoding="utf-8")

    assert cmd_arm(tmp_path, tdd=True) == 0

    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["tdd_block_armed"] is True


def test_arm_tdd_preserves_inline_comment(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("tdd_block_armed = false  # bake note\n", encoding="utf-8")

    assert cmd_arm(tmp_path, tdd=True) == 0

    got = toml.read_text(encoding="utf-8")
    assert got == "tdd_block_armed = true  # bake note\n"
    assert tomllib.loads(got)["tdd_block_armed"] is True


def test_arm_tdd_root_key_not_inserted_inside_trailing_section(tmp_path):
    """Same regression class as test_root_key_inserted_before_first_section_not_eof
    for semgrep: a hand-edited config with no tdd key but a trailing [llm]
    section must get the key at ROOT scope, not inside the table."""
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\n\n[llm]\nenabled = true\n", encoding="utf-8")

    assert cmd_arm(tmp_path, tdd=True) == 0

    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["tdd_block_armed"] is True
    assert "tdd_block_armed" not in parsed["llm"]


def test_cmd_arm_missing_toml_errors_for_tdd(tmp_path):
    assert cmd_arm(tmp_path, tdd=True) == 3


def test_cmd_arm_tdd_reports(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")

    assert cmd_arm(tmp_path, tdd=True) == 0

    out = capsys.readouterr().out
    assert "tdd_block_armed=true" in out
    assert "TDD bake ended" in out


def test_cmd_arm_plain_does_not_touch_tdd_key(tmp_path, monkeypatch):
    """Plain `arm` (no flags) must keep arming semgrep only -- tdd_block_armed
    is untouched unless --tdd is passed explicitly."""
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user-config.toml")
    (tmp_path / "aramid.toml").write_text(
        "semgrep_block_armed = false\ntdd_block_armed = false\n", encoding="utf-8")

    assert cmd_arm(tmp_path) == 0

    cfg = config_mod.load_config(tmp_path)
    assert cfg.semgrep_block_armed is True
    assert cfg.tdd_block_armed is False
