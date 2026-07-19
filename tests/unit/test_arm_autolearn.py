"""arm --autolearn: comment-preserving [llm.autolearn] armed=true rewrite
(mirrors test_arm_llm.py's coverage of _arm_llm_text)."""
import tomllib

from aramid.commands.arm import _arm_autolearn_text, cmd_arm


def test_appends_fresh_section_when_absent():
    got = _arm_autolearn_text("schema_version = 1\n")
    assert got.endswith("[llm.autolearn]\narmed = true\n")
    assert "schema_version = 1" in got


def test_substitutes_existing_key_in_section():
    text = "[llm.autolearn]\nenabled = true\narmed = false\n\n[pack]\nenabled = true\n"
    got = _arm_autolearn_text(text)
    assert got == "[llm.autolearn]\nenabled = true\narmed = true\n\n[pack]\nenabled = true\n"
    parsed = tomllib.loads(got)
    assert parsed["llm"]["autolearn"]["armed"] is True


def test_substitution_preserves_trailing_newline_when_section_is_last():
    text = "[llm.autolearn]\narmed = false\n"
    got = _arm_autolearn_text(text)
    assert got == "[llm.autolearn]\narmed = true\n"
    parsed = tomllib.loads(got)
    assert parsed["llm"]["autolearn"]["armed"] is True


def test_inserts_key_under_existing_section_without_key():
    text = "[llm.autolearn]\nenabled = true\n"
    got = _arm_autolearn_text(text)
    assert "[llm.autolearn]\narmed = true\nenabled = true\n" == got


def test_armed_key_in_other_section_untouched():
    text = "[other]\narmed = false\n"
    got = _arm_autolearn_text(text)
    assert "[other]\narmed = false" in got
    assert got.endswith("[llm.autolearn]\narmed = true\n")


def test_cmd_arm_autolearn_writes_and_reports(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n",
                                          encoding="utf-8")
    assert cmd_arm(tmp_path, autolearn=True) == 0
    text = (tmp_path / "aramid.toml").read_text(encoding="utf-8")
    assert "[llm.autolearn]\narmed = true" in text
    out = capsys.readouterr().out
    assert "auto-learn armed" in out and "shadow record" in out


def test_cmd_arm_autolearn_missing_toml_errors(tmp_path, capsys):
    assert cmd_arm(tmp_path, autolearn=True) == 3
