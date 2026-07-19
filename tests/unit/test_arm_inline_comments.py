"""Inline-comment tolerance + root-key placement for the arm rewrite family
(_KEY_RE / _LLM_KEY_RE / _AL_KEY_RE): a trailing `# comment` on the key line
must be matched (no duplicate-key TOML corruption) and preserved verbatim,
and a missing ROOT key must never be appended inside a trailing [table]."""
import tomllib

from aramid.commands.arm import _arm_autolearn_text, _arm_llm_text, cmd_arm


def test_semgrep_key_with_inline_comment_rewritten_in_place(tmp_path):
    (tmp_path / "aramid.toml").write_text(
        "schema_version = 1\n"
        "semgrep_block_armed = false  # ends the bake\n"
        'bake_started = "2026-07-01"\n', encoding="utf-8")
    assert cmd_arm(tmp_path) == 0
    got = (tmp_path / "aramid.toml").read_text(encoding="utf-8")
    assert got == ("schema_version = 1\n"
                   "semgrep_block_armed = true  # ends the bake\n"
                   'bake_started = "2026-07-01"\n')
    assert tomllib.loads(got)["semgrep_block_armed"] is True


def test_semgrep_key_comment_without_space_before_hash(tmp_path):
    (tmp_path / "aramid.toml").write_text(
        "semgrep_block_armed = false# x\n", encoding="utf-8")
    assert cmd_arm(tmp_path) == 0
    got = (tmp_path / "aramid.toml").read_text(encoding="utf-8")
    assert got == "semgrep_block_armed = true# x\n"
    assert tomllib.loads(got)["semgrep_block_armed"] is True


def test_llm_key_with_inline_comment_rewritten_in_place():
    text = "[llm]\nllm_block_armed = false  # baking since 07-01\n"
    got = _arm_llm_text(text)
    assert got == "[llm]\nllm_block_armed = true  # baking since 07-01\n"
    assert tomllib.loads(got)["llm"]["llm_block_armed"] is True


def test_autolearn_key_with_inline_comment_rewritten_in_place():
    text = "[llm.autolearn]\nenabled = true\narmed = false  # shadow\n"
    got = _arm_autolearn_text(text)
    assert got == "[llm.autolearn]\nenabled = true\narmed = true  # shadow\n"
    assert tomllib.loads(got)["llm"]["autolearn"]["armed"] is True


def test_no_duplicate_key_inserted_when_comment_present():
    """The corruption regression: pre-fix, a commented key line missed the
    regex -> a SECOND llm_block_armed was inserted under [llm] -> tomllib
    'Cannot overwrite a value' on every later load."""
    text = "[llm]\nllm_block_armed = false  # note\n"
    got = _arm_llm_text(text)
    assert got.count("llm_block_armed") == 1
    tomllib.loads(got)          # must not raise


def test_semgrep_newline_boundary_not_swallowed(tmp_path):
    """Same family as Task 11's _AL_KEY_RE critical: `\\s*$` in (?m) mode
    swallows the blank line before a following section. The horizontal-only
    classes must preserve the section boundary byte-for-byte."""
    (tmp_path / "aramid.toml").write_text(
        "semgrep_block_armed = false\n\n[pack]\nenabled = true\n",
        encoding="utf-8")
    assert cmd_arm(tmp_path) == 0
    got = (tmp_path / "aramid.toml").read_text(encoding="utf-8")
    assert got == "semgrep_block_armed = true\n\n[pack]\nenabled = true\n"


def test_root_key_inserted_before_first_section_not_eof(tmp_path):
    """Hand-edited config with no root key but a trailing [llm] section:
    the key must land at ROOT scope, not inside the trailing table."""
    (tmp_path / "aramid.toml").write_text(
        "schema_version = 1\n\n[llm]\nenabled = true\n", encoding="utf-8")
    assert cmd_arm(tmp_path) == 0
    parsed = tomllib.loads((tmp_path / "aramid.toml").read_text(encoding="utf-8"))
    assert parsed["semgrep_block_armed"] is True
    assert "semgrep_block_armed" not in parsed["llm"]


def test_root_key_appended_at_eof_when_no_sections(tmp_path):
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")
    assert cmd_arm(tmp_path) == 0
    parsed = tomllib.loads((tmp_path / "aramid.toml").read_text(encoding="utf-8"))
    assert parsed["semgrep_block_armed"] is True
