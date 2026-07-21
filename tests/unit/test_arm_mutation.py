"""arm --mutation: ends the mutation bake by setting mutation_block_armed =
true INSIDE the [mutation] table in aramid.toml -- mirrors the SECTION-scoped
_arm_llm_text path (NOT the root-scoped _arm_tdd path), and must never touch
the sibling [js_mutation] table."""
import tomllib

from aramid import config as config_mod
from aramid.commands.arm import cmd_arm


def test_arm_mutation_writes_into_mutation_section(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\n\n[mutation]\nenabled = true\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, mutation=True) == 0

    text = toml.read_text(encoding="utf-8")
    assert "mutation_block_armed = true" in text
    # key lands INSIDE [mutation], after the header
    assert text.index("[mutation]") < text.index("mutation_block_armed = true")
    cfg = config_mod.load_config(tmp_path)
    assert cfg.mutation["mutation_block_armed"] is True


def test_arm_mutation_appends_fresh_section_when_absent(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\n", encoding="utf-8")

    assert cmd_arm(tmp_path, mutation=True) == 0

    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["mutation"]["mutation_block_armed"] is True


def test_arm_mutation_idempotent(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("[mutation]\nmutation_block_armed = false\n", encoding="utf-8")

    cmd_arm(tmp_path, mutation=True)
    cmd_arm(tmp_path, mutation=True)

    text = toml.read_text(encoding="utf-8")
    assert text.count("mutation_block_armed") == 1
    assert "mutation_block_armed = true" in text
    tomllib.loads(text)                      # no duplicate-key corruption


def test_arm_mutation_preserves_inline_comment(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("[mutation]\nmutation_block_armed = false  # bake note\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, mutation=True) == 0

    got = toml.read_text(encoding="utf-8")
    assert "mutation_block_armed = true  # bake note" in got
    assert tomllib.loads(got)["mutation"]["mutation_block_armed"] is True


def test_arm_mutation_does_not_touch_js_mutation(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("[js_mutation]\nenabled = true\n\n[mutation]\nenabled = true\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, mutation=True) == 0

    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["mutation"]["mutation_block_armed"] is True
    assert "mutation_block_armed" not in parsed["js_mutation"]


def test_cmd_arm_missing_toml_errors_for_mutation(tmp_path):
    assert cmd_arm(tmp_path, mutation=True) == 3


def test_cmd_arm_mutation_reports(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")

    assert cmd_arm(tmp_path, mutation=True) == 0

    out = capsys.readouterr().out
    assert "mutation_block_armed=true" in out
    assert "mutation bake ended" in out


def test_cmd_arm_plain_does_not_touch_mutation(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    (tmp_path / "aramid.toml").write_text(
        "semgrep_block_armed = false\n\n[mutation]\nmutation_block_armed = false\n",
        encoding="utf-8")

    assert cmd_arm(tmp_path) == 0

    cfg = config_mod.load_config(tmp_path)
    assert cfg.semgrep_block_armed is True
    assert cfg.mutation["mutation_block_armed"] is False
