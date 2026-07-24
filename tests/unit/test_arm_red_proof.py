"""arm --red-proof (sub-project 3): sets red_proof_block_armed = true INSIDE
the [red_proof] table -- mirrors the section-scoped arm --mutation-score
path; must never touch other tables or the root tdd_block_armed key."""
import tomllib

from aramid import config as config_mod
from aramid.commands.arm import cmd_arm


def test_arm_red_proof_writes_into_section(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\n\n[red_proof]\nenabled = true\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, red_proof=True) == 0

    text = toml.read_text(encoding="utf-8")
    assert "red_proof_block_armed = true" in text
    assert text.index("[red_proof]") < text.index("red_proof_block_armed = true")
    cfg = config_mod.load_config(tmp_path)
    assert cfg.red_proof["red_proof_block_armed"] is True


def test_arm_red_proof_appends_fresh_section_when_absent(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\n", encoding="utf-8")

    assert cmd_arm(tmp_path, red_proof=True) == 0

    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["red_proof"]["red_proof_block_armed"] is True


def test_arm_red_proof_idempotent(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("[red_proof]\nred_proof_block_armed = false\n",
                    encoding="utf-8")

    cmd_arm(tmp_path, red_proof=True)
    cmd_arm(tmp_path, red_proof=True)

    text = toml.read_text(encoding="utf-8")
    assert text.count("red_proof_block_armed") == 1
    assert "red_proof_block_armed = true" in text
    tomllib.loads(text)                  # no duplicate-key corruption


def test_arm_red_proof_preserves_inline_comment(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("[red_proof]\nred_proof_block_armed = false  # bake note\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, red_proof=True) == 0

    got = toml.read_text(encoding="utf-8")
    assert "red_proof_block_armed = true  # bake note" in got
    assert tomllib.loads(got)["red_proof"]["red_proof_block_armed"] is True


def test_arm_red_proof_missing_toml_errors(tmp_path):
    assert cmd_arm(tmp_path, red_proof=True) == 3


def test_cmd_arm_red_proof_reports(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n",
                                          encoding="utf-8")

    assert cmd_arm(tmp_path, red_proof=True) == 0

    out = capsys.readouterr().out
    assert "red_proof_block_armed=true" in out
    assert "red-first bake ended" in out


def test_arm_red_proof_and_tdd_do_not_interfere(tmp_path):
    """red_proof_block_armed ([red_proof] table) and tdd_block_armed (root
    key) are independent: arming one never rewrites the other."""
    toml = tmp_path / "aramid.toml"
    toml.write_text("tdd_block_armed = false\n\n"
                    "[red_proof]\nred_proof_block_armed = false\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, red_proof=True) == 0
    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["tdd_block_armed"] is False
    assert parsed["red_proof"]["red_proof_block_armed"] is True

    assert cmd_arm(tmp_path, tdd=True) == 0
    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["tdd_block_armed"] is True
    assert parsed["red_proof"]["red_proof_block_armed"] is True
