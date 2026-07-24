"""arm --mutation-score (2b): ends the mutation-score bake by setting
score_block_armed = true INSIDE the [mutation] table -- mirrors the
section-scoped arm --mutation path and must never touch [js_mutation] or
the sibling mutation_block_armed key."""
import tomllib

from aramid import config as config_mod
from aramid.commands.arm import cmd_arm


def test_arm_mutation_score_writes_into_mutation_section(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\n\n[mutation]\nenabled = true\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, mutation_score=True) == 0

    text = toml.read_text(encoding="utf-8")
    assert "score_block_armed = true" in text
    assert text.index("[mutation]") < text.index("score_block_armed = true")
    cfg = config_mod.load_config(tmp_path)
    assert cfg.mutation["score_block_armed"] is True


def test_arm_mutation_score_appends_fresh_section_when_absent(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\n", encoding="utf-8")

    assert cmd_arm(tmp_path, mutation_score=True) == 0

    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["mutation"]["score_block_armed"] is True


def test_arm_mutation_score_idempotent(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("[mutation]\nscore_block_armed = false\n",
                    encoding="utf-8")

    cmd_arm(tmp_path, mutation_score=True)
    cmd_arm(tmp_path, mutation_score=True)

    text = toml.read_text(encoding="utf-8")
    assert text.count("score_block_armed") == 1
    assert "score_block_armed = true" in text
    tomllib.loads(text)                  # no duplicate-key corruption


def test_arm_mutation_score_preserves_inline_comment(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("[mutation]\nscore_block_armed = false  # bake note\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, mutation_score=True) == 0

    got = toml.read_text(encoding="utf-8")
    assert "score_block_armed = true  # bake note" in got
    assert tomllib.loads(got)["mutation"]["score_block_armed"] is True


def test_arm_mutation_score_does_not_touch_js_mutation(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text(
        "[js_mutation]\nenabled = true\n\n[mutation]\nenabled = true\n",
        encoding="utf-8")

    assert cmd_arm(tmp_path, mutation_score=True) == 0

    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["mutation"]["score_block_armed"] is True
    assert "score_block_armed" not in parsed["js_mutation"]


def test_arm_mutation_score_missing_toml_errors(tmp_path):
    assert cmd_arm(tmp_path, mutation_score=True) == 3


def test_cmd_arm_mutation_score_reports(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n",
                                          encoding="utf-8")

    assert cmd_arm(tmp_path, mutation_score=True) == 0

    out = capsys.readouterr().out
    assert "score_block_armed=true" in out
    assert "mutation-score bake ended" in out


def test_arm_mutation_and_score_keys_do_not_interfere(tmp_path):
    """The two [mutation] arming keys are independent: arming one never
    rewrites the other (the _MUT_KEY_RE / _SCORE_KEY_RE literals cannot
    cross-match)."""
    toml = tmp_path / "aramid.toml"
    toml.write_text("[mutation]\nmutation_block_armed = false\n"
                    "score_block_armed = false\n", encoding="utf-8")

    assert cmd_arm(tmp_path, mutation=True) == 0
    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["mutation"]["mutation_block_armed"] is True
    assert parsed["mutation"]["score_block_armed"] is False

    assert cmd_arm(tmp_path, mutation_score=True) == 0
    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["mutation"]["mutation_block_armed"] is True
    assert parsed["mutation"]["score_block_armed"] is True
