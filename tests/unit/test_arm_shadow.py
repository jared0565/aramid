"""arm --shadow: sets shadow_block_armed = true INSIDE the [shadow] table.

`shadow` was the only armable consumer with no CLI path -- 0.4.1's
`aramid arm --help` listed --llm/--autolearn/--tdd/--mutation/--mutation-score
/--red-proof and nothing for shadow, so an operator reaching for the command
that exists to arm things concluded it could not be armed. It could: the key
`[shadow].shadow_block_armed` was read by `policy.classify` all along. The gap
was the surface, not the mechanism (interop round 126 section 4a).

ONE THING HERE IS NOT A COPY OF ITS SIBLINGS. Every other arm flag reports
"now BLOCK at pre-push", because every other armable runner is pre-push only.
`shadow` runs on PRE_COMMIT, PRE_PUSH and ALL (`pipeline._GATE_TOOLS`), so
arming it changes what happens at COMMIT time as well. Copying the sibling
sentence would have shipped a claim that is false in the direction that
matters -- an operator told "pre-push" would not expect their next commit to
be refused.
"""
import tomllib

from aramid import config as config_mod
from aramid.commands.arm import cmd_arm


def test_arm_shadow_writes_into_section(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user-config.toml")
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\n\n[shadow]\nenabled = true\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, shadow=True) == 0

    text = toml.read_text(encoding="utf-8")
    assert "shadow_block_armed = true" in text
    assert text.index("[shadow]") < text.index("shadow_block_armed = true")
    cfg = config_mod.load_config(tmp_path)
    assert cfg.shadow["shadow_block_armed"] is True


def test_arm_shadow_appends_fresh_section_when_absent(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\n", encoding="utf-8")

    assert cmd_arm(tmp_path, shadow=True) == 0

    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["shadow"]["shadow_block_armed"] is True


def test_arm_shadow_idempotent(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("[shadow]\nshadow_block_armed = false\n", encoding="utf-8")

    cmd_arm(tmp_path, shadow=True)
    cmd_arm(tmp_path, shadow=True)

    text = toml.read_text(encoding="utf-8")
    assert text.count("shadow_block_armed") == 1
    assert "shadow_block_armed = true" in text
    tomllib.loads(text)                  # no duplicate-key corruption


def test_arm_shadow_preserves_inline_comment(tmp_path):
    toml = tmp_path / "aramid.toml"
    toml.write_text("[shadow]\nshadow_block_armed = false  # bake note\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, shadow=True) == 0

    got = toml.read_text(encoding="utf-8")
    assert "shadow_block_armed = true  # bake note" in got
    assert tomllib.loads(got)["shadow"]["shadow_block_armed"] is True


def test_arm_shadow_missing_toml_errors(tmp_path):
    assert cmd_arm(tmp_path, shadow=True) == 3


def test_cmd_arm_shadow_reports_that_it_blocks_at_COMMIT_time_too(tmp_path, capsys):
    """The message, and the one place this must not mirror its siblings.

    `shadow` is in _GATE_TOOLS for PRE_COMMIT as well as PRE_PUSH, so the
    "now BLOCK at pre-push" wording every other arm flag uses would understate
    where the block lands. Pinned, because the sibling wording is exactly what
    a copy-paste would produce.
    """
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")

    assert cmd_arm(tmp_path, shadow=True) == 0

    out = capsys.readouterr().out
    assert "shadow_block_armed=true" in out
    assert "pre-commit" in out, (
        f"the message must say the block reaches COMMIT time:\n{out}")
    assert "pre-push only" not in out


def test_arm_shadow_and_siblings_do_not_interfere(tmp_path):
    """shadow_block_armed ([shadow]) is a globally unique key, so no sibling
    regex can match it and it can match no sibling. Checked both directions,
    because a key-rewrite family that matches too widely corrupts the file
    with a duplicate rather than failing loudly."""
    toml = tmp_path / "aramid.toml"
    toml.write_text("tdd_block_armed = false\n\n"
                    "[mutation]\nmutation_block_armed = false\n\n"
                    "[shadow]\nshadow_block_armed = false\n",
                    encoding="utf-8")

    assert cmd_arm(tmp_path, shadow=True) == 0
    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["shadow"]["shadow_block_armed"] is True
    assert parsed["mutation"]["mutation_block_armed"] is False
    assert parsed["tdd_block_armed"] is False

    assert cmd_arm(tmp_path, mutation=True) == 0
    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["shadow"]["shadow_block_armed"] is True
    assert parsed["mutation"]["mutation_block_armed"] is True


def test_arm_shadow_does_not_arm_semgrep(tmp_path):
    """The bare `aramid arm` arms semgrep, and every flag is an alternative to
    that default. A --shadow that also flipped semgrep_block_armed would arm a
    blocking class the operator never asked for."""
    toml = tmp_path / "aramid.toml"
    toml.write_text("semgrep_block_armed = false\n", encoding="utf-8")

    assert cmd_arm(tmp_path, shadow=True) == 0

    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["semgrep_block_armed"] is False, "arming shadow armed semgrep"
    assert parsed["shadow"]["shadow_block_armed"] is True
