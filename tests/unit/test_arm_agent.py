"""`aramid arm --agent` -- flips agent_block_armed (root table), the
pre-tool-use rejector's posture switch. Same comment-preserving machinery
as every other arm flag."""
from pathlib import Path

from aramid import config as config_mod
from aramid.commands.arm import cmd_arm


def _repo(tmp_path: Path, toml_text: str) -> Path:
    (tmp_path / "aramid.toml").write_text(toml_text, encoding="utf-8")
    return tmp_path


def test_arm_agent_flips_the_key(tmp_path, capsys):
    root = _repo(tmp_path, "schema_version = 1\nagent_block_armed = false\n")
    assert cmd_arm(root, agent=True) == 0
    cfg = config_mod.load_config(root)
    assert cfg.agent_block_armed is True
    out = capsys.readouterr().out
    assert f"aramid: arm: agent_block_armed=true written to {root / 'aramid.toml'}\n" in out
    assert ("aramid: arm: agent bake ended -- the pre-tool-use hook now "
            "REJECTS git hook-bypass flags (--no-verify / core.hooksPath) "
            "in agent sessions; humans at a terminal are unaffected.\n") in out


def test_arm_agent_adds_key_when_absent(tmp_path):
    root = _repo(tmp_path, "schema_version = 1\n")
    assert cmd_arm(root, agent=True) == 0
    assert config_mod.load_config(root).agent_block_armed is True


def test_arm_agent_preserves_comments(tmp_path):
    root = _repo(tmp_path,
                 "# header comment\n"
                 "agent_block_armed = false  # inline note\n")
    assert cmd_arm(root, agent=True) == 0
    text = (root / "aramid.toml").read_text(encoding="utf-8")
    assert "# header comment" in text
    assert "agent_block_armed = true  # inline note" in text


def test_arm_agent_without_toml_refuses(tmp_path):
    assert cmd_arm(tmp_path, agent=True) == 3


def test_default_is_false_and_stub_carries_it(tmp_path):
    root = _repo(tmp_path, "schema_version = 1\n")
    assert config_mod.load_config(root).agent_block_armed is False
    stub = config_mod.render_repo_stub("python", "pip")
    assert "agent_block_armed = false\n" in stub


def test_agent_flag_is_recorded_in_arming_state(tmp_path):
    """The walk captures any Config bool ending _armed -- pinned here so
    the premise-recording behavior is a choice, not an accident. It cannot
    invalidate overrides: invalidation is classification-driven and this
    flag never moves a finding's tier."""
    root = _repo(tmp_path, "agent_block_armed = true\n")
    cfg = config_mod.load_config(root)
    assert config_mod.arming_state(cfg)["agent_block_armed"] is True
