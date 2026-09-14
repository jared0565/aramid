"""Every `aramid arm` flag refuses with exit 3, the file untouched and one
stderr line, when `aramid.toml` does not parse -- the `return 3` after each
flag's `_write_armed` refusal, which tests/integration/test_arm.py reached
and the unit suite (the suite the drain confirms a mutant against) never
did for eight of the nine flags."""
import pytest

from aramid.commands.arm import cmd_arm

FLAGS = ("autolearn", "llm", "mutation", "mutation_score", "red_proof", "shadow",
         "agent", "tdd", None)


@pytest.mark.parametrize("flag", FLAGS)
def test_arm_refuses_an_unparseable_toml_for_every_flag(tmp_path, capsys, flag):
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\nthis is = not = toml\n", encoding="utf-8")

    assert cmd_arm(tmp_path, **({flag: True} if flag else {})) == 3
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith(f"aramid: arm: {toml} does not parse as TOML (")
    assert err.endswith("); left unchanged -- repair it, then re-run.\n")
    assert toml.read_text(encoding="utf-8") == "schema_version = 1\nthis is = not = toml\n"


@pytest.mark.parametrize("flag", FLAGS)
def test_arm_refuses_without_a_toml_for_every_flag(tmp_path, capsys, flag):
    assert cmd_arm(tmp_path, **({flag: True} if flag else {})) == 3
    assert capsys.readouterr() == (
        "", f"aramid: arm: {tmp_path / 'aramid.toml'} not found -- run `aramid init` first\n")


def test_arm_autolearn_reads_a_shadow_record_with_missing_counters_as_zero(tmp_path, capsys):
    """The record printed at arming falls back to 0 for every counter the
    state does not carry; `empty_state()` carries them all, so the
    defaults were never read. A state with bare shadow/audits tables."""
    from aramid import autolearn
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")
    state = autolearn.empty_state()
    state["shadow"], state["audits"] = {}, {}
    autolearn.save_state(state, "2026-09-14T12:00:00+00:00")

    assert cmd_arm(tmp_path, autolearn=True) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == f"aramid: arm: [llm.autolearn] armed=true written to {tmp_path / 'aramid.toml'}"
    assert out[1] == "aramid: arm: shadow record at arming: would-uplift 0/0, audits 0, misses 0"
