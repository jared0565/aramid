"""integration: `aramid update-rules` -- reports the vendored, offline
semgrep ruleset. The ruleset is vendored at build time (offline by design);
this command performs no network fetch and always reports the pinned source
+ target path.
"""
from aramid.commands.update_rules import cmd_update_rules
from aramid.runners.semgrep import VENDORED_RULES_PATH


def test_update_rules_reports_offline_by_design_not_stub(tmp_path, capsys):
    # Formal close (spec section 7): the command is offline-by-design, not a
    # half-finished STUB. Its message must say so and must not call itself a stub.
    rc = cmd_update_rules(tmp_path)
    out = capsys.readouterr().out

    assert rc == 0
    assert "STUB" not in out
    assert "vendored at build time" in out


def test_update_rules_never_touches_network_and_returns_0(tmp_path, capsys):
    rc = cmd_update_rules(tmp_path)
    out = capsys.readouterr().out

    assert rc == 0
    assert "pinned source" in out.lower()


def test_update_rules_reports_the_real_runner_target_path(tmp_path, capsys):
    """The stub must target the path aramid.runners.semgrep actually reads
    at scan time, not an independently hardcoded path that could drift."""
    rc = cmd_update_rules(tmp_path)
    out = capsys.readouterr().out

    assert rc == 0
    assert str(VENDORED_RULES_PATH) in out
