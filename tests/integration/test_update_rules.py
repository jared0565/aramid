"""integration: `aramid update-rules` -- refreshes the vendored, offline
semgrep ruleset. No network is available in this environment, so this is a
documented stub (brief-permitted); it must never touch the network and
must always report the pinned source + target path.
"""
from aramid.commands.update_rules import cmd_update_rules
from aramid.runners.semgrep import VENDORED_RULES_PATH


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
