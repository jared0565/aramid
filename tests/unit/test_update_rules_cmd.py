"""`aramid update-rules` at unit scope: every line for a vendored and a
missing ruleset, and the exit -- the one generator mutant tests/integration
reached and the unit suite (the suite the drain confirms a mutant against)
never did."""
from aramid.commands import update_rules



def test_update_rules_reports_the_vendored_ruleset_and_exits_0(tmp_path, capsys, monkeypatch):
    head = ("aramid: update-rules: the OWASP ruleset is vendored at build time (offline by "
            "design). To refresh, re-vendor from a pinned semgrep-rules ref and rebuild the "
            "package.\n"
            f"aramid: update-rules: pinned source: {update_rules.PINNED_SOURCE}\n")
    present = tmp_path / "rules.yml"
    present.write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr(update_rules, "VENDORED_RULES_PATH", present)
    assert update_rules.cmd_update_rules(tmp_path) == 0
    assert capsys.readouterr() == (
        head + f"aramid: update-rules: target path:   {present}\n"
        "aramid: update-rules: a vendored ruleset is currently installed.\n", "")

    absent = tmp_path / "missing.yml"
    monkeypatch.setattr(update_rules, "VENDORED_RULES_PATH", absent)
    assert update_rules.cmd_update_rules() == 0
    assert capsys.readouterr() == (
        head + f"aramid: update-rules: target path:   {absent}\n",
        "aramid: update-rules: WARNING -- no vendored ruleset is installed yet; semgrep "
        "scans will crash/degrade (never silently pass) until this is populated.\n")
