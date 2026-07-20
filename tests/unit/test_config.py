from pathlib import Path

from aramid import config
from aramid.models import Verdict


def _no_user_config(tmp_path):
    """Point the user-config layer at a path that doesn't exist, so tests
    never touch a real ~/.aramid/config.toml on the machine running them."""
    return tmp_path / "no-such-user-config" / "config.toml"


# --- (a) layered merge: user config + repo config both land, and built-in
#     ignore paths are always unioned in even if repo toml sets ignore_paths=[]

def test_user_and_repo_layers_both_land_and_builtin_ignores_always_present(tmp_path, monkeypatch):
    user_cfg = tmp_path / "user" / "config.toml"
    user_cfg.parent.mkdir(parents=True)
    user_cfg.write_text(
        '[block_rules.deps]\nblock_severity = "high"\n', encoding="utf-8")
    monkeypatch.setattr(config, "_user_config_path", lambda: user_cfg)

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "aramid.toml").write_text(
        'test_command = "pytest -k smoke"\nignore_paths = []\n', encoding="utf-8")

    cfg = config.load_config(repo)

    assert cfg.block_rules["deps"]["block_severity"] == "high"  # user layer landed
    assert cfg.test_command == "pytest -k smoke"                # repo layer landed
    for builtin in (".aramid/", "graph-out/", ".graphite*", ".cache/",
                    "node_modules/", ".venv/", "__pycache__/", ".git/"):
        assert builtin in cfg.ignore_paths                      # never removable


def test_defaults_only_when_no_user_or_repo_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: _no_user_config(tmp_path))
    repo = tmp_path / "repo2"
    repo.mkdir()

    cfg = config.load_config(repo)

    assert cfg.schema_version == config.CURRENT_SCHEMA_VERSION
    assert cfg.semgrep_block_armed is False
    assert cfg.bake_started is None
    assert cfg.test_command is None
    assert cfg.scope_subpath is None
    assert cfg.timeouts["pre_commit"] == 5
    assert cfg.timeouts["pre_push"] == 300
    assert cfg.block_rules["deps"]["block_severity"] == "critical"


# --- (b) is_ignored / filter_paths ------------------------------------------

def test_is_ignored_matches_prefix_and_fnmatch():
    ignore_paths = [".aramid/", "graph-out/", ".graphite*", ".cache/"]
    assert config.is_ignored("graph-out/x.json", ignore_paths) is True
    assert config.is_ignored(".graphite/state.json", ignore_paths) is True
    assert config.is_ignored("src/app.py", ignore_paths) is False


def test_filter_paths_drops_ignored(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: _no_user_config(tmp_path))
    repo = tmp_path / "repo3"
    repo.mkdir()
    cfg = config.load_config(repo)

    files = ["src/app.py", "graph-out/x.json", ".aramid/salt", "src/util.py"]
    out = config.filter_paths(files, cfg)

    assert out == ["src/app.py", "src/util.py"]


# --- (c) suppression entry with no reason -----------------------------------

def test_suppression_without_reason_yields_synthetic_warn_finding(tmp_path):
    root = tmp_path / "repo4"
    root.mkdir()
    (root / ".aramid-suppressions.toml").write_text(
        '[[suppress]]\n'
        'id = "abc123"\n'
        'tool = "semgrep"\n'
        'rule = "owasp.sqli"\n'
        'path = "src/app.py"\n'
        'reason = ""\n',
        encoding="utf-8")

    records, warnings = config.load_suppressions(root)

    assert records == []
    assert len(warnings) == 1
    assert warnings[0].tool == "aramid"
    assert warnings[0].rule == "suppression-without-reason"
    assert warnings[0].verdict is Verdict.WARN


def test_suppression_with_reason_yields_override_record_not_warning(tmp_path):
    root = tmp_path / "repo5"
    root.mkdir()
    (root / ".aramid-suppressions.toml").write_text(
        '[[suppress]]\n'
        'id = "abc123"\n'
        'tool = "semgrep"\n'
        'rule = "owasp.sqli"\n'
        'path = "src/app.py"\n'
        'reason = "reviewed, false positive"\n',
        encoding="utf-8")

    records, warnings = config.load_suppressions(root)

    assert warnings == []
    assert len(records) == 1
    assert records[0].id == "abc123"
    assert records[0].reason == "reviewed, false positive"


def test_load_suppressions_missing_file_returns_empty(tmp_path):
    root = tmp_path / "repo6"
    root.mkdir()
    records, warnings = config.load_suppressions(root)
    assert records == []
    assert warnings == []


# --- (d) schema migration message -------------------------------------------

def test_repo_toml_older_schema_version_prints_migration_message(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "_user_config_path", lambda: _no_user_config(tmp_path))
    repo = tmp_path / "repo7"
    repo.mkdir()
    (repo / "aramid.toml").write_text("schema_version = 0\n", encoding="utf-8")

    config.load_config(repo)

    err = capsys.readouterr().err
    expected = f"aramid: config schema v0→v{config.CURRENT_SCHEMA_VERSION}; review aramid.toml"
    assert expected in err


def test_repo_toml_current_schema_version_prints_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "_user_config_path", lambda: _no_user_config(tmp_path))
    repo = tmp_path / "repo8"
    repo.mkdir()
    (repo / "aramid.toml").write_text(
        f"schema_version = {config.CURRENT_SCHEMA_VERSION}\n", encoding="utf-8")

    config.load_config(repo)

    err = capsys.readouterr().err
    assert err == ""


# --- render_repo_stub --------------------------------------------------------

def test_render_repo_stub_contains_mandated_keys():
    text = config.render_repo_stub({"python"}, None, today="2026-07-12")
    assert f"schema_version = {config.CURRENT_SCHEMA_VERSION}" in text
    assert "semgrep_block_armed = false" in text
    assert 'bake_started = "2026-07-12"' in text


def test_render_repo_stub_omits_scope_subpath_and_ignore_paths_by_default():
    """A repo initted at its own root (no scope narrowing, no nested .git
    exclusions) gets a stub with neither key -- init's target==root case."""
    text = config.render_repo_stub({"python"}, None, today="2026-07-12")
    assert "scope_subpath" not in text
    assert "ignore_paths" not in text


def test_render_repo_stub_records_scope_subpath_when_given():
    text = config.render_repo_stub({"python"}, None, today="2026-07-12",
                                    scope_subpath="sub/dir")
    assert 'scope_subpath = "sub/dir"' in text


def test_render_repo_stub_records_extra_ignore_paths_when_given():
    text = config.render_repo_stub({"python"}, None, today="2026-07-12",
                                    extra_ignore_paths=["vendor/sub/"])
    assert "ignore_paths" in text
    assert "vendor/sub/" in text


# --- (e) Phase 2a: triage, drain, pack config sections -----

def test_phase2a_defaults_present(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "nouser.toml")
    cfg = config.load_config(tmp_path)
    assert cfg.triage["min_score"] == 40
    assert cfg.triage["extra_security_paths"] == []
    assert cfg.drain["interval_hours"] == 4
    assert cfg.drain["max_items_per_drain"] == 10
    assert cfg.drain["item_expiry_days"] == 30
    assert cfg.drain["wall_clock_budget_s"] == 600
    assert cfg.pack["enabled"] is True


def test_repo_config_overrides_triage(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "nouser.toml")
    (tmp_path / "aramid.toml").write_text(
        'schema_version = 1\n[triage]\nmin_score = 70\n', encoding="utf-8")
    cfg = config.load_config(tmp_path)
    assert cfg.triage["min_score"] == 70
    assert cfg.triage["extra_security_paths"] == []  # deep merge keeps sibling default


# --- (f) Phase 2b: LLM config section ----------------------------------------

def test_llm_defaults_present(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: _no_user_config(tmp_path))
    cfg = config.load_config(tmp_path)
    assert cfg.llm["enabled"] is True
    assert cfg.llm["max_items_per_drain"] == 3
    assert cfg.llm["call_timeout_s"] == 240
    assert cfg.llm["packet_max_bytes"] == 120000
    assert cfg.llm["llm_block_armed"] is False
    assert cfg.llm["provider_order"] == ["claude-cli", "codex-cli", "ollama-cloud"]
    assert cfg.llm["model_openrouter"] == "anthropic/claude-sonnet-4-5"
    assert cfg.llm["openrouter_monthly_cap_usd"] == 5.0
    assert cfg.llm["max_refutes_per_drain"] == 6
    # Ladder assertions
    ladder = cfg.llm["ladder"]
    assert [a["tier"] for a in ladder] == ["cheap", "mid", "frontier"]
    assert [a["provider"] for a in ladder] == ["ollama-cloud", "codex-cli", "claude-cli"]
    assert [a["min_score"] for a in ladder] == [40, 60, 80]
    # effort: all three tiers live-verified 2026-07-14; cheap/ollama stays ""
    # deliberately (non-empty effort => think:true, wrong for the cheap tier).
    assert [a["effort"] for a in ladder] == ["", "medium", "high"]
    assert [a["model"] for a in ladder] == ["deepseek-v4-flash", "gpt-5.5", "opus"]


def test_llm_repo_override_merges(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: _no_user_config(tmp_path))
    (tmp_path / "aramid.toml").write_text(
        "[llm]\nmax_items_per_drain = 1\n", encoding="utf-8")
    cfg = config.load_config(tmp_path)
    assert cfg.llm["max_items_per_drain"] == 1
    assert cfg.llm["enabled"] is True  # other keys keep defaults (deep merge)


def test_autolearn_defaults_present(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: _no_user_config(tmp_path))
    cfg = config.load_config(tmp_path)
    al = cfg.llm["autolearn"]
    assert al["enabled"] is True
    assert al["armed"] is False
    assert al["uplift_threshold"] == 0.15
    assert al["audit_every"] == 8
    assert al["max_audits_per_drain"] == 1
    assert al["cascade_hallucination_min"] == 3


def test_autolearn_repo_override_deep_merges(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: _no_user_config(tmp_path))
    (tmp_path / "aramid.toml").write_text(
        "[llm.autolearn]\narmed = true\n", encoding="utf-8")
    cfg = config.load_config(tmp_path)
    assert cfg.llm["autolearn"]["armed"] is True
    assert cfg.llm["autolearn"]["enabled"] is True   # sibling default survives


def test_fuzz_defaults_present(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: _no_user_config(tmp_path))
    cfg = config.load_config(tmp_path)
    assert cfg.fuzz["enabled"] is True
    assert cfg.fuzz["max_functions"] == 10
    assert cfg.fuzz["cases_per_function"] == 50
    assert cfg.fuzz["batch_timeout_s"] == 120
    assert "*deploy*" in cfg.fuzz["skip_name_patterns"]


def test_fuzz_repo_override_merges(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: _no_user_config(tmp_path))
    (tmp_path / "aramid.toml").write_text(
        "schema_version = 1\n[fuzz]\nmax_functions = 3\n", encoding="utf-8")
    cfg = config.load_config(tmp_path)
    assert cfg.fuzz["max_functions"] == 3
    assert cfg.fuzz["enabled"] is True  # deep-merge keeps defaults


def test_mutation_defaults_present(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: _no_user_config(tmp_path))
    cfg = config.load_config(tmp_path)
    assert cfg.mutation["enabled"] is True
    assert cfg.mutation["max_mutants"] == 20
    assert cfg.mutation["wall_budget_s"] == 600
    assert cfg.mutation["mutant_timeout_s"] == 120
    assert cfg.mutation["confirm_cap"] == 3


def test_mutation_repo_override_merges(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: _no_user_config(tmp_path))
    (tmp_path / "aramid.toml").write_text(
        "schema_version = 1\n[mutation]\nmax_mutants = 4\n", encoding="utf-8")
    cfg = config.load_config(tmp_path)
    assert cfg.mutation["max_mutants"] == 4
    assert cfg.mutation["enabled"] is True  # deep-merge keeps defaults
