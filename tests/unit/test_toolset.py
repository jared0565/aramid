"""RUNNER_TOOL_NAMES/PRODUCER_TOOL_NAMES membership, selected_tool_names'
per-key expansion, and ghost_candidates' predicate (T-8 section 3)."""
from aramid import config as config_mod
from aramid import toolset
from aramid.runners import deps, typecheck


def _cfg(tmp_path, monkeypatch, root) -> config_mod.Config:
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    return config_mod.load_config(root)


# ------------------------------------------------------- universe/disjoint --

def test_runner_and_producer_tool_names_are_disjoint():
    assert toolset.RUNNER_TOOL_NAMES.isdisjoint(toolset.PRODUCER_TOOL_NAMES)


def test_universe_contains_every_real_runner_tool_constant():
    # Pins the frozensets against the REAL constants each module defines --
    # a rename in any runner module fails this, not a silently-drifted copy.
    from aramid.runners import eslint, gitleaks, ruff, semgrep
    for name in (gitleaks.NAME, ruff.NAME, semgrep.NAME, eslint.NAME,
                 typecheck.NAME_TSC, typecheck.NAME_MYPY, deps.NAME_PIP_AUDIT,
                 deps.NAME_CARGO_AUDIT, "npm", "pnpm", "yarn", "pytest", "tests"):
        assert name in toolset.RUNNER_TOOL_NAMES, name


def test_producer_tools_are_never_in_the_runner_universe():
    from aramid import mutation_gate, mutation_score_gate, red_proof, tdd
    for name in (tdd._TOOL, red_proof._TOOL, mutation_gate.TOOL,
                 mutation_score_gate.TOOL, "llm-review", "js-mutation",
                 "fuzz", "dast"):
        assert name in toolset.PRODUCER_TOOL_NAMES
        assert name not in toolset.RUNNER_TOOL_NAMES


def test_regression_pack_needs_no_entry_in_either_set():
    """T-8 Global Constraint 6: regression_pack reuses "semgrep", it never
    stamps its own name -- so its own module name has no place in either
    frozenset, and must not silently start matching one."""
    from aramid.consumers import regression_pack
    assert regression_pack.NAME not in toolset.RUNNER_TOOL_NAMES
    assert regression_pack.NAME not in toolset.PRODUCER_TOOL_NAMES


# ---------------------------------------------------- selected_tool_names ---

def test_gitleaks_always_selected_even_in_an_empty_repo(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    assert "gitleaks" in toolset.selected_tool_names(tmp_path, cfg)


def test_ruff_selected_only_for_python_stack(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    assert "ruff" not in toolset.selected_tool_names(tmp_path, cfg)
    (tmp_path / "pyproject.toml").write_text("[tool.x]\n", encoding="utf-8")
    assert "ruff" in toolset.selected_tool_names(tmp_path, cfg)


def test_deps_npm_selected_by_its_own_package_manager_name(tmp_path, monkeypatch):
    """Regression guard for the npm/pnpm/yarn case: tool name equals package
    manager name there, unlike cargo below -- must not regress once cargo's
    special case is added."""
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    assert "npm" in toolset.selected_tool_names(tmp_path, cfg)


def test_deps_cargo_selected_as_cargo_audit_not_as_cargo(tmp_path, monkeypatch):
    """Unlike npm/pnpm/yarn, the package manager ("cargo") and the security
    tool that actually stamps Finding.tool ("cargo-audit") are different
    names -- selected_tool_names must add the TOOL name, or mark-unreachable
    logic and ghost_candidates would never recognize a real cargo-audit
    finding as selected."""
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    (tmp_path / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
    selected = toolset.selected_tool_names(tmp_path, cfg)
    assert deps.NAME_CARGO_AUDIT in selected
    assert "cargo" not in selected


def test_tsc_selected_when_tsconfig_present(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")
    assert typecheck.NAME_TSC in toolset.selected_tool_names(tmp_path, cfg)


def test_pytest_selected_when_a_real_test_file_exists(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    (tmp_path / "test_x.py").write_text("def test_a(): pass\n", encoding="utf-8")
    selected = toolset.selected_tool_names(tmp_path, cfg)
    assert "pytest" in selected
    assert "tests" in selected  # the registry key itself, Global Constraint 5


def test_pytest_no_longer_selected_once_the_test_file_is_gone(tmp_path, monkeypatch):
    """Proves the ghost scenario end to end at the toolset layer: a repo
    that once had a pytest suite, and no longer does, drops BOTH "pytest"
    and the "tests" registry key from the selected set."""
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    selected = toolset.selected_tool_names(tmp_path, cfg)
    assert "pytest" not in selected
    assert "tests" not in selected


def test_tests_key_stays_selected_when_binary_missing_but_suite_still_detected(
        tmp_path, monkeypatch):
    """Global Constraint 5: a broken-but-still-configured test setup must
    stay "selected" -- mark-unreachable must refuse it (broken toolchain is
    `aramid doctor`'s problem), not silently retire it. selected_tool_names
    never inspects whether the pytest BINARY resolves -- only whether
    detect_tests() still finds a real suite -- so this holds regardless of
    whether pytest is actually installed on the machine running this test."""
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    (tmp_path / "test_x.py").write_text("def test_a(): pass\n", encoding="utf-8")
    assert "tests" in toolset.selected_tool_names(tmp_path, cfg)


def test_custom_test_command_basename_is_selected_not_pytest_or_npm(tmp_path, monkeypatch):
    (tmp_path / "aramid.toml").write_text(
        'schema_version = 1\n[tests]\ncommand = "make test"\n', encoding="utf-8")
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    selected = toolset.selected_tool_names(tmp_path, cfg)
    assert "make" in selected
    assert "tests" in selected
    assert "pytest" not in selected


def test_tests_disabled_removes_the_tests_key_from_selection(tmp_path, monkeypatch):
    (tmp_path / "test_x.py").write_text("def test_a(): pass\n", encoding="utf-8")
    (tmp_path / "aramid.toml").write_text(
        'schema_version = 1\n[tests]\nenabled = false\n', encoding="utf-8")
    cfg = _cfg(tmp_path, monkeypatch, tmp_path)
    selected = toolset.selected_tool_names(tmp_path, cfg)
    assert "tests" not in selected
    assert "pytest" not in selected


# ------------------------------------------------------- ghost_candidates ---

def test_ghost_candidates_excludes_producer_tools_even_if_never_selected():
    state = {"f1": {"status": "open", "tool": "mutation"}}
    assert toolset.ghost_candidates(state, selected=set()) == {}


def test_ghost_candidates_excludes_non_open_status():
    state = {"f1": {"status": "historical", "tool": "gitleaks"}}
    assert toolset.ghost_candidates(state, selected=set()) == {}


def test_ghost_candidates_includes_open_finding_whose_tool_left_selection():
    state = {"f1": {"status": "open", "tool": "ruff"}}
    assert "f1" in toolset.ghost_candidates(state, selected=set())


def test_ghost_candidates_excludes_a_still_selected_tool():
    state = {"f1": {"status": "open", "tool": "ruff"}}
    assert toolset.ghost_candidates(state, selected={"ruff"}) == {}


# ------------------ cargo-audit informational warnings (round 20) ----------

def _cargo_repo(tmp_path):
    (tmp_path / "Cargo.toml").write_text("[package]\nname = \"x\"\n")
    (tmp_path / "Cargo.lock").write_text("[[package]]\nname = \"x\"\n")
    return tmp_path


def test_cargo_warnings_tool_is_selected_only_while_opted_in(tmp_path, monkeypatch):
    """The opt-in has to reach `selected_tool_names`, not just the parser.

    `ghost_candidates` retires an OPEN finding whose tool is in the
    retireable universe but is NOT currently selected. So if this name were
    selected unconditionally, turning `[deps].cargo_audit_warnings` back off
    would strand every warning it had already written -- open forever, with
    no producer left that could ever resolve them. Selection must track the
    flag for the feature to be reversible.
    """
    root = _cargo_repo(tmp_path)
    cfg = _cfg(tmp_path, monkeypatch, root)

    cfg.deps = {"cargo_audit_warnings": False}
    off = toolset.selected_tool_names(root, cfg)
    cfg.deps = {"cargo_audit_warnings": True}
    on = toolset.selected_tool_names(root, cfg)

    # The real advisory path is unconditional either way -- only the
    # informational one is gated.
    assert deps.NAME_CARGO_AUDIT in off and deps.NAME_CARGO_AUDIT in on
    assert deps.NAME_CARGO_AUDIT_WARNINGS not in off
    assert deps.NAME_CARGO_AUDIT_WARNINGS in on


def test_cargo_warnings_findings_become_ghosts_when_the_flag_is_turned_off(tmp_path, monkeypatch):
    """The consequence of the above, asserted where an operator would feel
    it: an existing open warning is offered for retirement once opted out."""
    root = _cargo_repo(tmp_path)
    cfg = _cfg(tmp_path, monkeypatch, root)
    state = {"f1": {"tool": deps.NAME_CARGO_AUDIT_WARNINGS,
                    "rule": "unmaintained/RUSTSEC-2021-0139", "status": "open"}}

    cfg.deps = {"cargo_audit_warnings": True}
    assert toolset.ghost_candidates(state, toolset.selected_tool_names(root, cfg)) == {}

    cfg.deps = {"cargo_audit_warnings": False}
    assert "f1" in toolset.ghost_candidates(state, toolset.selected_tool_names(root, cfg))


def test_cargo_warnings_tool_is_in_the_retireable_universe():
    assert deps.NAME_CARGO_AUDIT_WARNINGS in toolset.RUNNER_TOOL_NAMES
    assert deps.NAME_CARGO_AUDIT_WARNINGS not in toolset.PRODUCER_TOOL_NAMES
