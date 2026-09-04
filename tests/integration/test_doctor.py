import subprocess
import sys
from pathlib import Path

import pytest

from aramid import toolpath
from aramid import config as config_mod
from aramid.commands import doctor


def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, check=True, capture_output=True)
    return r


def _all_present() -> dict[str, doctor.ToolStatus]:
    return {
        "gitleaks": doctor.ToolStatus("gitleaks", True, "8.21.2"),
        "semgrep": doctor.ToolStatus("semgrep", True, "1.100.0"),
        "ruff": doctor.ToolStatus("ruff", True, "0.6.0"),
        "pip-audit": doctor.ToolStatus("pip-audit", True, "2.7.0"),
        "interpreter": doctor.ToolStatus("interpreter", True, sys.executable),
    }


# --- pinned test: monkeypatch the prober, no network -----------------------

def test_cmd_doctor_returns_2_and_names_gitleaks_when_gitleaks_missing(tmp_path, monkeypatch, capsys):
    def fake_probe(root):
        statuses = _all_present()
        statuses["gitleaks"] = doctor.ToolStatus("gitleaks", False, detail="not found")
        return statuses

    monkeypatch.setattr(doctor, "probe_toolchain", fake_probe)

    rc = doctor.cmd_doctor(tmp_path)
    out = capsys.readouterr()

    assert rc == 2
    assert "gitleaks" in (out.out + out.err)


def test_cmd_doctor_returns_0_when_all_block_tier_tools_present(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())
    assert doctor.cmd_doctor(tmp_path) == 0


def test_cmd_doctor_missing_semgrep_also_returns_2(tmp_path, monkeypatch, capsys):
    def fake_probe(root):
        statuses = _all_present()
        statuses["semgrep"] = doctor.ToolStatus("semgrep", False, detail="not found")
        return statuses

    monkeypatch.setattr(doctor, "probe_toolchain", fake_probe)
    rc = doctor.cmd_doctor(tmp_path)
    out = capsys.readouterr()
    assert rc == 2
    assert "semgrep" in (out.out + out.err)


def test_cmd_doctor_missing_warn_tier_tool_does_not_fail(tmp_path, monkeypatch):
    """ruff/pip-audit are WARN-tier at runtime -- doctor reports them but a
    missing one must never drop the exit code below 0; only gitleaks/semgrep
    (BLOCK_TIER) gate the return code."""
    def fake_probe(root):
        statuses = _all_present()
        statuses["ruff"] = doctor.ToolStatus("ruff", False, detail="not found")
        statuses["pip-audit"] = doctor.ToolStatus("pip-audit", False, detail="not found")
        return statuses

    monkeypatch.setattr(doctor, "probe_toolchain", fake_probe)
    assert doctor.cmd_doctor(tmp_path) == 0


def test_block_tier_is_exactly_gitleaks_and_semgrep():
    assert set(doctor.BLOCK_TIER) == {"gitleaks", "semgrep"}


# --- fix=False must never touch network / pip / downloads -------------------

def test_cmd_doctor_fix_false_never_calls_repair_paths(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(doctor, "_fix_pip_toolchain", lambda: called.append("pip"))
    monkeypatch.setattr(doctor, "_fix_gitleaks", lambda: called.append("gitleaks"))
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())

    doctor.cmd_doctor(tmp_path, fix=False)

    assert called == []


def test_cmd_doctor_fix_true_calls_repair_and_reprobes_without_network(tmp_path, monkeypatch):
    """Exercises the --fix branch entirely through monkeypatched seams --
    no real pip install, no real download, per the brief's 'do not actually
    download anything in tests'."""
    calls = []
    probe_call_count = [0]

    def fake_probe(root):
        probe_call_count[0] += 1
        if probe_call_count[0] == 1:
            statuses = _all_present()
            statuses["gitleaks"] = doctor.ToolStatus("gitleaks", False, detail="not found")
            statuses["ruff"] = doctor.ToolStatus("ruff", False, detail="not found")
            return statuses
        return _all_present()  # post-fix re-probe: everything present

    monkeypatch.setattr(doctor, "_fix_pip_toolchain", lambda: calls.append("pip"))
    monkeypatch.setattr(doctor, "_fix_gitleaks", lambda: calls.append("gitleaks") or True)
    monkeypatch.setattr(doctor, "probe_toolchain", fake_probe)

    rc = doctor.cmd_doctor(tmp_path, fix=True)

    assert "pip" in calls
    assert "gitleaks" in calls
    assert probe_call_count[0] == 2  # re-probed after fixing
    assert rc == 0


def test_cmd_doctor_fix_true_skips_pip_repair_when_owned_toolchain_already_present(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(doctor, "_fix_pip_toolchain", lambda: calls.append("pip"))
    monkeypatch.setattr(doctor, "_fix_gitleaks", lambda: calls.append("gitleaks") or True)
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())

    doctor.cmd_doctor(tmp_path, fix=True)

    assert "pip" not in calls
    assert "gitleaks" not in calls


# --- gitleaks pins are real values, sanity-checked without network ----------

def test_gitleaks_checksums_are_well_formed_sha256_hex():
    assert len(doctor.GITLEAKS_SHA256) >= 1
    for digest in doctor.GITLEAKS_SHA256.values():
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)


# --- interpreter probing against a real installed shim (integration) -------

def test_probe_interpreter_reads_baked_path_from_installed_shim(tmp_path):
    from aramid import hooks

    root = _repo(tmp_path)
    interp = Path(sys.executable)
    hooks.install(root, interp)

    status = doctor.probe_interpreter(root)

    assert status.present
    assert status.version == hooks.win_sh_path(interp)


def test_probe_interpreter_with_no_shim_reports_current_interpreter(tmp_path):
    root = _repo(tmp_path)

    status = doctor.probe_interpreter(root)

    assert status.present
    assert status.version == sys.executable


# --- probe_tool against the REAL owned toolchain on this machine -----------
# (no monkeypatching -- this is what makes doctor's report trustworthy: the
# owned tools' console scripts live in the CURRENT interpreter's Scripts
# dir, which is not guaranteed to be on PATH.)

def test_probe_tool_finds_ruff_via_current_interpreters_scripts_dir():
    status = doctor.probe_tool("ruff")
    assert status.present, status.detail
    assert status.version


def test_probe_tool_finds_semgrep_despite_pysemgrep_sibling_lookup():
    """semgrep.exe's own wrapper shells out to a sibling pysemgrep.exe by
    bare name and fails if its directory isn't on PATH -- this is the real
    case the PATH-prepend in probe_tool exists for (ruff, above, is a
    standalone exe that would pass even without it)."""
    status = doctor.probe_tool("semgrep")
    assert status.present, status.detail
    assert status.version


def test_probe_tool_reports_missing_for_unknown_tool():
    status = doctor.probe_tool("definitely-not-a-real-tool-xyz")
    assert not status.present


# --- LLM providers probe (Phase 2b) ---

def test_probe_providers_zero_call(monkeypatch, tmp_path):
    import shutil as _shutil
    from aramid.providers import spend as spend_mod
    monkeypatch.setattr(spend_mod, "spend_path", lambda: tmp_path / "llm_spend.jsonl")
    monkeypatch.setattr(_shutil, "which",
                        lambda n: r"C:\bin\claude.exe" if n == "claude" else None)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    lines = doctor.probe_providers()
    text = "\n".join(lines)
    assert "claude-cli" in text and "OK" in text
    assert "codex-cli" in text and "MISSING" in text
    assert "openrouter" in text and "no OPENROUTER_API_KEY" in text


def test_probe_providers_reports_ollama(monkeypatch):
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    lines = doctor.probe_providers()
    text = "\n".join(lines)
    assert "ollama-cloud" in text and "MISSING" in text and "OLLAMA_API_KEY" in text


def test_doctor_exit_code_unchanged_by_missing_providers(monkeypatch, tmp_path):
    """Providers are informational: doctor's exit contract is driven by
    BLOCK_TIER tools only. Monkeypatch probe_toolchain to all-present and
    verify exit 0 with no provider installed."""
    import shutil as _shutil
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: {
        name: doctor.ToolStatus(name, True, "1.0")
        for name in (*doctor.ALL_TOOLS, "interpreter")})
    monkeypatch.setattr(_shutil, "which", lambda n: None)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert doctor.cmd_doctor(tmp_path) == 0


def test_probe_providers_spend_unreadable_with_key_set(monkeypatch, tmp_path):
    """Fail-closed money path: OPENROUTER_API_KEY is set but the spend log is
    unreadable (month_spend_usd None). probe_providers must surface 'spend log
    unreadable -- calls refused' and never raise; and cmd_doctor's exit code
    stays BLOCK_TIER-driven (0 here, since the toolchain is all-present)."""
    from aramid.providers import spend as spend_mod
    monkeypatch.setattr(spend_mod, "spend_path", lambda: tmp_path / "llm_spend.jsonl")
    monkeypatch.setattr(spend_mod, "month_spend_usd", lambda provider, now_iso: None)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")

    lines = doctor.probe_providers()  # must not raise
    text = "\n".join(lines)
    assert "openrouter" in text and "spend log unreadable -- calls refused" in text

    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: {
        name: doctor.ToolStatus(name, True, "1.0")
        for name in (*doctor.ALL_TOOLS, "interpreter")})
    assert doctor.cmd_doctor(tmp_path) == 0


def test_doctor_reports_autolearn_state(tmp_path, monkeypatch, capsys):
    from aramid.commands.doctor import _autolearn_probe_line
    line = _autolearn_probe_line()
    assert "autolearn" in line and "cold start" in line   # no state yet

    from aramid import autolearn
    autolearn.save_state(autolearn.empty_state(),
                         "2026-07-18T00:00:00+00:00")
    assert "state readable" in _autolearn_probe_line()

    autolearn.state_path().write_text("{corrupt", encoding="utf-8")
    assert "unreadable" in _autolearn_probe_line()


def test_doctor_reports_foreign_autolearn_state_version():
    """T13 gap: a state file from a different aramid version must probe as
    DEGRADED with the --rebuild hint (engine treats it as empty)."""
    import json as _json

    from aramid import autolearn
    from aramid.commands.doctor import _autolearn_probe_line
    autolearn.state_path().write_text(
        _json.dumps({"version": 999, "posteriors": {}}), encoding="utf-8")
    line = _autolearn_probe_line()
    assert "DEGRADED" in line
    assert "foreign state version" in line
    assert "--rebuild" in line


# --- "configured but NOT enforced": the fresh-clone hole --------------------
# .git/hooks is NOT version-controlled, so cloning an onboarded repo yields
# aramid.toml (committed) with no shims. The repo LOOKS onboarded and nothing
# fires. doctor must name that state distinctly -- probe_interpreter's existing
# "no shim installed yet" reads as benign and is not a substitute.

def _onboarded(tmp_path, with_shim: bool) -> Path:
    r = _repo(tmp_path)
    (r / "aramid.toml").write_text("[tool]\n", encoding="utf-8")
    if with_shim:
        from aramid.hooks import hooks_dir
        hdir = hooks_dir(r)
        hdir.mkdir(parents=True, exist_ok=True)
        (hdir / "pre-commit").write_bytes(b"#!/bin/sh\nexit 0\n")
        (hdir / "pre-push").write_bytes(b"#!/bin/sh\nexit 0\n")
    return r


def test_doctor_flags_config_present_but_hooks_missing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())
    root = _onboarded(tmp_path, with_shim=False)

    rc = doctor.cmd_doctor(root)
    out = capsys.readouterr()
    blob = out.out + out.err

    assert rc == 2, "a configured-but-unenforced repo must not report healthy"
    assert "NOT enforced" in blob
    # Distinctness: must not be mistakable for the benign interpreter line.
    assert "no shim installed yet" not in blob


def test_doctor_stays_quiet_when_repo_was_never_onboarded(tmp_path, monkeypatch, capsys):
    """No aramid.toml == deliberately not onboarded. Nagging here would make
    the warning noise, and noise is how a real one gets ignored."""
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())
    root = _repo(tmp_path)          # git repo, no aramid.toml

    rc = doctor.cmd_doctor(root)
    blob = capsys.readouterr()
    assert rc == 0
    assert "NOT enforced" not in (blob.out + blob.err)


def test_doctor_clean_when_config_and_shims_both_present(tmp_path, monkeypatch, capsys):
    """The counterfactual for the flag test: proves it keys on the SHIM's
    absence, not merely on aramid.toml existing."""
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())
    root = _onboarded(tmp_path, with_shim=True)

    rc = doctor.cmd_doctor(root)
    blob = capsys.readouterr()
    assert rc == 0
    assert "NOT enforced" not in (blob.out + blob.err)


def _shim_hooks(root: Path) -> None:
    """Install dummy hook shims so `probe_enforcement`'s 'configured but NOT
    enforced' check stays quiet. Several tests below write a custom
    aramid.toml to exercise `[tests]` specifically -- without this, the mere
    presence of aramid.toml with no `.git/hooks` shims ALSO contributes an
    unrelated exit-2 reason (probe_enforcement), confounding what's actually
    under test."""
    from aramid.hooks import hooks_dir
    hdir = hooks_dir(root)
    hdir.mkdir(parents=True, exist_ok=True)
    (hdir / "pre-commit").write_bytes(b"#!/bin/sh\nexit 0\n")
    (hdir / "pre-push").write_bytes(b"#!/bin/sh\nexit 0\n")


# --- T-2: doctor must probe the test toolchain ------------------------------
# `tests` is BLOCK-tier in the gate (pipeline.BLOCK_TIER_KEYS), but doctor's
# own BLOCK_TIER/ALL_TOOLS never covered it -- so doctor could print "all
# BLOCK-tier tools present" and exit 0 on a repo whose test tool is absent,
# and the very next push would be blocked by a degraded BLOCK-tier `tests`
# runner doctor never warned about. Each test below pins one of the three
# cases (custom command / detected suite / no suite) plus the exit-code rule.

def test_cmd_doctor_returns_2_and_reports_when_detected_pytest_tool_is_missing(
        tmp_path, monkeypatch, capsys):
    """THE bug this ticket exists to fix, pinned directly: a repo with a real
    test file but no pytest binary must make doctor exit 2 -- and say why --
    not print 'all BLOCK-tier tools present.' and exit 0."""
    root = _repo(tmp_path)
    (root / "test_something.py").write_text("def test_x():\n    assert True\n",
                                             encoding="utf-8")

    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())

    def fake_probe_tool(name):
        if name == "pytest":
            return doctor.ToolStatus("pytest", False, detail="not found on PATH")
        raise AssertionError(f"unexpected probe_tool call: {name}")

    monkeypatch.setattr(doctor, "probe_tool", fake_probe_tool)

    rc = doctor.cmd_doctor(root)
    blob = capsys.readouterr()
    text = blob.out + blob.err

    assert rc == 2
    assert "all BLOCK-tier tools present." not in text
    assert "pytest" in text and "MISSING" in text


def test_cmd_doctor_dual_stack_probes_both_pytest_and_npm(tmp_path, monkeypatch, capsys):
    """Case 2, dual-stack: detect_tests() returning BOTH kinds must probe
    BOTH -- not silently pick one, the exact bug class runners/tests.py's own
    dual-suite path exists to close, mirrored here for doctor's report."""
    root = _repo(tmp_path)
    (root / "test_something.py").write_text("def test_x():\n    assert True\n",
                                             encoding="utf-8")
    (root / "package.json").write_text('{"scripts": {"test": "jest"}}\n', encoding="utf-8")

    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())

    def fake_probe_tool(name):
        if name == "pytest":
            return doctor.ToolStatus("pytest", True, "8.0.0")
        if name == "npm":
            return doctor.ToolStatus("npm", False, detail="not found")
        raise AssertionError(f"unexpected probe_tool call: {name}")

    monkeypatch.setattr(doctor, "probe_tool", fake_probe_tool)

    rc = doctor.cmd_doctor(root)
    text = "".join(capsys.readouterr())

    assert rc == 2
    assert "pytest" in text and "npm" in text


def test_cmd_doctor_no_test_suite_reports_and_does_not_exit_2(tmp_path, monkeypatch, capsys):
    """Case 3: no test suite at all is a LEGITIMATE state, not a broken
    toolchain -- must not exit 2, and must say so (not just stay silent,
    which would be indistinguishable from doctor not having checked)."""
    root = _repo(tmp_path)          # no test files, no package.json
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())

    rc = doctor.cmd_doctor(root)
    text = "".join(capsys.readouterr()).lower()

    assert rc == 0
    assert "no test suite" in text


def test_cmd_doctor_configured_command_resolving_argv0_does_not_exit_2(
        tmp_path, monkeypatch, capsys):
    """Case 1, aramid's own repo shape: `[tests].command` is
    `["python", "-m", "pytest", "-q", "tests/unit"]` -- argv[0] is `python`,
    which always resolves. Must report truthfully without implying the
    suite actually runs or that its selector matches anything."""
    root = _repo(tmp_path)
    (root / "aramid.toml").write_text(
        '[tests]\ncommand = ["python", "-m", "pytest", "-q", "tests/unit"]\n',
        encoding="utf-8")
    _shim_hooks(root)
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())
    monkeypatch.setattr(toolpath, "resolve",
                        lambda name: Path(sys.executable) if name == "python" else None)

    rc = doctor.cmd_doctor(root)
    text = "".join(capsys.readouterr())

    assert rc == 0
    assert "python" in text
    assert "does not verify the suite runs" in text


def test_cmd_doctor_configured_command_argv0_missing_returns_2(tmp_path, monkeypatch, capsys):
    """Case 1, the failing half: a configured command whose argv[0] is not
    on PATH must make doctor exit 2, exactly like a detected-but-absent
    pytest/npm does."""
    root = _repo(tmp_path)
    (root / "aramid.toml").write_text(
        '[tests]\ncommand = ["definitely-not-a-real-exe-xyz", "-q"]\n', encoding="utf-8")
    _shim_hooks(root)
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())
    monkeypatch.setattr(toolpath, "resolve", lambda name: None)

    rc = doctor.cmd_doctor(root)
    text = "".join(capsys.readouterr())

    assert rc == 2
    assert "definitely-not-a-real-exe-xyz" in text


def test_cmd_doctor_configured_command_never_calls_probe_tool(tmp_path, monkeypatch):
    """SECURITY [T-2]: a `[tests].command` is EXTERNAL INPUT (aramid.toml
    ships with a cloned repo). probe_tool executes `<name> --version` under
    a S603 justification that assumes `name` is never external input --
    passing a configured argv[0] to it would invalidate that justification
    as written. This must go through toolpath.resolve (pure lookup) only."""
    root = _repo(tmp_path)
    (root / "aramid.toml").write_text(
        '[tests]\ncommand = ["some-configured-exe", "-q"]\n', encoding="utf-8")
    _shim_hooks(root)
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())
    monkeypatch.setattr(toolpath, "resolve", lambda name: None)

    def fail_if_called(name):
        raise AssertionError(f"probe_tool must never be called with external input: {name}")

    monkeypatch.setattr(doctor, "probe_tool", fail_if_called)

    doctor.cmd_doctor(root)     # must not raise via fail_if_called above


@pytest.mark.parametrize("toml_body", [
    '[tests]\ncommand = []\n',                    # empty list -> falsy, falls to detection
    '[tests]\ncommand = 42\n',                    # non-list, non-string
    '[tests]\ncommand = [123, "-q"]\n',           # list with a non-string element
    '[tests]\ncommand = "   "\n',                 # parses to an empty argv
])
def test_cmd_doctor_never_raises_on_malformed_tests_command(tmp_path, monkeypatch, toml_body):
    """`[tests].command` comes from a cloned repo's aramid.toml -- doctor
    must degrade a malformed value to a report, never an exception
    (probe_tool's own docstring says it never raises; this preserves that
    for the new test-toolchain probe too)."""
    root = _repo(tmp_path)
    (root / "aramid.toml").write_text(toml_body, encoding="utf-8")
    _shim_hooks(root)
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())

    rc = doctor.cmd_doctor(root)     # must not raise

    assert rc in (0, 2)


def test_cmd_doctor_tests_disabled_does_not_exit_2_even_with_no_tool(
        tmp_path, monkeypatch, capsys):
    """[tests].enabled = false removes the tests runner from selection
    entirely (pipeline._is_applicable) -- it can never surface as
    MISSING/degraded at the real gate, so doctor reporting exit 2 here would
    be lying in the OPPOSITE direction: the same error class this ticket
    exists to fix, just inverted."""
    root = _repo(tmp_path)
    (root / "test_something.py").write_text("def test_x():\n    assert True\n",
                                             encoding="utf-8")
    (root / "aramid.toml").write_text('[tests]\nenabled = false\n', encoding="utf-8")
    _shim_hooks(root)
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())

    def fail_if_called(name):
        raise AssertionError(f"a disabled test gate must not be probed: {name}")

    monkeypatch.setattr(doctor, "probe_tool", fail_if_called)

    rc = doctor.cmd_doctor(root)
    text = "".join(capsys.readouterr()).lower()

    assert rc == 0
    assert "disabled" in text


# --- [review] doctor must not crash on a malformed aramid.toml --------------
# config_mod.load_config(root) was unguarded: a real TOMLDecodeError from
# aramid.toml's own SYNTAX (not just a malformed [tests].command VALUE, which
# _configured_argv0 already handled) raised straight through cmd_doctor, with
# zero output and no dispatch-level handler in cli.main to catch it. A broken
# config is exactly when an operator reaches for `doctor`.

@pytest.mark.parametrize("label,toml_body", [
    ("unclosed string", 'name = "unterminated\n'),
    ("bad table header", '[tests\ncommand = ["pytest"]\n'),
    ("duplicate key", 'schema_version = 1\nschema_version = 2\n'),
])
def test_cmd_doctor_never_raises_on_unparseable_aramid_toml(
        tmp_path, monkeypatch, capsys, label, toml_body):
    """Red-first per shape: each of these raised tomllib.TOMLDecodeError
    straight out of cmd_doctor before the fix. After the fix: readable
    output naming the unparseable config, no traceback, the rest of the
    probe (tools/interpreter/providers/autolearn) still runs, and a DISTINCT
    exit code from 2 (BLOCK-tier tool missing) -- these are different
    problems with different remedies."""
    root = _repo(tmp_path)
    (root / "aramid.toml").write_text(toml_body, encoding="utf-8")
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())

    rc = doctor.cmd_doctor(root)     # must not raise, label=label
    text = "".join(capsys.readouterr())

    assert rc == 3, label
    assert "aramid.toml" in text, label
    assert rc != 2, f"{label}: must not be conflated with BLOCK-tier-tool-missing"
    # the rest of the probe still ran and printed, config error notwithstanding
    assert "gitleaks" in text, label
    assert "llm providers:" in text, label


# --- B (graphite round 14): doctor must not report green while the only ---
# supply-chain gate on a Rust repo is absent ---------------------------------
#
# `ALL_TOOLS` covers gitleaks/semgrep/ruff/pip-audit, so on a Cargo workspace
# cargo-audit could be SELECTED by the gate, MISSING at run time, and doctor
# still print a clean bill of health -- the same "control that looks like
# coverage and is not" shape as the cargo-audit severity bug. Probed like
# `probe_tests` (stack-conditional, outside ALL_TOOLS so `--fix` never tries
# to install it), but unlike tests it must NEVER affect the exit code: `deps`
# is not in pipeline.BLOCK_TIER_KEYS, so a missing cargo-audit cannot fail a
# gate and must not fail doctor either. Report, do not block.

def test_probe_deps_reports_cargo_audit_on_a_cargo_workspace(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    (root / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
    monkeypatch.setattr(doctor.toolpath, "resolve",
                        lambda name: f"/fake/{name}" if name == "cargo-audit" else None)

    statuses = doctor.probe_deps(root)

    assert [s.name for s in statuses] == ["cargo-audit"]
    assert statuses[0].present is True


def test_probe_deps_reports_absent_cargo_audit_rather_than_staying_silent(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    (root / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
    monkeypatch.setattr(doctor.toolpath, "resolve", lambda name: None)

    statuses = doctor.probe_deps(root)

    assert [s.name for s in statuses] == ["cargo-audit"]
    assert statuses[0].present is False
    assert statuses[0].detail, "an absent supply-chain gate must say why it matters"


def test_probe_deps_is_silent_on_a_repo_with_no_cargo_lock(tmp_path):
    # No false alarm on Python/JS repos -- cargo-audit is not selected there.
    assert doctor.probe_deps(_repo(tmp_path)) == []


def test_missing_cargo_audit_does_not_change_doctor_exit_code(tmp_path, monkeypatch, capsys):
    """deps is not BLOCK-tier, so its absence cannot fail a gate -- doctor
    must report it without inventing a failure the gate would never produce."""
    root = _repo(tmp_path)
    (root / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
    monkeypatch.setattr(doctor, "probe_toolchain", lambda r: _all_present())
    monkeypatch.setattr(doctor.toolpath, "resolve", lambda name: None)

    code = doctor.cmd_doctor(root)
    out = capsys.readouterr().out

    assert "cargo-audit" in out, "doctor must name the tool it did not find"
    assert code == 0, "a missing non-BLOCK-tier deps tool must not fail doctor"


# --- doctor must not report a green test toolchain it never probed ----------
#
# Measured on synthetic Rust and Go repos, both carrying a real working suite:
# doctor printed `OK tests (no test suite detected -- nothing to probe)` and
# `all BLOCK-tier tools present.`, exiting 0 -- while `tests` is BLOCK-tier
# and `detect_tests` recognizes only a pytest-shaped file or an npm `test`
# script, so `cargo test`/`go test` are invisible to it. This module's own
# header docstring names that exact failure ("doctor could print 'all
# BLOCK-tier tools present' and exit 0 on a repo whose test tool is absent"),
# but only the detected-kind-with-missing-tool case was ever closed.
#
# Report, do not block -- the same rule as cargo-audit above. A repo may
# legitimately have no tests; what it may not do is read as covered.

def test_probe_tests_does_not_report_OK_when_it_probed_nothing(tmp_path):
    root = _repo(tmp_path)
    statuses = doctor.probe_tests(root, config_mod.load_config(root))

    assert len(statuses) == 1
    line = doctor._report_line(statuses[0])
    assert not line.lstrip().startswith("OK"), (
        f"a tier that was never probed rendered as OK: {line!r}")


def test_a_repo_with_no_detectable_suite_is_told_the_gate_runs_nothing(
        tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    monkeypatch.setattr(doctor, "probe_toolchain", lambda r: _all_present())

    doctor.cmd_doctor(root)
    cap = capsys.readouterr()
    both = cap.out + cap.err

    assert "BLOCK-tier" in both and "tests" in both
    assert "[tests].command" in both, "the remedy must be named"
    assert "enabled" in both, "the opt-out must be named too"


def test_no_detectable_suite_does_not_change_doctor_exit_code(
        tmp_path, monkeypatch, capsys):
    """Report, do not block. A docs or config repo genuinely has no suite;
    inventing a failure doctor's own gate would never produce would make
    `doctor` useless in exactly the repos most likely to run it first."""
    root = _repo(tmp_path)
    monkeypatch.setattr(doctor, "probe_toolchain", lambda r: _all_present())

    code = doctor.cmd_doctor(root)
    capsys.readouterr()

    assert code == 0


# --- an EDITABLE live install with registered repos is a failure -----------
#
# `install_mode_lines` reports an editable aramid and, on its own, never
# fails: an operator with an editable install and NO consumers is doing
# something legitimate. The moment a repo is registered that stops being
# true -- its hooks run `python -P -m aramid`, which resolves to the live
# install, which is this working tree, uncommitted edits included. That is
# the state every consumer's gate is compromised in, and `doctor` answering
# 0 to it was a false green light of exactly the kind its `unenforced`
# branch already refuses to give. Ledger 53073121 / 02e89b6e.
#
# Both inputs are seamed: the probe (`_installed_direct_url`) because CI
# installs this checkout editable and would otherwise decide these tests
# by its own install mode, and the registry via the autouse isolation.

_EDITABLE_DIRECT_URL = ('{"url": "file:///F:/Projects/aramid", '
                        '"dir_info": {"editable": true}}')
_WHEEL_DIRECT_URL = ('{"url": "file:///tmp/aramid-0.5.1-py3-none-any.whl", '
                     '"archive_info": {"hash": "sha256=abc"}}')


def _register(tmp_path, *names):
    from aramid import registry
    for name in names:
        p = tmp_path / name
        p.mkdir(exist_ok=True)
        registry.register(p, "2026-08-28T00:00:00+00:00")


def test_editable_install_with_registered_repos_returns_2_and_names_the_remedy(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(doctor, "probe_toolchain", lambda r: _all_present())
    monkeypatch.setattr(doctor, "_installed_direct_url", lambda: _EDITABLE_DIRECT_URL)
    _register(tmp_path, "consumer-a", "consumer-b")

    rc = doctor.cmd_doctor(_repo(tmp_path))
    out = capsys.readouterr()

    assert rc == 2
    assert "EDITABLE" in out.out, "the advisory notice still prints"
    assert ("aramid: doctor: aramid is installed EDITABLE while 2 registered "
            "repo(s) run it") in out.err
    assert "promote_live.py" in out.err, "the remedy is named, not implied"


def test_editable_install_with_nothing_registered_stays_advisory(
        tmp_path, monkeypatch, capsys):
    """The docstring's own words: no consumers, nothing compromised."""
    monkeypatch.setattr(doctor, "probe_toolchain", lambda r: _all_present())
    monkeypatch.setattr(doctor, "_installed_direct_url", lambda: _EDITABLE_DIRECT_URL)

    rc = doctor.cmd_doctor(_repo(tmp_path))
    out = capsys.readouterr()

    assert rc == 0
    assert "EDITABLE" in out.out
    assert "registered" not in out.err


def test_a_promoted_wheel_with_registered_repos_is_not_flagged(
        tmp_path, monkeypatch, capsys):
    """The promoted state -- `archive_info`, no `dir_info` -- with consumers
    is exactly what the machine should look like."""
    monkeypatch.setattr(doctor, "probe_toolchain", lambda r: _all_present())
    monkeypatch.setattr(doctor, "_installed_direct_url", lambda: _WHEEL_DIRECT_URL)
    _register(tmp_path, "consumer-a")

    rc = doctor.cmd_doctor(_repo(tmp_path))
    out = capsys.readouterr()

    assert rc == 0
    assert "EDITABLE" not in out.out + out.err


def test_the_repo_being_doctored_counts_as_a_registered_consumer(
        tmp_path, monkeypatch, capsys):
    """Registering only the checkout itself still fails. Its own hooks run
    the live install too, and an editable live install makes them gate the
    working tree with the working tree -- the state this repo's own history
    calls a hazard, not a dogfooding convenience."""
    monkeypatch.setattr(doctor, "probe_toolchain", lambda r: _all_present())
    monkeypatch.setattr(doctor, "_installed_direct_url", lambda: _EDITABLE_DIRECT_URL)
    root = _repo(tmp_path)
    from aramid import registry
    registry.register(root, "2026-08-28T00:00:00+00:00")

    rc = doctor.cmd_doctor(root)
    out = capsys.readouterr()

    assert rc == 2
    assert "while 1 registered repo(s) run it" in out.err


# --- relocated shims: doctor REPORTS a stale one and never rewrites it ---------
# Interop round 112 gave `install()` the refresh: when another managing tool
# occupies a hook slot, aramid's own shim survives relocated beside it and
# `install()` regenerates that sibling in place, naming it "STALE" only when
# the write is refused. But `install()` is a write; the read-only surfaces
# (`doctor`, and `status` through it) said nothing, so a pre-`-P` relocated
# shim was invisible to every command that does not rewrite hooks -- and
# `probe_enforcement` is quiet too, because the slot itself EXISTS.

_FOREIGN_SLOT = (b"#!/bin/sh\n# >>> graphite managed >>>\necho gt\n"
                 b"# <<< graphite managed <<<\n")
_INTERP = Path("C:/py/python.exe")


def _foreign_managed(tmp_path, relocated: bytes | None):
    from aramid import hooks
    root = _onboarded(tmp_path, with_shim=True)
    hdir = hooks.hooks_dir(root)
    (hdir / "pre-commit").write_bytes(_FOREIGN_SLOT)
    if relocated is not None:
        (hdir / "pre-commit.local").write_bytes(relocated)
    return root, hdir


def test_doctor_reports_a_stale_relocated_shim_and_leaves_it_alone(tmp_path, monkeypatch, capsys):
    from aramid import hooks
    from aramid.models import Gate
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())
    stale = hooks.render_shim(Gate.PRE_COMMIT, _INTERP).replace(b" -P -m aramid", b" -m aramid")
    root, hdir = _foreign_managed(tmp_path, stale)

    rc = doctor.cmd_doctor(root)
    out = capsys.readouterr()
    blob = out.out + out.err

    assert rc == 2, "a stale relocated shim means the gate is not what init would install"
    assert "STALE" in blob and "pre-commit.local" in blob
    assert "aramid init" in blob, "must say how to regenerate it"
    assert (hdir / "pre-commit.local").read_bytes() == stale, "doctor is read-only"
    assert (hdir / "pre-commit").read_bytes() == _FOREIGN_SLOT


def test_doctor_is_quiet_about_a_current_relocated_shim(tmp_path, monkeypatch, capsys):
    """The counterfactual: proves the flag keys on the BYTES differing, not
    on the slot being foreign-managed."""
    from aramid import hooks
    from aramid.models import Gate
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())
    root, _ = _foreign_managed(tmp_path, hooks.render_shim(Gate.PRE_COMMIT, _INTERP))

    rc = doctor.cmd_doctor(root)
    out = capsys.readouterr()
    blob = out.out + out.err

    assert rc == 0
    assert "STALE" not in blob and "NOT running" not in blob


def test_doctor_flags_a_foreign_managed_slot_with_no_surviving_relocation(tmp_path, monkeypatch, capsys):
    """`probe_enforcement` sees a slot that exists and says nothing, yet
    aramid's gate is not running at all: the other tool's trampoline chains
    to a file that is not there. `init` catches this at onboarding; doctor
    has to catch it afterwards."""
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())
    root, _ = _foreign_managed(tmp_path, None)

    rc = doctor.cmd_doctor(root)
    out = capsys.readouterr()
    blob = out.out + out.err

    assert rc == 2
    assert "NOT running" in blob and "graphite" in blob and "pre-commit" in blob


# --- pip-audit: PRESENT is not RUNNING ---------------------------------------
# Interop round 149 s2: `doctor` printed `OK  pip-audit` on two machines while
# no gate run had ever emitted it -- the deps runner audits requirements*.txt
# at the repo root and nothing else, so a pyproject-only Python repo is never
# audited, and nothing said so. Same "control that looks like coverage and is
# not" shape as the cargo-audit case above. Report, do not block.

def test_probe_deps_stays_quiet_when_the_pyproject_has_a_project_table(tmp_path, monkeypatch):
    # A [project] table is a dependency source pip-audit can audit directly
    # (project-path mode), so the "does NOT run" note would now be a lie.
    root = _repo(tmp_path)
    (root / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    monkeypatch.setattr(doctor.toolpath, "resolve", lambda name: None)

    assert doctor.probe_deps(root) == []


def test_probe_deps_says_pip_audit_does_not_run_on_a_tool_only_pyproject(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    (root / "pyproject.toml").write_text("[tool.ruff]\nline-length = 100\n", encoding="utf-8")
    monkeypatch.setattr(doctor.toolpath, "resolve", lambda name: None)

    statuses = doctor.probe_deps(root)

    assert [s.name for s in statuses] == ["pip-audit"]
    assert statuses[0].warn is True
    assert "[project]" in statuses[0].detail and "does NOT run" in statuses[0].detail


def test_probe_deps_stays_quiet_about_pip_audit_when_a_requirements_file_exists(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    (root / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    (root / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
    monkeypatch.setattr(doctor.toolpath, "resolve", lambda name: None)

    assert doctor.probe_deps(root) == []


def test_pip_audit_applicability_note_does_not_change_doctor_exit_code(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())
    root = _onboarded(tmp_path, with_shim=True)
    # A tool-only pyproject: the one Python shape the audit still cannot cover.
    (root / "pyproject.toml").write_text("[tool.ruff]\nline-length = 100\n", encoding="utf-8")

    rc = doctor.cmd_doctor(root)
    out = capsys.readouterr()

    assert rc == 0
    assert "pip-audit" in out.out and "does NOT run" in out.out


def test_probe_tests_resolves_a_repo_relative_command_from_a_foreign_cwd(
        tmp_path, monkeypatch):
    """doctor and the drain must agree on whether `[tests].command` resolves.
    Interop round 174: the drain said MISSING for a repo-relative interpreter
    that doctor, run from the repo root, called present. Both now anchor a
    relative argv[0] to the repo, so the verdict no longer depends on cwd."""
    root = _repo(tmp_path)
    d = root / "tools"
    d.mkdir()
    p = d / ("py.cmd" if sys.platform == "win32" else "py")
    p.write_text("@echo off\r\n" if sys.platform == "win32" else "#!/bin/sh\n",
                 encoding="utf-8")
    if sys.platform != "win32":
        p.chmod(0o755)
    (root / "aramid.toml").write_text(
        f'schema_version = 1\n[tests]\ncommand = ["tools/{p.name}", "-m", "pytest"]\n',
        encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    statuses = doctor.probe_tests(root, config_mod.load_config(root))

    assert len(statuses) == 1
    assert statuses[0].present, statuses[0].detail
