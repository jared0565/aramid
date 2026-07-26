import subprocess
import sys
from pathlib import Path

import pytest

from aramid import toolpath
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
