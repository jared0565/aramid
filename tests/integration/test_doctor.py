import subprocess
import sys
from pathlib import Path

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
