"""Tool resolution must AGREE between doctor's probe and the runner.

The bug this pins: `aramid doctor --fix` downloads gitleaks into
`~/.aramid/tools/`, doctor's probe looked there and reported "OK gitleaks",
but `run_subprocess` resolved the bare name through `shutil.which` only --
which never sees that directory -- so the gate reported
"skipped (degraded tools): gitleaks" while doctor reported healthy.

An operator running the REPAIR command was told secrets were being scanned
when they were not, and CI could never catch it because CI installs gitleaks
onto the real PATH.
"""
import shutil
import sys

from aramid import toolpath
from aramid.runners.base import ToolState, run_subprocess


def _fake_tool(tools: "object", name: str):
    """A REAL executable under `name` -- a copy of this interpreter, so it
    genuinely runs and `--version` succeeds. Asserting on a non-executable
    stub would prove resolution but not usability, and usability is the
    thing that was broken."""
    tools.mkdir(parents=True, exist_ok=True)
    dst = tools / toolpath.exe_name(name)
    shutil.copy(sys.executable, dst)
    return dst


def test_resolve_prefers_path_over_the_managed_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(toolpath, "tools_dir", lambda: tmp_path / "tools")
    _fake_tool(tmp_path / "tools", "python")

    got = toolpath.resolve("python")
    assert got is not None
    # python IS on PATH here, so PATH must win -- the managed dir is a
    # fallback, never an override of the operator's own toolchain.
    assert str(got) != str(tmp_path / "tools" / toolpath.exe_name("python"))


def test_resolve_falls_back_to_the_managed_tools_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(toolpath, "tools_dir", lambda: tmp_path / "tools")
    dst = _fake_tool(tmp_path / "tools", "notonpath-xyzzy")

    assert toolpath.resolve("notonpath-xyzzy") == dst


def test_resolve_returns_none_when_the_tool_is_nowhere(tmp_path, monkeypatch):
    monkeypatch.setattr(toolpath, "tools_dir", lambda: tmp_path / "tools")
    assert toolpath.resolve("definitely-not-installed-xyzzy") is None


def test_run_subprocess_uses_a_tool_that_is_only_in_the_managed_dir(tmp_path, monkeypatch):
    """THE regression test. Before the fix this returned ToolState.MISSING."""
    monkeypatch.setattr(toolpath, "tools_dir", lambda: tmp_path / "tools")
    _fake_tool(tmp_path / "tools", "notonpath-xyzzy")

    res = run_subprocess(["notonpath-xyzzy", "--version"], tmp_path, 60)

    assert res.state is not ToolState.MISSING, \
        "runner ignored aramid's own managed toolchain"
    assert res.state is ToolState.OK


def test_still_missing_when_genuinely_absent(tmp_path, monkeypatch):
    """Counterfactual: the fix must not make everything look present."""
    monkeypatch.setattr(toolpath, "tools_dir", lambda: tmp_path / "tools")
    res = run_subprocess(["definitely-not-installed-xyzzy"], tmp_path, 60)
    assert res.state is ToolState.MISSING


def test_doctor_probe_and_runner_agree_on_gitleaks(tmp_path, monkeypatch):
    """The INVARIANT the bug violated, stated directly: if doctor reports a
    tool present, the gate must be able to run it. Any future divergence
    between the two resolution paths fails here."""
    from aramid.commands import doctor

    monkeypatch.setattr(toolpath, "tools_dir", lambda: tmp_path / "tools")
    _fake_tool(tmp_path / "tools", "gitleaks")

    located = doctor._locate_gitleaks()
    res = run_subprocess(["gitleaks", "--version"], tmp_path, 60)

    assert located is not None, "doctor could not find the managed gitleaks"
    assert res.state is not ToolState.MISSING, \
        "doctor reports gitleaks present but the runner cannot execute it"
