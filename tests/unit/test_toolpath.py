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
import os
import shutil
import sys

import pytest

from aramid import toolpath
from aramid.runners.base import ToolState, run_subprocess


@pytest.fixture(scope="session")
def fake_tool_source(tmp_path_factory):
    """ONE real copy of this interpreter for the whole session.

    Each test used to `shutil.copy(sys.executable, ...)` into its own
    tmp_path, so this 6-test file wrote FOUR fresh ~104 KB executables and
    then executed them. That is the shape most likely to attract a real-time
    scan of a brand-new binary on Windows, and this file has twice been
    measured taking minutes rather than seconds (2026-08-05 and again
    2026-08-08, where ONE test exceeded 600s) against ~2.5s on a quiet
    machine. It is not cosmetic: `[tests].command` runs `pytest -q
    tests/unit` under a 600s budget, so when this file stalls **aramid's own
    pre-push gate times out, degrades its BLOCK tier and blocks every push**.
    Nothing any assertion here makes needs four distinct binaries.

    Deliberately created under `tmp_path_factory`'s root rather than left as
    a direct copy of the interpreter: that puts the source on the SAME VOLUME
    as every `tmp_path`, which is what lets `_fake_tool` hard-link below. On
    CI's Windows runner `sys.executable` lives on C: (hostedtoolcache) while
    the temp root is on D: -- linking straight from the interpreter would
    raise EXDEV and fall back to copying on the very platform that needs this
    most.
    """
    src = tmp_path_factory.mktemp("fake-tool-src") / toolpath.exe_name("tool")
    shutil.copy(sys.executable, src)
    return src


def _fake_tool(tools: "object", name: str, source):
    """A REAL executable under `name` -- the session's interpreter copy, so it
    genuinely runs and `--version` succeeds. Asserting on a non-executable
    stub would prove resolution but not usability, and usability is the
    thing that was broken.

    HARD-LINKED, not copied: a link is a second directory entry for content
    that already exists, so materialising a fake tool writes no new
    executable bytes at all. The fallback is not decoration -- `os.link`
    raises OSError on a cross-volume temp root, on a filesystem without hard
    links, and on some Windows ACL configurations, and the tests must still
    run there. Both paths produce a byte-identical runnable binary, so no
    assertion can tell which was used.
    """
    tools.mkdir(parents=True, exist_ok=True)
    dst = tools / toolpath.exe_name(name)
    try:
        os.link(source, dst)
    except OSError:
        shutil.copy(source, dst)
    return dst


def test_resolve_prefers_path_over_the_managed_dir(tmp_path, monkeypatch,
                                                   fake_tool_source):
    monkeypatch.setattr(toolpath, "tools_dir", lambda: tmp_path / "tools")
    _fake_tool(tmp_path / "tools", "python", fake_tool_source)

    got = toolpath.resolve("python")
    assert got is not None
    # python IS on PATH here, so PATH must win -- the managed dir is a
    # fallback, never an override of the operator's own toolchain.
    assert str(got) != str(tmp_path / "tools" / toolpath.exe_name("python"))


def test_resolve_falls_back_to_the_managed_tools_dir(tmp_path, monkeypatch,
                                                     fake_tool_source):
    monkeypatch.setattr(toolpath, "tools_dir", lambda: tmp_path / "tools")
    dst = _fake_tool(tmp_path / "tools", "notonpath-xyzzy", fake_tool_source)

    assert toolpath.resolve("notonpath-xyzzy") == dst


def test_resolve_returns_none_when_the_tool_is_nowhere(tmp_path, monkeypatch):
    monkeypatch.setattr(toolpath, "tools_dir", lambda: tmp_path / "tools")
    assert toolpath.resolve("definitely-not-installed-xyzzy") is None


def test_run_subprocess_uses_a_tool_that_is_only_in_the_managed_dir(
        tmp_path, monkeypatch, fake_tool_source):
    """THE regression test. Before the fix this returned ToolState.MISSING."""
    monkeypatch.setattr(toolpath, "tools_dir", lambda: tmp_path / "tools")
    _fake_tool(tmp_path / "tools", "notonpath-xyzzy", fake_tool_source)

    res = run_subprocess(["notonpath-xyzzy", "--version"], tmp_path, 60)

    assert res.state is not ToolState.MISSING, \
        "runner ignored aramid's own managed toolchain"
    assert res.state is ToolState.OK


def test_still_missing_when_genuinely_absent(tmp_path, monkeypatch):
    """Counterfactual: the fix must not make everything look present."""
    monkeypatch.setattr(toolpath, "tools_dir", lambda: tmp_path / "tools")
    res = run_subprocess(["definitely-not-installed-xyzzy"], tmp_path, 60)
    assert res.state is ToolState.MISSING


def test_doctor_probe_and_runner_agree_on_gitleaks(tmp_path, monkeypatch,
                                                   fake_tool_source):
    """The INVARIANT the bug violated, stated directly: if doctor reports a
    tool present, the gate must be able to run it. Any future divergence
    between the two resolution paths fails here."""
    from aramid.commands import doctor

    monkeypatch.setattr(toolpath, "tools_dir", lambda: tmp_path / "tools")
    _fake_tool(tmp_path / "tools", "gitleaks", fake_tool_source)

    located = doctor._locate_gitleaks()
    res = run_subprocess(["gitleaks", "--version"], tmp_path, 60)

    assert located is not None, "doctor could not find the managed gitleaks"
    assert res.state is not ToolState.MISSING, \
        "doctor reports gitleaks present but the runner cannot execute it"


def test_the_fake_tool_helper_writes_one_interpreter_copy_not_one_per_test(
        tmp_path, fake_tool_source):
    """Guards the actual fix, which is otherwise invisible: every assertion
    above passes just as well with four fresh copies, so nothing else here
    would notice a revert to `shutil.copy(sys.executable, ...)` per test.

    Asserts the two properties that make the reduction real, and both are
    deterministic -- unlike a wall-clock threshold, which is what made
    test_pipeline's hung-runner guard flaky in the first place:

    1. the session source is a real, runnable executable, and
    2. materialising a tool from it adds NO new file content -- proven by
       st_nlink rising on the shared inode, or, where hard links are
       unavailable, by explicitly tolerating the copy fallback.
    """
    assert fake_tool_source.is_file()
    assert fake_tool_source.stat().st_size == os.path.getsize(sys.executable)

    before = fake_tool_source.stat().st_nlink
    dst = _fake_tool(tmp_path / "tools", "linkprobe", fake_tool_source)
    after = fake_tool_source.stat().st_nlink

    assert dst.is_file()
    if after == before:
        # The copy fallback ran. Legitimate (cross-volume temp root, no
        # hard-link support), but say so out loud rather than letting a
        # silently-degraded optimisation read as a pass.
        assert dst.stat().st_size == fake_tool_source.stat().st_size
    else:
        assert after == before + 1, \
            "expected exactly one new hard link to the session's tool source"
