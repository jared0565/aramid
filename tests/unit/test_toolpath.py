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
import ast
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from aramid import gitutil, toolpath
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


def test_fake_tool_hard_links_rather_than_writing_a_new_executable(
        tmp_path, fake_tool_source):
    """Guards the actual fix, which is otherwise invisible: every assertion
    above passes just as well with four fresh interpreter copies, so nothing
    else here would notice a revert to `shutil.copy(sys.executable, ...)`
    per test.

    [Rewritten immediately after being written -- aramid's own red-proof
    consumer flagged this test, correctly.] The first version branched on
    `after == before` and asserted only a size match in that branch, i.e. it
    PASSED whether a link or a copy happened. It could not fail, which makes
    it exactly the defect it was written to prevent: a check indistinguishable
    from one that never ran.

    Hard-link support is now established by an INDEPENDENT probe on the same
    filesystem, never inferred from the outcome under test -- otherwise the
    fallback and the regression are the same observation. `tmp_path` and
    `fake_tool_source` both live under `tmp_path_factory`'s root, so a probe
    here is representative of the link the helper actually attempts.

    Deliberately asserts a DETERMINISTIC property (st_nlink on the shared
    inode) rather than a duration -- a wall-clock threshold is what made
    test_pipeline's hung-runner guard flaky.
    """
    assert fake_tool_source.is_file()
    assert fake_tool_source.stat().st_size == os.path.getsize(sys.executable)

    probe = tmp_path / "link-probe"
    probe.write_bytes(b"x")
    try:
        os.link(probe, tmp_path / "link-probe-alias")
        links_supported = True
    except OSError:
        links_supported = False

    before = fake_tool_source.stat().st_nlink
    dst = _fake_tool(tmp_path / "tools", "linkprobe", fake_tool_source)
    after = fake_tool_source.stat().st_nlink

    assert dst.is_file()
    if not links_supported:
        pytest.skip("no hard-link support on this filesystem -- _fake_tool's "
                    "copy fallback is the correct behaviour here, and this "
                    "test has nothing left to prove")
    assert after == before + 1, (
        "expected exactly one new hard link to the session's tool source; "
        f"st_nlink went {before} -> {after}, which means a fresh executable "
        "was written per test again")


def test_resolve_returns_an_absolute_path_for_a_relative_hit(tmp_path, monkeypatch):
    """A relative argv[0] that resolves against the cwd used to come back
    relative, and `run_subprocess` then launched it with a DIFFERENT cwd
    (the mutation worktree), where it no longer resolved -- despite the
    comment there promising an absolute launch. Absolutize at resolution.
    (interop round 174)"""
    d = tmp_path / "tools"
    d.mkdir()
    p = d / ("py.cmd" if os.name == "nt" else "py")
    p.write_text("@echo off\r\n" if os.name == "nt" else "#!/bin/sh\n", encoding="utf-8")
    if os.name != "nt":
        p.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    got = toolpath.resolve("tools/" + p.name)
    assert got is not None
    assert got.is_absolute(), f"relative hit returned relative: {got}"
    assert got == p.resolve()


# --- a bare name is never answered from the current directory (FN-46) -----
#
# aramid's current directory is the repo it is judging. Windows looks there
# before PATH, and an empty PATH entry does the same elsewhere, so a
# `gitleaks.bat` in a repo's root was started in place of gitleaks.

_PROBE = "aramid-fn46-probe"


def _program(directory, name=_PROBE):
    """A file the platform's lookup takes for the program `name`: `name.cmd`
    on Windows, `name` with its x bit anywhere else."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (f"{name}.cmd" if os.name == "nt" else name)
    path.write_text("@echo off\r\n" if os.name == "nt" else "#!/bin/sh\n", encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o755)
    return path


@pytest.fixture
def looked_in(tmp_path, monkeypatch):
    """A process whose lookups reach the current directory, the way this
    platform lets them: on Windows NoDefaultCurrentDirectoryInExePath is not
    set, which is the default; elsewhere PATH starts with an empty entry.
    Nothing aramid manages holds the probe. Returns the current directory and
    a directory that PATH names."""
    here, on_path = tmp_path / "repo", tmp_path / "bin"
    here.mkdir()
    on_path.mkdir()
    monkeypatch.chdir(here)
    monkeypatch.delenv("NoDefaultCurrentDirectoryInExePath", raising=False)
    front = "" if os.name == "nt" else os.pathsep
    monkeypatch.setenv("PATH", f"{front}{on_path}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setattr(toolpath, "tools_dir", lambda: tmp_path / "no-tools")
    monkeypatch.setattr(toolpath, "scripts_dirs", lambda: [])
    return here, on_path


def test_a_file_of_the_tools_name_in_the_current_directory_is_not_the_tool(looked_in):
    here, on_path = looked_in
    planted, real = _program(here), _program(on_path)

    # The hazard is live in this process: the standard lookup answers with
    # the file in the current directory. Without this line the two below
    # could pass on a machine where nothing ever looked there.
    assert os.path.samefile(shutil.which(_PROBE), planted)
    assert os.path.samefile(toolpath.which(_PROBE), real)
    assert os.path.samefile(toolpath.resolve(_PROBE), real)


def test_with_the_tool_on_no_path_the_file_in_the_current_directory_is_still_not_it(
        looked_in):
    here, _on_path = looked_in
    planted = _program(here)

    assert os.path.samefile(shutil.which(_PROBE), planted)
    assert toolpath.which(_PROBE) is None
    assert toolpath.resolve(_PROBE) is None
    res = run_subprocess([_PROBE], here, 60)
    assert res.state is ToolState.MISSING


def test_a_file_named_exactly_as_the_tool_is_not_handed_through_as_a_path(
        tmp_path, monkeypatch):
    """`Path("gitleaks")` names a file of the current directory. A bare name
    is a program to look up, never that file -- on any platform, executable
    or not."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(toolpath, "tools_dir", lambda: tmp_path / "no-tools")
    monkeypatch.setattr(toolpath, "scripts_dirs", lambda: [])
    (tmp_path / _PROBE).write_text("#!/bin/sh\n", encoding="utf-8")

    assert toolpath.resolve(_PROBE) is None
    # A name that carries a directory is a path, and is still handed through.
    assert toolpath.resolve(f"./{_PROBE}") == (tmp_path / _PROBE).resolve()


def test_the_current_directory_is_looked_in_where_path_names_it(looked_in, monkeypatch):
    """`.` on PATH is the operator's own choice, as any PATH entry is."""
    here, _on_path = looked_in
    planted = _program(here)
    monkeypatch.setenv("PATH", os.curdir + os.pathsep + os.environ["PATH"])

    assert os.path.samefile(toolpath.which(_PROBE), planted)


def test_path_is_walked_in_order_past_what_is_no_program(tmp_path, monkeypatch):
    """`_on_path`: the first PATH entry that holds the program as a file
    wins. An empty entry names no directory -- not the current one, which
    holds the program here -- and a directory of the program's name is not
    the program."""
    first, second, third = tmp_path / "a", tmp_path / "b", tmp_path / "c"
    first.mkdir()
    _program(tmp_path)
    blocker = _program(second)
    blocker.unlink()
    blocker.mkdir()
    real = _program(third)
    _program(tmp_path / "d")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", os.pathsep.join(
        ["", str(first), str(second), str(third), str(tmp_path / "d")]))

    assert os.path.samefile(toolpath._on_path(_PROBE), real)
    assert toolpath._on_path("aramid-fn46-nothing") is None


@pytest.mark.skipif(os.name == "nt", reason="Windows has no x bit: every file may be run")
def test_a_file_that_may_not_be_run_is_not_the_program(tmp_path, monkeypatch):
    plain = _program(tmp_path / "a")
    plain.chmod(0o644)
    real = _program(tmp_path / "b")
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "a"), str(tmp_path / "b")]))

    assert os.path.samefile(toolpath._on_path(_PROBE), real)


def test_the_names_a_program_may_have_in_a_directory(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("PATHEXT", ".COM;.EXE;;.CMD")
    assert toolpath._spellings("ruff") == ["ruff.COM", "ruff.EXE", "ruff.CMD"]
    # A name that already ends in one of them is tried as it is, first.
    assert toolpath._spellings("ruff.exe") == [
        "ruff.exe", "ruff.exe.COM", "ruff.exe.EXE", "ruff.exe.CMD"]
    for unset in ("", None):
        if unset is None:
            monkeypatch.delenv("PATHEXT")
        else:
            monkeypatch.setenv("PATHEXT", unset)
        assert toolpath._spellings("ruff") == ["ruff.COM", "ruff.EXE", "ruff.BAT", "ruff.CMD"]
    monkeypatch.setattr(sys, "platform", "linux")
    assert toolpath._spellings("ruff.exe") == ["ruff.exe"]


def test_a_name_with_a_directory_is_no_path_lookup(tmp_path, monkeypatch):
    """`./py` names a file where the caller says it is. It is asked of
    `shutil.which` as it stands and is not looked for along PATH."""
    planted = _program(tmp_path, "py")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path / "nowhere"))

    assert os.path.samefile(toolpath.which(f"./{planted.name}"), planted)


def test_a_stand_in_answer_that_names_no_file_is_passed_on(tmp_path, monkeypatch):
    """Tests stand in for the lookup with an answer such as `C:\\bin\\claude.exe`,
    which on another platform reads as a bare file name. It is a hit in the
    current directory only when something of that name is there."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: "C:\\bin\\claude.exe")
    assert toolpath.which("claude") == "C:\\bin\\claude.exe"
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: "stand-in.cmd")
    assert toolpath.which("stand-in") == "stand-in.cmd"


def test_a_hit_outside_the_current_directory_is_the_answer(tmp_path, monkeypatch):
    """Only a hit that lies in the current directory is asked again of PATH.
    Any other is the platform's own answer and is kept as it is."""
    real = _program(tmp_path / "elsewhere")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path / "nowhere"))
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: str(real))

    assert toolpath.which(_PROBE) == str(real)


# --- a launch never names its program by a bare word (FN-47) --------------
#
# `subprocess.run(["git", ...])` asks no lookup of aramid's: the system finds
# the program, and on Windows it looks in the current directory before
# System32 and PATH. `toolpath.program` finds it first, and the launch is
# made by the absolute path.

def _launch_file(directory, name=_PROBE):
    """A file that a launch of the bare `name` would start from `directory`:
    `name.exe` on Windows (CreateProcess adds `.exe` and nothing else), `name`
    with its x bit anywhere else. `program` looks and does not start, so the
    file is empty."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / toolpath.exe_name(name)
    path.write_bytes(b"")
    path.chmod(0o755)
    return path


def test_a_bare_launch_starts_the_file_in_the_current_directory_and_ours_does_not(
        looked_in, fake_tool_source):
    here, _on_path = looked_in
    _fake_tool(here, _PROBE, fake_tool_source)

    # The hazard, live in this process: a launch by the bare name starts the
    # copy of the interpreter that lies in the current directory.
    control = subprocess.run([_PROBE, "--version"], capture_output=True, text=True)
    assert control.returncode == 0
    assert "Python" in control.stdout + control.stderr

    with pytest.raises(FileNotFoundError):
        subprocess.run(toolpath.launchable([_PROBE, "--version"]), capture_output=True)


def test_a_git_in_the_current_directory_is_not_the_git_aramid_runs(looked_in, fake_tool_source):
    """What FN-47 is about, end to end: every gate asks git first, with the
    repo as its current directory."""
    here, _on_path = looked_in
    _fake_tool(here, "git", fake_tool_source)

    control = subprocess.run(["git", "--version"], capture_output=True, text=True)
    assert "Python" in control.stdout + control.stderr, "the planted copy did not run"

    answer = gitutil._run(here, "--version")
    assert (answer.returncode, answer.stdout[:12]) == (0, "git version ")


def test_git_is_handed_to_the_system_by_its_absolute_path(tmp_path, monkeypatch):
    seen = []

    class Stop(Exception):
        pass

    def popen(argv, **kw):
        seen.append(argv)
        raise Stop
    monkeypatch.setattr(subprocess, "Popen", popen)

    with pytest.raises(Stop):
        gitutil._run(tmp_path, "status", "--porcelain")

    assert seen == [toolpath.launchable(["git", "status", "--porcelain"])]
    assert os.path.isabs(seen[0][0])


def test_a_program_is_found_along_path_and_named_in_full(tmp_path, monkeypatch):
    """The first PATH directory that holds it. The empty entry names none:
    not the current directory, which holds the program here."""
    (tmp_path / "a").mkdir()
    _launch_file(tmp_path)
    real = _launch_file(tmp_path / "b")
    _launch_file(tmp_path / "c")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", os.pathsep.join(
        ["", str(tmp_path / "a"), str(tmp_path / "b"), str(tmp_path / "c")]))

    got = toolpath.program(_PROBE)

    assert os.path.isabs(got)
    assert os.path.samefile(got, real)
    assert toolpath.launchable([_PROBE, "-q", "x"]) == [got, "-q", "x"]

    # A PATH entry that is relative is the operator's own; the answer is in
    # full all the same, so a child started in another directory finds it.
    monkeypatch.setenv("PATH", "b")
    assert toolpath.program(_PROBE) == os.path.abspath(os.path.join("b", real.name))


def test_a_program_that_is_nowhere_is_named_where_it_was_looked_for_first(looked_in):
    """Never the bare name, which the system would look for in the current
    directory: a path that is not there, so the launch fails as a missing
    program does."""
    here, _on_path = looked_in
    _launch_file(here)

    got = toolpath.program(_PROBE)

    assert os.path.isabs(got)
    assert not os.path.exists(got)
    assert got == os.path.abspath(
        os.path.join(toolpath._launch_dirs()[0], toolpath.exe_name(_PROBE)))
    assert not os.path.samefile(os.path.dirname(got), here)


def test_a_directory_of_the_programs_name_is_not_the_program(tmp_path, monkeypatch):
    blocker = _launch_file(tmp_path / "a")
    blocker.unlink()
    blocker.mkdir()
    real = _launch_file(tmp_path / "b")
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "a"), str(tmp_path / "b")]))

    assert os.path.samefile(toolpath.program(_PROBE), real)


@pytest.mark.skipif(os.name == "nt", reason="Windows has no x bit: every file may be run")
def test_a_file_that_may_not_be_run_is_not_what_a_launch_starts(tmp_path, monkeypatch):
    plain = _launch_file(tmp_path / "a")
    plain.chmod(0o644)
    real = _launch_file(tmp_path / "b")
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "a"), str(tmp_path / "b")]))

    assert os.path.samefile(toolpath.program(_PROBE), real)


def test_where_a_bare_name_is_looked_for(monkeypatch):
    # Python's default path leads with `.` on Windows. Here it does everywhere.
    monkeypatch.setattr(os, "defpath", os.pathsep.join([os.curdir, "/d", "", "/e"]))
    defaults = ["/d", "/e"]
    monkeypatch.setenv("PATH", os.pathsep.join(["", "/a", "", "/b"]))
    monkeypatch.setattr(sys, "platform", "linux")
    assert toolpath._path_dirs() == ["/a", "/b"]
    assert toolpath._launch_dirs() == ["/a", "/b"]

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("SystemRoot", "/win")
    assert toolpath._launch_dirs() == [os.path.join("/win", "System32"), "/a", "/b"]
    for unset in ("", None):
        if unset is None:
            monkeypatch.delenv("SystemRoot")
        else:
            monkeypatch.setenv("SystemRoot", unset)
        assert toolpath._launch_dirs() == [os.path.join("C:\\Windows", "System32"), "/a", "/b"]

    # A PATH that names no directory, or no PATH at all: the default one,
    # and never the current directory.
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("PATH", os.pathsep)
    assert toolpath._path_dirs() == []
    assert toolpath._launch_dirs() == defaults
    monkeypatch.delenv("PATH")
    assert toolpath._path_dirs() == defaults
    assert toolpath._launch_dirs() == defaults
    monkeypatch.setattr(sys, "platform", "win32")
    assert toolpath._launch_dirs() == [os.path.join("C:\\Windows", "System32"), *defaults]


def test_on_windows_system32_is_looked_in_before_path(tmp_path, monkeypatch):
    """As CreateProcess has them: `taskkill` is System32's, whatever PATH
    holds under that name, and `git` is PATH's. `.exe` is the one extension
    a launch adds."""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("SystemRoot", str(tmp_path / "win"))
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    system = _launch_file(tmp_path / "win" / "System32")
    on_path = _launch_file(tmp_path / "bin")
    assert (system.name, on_path.name) == (f"{_PROBE}.exe", f"{_PROBE}.exe")

    assert os.path.samefile(toolpath.program(_PROBE), system)
    system.unlink()
    assert os.path.samefile(toolpath.program(_PROBE), on_path)


def test_a_name_that_has_a_directory_is_a_path_already():
    assert toolpath.program("tools/run") == "tools/run"
    assert toolpath.launchable([sys.executable, "-c", "pass"]) == [sys.executable, "-c", "pass"]


_LAUNCHES = {"run", "Popen", "call", "check_call", "check_output", "getoutput",
             "getstatusoutput"}
# A launch whose program is not a bare word because of what happens before
# the call. Each was read: adding a line here is a claim about that code.
_RESOLVED_BEFORE = {
    # `exe` comes from `toolpath.resolve` / `toolpath.which`.
    ("commands/doctor.py", '[str(exe), "--version"]'),
    ("commands/doctor.py", '[exe, "-P", "-c", "import aramid"]'),
    # `run_subprocess` has replaced argv[0] with `toolpath.resolve`'s answer.
    ("runners/base.py", "argv"),
    # Built by a provider module from `toolpath.which`'s answer.
    ("providers/base.py", "argv"),
}


def _launches_in_src():
    """Every call in src/aramid: (file, node, what it is called on, its
    name, the file's text)."""
    src = Path(toolpath.__file__).parent
    for path in sorted(src.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(text)):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            on = func.value.id if isinstance(func, ast.Attribute) \
                and isinstance(func.value, ast.Name) else None
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            yield path.relative_to(src).as_posix(), node, on, name, text


def test_no_launch_in_aramid_names_its_program_by_a_bare_word():
    """Every `subprocess` call in src/ starts `toolpath.launchable(...)`, this
    interpreter, or a program the lines before it resolved. A new launch
    fails here until it is one of the three."""
    bare, seen = [], 0
    for rel, node, on, name, text in _launches_in_src():
        if on == "subprocess" and name in _LAUNCHES:
            seen += 1
            first = ast.get_source_segment(text, node.args[0]) if node.args else ""
            first = " ".join((first or "").split())
            if first.startswith(("toolpath.launchable(", "[sys.executable,")) \
                    or (rel, first) in _RESOLVED_BEFORE:
                continue
            bare.append(f"{rel}:{node.lineno}: {first}")
    assert seen >= 20, "the walk found too few launches to be looking at the right tree"
    assert bare == []


def test_no_launch_goes_through_a_shell_or_around_subprocess():
    """`shell=True` hands the line to cmd.exe or sh, and `os.system`,
    `os.popen`, `os.startfile` and the `os.exec*` / `os.spawn*` family find
    their program themselves. None is used; `subprocess` is not imported
    under another name either, which the test above would not see."""
    found = []
    for rel, node, on, name, _text in _launches_in_src():
        if any(k.arg == "shell" for k in node.keywords):
            found.append(f"{rel}:{node.lineno}: shell=")
        if on == "os" and (name in ("system", "popen", "startfile")
                           or name.startswith(("exec", "spawn"))):
            found.append(f"{rel}:{node.lineno}: os.{name}")
    src = Path(toolpath.__file__).parent
    for path in sorted(src.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module == "subprocess":
                found.append(f"{path.name}: from subprocess import")
            if isinstance(node, ast.Import):
                found += [f"{path.name}: import subprocess as {a.asname}"
                          for a in node.names if a.name == "subprocess" and a.asname]
    assert found == []


def test_shutil_which_is_called_in_one_place():
    """A second caller is a second lookup that answers from the current
    directory. Every other module asks `toolpath.which`."""
    callers = [rel for rel, _node, on, name, _text in _launches_in_src()
               if on == "shutil" and name == "which"]
    assert callers == ["toolpath.py"]
    src = Path(toolpath.__file__).parent
    for path in sorted(src.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            assert not (isinstance(node, ast.ImportFrom) and node.module == "shutil"
                        and any(a.name == "which" for a in node.names)), path.name
