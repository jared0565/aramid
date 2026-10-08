import subprocess
import sys
import time

import pytest

from aramid.runners import base
from types import SimpleNamespace
from aramid.runners.base import (CONTENT_UNREADABLE, run_subprocess, ToolState,
                                  scanned_line_reader)


# ------------------------------------------- scanned_line_reader (R77-3) ----
# The fingerprint fix depends on reading back the line a runner scanned. A
# tool-reported path is not uniformly absolute -- semgrep runs with
# `cwd=ctx.root` and reports invocation-relative paths -- so resolving one
# against the aramid PROCESS's cwd is wrong whenever the two differ. Flagged by
# aramid's own reviewer against the commit that introduced this.


def test_a_relative_tool_path_resolves_against_root_not_the_process_cwd(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "a.py").write_text("zero\none\ntwo\n", encoding="utf-8")

    # A same-named file somewhere else, holding DIFFERENT content. This is the
    # dangerous half: resolving against the wrong root can silently succeed and
    # fingerprint a line from an unrelated file, rather than merely failing.
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "pkg").mkdir(parents=True)
    (elsewhere / "pkg" / "a.py").write_text("DECOY\nDECOY\nDECOY\n", encoding="utf-8")

    monkeypatch.chdir(elsewhere)
    read = scanned_line_reader(root)

    assert read("pkg/a.py", 2) == "one", \
        "a relative path must resolve against the runner's root, not os.getcwd()"


def test_an_absolute_tool_path_is_used_as_given(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    f = root / "b.py"
    f.write_text("alpha\nbeta\n", encoding="utf-8")
    read = scanned_line_reader(root)
    assert read(str(f), 2) == "beta"


def test_an_unreadable_file_or_row_yields_the_sentinel_not_none(tmp_path):
    """None means "this runner does not participate" and routes to the ref
    lookup -- the skewed path the sentinel exists to keep failures out of. A
    converted runner must always make a positive statement, so a failed read
    gets a value that cannot occur in source and therefore cannot collide with
    an adjudicated finding's id."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "c.py").write_text("only\n", encoding="utf-8")
    read = scanned_line_reader(root)

    assert read("missing.py", 1) == CONTENT_UNREADABLE
    assert read("c.py", 99) == CONTENT_UNREADABLE
    assert read("c.py", 1) == "only"          # control: it does read real lines
    assert CONTENT_UNREADABLE not in ("", None)


def test_the_reader_caches_per_file(tmp_path):
    """A rule firing many times in one file must not re-read it each time."""
    root = tmp_path / "repo"
    root.mkdir()
    p = root / "d.py"
    p.write_text("first\nsecond\n", encoding="utf-8")
    read = scanned_line_reader(root)
    assert read("d.py", 1) == "first"
    p.write_text("REWRITTEN\nREWRITTEN\n", encoding="utf-8")
    assert read("d.py", 2) == "second", "second lookup must come from the cache"

def test_missing_binary_is_missing(tmp_path):
    r = run_subprocess(["definitely-not-a-real-binary-xyz"], tmp_path, 5)
    assert r.state is ToolState.MISSING

def test_ok_captures_stdout(tmp_path):
    r = run_subprocess([sys.executable, "-c", "print('hi')"], tmp_path, 10)
    assert r.state is ToolState.OK and "hi" in r.raw

def test_ok_captures_zero_returncode(tmp_path):
    r = run_subprocess([sys.executable, "-c", "pass"], tmp_path, 10)
    assert r.state is ToolState.OK and r.returncode == 0

def test_ok_captures_nonzero_returncode(tmp_path):
    # A checker that "finds issues" exits non-zero without crashing --
    # run_subprocess must surface that exit code (needed by the tests
    # adapter, which has no JSON/text signal other than the exit code
    # itself to know pytest/npm-test failed).
    r = run_subprocess([sys.executable, "-c", "import sys;sys.exit(3)"], tmp_path, 10)
    assert r.state is ToolState.OK and r.returncode == 3

def test_timeout_kills(tmp_path):
    r = run_subprocess([sys.executable, "-c", "import time;time.sleep(30)"], tmp_path, 1)
    assert r.state is ToolState.TIMEOUT

def test_invalid_utf8_output_never_raises(tmp_path):
    # A scanner emitting a byte that is invalid UTF-8 AND undefined in cp1252
    # (0x81) must yield replaced text, not a UnicodeDecodeError crash. Before
    # the encoding="utf-8", errors="replace" fix, text=True decoded with the
    # locale codec strictly -> this raised out of run_subprocess on cp1252
    # hosts (the target platform and CI's windows-latest).
    code = "import sys; sys.stdout.buffer.write(b'pre\\x81post')"
    r = run_subprocess([sys.executable, "-c", code], tmp_path, 10)
    assert r.state is ToolState.OK
    assert "pre" in r.raw and "post" in r.raw
    assert "�" in r.raw  # replaced, never raised

# Each piece is a separate flushed write with a pause after it, so the reader
# meets the boundaries the old text-mode pipes hid: a \r\n split across two
# reads, a lone \r, an `é` whose two bytes arrive apart, an invalid byte, and
# (second script) a \r that only the final flush can resolve.
_PIECES = {
    "mixed": (b"a\r", b"\nb\rc\n", b"\xc3", b"\xa9", b"\xff"),
    "trailing-cr": (b"x\r",),
}


@pytest.mark.parametrize("name", sorted(_PIECES))
def test_the_binary_reader_decodes_exactly_like_text_mode_pipes(tmp_path, name):
    """Runners parse JSON out of `raw`: the chunked binary reader must give the
    same string the old `text=True, encoding="utf-8", errors="replace"` pipes
    gave for the same bytes, and the tap the same lines."""
    code = ("import sys, time\n"
            f"for piece in {_PIECES[name]!r}:\n"
            "    sys.stdout.buffer.write(piece); sys.stdout.buffer.flush(); time.sleep(0.2)\n")
    argv = [sys.executable, "-c", code]
    want = subprocess.run(argv, cwd=tmp_path, capture_output=True, text=True,  # noqa: S603
                          encoding="utf-8", errors="replace").stdout
    # Control: the reference really does translate newlines and replace bytes.
    assert want == {"mixed": "a\nb\nc\né�", "trailing-cr": "x\n"}[name]
    lines = []
    r = run_subprocess(argv, tmp_path, 30, on_stdout_line=lines.append)
    assert r.state is ToolState.OK and r.returncode == 0, r.stderr
    assert r.raw == want
    expected = want.split("\n")
    if expected[-1] == "":
        expected.pop()
    assert lines == expected


def test_timeout_returns_promptly_and_bounded(tmp_path):
    # Confirms the happy path still returns TIMEOUT promptly after the
    # bounded post-kill drain was added (no regression from the fix).
    # Note: this does not exercise the "taskkill silently fails" branch
    # that motivated the fix -- on this path _kill_tree succeeds, so the
    # post-kill communicate() returns immediately regardless of its 5s
    # cap. The guarantee that a *failed* kill can no longer hang forever
    # rests on the bounded-timeout code itself (see base.py) plus
    # inspection, not on this test reproducing the failure.
    start = time.monotonic()
    r = run_subprocess([sys.executable, "-c", "import time;time.sleep(5)"], tmp_path, 0.5)
    elapsed = time.monotonic() - start
    assert r.state is ToolState.TIMEOUT
    assert elapsed < 10  # well under the 5s sleep + old unbounded-wait failure mode


def test_failed_kill_tree_bounds_the_post_kill_wait(tmp_path, monkeypatch):
    # The safety branch the bounded wait exists for: if _kill_tree fails to
    # reap the child, the post-kill communicate(timeout=_POST_KILL_DRAIN_S)
    # must cap the wait -- not hang for the child's full sleep. This is the
    # failed-kill reproduction test_timeout_returns_promptly_and_bounded lacks.
    from aramid.runners import base
    monkeypatch.setattr(base, "_kill_tree", lambda proc: None)   # kill "fails"
    monkeypatch.setattr(base, "_POST_KILL_DRAIN_S", 1.0)          # shrink the cap
    start = time.monotonic()
    result = base.run_subprocess(
        [sys.executable, "-c", "import time; time.sleep(30)"], tmp_path, 0.5)
    elapsed = time.monotonic() - start
    assert result.state is base.ToolState.TIMEOUT
    assert elapsed < 10, f"post-kill wait was not bounded: {elapsed:.1f}s"


def test_timeout_result_says_what_happened(tmp_path):
    """A TIMEOUT result used to carry no output at all, so the tool's log was
    a 0-byte file and the gate printed `skipped (degraded tools): gitleaks`
    with nothing anywhere naming the budget it blew (2026-09-04: two pushes
    refused on a gate with blocking 0). The result says so itself now;
    `pipeline._log_body` persists stderr as it always did."""
    r = run_subprocess([sys.executable, "-c", "import time;time.sleep(30)"], tmp_path, 0.5)
    assert r.state is ToolState.TIMEOUT
    assert "timed out after 0.5 s" in r.stderr, r.stderr
    assert "killed" in r.stderr, r.stderr


# ------------------------------------------------ on_stdout_line streaming ----
# The gate ran the test suite for ~19 min with nothing on screen, because the
# launcher pipes the child and only reads it at exit. `on_stdout_line` is an
# OPT-IN tap: with it, every stdout line reaches the callback as it is
# written; without it, nothing about the launcher changes.

_THREE_LINES = "import sys\nfor i in range(3):\n    print('line', i); sys.stdout.flush()\n"


def test_on_stdout_line_sees_every_line_in_order_and_raw_is_still_complete(tmp_path):
    seen = []
    r = run_subprocess([sys.executable, "-c", _THREE_LINES], tmp_path, 10,
                       on_stdout_line=seen.append)
    assert seen == ["line 0", "line 1", "line 2"]
    assert r.state is ToolState.OK and r.returncode == 0
    assert r.raw.splitlines() == ["line 0", "line 1", "line 2"]


def test_on_stdout_line_arrives_before_the_child_exits(tmp_path):
    # Streaming means the tap fires while the child is still alive -- a
    # callback that only ran at exit would satisfy the ordering test above.
    code = ("import sys, time\nprint('early'); sys.stdout.flush()\n"
            "time.sleep(1.5)\nprint('late')\n")
    stamps = []
    start = time.monotonic()
    run_subprocess([sys.executable, "-c", code], tmp_path, 10,
                   on_stdout_line=lambda line: stamps.append((line, time.monotonic() - start)))
    assert [s[0] for s in stamps] == ["early", "late"]
    assert stamps[0][1] < 1.0, stamps


def test_on_stdout_line_still_captures_a_large_stderr_without_deadlock(tmp_path):
    # Two pipes, one reader per pipe: a child that fills stderr past the OS
    # buffer while stdout is being tapped must still finish.
    code = ("import sys\nsys.stderr.write('e' * 300000); sys.stderr.flush()\n"
            "print('done')\n")
    seen = []
    r = run_subprocess([sys.executable, "-c", code], tmp_path, 20, on_stdout_line=seen.append)
    assert r.state is ToolState.OK and seen == ["done"]
    assert len(r.stderr) == 300000


def test_on_stdout_line_timeout_still_kills(tmp_path):
    code = "import sys, time\nprint('tick'); sys.stdout.flush()\ntime.sleep(30)\n"
    seen = []
    r = run_subprocess([sys.executable, "-c", code], tmp_path, 0.5, on_stdout_line=seen.append)
    assert r.state is ToolState.TIMEOUT
    assert seen == ["tick"]
    assert "timed out after 0.5 s" in r.stderr


def test_a_raising_tap_is_switched_off_and_never_fails_the_run(tmp_path, capsys):
    # A progress reporter is decoration: it must never turn a green suite
    # red, and a broken one must not be retried once per test line either.
    calls = []

    def boom(line):
        calls.append(line)
        raise RuntimeError("reporter bug")
    r = run_subprocess([sys.executable, "-c", _THREE_LINES], tmp_path, 10, on_stdout_line=boom)
    assert r.state is ToolState.OK and r.returncode == 0
    assert r.raw.splitlines() == ["line 0", "line 1", "line 2"]
    assert calls == ["line 0"]
    assert capsys.readouterr().err == \
        "aramid: progress reporting stopped: RuntimeError('reporter bug')\n"


def test_kill_tree_off_windows_kills_the_process_group_with_sigkill(monkeypatch):
    """The drain confirms a mutant against the unit suite alone, and it runs
    on Windows: the POSIX branch's `os.killpg(pgid, 9)` was never executed
    there. The two os calls are recorded, so the branch runs on every leg."""
    calls = []
    monkeypatch.setattr(base, "_WIN", False)
    monkeypatch.setattr(base.os, "getpgid", lambda pid: calls.append(("getpgid", pid)) or 4242,
                        raising=False)
    monkeypatch.setattr(base.os, "killpg", lambda pgid, sig: calls.append(("killpg", pgid, sig)),
                        raising=False)
    proc = SimpleNamespace(pid=77, kill=lambda: calls.append(("kill",)))
    base._kill_tree(proc)
    assert calls == [("getpgid", 77), ("killpg", 4242, 9)]

    def refuse(pid):
        raise ProcessLookupError(pid)
    monkeypatch.setattr(base.os, "getpgid", refuse, raising=False)
    calls.clear()
    base._kill_tree(proc)
    assert calls == [("kill",)], "no group: the process itself is killed"


@pytest.mark.skipif(sys.platform != "win32", reason="cmd.exe's limit applies to .cmd/.bat programs on Windows")
def test_a_batch_file_over_cmd_exe_s_limit_is_refused_not_launched(tmp_path):
    """FN-34: cmd.exe refuses a command line over its limit and exits 1,
    which several tools accept as a verdict. The launcher must not start such
    a program at all, and must say why. The boundary is real cmd.exe's, read
    on both sides: a line of exactly the budget runs, and one character more
    -- which cmd.exe refuses when launched directly -- is never started.
    Against the raw 8,191 the launcher started lines up to 8,191 and cmd.exe
    refused every one from 8,161 (the CI-review finding on the first fix)."""
    marker = tmp_path / "ran.txt"
    shim = tmp_path / "tool.cmd"
    shim.write_text(f'@echo off\r\necho ran> "{marker}"\r\nexit /b 0\r\n', encoding="utf-8")
    exe = str(base.toolpath.resolve(str(shim)))
    budget = base.cmd_exe_line_budget()

    def argv_of(length):
        arg = "y" * (length - len(subprocess.list2cmdline([exe])) - 1)
        assert len(subprocess.list2cmdline([exe, arg])) == length
        return [exe, arg]

    at = run_subprocess(argv_of(budget), tmp_path, 30)
    assert at.state is ToolState.OK and at.returncode == 0 and marker.exists(), \
        "a line of exactly the budget is within cmd.exe's limit"
    marker.unlink()

    # The control: launched directly, cmd.exe itself refuses one more.
    direct = subprocess.run(argv_of(budget + 1), capture_output=True, text=True)
    assert direct.returncode == 1 and not marker.exists()

    over = run_subprocess(argv_of(budget + 1), tmp_path, 30)
    assert over.state is ToolState.CRASHED
    assert not marker.exists()
    assert f"{budget + 1:,} characters, over the {budget:,} cmd.exe allows" in over.stderr

    # cmd.exe counts UTF-16 units: the budget in code points, one of them
    # outside the BMP, is one unit over -- refused directly, never started.
    wide = argv_of(budget)
    wide[1] = "\U0001F600" + wide[1][1:]
    assert len(subprocess.list2cmdline(wide)) == budget
    direct = subprocess.run(wide, capture_output=True)
    assert direct.returncode == 1 and not marker.exists()
    assert run_subprocess(wide, tmp_path, 30).state is ToolState.CRASHED
    assert not marker.exists()


def test_the_cmd_exe_budget_is_held_at_its_boundary_and_only_against_a_batch_file(tmp_path, monkeypatch):
    """FN-34, on every leg. The test above is the only one that launches a
    real shim, so off Windows the comparison never ran at all (the CI
    latent-mutant ratchet, 2026-10-08). The launch is stubbed here, because
    the question is only which command lines the launcher STARTS. The budget
    is cmd.exe's 8,191 less `%COMSPEC% /c `, from this process's COMSPEC
    (measured, see `cmd_exe_line_budget`): a line at the budget starts, one
    more does not, the suffix is matched in any case, and a program that is
    not a .cmd/.bat is never held to it."""
    class Launched(Exception):
        pass

    launched = []

    def popen(argv, *args, **kwargs):
        launched.append(len(subprocess.list2cmdline(argv)))
        raise Launched

    monkeypatch.setattr(base.subprocess, "Popen", popen)

    def argv_of(name, length):
        program = tmp_path / name
        program.write_text("", encoding="utf-8")
        exe = str(base.toolpath.resolve(str(program)))    # what the launcher measures
        arg = "y" * (length - len(subprocess.list2cmdline([exe])) - 1)
        assert len(subprocess.list2cmdline([exe, arg])) == length
        return [str(program), arg]

    monkeypatch.setenv("COMSPEC", r"C:\WINDOWS\system32\cmd.exe")         # 27 characters
    assert base.cmd_exe_line_budget() == 8160

    with pytest.raises(Launched):
        run_subprocess(argv_of("tool.cmd", 8160), tmp_path, 30)
    assert launched == [8160], "a line AT the budget is within it"

    over = run_subprocess(argv_of("tool.cmd", 8161), tmp_path, 30)
    assert over.state is ToolState.CRASHED
    assert over.stderr == ("aramid: tool.cmd not started: its command line is 8,161 characters, "
                           "over the 8,160 cmd.exe allows a .cmd/.bat program "
                           "(8,191 less its own `%COMSPEC% /c `)")
    assert launched == [8160], "a line over the budget is never started"

    assert run_subprocess(argv_of("upper.BAT", 8161), tmp_path, 30).state is ToolState.CRASHED
    assert launched == [8160]

    with pytest.raises(Launched):
        run_subprocess(argv_of("prog.exe", 8161), tmp_path, 30)
    assert launched == [8160, 8161], "only a batch file goes through cmd.exe"

    monkeypatch.setenv("COMSPEC", r"C:\WINDOWS\system32\..\system32\..\system32\cmd.exe")  # 51
    assert base.cmd_exe_line_budget() == 8136
    assert run_subprocess(argv_of("tool.cmd", 8137), tmp_path, 30).state is ToolState.CRASHED
    with pytest.raises(Launched):
        run_subprocess(argv_of("tool.cmd", 8136), tmp_path, 30)
    assert launched == [8160, 8161, 8136], "the budget follows COMSPEC"

    monkeypatch.delenv("COMSPEC", raising=False)
    monkeypatch.setenv("SystemRoot", r"C:\WINDOWS")
    assert base.cmd_exe_line_budget() == 8160, "unset: the system directory's cmd.exe"


def test_the_budget_counts_what_cmd_exe_counts(tmp_path, monkeypatch):
    """cmd.exe counts UTF-16 units, and a COMSPEC holding a space reaches it
    quoted. Measured 2026-10-08: a line of 8,160 code points carrying one
    character outside the BMP (8,161 units) was refused while the same line
    one code point shorter ran; a 130-character COMSPEC with a space put the
    boundary at 8,055, two under the unquoted 8,057. Counting code points,
    or the bare COMSPEC, started both lines cmd.exe then refused."""
    class Launched(Exception):
        pass

    launched = []

    def popen(argv, *args, **kwargs):
        launched.append(list(argv))
        raise Launched

    monkeypatch.setattr(base.subprocess, "Popen", popen)
    monkeypatch.setenv("COMSPEC", r"C:\WINDOWS\system32\cmd.exe")
    program = tmp_path / "tool.cmd"
    program.write_text("", encoding="utf-8")
    exe = str(base.toolpath.resolve(str(program)))
    wide = "\U0001F600" + "y" * (8160 - len(subprocess.list2cmdline([exe])) - 2)
    assert len(subprocess.list2cmdline([exe, wide])) == 8160          # code points

    over = run_subprocess([str(program), wide], tmp_path, 30)
    assert over.state is ToolState.CRASHED
    assert "its command line is 8,161 characters, over the 8,160" in over.stderr
    assert launched == []
    with pytest.raises(Launched):
        run_subprocess([str(program), wide[:-1]], tmp_path, 30)      # 8,160 units
    assert len(launched) == 1

    monkeypatch.setenv("COMSPEC", r"C:\Program Files\x\cmd.exe")      # 26, quoted 28
    assert base.cmd_exe_line_budget() == 8191 - 28 - 4
