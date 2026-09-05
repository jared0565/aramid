import sys
import time
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
