"""Tiny helpers shared by the tool adapters (kept deliberately small).

Not a framework -- just the two bits of boilerplate that would otherwise be
copy-pasted into every adapter: making a tool's file paths safe to hand to
git as a pathspec, and turning an already-run subprocess result into a
RunnerResult with per-runner (not exit-code-based) CRASHED detection.

Deliberately does NOT call run_subprocess itself: each adapter imports and
calls run_subprocess in its own module namespace so that
`monkeypatch.setattr(<adapter_module>, "run_subprocess", fake)` in tests
actually intercepts the call (a module-level helper calling its own
same-module binding would silently bypass such a patch -- see
aramid.gitutil.read_for_fingerprint / normalizer.py for the same convention).
"""
import dataclasses
import json
from pathlib import Path

from aramid.runners.base import RunnerResult, ToolState


def relativize(path_str: str, root: Path) -> str:
    """Best-effort: make path_str root-relative with forward slashes.

    RawFinding.file is fed straight to `git show <ref>:<path>` by the
    normalizer, which requires a forward-slash pathspec even on Windows.
    Falls back to the original string (slashes normalized) if it isn't
    under root or isn't a valid path at all.

    Backslashes are normalized EXPLICITLY, before `Path` ever sees the
    string, because that is the one part of this that `Path` cannot do
    portably: `\\` is a separator on Windows but a legal FILENAME CHARACTER
    on POSIX, so `PurePosixPath("src\\main.rs").as_posix()` hands the
    backslash straight back. Delegating to `Path` therefore honoured this
    docstring on Windows and silently violated it on every POSIX host --
    which is exactly how a Windows-captured clippy fixture passed locally
    and reddened all five POSIX CI legs. The trade is deliberate: a POSIX
    file whose name genuinely contains a backslash is mangled, but such a
    name could never survive the git pathspec this exists to produce.
    """
    try:
        p = Path(path_str.replace("\\", "/"))
        if p.is_absolute():
            p = p.relative_to(root)
        return p.as_posix()
    except (ValueError, OSError):
        return path_str.replace("\\", "/")


def json_or_crashed(tool: str, result: RunnerResult, ok_returncodes: set[int],
                     empty: str = "[]") -> RunnerResult:
    """Validate an already-run subprocess result's stdout as JSON, gated by
    the tool's own known-good exit codes.

    MISSING/TIMEOUT keep their state (the process never ran to completion,
    so there's no exit code to evaluate and no report to distrust) but are
    still RESTAMPED with `tool`. They used to return unchanged, and that
    was a real defect: `run_subprocess` names every result -- including the
    MISSING/TIMEOUT ones it builds itself -- after `Path(argv[0]).name`,
    which is not the runner's name whenever the two differ. cargo-audit
    shells out to `cargo` and eslint to `eslint.cmd` on win32, so exactly
    the degraded results, the ones whose only purpose is diagnosis, reached
    the pipeline under a name absent from `toolset.RUNNER_TOOL_NAMES`.
    Worse, cargo-audit and clippy both collapsed onto `cargo`, and since
    `pipeline.degraded_tools` is a set and `_write_logs` keys its filename
    on `.tool`, a run where both Rust gates timed out lost one gate from
    the report and silently overwrote one diagnostic log with the other.
    Not evaluating an exit code never required keeping the wrong name.
    (`typecheck.run_tsc` reached the same conclusion locally -- T-8
    section 11 -- and relabels unconditionally for these same reasons.)

    A tool that runs to completion but finds issues typically exits
    non-zero -- that alone is not a crash, which is why `ok_returncodes` is
    a per-tool SET (e.g. {0, 1}), not just "== 0".

    The returncode check runs BEFORE the JSON check and independently of
    it: empty stdout parses just as cleanly as "[]"/"{}" whether the tool
    ran clean and found nothing OR errored before writing anything (bad
    args, permission error, etc). Without the returncode gate those two
    cases are indistinguishable and a crashed BLOCK-tier scanner silently
    reads as "ran, zero findings". A returncode outside ok_returncodes is
    therefore always CRASHED, even if the (usually empty) output happens
    to parse.
    """
    if result.state in (ToolState.MISSING, ToolState.TIMEOUT):
        return dataclasses.replace(result, tool=tool)
    if result.returncode not in ok_returncodes:
        return RunnerResult(tool, ToolState.CRASHED, result.raw, result.stderr,
                             result.duration_s, result.returncode)
    try:
        json.loads(result.raw or empty)
    except json.JSONDecodeError:
        return RunnerResult(tool, ToolState.CRASHED, result.raw, result.stderr,
                             result.duration_s, result.returncode)
    return RunnerResult(tool, ToolState.OK, result.raw or empty, result.stderr,
                         result.duration_s, result.returncode)
