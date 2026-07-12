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
import json
from pathlib import Path

from aramid.runners.base import RunnerResult, ToolState


def relativize(path_str: str, root: Path) -> str:
    """Best-effort: make path_str root-relative with forward slashes.

    RawFinding.file is fed straight to `git show <ref>:<path>` by the
    normalizer, which requires a forward-slash pathspec even on Windows.
    Falls back to the original string (slashes normalized) if it isn't
    under root or isn't a valid path at all.
    """
    try:
        p = Path(path_str)
        if p.is_absolute():
            p = p.relative_to(root)
        return p.as_posix()
    except (ValueError, OSError):
        return path_str.replace("\\", "/")


def json_or_crashed(tool: str, result: RunnerResult, ok_returncodes: set[int],
                     empty: str = "[]") -> RunnerResult:
    """Validate an already-run subprocess result's stdout as JSON, gated by
    the tool's own known-good exit codes.

    MISSING/TIMEOUT pass through unchanged (the process never ran to
    completion, so there's no exit code to evaluate and no report to
    distrust). A tool that runs to completion but finds issues typically
    exits non-zero -- that alone is not a crash, which is why
    `ok_returncodes` is a per-tool SET (e.g. {0, 1}), not just "== 0".

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
        return result
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
