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


def json_or_crashed(tool: str, result: RunnerResult, empty: str = "[]") -> RunnerResult:
    """Validate an already-run subprocess result's stdout as JSON.

    MISSING/TIMEOUT pass through unchanged. A tool that runs to completion but
    finds issues typically exits non-zero -- that alone is not a crash, so we
    never look at the exit code here. CRASHED is reserved for output that
    doesn't parse as JSON (the tool errored before producing a report).
    """
    if result.state in (ToolState.MISSING, ToolState.TIMEOUT):
        return result
    try:
        json.loads(result.raw or empty)
    except json.JSONDecodeError:
        return RunnerResult(tool, ToolState.CRASHED, result.raw, result.stderr, result.duration_s)
    return RunnerResult(tool, ToolState.OK, result.raw or empty, result.stderr, result.duration_s)
