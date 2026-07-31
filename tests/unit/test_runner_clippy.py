"""clippy runner -- Rust lint as first-class aramid findings.

Closes the half of Codex's point 1 that `37a9bd6` left open. That point read:
the Cargo misdetection "means Aramid does not natively provide Rust
dependency auditing **or Rust-specific gate discovery**". cargo-audit closed
the dependency half; until now the analysis half had nothing at all --
aramid's language runners were ruff (Python), eslint (JS/TS) and typecheck
(tsc/mypy), and its vendored semgrep ruleset is 13 rules covering only
JS/TS and Python. On a Rust repo clippy ran only if the repo wired it into
its own script, where it collapses to one pass/fail bit with no fingerprint,
no tier, no triage and no baseline.

The fixture is a verbatim `cargo clippy --message-format=json` capture
(cargo 1.x, this machine, 2026-07-31) with only the bulky `rendered`/
`children` fields trimmed -- not a hand-written guess at the shape.
"""
import json
from pathlib import Path

import pytest

from aramid.runners import clippy
from aramid.runners.base import RunContext, RunnerResult, ToolState

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
CLIPPY_JSONL = FIXTURES / "cargo-clippy.jsonl"


def _rust_repo(tmp_path: Path) -> Path:
    (tmp_path / "Cargo.toml").write_text("[package]\nname = \"x\"\n", encoding="utf-8")
    (tmp_path / "src").mkdir(exist_ok=True)
    return tmp_path


# ---------------------------------------------------------------- parse ----

def test_parse_real_clippy_output_yields_both_rustc_and_clippy_lints(tmp_path):
    result = RunnerResult(clippy.NAME, ToolState.OK, raw=CLIPPY_JSONL.read_text(encoding="utf-8"))
    findings = {f.rule: f for f in clippy.parse(result, RunContext(root=tmp_path))}

    # A bare rustc lint and a namespaced clippy lint both arrive, and the
    # namespacing is preserved so `block_rules.clippy` can target either.
    assert set(findings) == {"unused_variables", "clippy::needless_range_loop"}

    f = findings["clippy::needless_range_loop"]
    assert f.tool == "clippy"
    assert f.severity_raw == "warning"      # maps to MEDIUM via policy aliases
    assert f.line == 4
    assert f.file.endswith("main.rs")
    assert "\\" not in f.file, "paths must be normalised, not raw Windows spans"
    assert "loop variable" in f.message


def test_parse_ignores_non_diagnostic_records(tmp_path):
    """The stream also carries `compiler-artifact` and `build-finished`
    records. They are not findings and must not become one."""
    result = RunnerResult(clippy.NAME, ToolState.OK, raw=CLIPPY_JSONL.read_text(encoding="utf-8"))
    assert len(clippy.parse(result, RunContext(root=tmp_path))) == 2


def test_parse_skips_diagnostics_with_no_code_or_no_span(tmp_path):
    """rustc emits summary messages ("N warnings emitted") with a null
    `code` and no primary span. Emitting those as findings would produce
    unfingerprintable noise that can never be triaged away."""
    raw = "\n".join([
        '{"reason":"compiler-message","message":{"level":"warning","code":null,'
        '"message":"2 warnings emitted","spans":[]}}',
        '{"reason":"compiler-message","message":{"level":"warning",'
        '"code":{"code":"dead_code"},"message":"never used","spans":[]}}',
    ])
    result = RunnerResult(clippy.NAME, ToolState.OK, raw=raw)
    assert clippy.parse(result, RunContext(root=tmp_path)) == []


def test_parse_skips_non_ok_state(tmp_path):
    for state in (ToolState.MISSING, ToolState.CRASHED, ToolState.TIMEOUT):
        assert clippy.parse(RunnerResult(clippy.NAME, state), RunContext(root=tmp_path)) == []


# ------------------------------------------------------------------ run ----

def test_run_missing_when_clippy_plugin_absent(tmp_path, monkeypatch):
    """Same lesson as cargo-audit (`6efed44`): `cargo` resolving is not
    evidence that `cargo clippy` works -- clippy is a separately-installed
    component (`rustup component add clippy`) shipped as a `cargo-clippy`
    binary. Without it cargo exits 101 with no JSON on stdout, which a
    return-code-only check would read as a crash and an output-only check
    would read as CLEAN. Probe the binary and report MISSING."""
    _rust_repo(tmp_path)
    monkeypatch.setattr(clippy.toolpath, "resolve", lambda name: None)

    def explode(*a, **k):  # pragma: no cover - must never be reached
        raise AssertionError("cargo must not run when the clippy component is absent")

    monkeypatch.setattr(clippy, "run_subprocess", explode)
    result = clippy.run(RunContext(root=tmp_path))
    assert result.state is ToolState.MISSING
    assert result.tool == "clippy"


def test_run_missing_without_a_cargo_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(clippy.toolpath, "resolve", lambda name: f"/fake/{name}")
    assert clippy.run(RunContext(root=tmp_path)).state is ToolState.MISSING


def test_run_invokes_cargo_clippy_with_json_message_format(tmp_path, monkeypatch):
    _rust_repo(tmp_path)
    monkeypatch.setattr(clippy.toolpath, "resolve", lambda name: f"/fake/{name}")
    captured = {}

    def fake(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        return RunnerResult("cargo", ToolState.OK,
                            raw=CLIPPY_JSONL.read_text(encoding="utf-8"), returncode=0)

    monkeypatch.setattr(clippy, "run_subprocess", fake)
    result = clippy.run(RunContext(root=tmp_path))

    assert result.state is ToolState.OK
    # run_subprocess names the result after argv[0] ("cargo"); the runner
    # must restamp it, or the pipeline records a tool name that is not in
    # RUNNER_TOOL_NAMES and disagrees with the one every Finding carries.
    assert result.tool == clippy.NAME
    assert captured["argv"][:2] == ["cargo", "clippy"]
    assert "--message-format=json" in captured["argv"]


@pytest.mark.parametrize("returncode", [0, 101])
def test_run_accepts_both_clean_and_compile_error_return_codes(tmp_path, monkeypatch, returncode):
    """clippy exits 0 with warnings and 101 when the crate fails to compile.
    A failing compile still emits real `level: "error"` diagnostics on
    stdout, and discarding them as a crash would throw away the most severe
    findings the tool ever produces. The MISSING probe above is what keeps
    101-because-the-component-is-absent from reaching here."""
    _rust_repo(tmp_path)
    monkeypatch.setattr(clippy.toolpath, "resolve", lambda name: f"/fake/{name}")
    monkeypatch.setattr(
        clippy, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult(
            "cargo", ToolState.OK,
            raw=CLIPPY_JSONL.read_text(encoding="utf-8"), returncode=returncode))

    assert clippy.run(RunContext(root=tmp_path)).state is ToolState.OK


def test_run_unparseable_output_is_crashed(tmp_path, monkeypatch):
    _rust_repo(tmp_path)
    monkeypatch.setattr(clippy.toolpath, "resolve", lambda name: f"/fake/{name}")
    monkeypatch.setattr(
        clippy, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult(
            "cargo", ToolState.OK, raw="not json at all", returncode=0))

    assert clippy.run(RunContext(root=tmp_path)).state is ToolState.CRASHED


def test_run_empty_output_is_ok_not_crashed(tmp_path, monkeypatch):
    """A genuinely clean crate emits no compiler-message records at all."""
    _rust_repo(tmp_path)
    monkeypatch.setattr(clippy.toolpath, "resolve", lambda name: f"/fake/{name}")
    monkeypatch.setattr(
        clippy, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult(
            "cargo", ToolState.OK, raw="", returncode=0))

    result = clippy.run(RunContext(root=tmp_path))
    assert result.state is ToolState.OK
    assert clippy.parse(result, RunContext(root=tmp_path)) == []


@pytest.mark.parametrize("state", [ToolState.TIMEOUT, ToolState.MISSING])
def test_degraded_result_still_carries_the_runner_name(tmp_path, monkeypatch, state):
    """The restamp must NOT be gated on the OK branch.

    `run_subprocess` names every result it returns after `argv[0]` --
    including the ones it builds itself on the TIMEOUT (base.py) and MISSING
    paths, which never reach the runner's own early returns. Gating the
    restamp on OK therefore leaves exactly the degraded results, the ones
    whose whole purpose is diagnosis, labelled "cargo": a name absent from
    `toolset.RUNNER_TOOL_NAMES` and shared with cargo-audit.

    Reachable at stock defaults, and on the path this runner's own docstring
    names as expected: `TIMEOUT_S` is 240s against a 300s pre-push budget,
    so a cold-cache crate trips the runner's timeout, not the pipeline's.

    `typecheck.run_tsc` already learned this (T-8 section 11) and relabels
    unconditionally for the same reason.
    """
    _rust_repo(tmp_path)
    monkeypatch.setattr(clippy.toolpath, "resolve", lambda name: f"/fake/{name}")
    monkeypatch.setattr(
        clippy, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult("cargo", state))

    result = clippy.run(RunContext(root=tmp_path))
    assert result.state is state
    assert result.tool == clippy.NAME


# ------------------------------------------------- --all-targets ------------

CLIPPY_ALL_TARGETS = FIXTURES / "cargo-clippy-all-targets.jsonl"


def test_run_lints_all_targets(tmp_path, monkeypatch):
    """Without `--all-targets`, cargo lints the default targets only -- so
    inline `#[cfg(test)]` modules, integration tests, benches and examples
    are NOT linted at all.

    Measured on a throwaway crate rather than assumed: the same
    `clippy::ptr_arg` in ordinary library code, in a `#[cfg(test)]` module
    and in `tests/integration.rs` yielded ONE finding by default and all
    three with the flag. `#[cfg(test)]` code is invisible by default because
    the cfg is only active when building the test target.

    Reported by graphite (operation-firewall round 19), which noted this repo
    has inline test modules -- real Rust the gate could not see.
    """
    _rust_repo(tmp_path)
    monkeypatch.setattr(clippy.toolpath, "resolve", lambda name: f"/fake/{name}")
    captured = {}

    def fake(argv, cwd, timeout_s, env=None):
        captured["argv"] = argv
        return RunnerResult("cargo", ToolState.OK, raw="", returncode=0)

    monkeypatch.setattr(clippy, "run_subprocess", fake)
    clippy.run(RunContext(root=tmp_path))

    assert "--all-targets" in captured["argv"]


def test_parse_deduplicates_the_same_lint_reported_by_two_targets(tmp_path):
    """`--all-targets` makes cargo compile a source file once per target, and
    each compilation re-reports the lints in it. A lint in `lib.rs` therefore
    arrives TWICE -- once for the lib target, once for the test target --
    naming the identical file and line.

    That must collapse to one finding, and the reason is not cosmetic.
    `normalizer.normalize` gives gate callers a POSITIONAL occurrence index,
    so two identical raws become two findings with DIFFERENT ids rather than
    being deduplicated downstream. One real lint would be reported twice,
    tracked twice in the ledger, and -- since both are new -- escalated to
    BLOCK twice by the pre-push ratchet.

    Fixture is a verbatim `cargo clippy --all-targets --message-format=json`
    capture whose 4 compiler-message records contain a genuine 2x duplicate
    of `src/lib.rs:1`.
    """
    raw = CLIPPY_ALL_TARGETS.read_text(encoding="utf-8")
    result = RunnerResult(clippy.NAME, ToolState.OK, raw=raw)
    findings = clippy.parse(result, RunContext(root=tmp_path))

    locations = sorted((f.rule, f.file, f.line) for f in findings)
    assert locations == [
        ("clippy::ptr_arg", "src/lib.rs", 1),    # lib + test target -> ONE
        ("clippy::ptr_arg", "src/lib.rs", 11),   # the #[cfg(test)] module
        ("clippy::ptr_arg", "tests/integration.rs", 3),
    ], locations


def test_parse_keeps_distinct_lints_that_share_a_file(tmp_path):
    """The dedupe key must not be so coarse it merges real findings: two
    different rules on the same line, and the same rule on different lines,
    both survive."""
    raw = "\n".join(json.dumps({
        "reason": "compiler-message",
        "message": {"level": "warning", "code": {"code": code},
                    "message": "m",
                    "spans": [{"is_primary": True, "file_name": "src/lib.rs",
                               "line_start": line}]},
    }) for code, line in [("clippy::ptr_arg", 1), ("clippy::needless_range_loop", 1),
                          ("clippy::ptr_arg", 2)])

    findings = clippy.parse(RunnerResult(clippy.NAME, ToolState.OK, raw=raw),
                            RunContext(root=tmp_path))
    assert len(findings) == 3
