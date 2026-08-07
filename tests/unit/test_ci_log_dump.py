"""The CI step that surfaces `.aramid/logs/` must not fail silently.

A gate that blocks in CI writes the reason to `.aramid/logs/<tool>-<run>.log`
and nothing else. That directory is gitignored and CI never uploaded it, so a
`windows-latest / py3.14` leg failed at the pre-push gate, passed on re-run
with no code change, and the one artifact naming the failing test existed only
inside a container that was already gone.

`.github/scripts/dump_aramid_logs.py` closes that. It runs under
`if: failure()` and ALWAYS exits 0 -- which is exactly what makes it dangerous
to ship untested: a dump that prints nothing because it resolved the path
wrong looks identical to a dump that correctly found nothing, and the first
real exercise would be the incident we spent weeks waiting for.

So every branch is proven here, as a SUBPROCESS with `cwd` set. Importing it
with a patched cwd would not exercise the thing most likely to break across
windows/ubuntu/macos: relative path resolution from the workspace root.
"""
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "dump_aramid_logs.py"


def _run(cwd: Path, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    import os

    env = {**os.environ, **(env_extra or {})}
    return subprocess.run(
        [sys.executable, str(SCRIPT)], cwd=cwd, env=env,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=60, check=False)


def _plant(root: Path, name: str, body: str) -> Path:
    d = root / ".aramid" / "logs"
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text(body, encoding="utf-8")
    return p


def test_the_script_exists_where_the_workflow_calls_it():
    """Non-vacuity. Every other test here shells out; if the path were wrong
    they would all fail the same confusing way, so say it once, plainly."""
    assert SCRIPT.is_file(), f"no dump script at {SCRIPT}"


def test_a_missing_logs_dir_is_reported_not_silent(tmp_path):
    """The worst outcome is an empty step. `.aramid/logs` absent is a real
    diagnosis -- the gate died before any runner produced output -- and must
    read differently from 'found logs, they were empty'."""
    r = _run(tmp_path)

    assert r.returncode == 0
    assert ".aramid" in r.stdout
    assert "no" in r.stdout.lower()


def test_an_empty_log_file_is_announced_as_empty(tmp_path):
    """A 0-byte `python-<run>.log` is the signal that the fix in fb9a775
    regressed -- stdout stopped being persisted. Skipping empties as
    uninteresting would hide precisely that."""
    _plant(tmp_path, "python-run1.log", "")

    r = _run(tmp_path)

    assert r.returncode == 0
    assert "python-run1.log" in r.stdout
    assert "EMPTY" in r.stdout


def test_the_failing_test_name_reaches_stdout(tmp_path):
    """The whole point: name the flake."""
    _plant(tmp_path, "python-run1.log",
           "--- stdout ---\nFAILED tests/unit/test_x.py::test_boom - assert 0\n")

    r = _run(tmp_path)

    assert r.returncode == 0
    assert "test_boom" in r.stdout


def test_every_log_file_is_inventoried_with_its_size(tmp_path):
    """An inventory printed BEFORE the bodies means a truncated or
    size-capped step still tells you which runners reported at all."""
    _plant(tmp_path, "python-run1.log", "BODY_MARKER")
    _plant(tmp_path, "gitleaks-run1.log", "")

    r = _run(tmp_path)

    assert "11" in r.stdout, "the byte size of the 11-char body is not reported"
    # both named, including the empty one -- an absent runner is a diagnosis
    assert "gitleaks-run1.log" in r.stdout
    # the inventory comes first: a step truncated by GitHub still lists them
    assert r.stdout.index("gitleaks-run1.log") < r.stdout.index("BODY_MARKER")


def test_logs_from_both_gate_runs_are_dumped(tmp_path):
    """CI runs the gate twice (pre-commit, then pre-push) and the run_id keys
    the filename, so nothing clobbers. Dumping only the newest would drop the
    tier the flake actually lives in."""
    _plant(tmp_path, "ruff-aaa.log", "from the pre-commit run")
    _plant(tmp_path, "python-bbb.log", "from the pre-push run")

    r = _run(tmp_path)

    assert "from the pre-commit run" in r.stdout
    assert "from the pre-push run" in r.stdout


def test_a_huge_log_is_truncated_from_the_FRONT(tmp_path):
    """pytest prints its short summary LAST. `_log_body` caps stdout at 64K
    but leaves stderr UNCAPPED, so a spewing runner can still write megabytes
    -- this cap is what keeps that from burying the step."""
    tail = "1 failed, 4000 passed"
    _plant(tmp_path, "python-run1.log", ("x" * 400_000) + tail)

    r = _run(tmp_path)

    assert tail in r.stdout
    assert "truncated" in r.stdout.lower()
    assert len(r.stdout) < 300_000


def test_workflow_commands_in_a_body_cannot_hijack_the_step(tmp_path):
    """A log body is untrusted text. `::add-mask::` would make GitHub redact
    that value from all later output -- i.e. a failing test could suppress the
    very diagnostic this step exists to print -- and `::endgroup::` would close
    the fold early. Neutralise leading `::` rather than trust the content."""
    _plant(tmp_path, "python-run1.log",
           "::add-mask::secretish\n::endgroup::\nFAILED test_boom\n")

    r = _run(tmp_path)

    assert "test_boom" in r.stdout
    body = r.stdout.split("python-run1.log", 1)[-1]
    assert "\n::add-mask::" not in body
    assert "\n::endgroup::\n::endgroup::" not in body


def test_non_ascii_survives_a_non_utf8_stdout_encoding(tmp_path):
    """Windows CI hands Python a redirected pipe, so `sys.stdout.encoding`
    follows the locale (cp1252), and one box-drawing character out of pytest
    raises UnicodeEncodeError -- the dump dies at the moment it matters, on
    the exact leg that flakes. The script forces UTF-8 rather than hope."""
    _plant(tmp_path, "python-run1.log", "FAILED test_boom ── café ✓\n")

    r = _run(tmp_path, {"PYTHONIOENCODING": "cp1252"})

    assert r.returncode == 0, r.stderr
    assert "test_boom" in r.stdout
    assert "café" in r.stdout


def test_an_undecodable_log_does_not_kill_the_dump(tmp_path):
    """Logs are written as UTF-8, but a runner's raw bytes can land here from
    an older aramid or a truncated write. One bad file must not cost us the
    others."""
    d = tmp_path / ".aramid" / "logs"
    d.mkdir(parents=True)
    (d / "gitleaks-run1.log").write_bytes(b"\xff\xfe not utf-8 \x00")
    _plant(tmp_path, "python-run1.log", "FAILED test_boom\n")

    r = _run(tmp_path)

    assert r.returncode == 0, r.stderr
    assert "test_boom" in r.stdout


def test_the_body_count_is_capped_and_the_cap_is_ANNOUNCED(tmp_path):
    """`.aramid/logs` has no rotation: it accumulates one file per runner per
    gate run forever. Measured on a real dev checkout, 477 files. CI is a
    fresh checkout so it sees ~5, but a silent cap would make a truncated
    dump read as a complete one -- the exact failure this script exists to
    avoid. Print the newest, and say how many were left out."""
    import os

    for i in range(45):
        p = _plant(tmp_path, f"python-run{i:03d}.log", f"BODY_{i:03d}")
        os.utime(p, (1_700_000_000 + i, 1_700_000_000 + i))

    r = _run(tmp_path)

    assert "BODY_044" in r.stdout, "the newest body must always be printed"
    assert "BODY_000" not in r.stdout, "the oldest body should have been capped"
    assert "45" in r.stdout, "the inventory must still name every file"
    lowered = r.stdout.lower()
    assert "not printed" in lowered or "omitted" in lowered, (
        "the cap was applied silently -- a truncated dump then reads exactly "
        "like a complete one")


# ------------------------------------------------------------- the wiring ---
# The tests above prove the script. These prove CI actually calls it -- a
# perfect script nobody invokes buys nothing, and that half is invisible from
# a local run. Parsed as YAML, not grepped: a commented-out or misindented
# step still contains the right substring.

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "aramid.yml"


def _ci_steps() -> list[dict]:
    import yaml

    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["ci"]["steps"]


def _dump_step_index() -> int:
    for i, step in enumerate(_ci_steps()):
        if SCRIPT.name in (step.get("run") or ""):
            return i
    raise AssertionError(
        f"no step in {WORKFLOW.name} runs {SCRIPT.name}. The gate's only "
        "record of WHY it blocked would again die with the container.")


def test_the_workflow_runs_the_dump_when_the_job_fails():
    step = _ci_steps()[_dump_step_index()]
    cond = str(step.get("if", ""))

    assert "failure()" in cond, (
        "the dump step must be guarded by `if: failure()`. Without a "
        f"condition it is SKIPPED on failure (got if: {cond!r}) -- which is "
        "exactly and only when it is wanted.")


def test_the_dump_runs_after_both_gate_steps():
    """Order is the whole point: it must see the logs of every gate tier. It
    need not be last, but it cannot precede the steps it explains."""
    steps = _ci_steps()
    gates = [i for i, s in enumerate(steps)
             if "aramid check" in (s.get("run") or "")]

    assert len(gates) == 2, f"expected 2 gate steps, found {len(gates)}"
    assert _dump_step_index() > max(gates)


def test_it_never_fails_the_job(tmp_path):
    """It runs under `if: failure()`, where the job is already red for a real
    reason. A non-zero exit here would add a second, misleading failure to the
    step list and bury the first."""
    (tmp_path / ".aramid").write_text("not a directory", encoding="utf-8")

    r = _run(tmp_path)

    assert r.returncode == 0, r.stderr
