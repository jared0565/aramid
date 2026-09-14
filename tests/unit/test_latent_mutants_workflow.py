"""The latent-mutant count runs on exactly one CI leg, after the full suite,
on a coverage JSON the same leg just wrote.

Structural, like test_workflow_pinning.py: a snapshot of today's step text
would fail on every legitimate rewording and teach whoever hits it to edit
the expected value. What must hold: the step exists (non-vacuity), it is
guarded onto one (os, python) pair that the matrix actually runs, the
coverage run feeding it carries the same guard and names the same file,
and both come after the unpatched full-suite step so a red suite is
reported as a red suite, not as a coverage failure."""
import json
import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "aramid.yml"
BASELINE = REPO / "tests" / "latent_mutants_baseline.json"
SCRIPT = "scripts/latent_mutants.py"


def _steps() -> list[dict]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["ci"]["steps"]


def _matrix() -> list[tuple[str, str]]:
    wf = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return [(leg["os"], str(leg["python"]))
            for leg in wf["jobs"]["ci"]["strategy"]["matrix"]["include"]]


def _guarded_leg(step: dict) -> tuple[str, str]:
    """The single (os, python) pair a step's `if:` admits."""
    cond = step.get("if", "")
    m = re.fullmatch(r"matrix\.os == '([^']+)' && matrix\.python == '([^']+)'", cond)
    assert m, f"{step.get('name')!r} is not guarded onto one leg: if={cond!r}"
    return m.group(1), m.group(2)


def test_the_guard_can_actually_see_the_ci_job():
    steps = _steps()
    assert steps and _matrix(), "ci job or its matrix is empty"
    assert any(s.get("name") == "Run test suite" for s in steps)


def test_the_count_runs_once_on_a_leg_the_matrix_has_after_the_full_suite():
    steps = _steps()
    counting = [s for s in steps if SCRIPT in str(s.get("run", ""))]
    assert len(counting) == 1, [s.get("name") for s in counting]
    (count,) = counting
    leg = _guarded_leg(count)
    assert leg in _matrix(), f"{leg} is not a matrix leg: {_matrix()}"
    assert _matrix().count(leg) == 1, "the guard would fire on two legs"
    suite = next(i for i, s in enumerate(steps) if s.get("name") == "Run test suite")
    assert steps.index(count) > suite, "the count must not pre-empt the full suite"
    assert " check " in count["run"], "a measurement is not a ratchet"
    assert "--baseline tests/latent_mutants_baseline.json" in count["run"]
    assert "--verbose" in count["run"], \
        "the log must name every latent mutant, not just count them"
    assert "continue-on-error" not in count, "a ratchet that cannot fail is decoration"


def test_the_coverage_run_feeding_the_count_has_the_same_guard_and_file():
    steps = _steps()
    count = next(s for s in steps if SCRIPT in str(s.get("run", "")))
    cov_file = re.search(r"latent_mutants\.py \S+ (\S+)", count["run"]).group(1)
    feeders = [s for s in steps[:steps.index(count)]
               if "--cov=aramid" in str(s.get("run", ""))]
    assert len(feeders) == 1, [s.get("name") for s in feeders]
    (cov,) = feeders
    assert _guarded_leg(cov) == _guarded_leg(count)
    assert "tests/unit" in cov["run"], "the count is of the UNIT suite's coverage"
    assert "tests/integration" not in cov["run"]
    assert f"--cov-report=json:{cov_file}" in cov["run"], \
        f"coverage writes {cov['run']!r} but the count reads {cov_file!r}"


def test_the_committed_baseline_is_the_one_the_step_names_and_adds_up():
    """The ratchet is only as honest as the file it compares against: every
    key a src/aramid path, every count a positive int, and `_total` the
    sum -- a hand edit that forgets the total is caught here, not in CI."""
    steps = _steps()
    count = next(s for s in steps if SCRIPT in str(s.get("run", "")))
    named = re.search(r"--baseline (\S+)", count["run"]).group(1)
    assert (REPO / named) == BASELINE and BASELINE.exists()
    base = json.loads(BASELINE.read_text(encoding="utf-8"))
    files = {k: v for k, v in base.items() if k != "_total"}
    assert files, "an empty baseline ratchets nothing"
    assert all(k.startswith("src/aramid/") and k.endswith(".py") for k in files), list(files)
    assert all(isinstance(v, int) and v > 0 for v in files.values())
    assert base["_total"] == sum(files.values())
    assert list(base) == sorted(base), "write-baseline writes sorted keys; keep it that way"
