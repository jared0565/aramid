"""Checks CI performs that the local pre-push gate could not, done locally.

`[tests].command` now runs the same tree CI runs, so the TEST SET matches. What
did not match were three CI steps around it. Two are environment-independent
and therefore had no business being CI-only -- a developer should not need a
matrix round-trip to learn something reproducible on their own machine. They
live here, in the suite the gate already runs, so they cost one local run and
CI gets them for free.

Deliberately NOT attempted here: the seven-leg matrix. Interpreter and platform
differences cannot be reproduced on one machine by definition, so CI remains
the authority for those, and a green run here is a filter rather than a proof.
"""
from pathlib import Path

from aramid import config as config_mod
from aramid import gitutil, toolset
from aramid.models import Gate
from aramid.pipeline import GATE_RUNNER_KEYS
from aramid.runners import ruff
from aramid.runners.base import RunContext, ToolState

REPO = Path(__file__).resolve().parents[2]


# --- CI step: `aramid check --all --strict` (pre-commit tier) ---------------
#
# `--all` widens the FILE set, never the runner set, and the pre-push tier does
# not include ruff (GATE_RUNNER_KEYS: pre-commit is [gitleaks, ruff], pre-push
# is [gitleaks, semgrep, eslint, clippy, typecheck, deps, tests]). The local
# pre-commit hook runs ruff over the STAGED scope only. So a ruff finding in a
# file this push never touched was invisible locally and surfaced only in CI --
# the exact round-trip this file exists to remove.

def test_ruff_is_clean_across_every_tracked_python_file():
    files = [f for f in gitutil.all_tracked_files(REPO) if f.endswith(".py")]
    assert len(files) > 100, (
        f"only {len(files)} python files discovered -- the walk is broken and "
        "this test would pass by looking at nothing")

    ctx = RunContext(root=REPO, files=files)
    res = ruff.run(ctx)
    assert res.state is ToolState.OK, f"ruff did not complete: {res.state}"

    # `run` returns the tool's raw output; `parse` is what turns it into
    # findings, and it is the pair the pipeline itself uses. Calling only
    # `run` and reading a `.findings` attribute that does not exist raises
    # AttributeError -- which pytest reports as a failure indistinguishable
    # from a real finding, and did on the first version of this test.
    findings = ruff.parse(res, ctx)

    assert findings == [], (
        "ruff findings in files this push may not have touched -- CI would "
        "have reported these one round-trip later:\n" +
        "\n".join(f"  {f.file}:{f.line} {f.rule} {f.message}"
                  for f in findings[:20]))


def test_ruff_is_not_in_the_pre_push_tier_so_this_test_is_load_bearing():
    """Guards this file's own reason to exist. If ruff is ever added to the
    pre-push tier, the gate covers the whole tree itself and the test above
    becomes redundant duplication -- worth knowing rather than carrying
    forever. If it is removed from pre-commit too, the test above is the ONLY
    ruff coverage left and must not be deleted with it."""
    assert "ruff" not in GATE_RUNNER_KEYS[Gate.PRE_PUSH]
    assert "ruff" in GATE_RUNNER_KEYS[Gate.PRE_COMMIT]


# --- CI step: "Assert the pre-push gate really ran semgrep" -----------------
#
# CI runs the gate, then reads the RUN_STARTED payload back out of the ledger
# and fails if semgrep is absent. Its reasoning is worth repeating: the gate's
# own exit code cannot tell you a runner ran, because selection is gate- AND
# stack-dependent, so an edit to GATE_RUNNER_KEYS or to applicability could
# quietly shrink the set to nothing and the step would still exit 0.
#
# A test cannot inspect the gate run that is currently executing it, so the
# post-hoc form is not available locally. What IS available is the property
# that makes that assertion meaningful in the first place -- semgrep is both
# SELECTED for this repo and IN the pre-push tier -- which is precisely the
# "quietly shrank the set" regression CI is guarding against. The half not
# covered here is "it ran and completed OK", which stays CI's.

def test_semgrep_is_selected_for_this_repo_at_the_pre_push_tier():
    """The two halves are NOT equally strong, and it is worth writing down
    which is load-bearing. Measured: `selected_tool_names` returns semgrep even
    for a JS-only repo with no python in it at all, so the selection assertion
    really only catches semgrep being removed from the registry outright. The
    TIER assertion is the discriminating one -- that is the set a refactor
    actually shrinks by accident."""
    cfg = config_mod.load_config(REPO)
    selected = toolset.selected_tool_names(REPO, cfg)

    assert "semgrep" in GATE_RUNNER_KEYS[Gate.PRE_PUSH], (
        "semgrep left the pre-push tier -- the gate would pass without ever "
        "running the security ruleset it exists to run")
    assert "semgrep" in selected, (
        f"semgrep is not selected for this repo: {sorted(selected)}. The gate "
        "would exit 0 having exercised no security rules at all.")


def test_the_owasp_ruleset_this_repo_gates_with_actually_exists():
    """The other half of what CI's semgrep step buys: that the vendored
    ruleset RESOLVES, not merely that semgrep is selected. A ruleset that
    moved would otherwise surface first in a consumer repo."""
    from aramid import toolset as _toolset  # noqa: F401  (kept for symmetry)

    rules = REPO / "src" / "aramid" / "rules" / "owasp.yml"
    assert rules.is_file(), f"vendored semgrep ruleset missing at {rules}"
    assert rules.stat().st_size > 0, "vendored semgrep ruleset is empty"
