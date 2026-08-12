"""integration: Task 8.1b -- fingerprint cross-mode id stability (spec
section 4) and stale-override re-fire (spec section 4, "Stale-override
rule").

Part A drives the REAL `pipeline.run_gate` against a single ruff-caught
violation (`exec(x)` -> S102) through the three git-object-reading MODES
(`pipeline._ref_for_builder`'s "staged"/"range"/"all") and asserts the
produced finding id (fingerprint) is IDENTICAL across all three -- proving
the per-mode blob-reading strategy in `gitutil.read_for_fingerprint` /
`normalizer.normalize` does not churn ids.

Part B takes that id, records a ledger override for it (the same
`Ledger.append(Event(FINDING_OVERRIDDEN, ...))` mechanism
`commands.override.cmd_override` uses and the exact source
`pipeline._overrides_from_ledger` reads), edits the violating line (still a
violation, different line content -> a different fingerprint), re-scans, and
asserts the finding RE-FIRES at its normal (BLOCK) tier -- the stale
override is not honored -- while `GateResult.stale_overrides` /
`reporter.render_console` surface the now-stale override record's
re-affirm line.

ADAPTATION (documented, not a workaround for a bug): `pipeline.GATE_RUNNER_KEYS`
wires ruff into `Gate.PRE_COMMIT` ONLY (design doc section 3's tool matrix --
ruff/S-rules appear exclusively in the pre-commit table, never the pre-push
one). A literal `Gate.PRE_PUSH` or `Gate.ALL` run would therefore never
select ruff at all and produce zero findings, proving nothing about
cross-mode id stability. `_discover_files`/`_ref_for_builder` -- the
functions that actually implement the spec's per-MODE (not per-gate)
blob-reading strategy -- key purely off the `mode` string
("staged"/"range"/"all"), entirely independent of `gate` (`gate` only drives
runner *selection*, the ratchet, and the wall-clock budget key). So every
call below holds `gate=Gate.PRE_COMMIT` fixed (keeps ruff selected, real
live tool) and varies only `mode`. This is the real, public
`pipeline.run_gate` function -- not a hand-called internal -- exercising
exactly the mechanism (`_discover_files` + `_ref_for_builder` +
`normalizer.normalize`) the spec's cross-mode-stability claim is about.

Similarly, Part B bypasses `commands.override.cmd_override` for the ONE
step of *recording* the override: that command actively refuses to override
a BLOCK-tier finding (design doc section 6 -- BLOCK requires a reviewed,
committed `.aramid-suppressions.toml` entry instead), and ruff S102 is
unconditionally BLOCK (no armed/bake gate -- `policy.classify` blocks on
rule-id membership in `block_rules.toml`'s `[ruff] block` list alone), so
the real CLI command cannot be used here. We go straight to the ledger
event the pipeline itself consumes ("the ledger/OverrideRecord path used by
the pipeline", per the task brief) -- bypassing only the command layer's UX
guard, not any pipeline/policy mechanism.
"""
import os
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from aramid import config as config_mod
from aramid import gitutil, pipeline, reporter
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Gate, Verdict
from aramid.runners.base import RunnerResult, ToolState

# --------------------------------------------------- live-ruff discovery ----
# Same search strategy as tests/integration/test_semgrep_rules.py's
# `_find_semgrep` / test_gates_end_to_end.py's `_find_tool`: ruff installs
# into this machine's per-user Scripts dir, not on PATH by default.


def _find_tool(name: str) -> Path | None:
    candidates: list[Path] = []
    which = shutil.which(name)
    if which:
        candidates.append(Path(which))
    exe_dir = Path(sys.executable).parent
    candidates.append(exe_dir / "Scripts" / f"{name}.exe")
    candidates.append(exe_dir / name)
    for entry in sys.path:
        p = Path(entry)
        if p.name == "site-packages":
            candidates.append(p.parent / "Scripts" / f"{name}.exe")
            candidates.append(p.parent / "bin" / name)
    for c in candidates:
        if c.exists():
            return c
    return None


_RUFF_BIN = _find_tool("ruff")
_SKIP_RUFF = "ruff console-script not found (see test_semgrep_rules.py discovery pattern)"


@pytest.fixture
def live_ruff_path_env(monkeypatch):
    if _RUFF_BIN is not None:
        monkeypatch.setenv("PATH", str(_RUFF_BIN.parent) + os.pathsep + os.environ.get("PATH", ""))


# --------------------------------------------------------- repo builder -----

def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(root), check=True, capture_output=True, text=True)


def _init_repo_with_upstream(tmp_path: Path, name: str = "repo") -> Path:
    """git init + a real bare 'origin' remote, with an initial commit pushed
    and tracked as the upstream. Needed so `gitutil.resolve_range` resolves
    to a genuine `@{u}..HEAD` range (rather than falling back to the literal
    string "HEAD"), so the "range" (pre-push) mode below reads the seeded
    violation from an actual commit sha -- not a same-string-as-"--all"
    coincidence that would prove nothing about distinct blob-reading modes.
    """
    bare = tmp_path / f"{name}-origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)],
                    check=True, capture_output=True, text=True)

    root = tmp_path / name
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")
    (root / "README.md").write_text("seed\n", encoding="utf-8")
    _git(root, "add", "README.md")
    _git(root, "commit", "-q", "-m", "initial")
    _git(root, "remote", "add", "origin", str(bare))
    _git(root, "push", "-q", "-u", "origin", "main")
    return root


def _no_user_config(tmp_path: Path, monkeypatch) -> None:
    """Never let a test read a real ~/.aramid/config.toml off this machine."""
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user-config.toml")


def _gitleaks_clean():
    """gitleaks is not installed on this machine and there is no network --
    fixture double, same pattern as test_gates_end_to_end.py's own
    `_gitleaks_clean`. Every other selected runner (ruff) is live."""
    return SimpleNamespace(run=lambda ctx: RunnerResult("gitleaks", ToolState.OK),
                            parse=lambda result, ctx: [])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _s102(findings):
    matches = [f for f in findings if f.tool == "ruff" and f.rule == "S102"]
    assert len(matches) == 1, findings
    return matches[0]


_EXEC_SRC = "def run_it(x):\n    exec(x)\n"
_EXEC_SRC_EDITED = "def run_it(x):\n    exec(y)\n"


# =============================================== Part A: cross-mode ids =====

@pytest.mark.skipif(_RUFF_BIN is None, reason=_SKIP_RUFF)
def test_fingerprint_identical_across_precommit_prepush_all_modes(
        tmp_path, monkeypatch, live_ruff_path_env):
    root = _init_repo_with_upstream(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks", _gitleaks_clean())

    (root / "danger.py").write_text(_EXEC_SRC, encoding="utf-8")
    _git(root, "add", "danger.py")  # staged, NOT committed yet

    cfg = config_mod.load_config(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        # 1. pre-commit mode: reads the INDEX blob (`git show :path`, ref ":").
        result_staged = pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg, ledger,
                                           run_id="r-staged")
        id_staged = _s102(result_staged.findings).id

        # Commit (do NOT push) -- HEAD now sits one commit ahead of
        # origin/main, exactly the "about to be pushed" pre-push shape.
        _git(root, "commit", "-q", "-m", "seed violation")

        # Sanity check the range really does resolve to a genuine commit
        # sha (not the fallback literal "HEAD") before trusting the id
        # comparison below to mean anything about distinct blob-reading modes.
        rng = gitutil.resolve_range(root)
        assert rng is not None and rng.endswith("..HEAD")
        commit_sha = gitutil.newest_commit_touching(root, rng, "danger.py")
        assert commit_sha != "HEAD"
        assert len(commit_sha) == 40 and all(c in "0123456789abcdef" for c in commit_sha)

        # 2. pre-push mode: reads the COMMIT blob (`git show <sha>:path`).
        result_range = pipeline.run_gate(root, Gate.PRE_COMMIT, "range", cfg, ledger,
                                          run_id="r-range")
        id_range = _s102(result_range.findings).id

        # 3. --all mode: reads the HEAD blob (`git show HEAD:path`).
        result_all = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger,
                                        run_id="r-all")
        id_all = _s102(result_all.findings).id
    finally:
        ledger.close()

    assert id_staged == id_range == id_all, (id_staged, id_range, id_all)


# ==================================== Part B: stale-override re-fire ========

@pytest.mark.skipif(_RUFF_BIN is None, reason=_SKIP_RUFF)
def test_stale_override_re_fires_at_normal_tier_after_line_edit(
        tmp_path, monkeypatch, live_ruff_path_env):
    root = _init_repo_with_upstream(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks", _gitleaks_clean())

    (root / "danger.py").write_text(_EXEC_SRC, encoding="utf-8")
    _git(root, "add", "danger.py")
    _git(root, "commit", "-q", "-m", "seed violation")

    cfg = config_mod.load_config(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        # "Part A" id for this violation (same tool/rule/path/line-content ->
        # same fingerprint as Part A's own id_all, by construction).
        result1 = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger, run_id="r1")
        original = _s102(result1.findings)
        assert original.verdict is Verdict.BLOCK  # ruff S102 is unconditional BLOCK

        # Record an override for it directly via the ledger event
        # `cmd_override` itself appends -- "the ledger/OverrideRecord path
        # used by the pipeline" (see module docstring for why the real
        # `cmd_override` CLI command can't be used for a BLOCK-tier finding).
        ledger.append(Event(EventType.FINDING_OVERRIDDEN, uuid.uuid4().hex, _now(),
                             finding_id=original.id,
                             payload={"reason": "tracked in TICKET-1, will fix properly"}))
        assert ledger.open_findings()[original.id]["status"] == "overridden"

        # Edit the violating line: still S102 (exec of a name), different
        # line content -> a different fingerprint (line content is hashed
        # into the id; the override's old id can never match again).
        (root / "danger.py").write_text(_EXEC_SRC_EDITED, encoding="utf-8")
        _git(root, "add", "danger.py")
        _git(root, "commit", "-q", "-m", "edit violating line")

        result2 = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger, run_id="r2")

        refired = _s102(result2.findings)
        # The id genuinely changed (proves the edit altered the fingerprint,
        # not merely re-detected the same one).
        assert refired.id != original.id
        # Re-fires at its NORMAL tier: still classified BLOCK by `policy.classify`
        # (ruff S102 is unconditional BLOCK, no armed/bake gate) and it BLOCKS
        # the run. NOTE: this by itself is NOT proof the override was ignored
        # -- `policy.apply_overrides` only ever downgrades a WARN verdict to
        # INFO (never BLOCK -> INFO), so a BLOCK-tier finding like this one
        # stays BLOCK whether an override for it is stale OR still fresh/
        # matching. The load-bearing proof that the STALE override was
        # specifically detected (not honored, not silently dropped) is the
        # `stale_overrides` / `render_console` assertions below -- see the
        # module docstring and task-81b-report.md for why S102 (reused from
        # Part A) being BLOCK-tier makes the verdict assertion necessary-but-
        # not-sufficient here.
        assert refired.verdict is Verdict.BLOCK
        assert result2.exit_code == 1

        # GateResult.stale_overrides carries the now-stale override record --
        # this (plus the render_console assertions below) is what actually
        # proves the stale override was detected and surfaced, not honored.
        stale_ids = {r.id for r in result2.stale_overrides}
        assert original.id in stale_ids

        # reporter.render_console surfaces the stale-override re-affirm line.
        console = reporter.render_console(result2, ledger)
    finally:
        ledger.close()

    assert "stale override" in console
    assert original.id in console
    assert "aramid override" in console
    assert ".aramid-suppressions.toml" in console


# ============ Part C: the id must follow the bytes that were SCANNED ========
# Part A proves ids agree across modes when the working tree and the git object
# agree. They do not always agree, and nothing above tested that.
#
# `normalizer.normalize` takes the line NUMBER from the scanner (which read the
# working tree) and the line CONTENT from a blob chosen by `_ref_for_builder`
# (the INDEX at pre-commit). An ordinary partially-staged edit desynchronises
# them, and the fingerprint then hashes a DIFFERENT LINE OF CODE than the one
# that was flagged.
#
# Reported from a downstream repo as "suppression ids bind to position, so a
# cosmetic edit un-suppresses". That diagnosis is wrong -- compute_fingerprint
# has no line number in it and a STAGED comment insertion is stable (measured).
# The premise was right and the mechanism was not, which is why this is pinned
# by the invariant rather than by the symptom they saw.


def _staged(root: Path, src: str) -> None:
    """Write `src` and stage it.

    danger.py is deliberately never COMMITTED in Part C. `staged_files` diffs
    the index against HEAD, so a committed file re-staged with identical
    content stages nothing, leaves scope, and the gate returns zero findings --
    which reads exactly like "the ids matched". The first version of these
    tests committed it and failed with `assert 0 == 1` instead of an id
    mismatch. Left uncommitted, danger.py is an added path and stays in scope
    no matter what its content is.
    """
    (root / "danger.py").write_text(src, encoding="utf-8")
    _git(root, "add", "danger.py")


@pytest.mark.skipif(_RUFF_BIN is None, reason=_SKIP_RUFF)
def test_fingerprint_follows_the_scanned_bytes_not_the_staged_blob(
        tmp_path, monkeypatch, live_ruff_path_env):
    root = _init_repo_with_upstream(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks", _gitleaks_clean())

    cfg = config_mod.load_config(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        # Reference ids, each with the index and the working tree in agreement.
        _staged(root, _EXEC_SRC)
        id_x = _s102(pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg,
                                        ledger, run_id="c-x").findings).id
        _staged(root, _EXEC_SRC_EDITED)
        id_y = _s102(pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg,
                                        ledger, run_id="c-y").findings).id
        assert id_x != id_y, \
            "precondition: the two line contents must fingerprint differently"

        # SKEW: index holds exec(x); the working tree -- the bytes ruff reads --
        # holds exec(y). Nothing here is exotic; it is an unstaged edit.
        _staged(root, _EXEC_SRC)
        (root / "danger.py").write_text(_EXEC_SRC_EDITED, encoding="utf-8")
        skewed = _s102(pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg,
                                          ledger, run_id="c-skew").findings)
    finally:
        ledger.close()

    assert skewed.id == id_y, (
        "the finding was raised against exec(y) -- the line ruff actually read "
        "-- so its identity must be exec(y)'s")
    assert skewed.id != id_x, (
        "hashing the INDEX line means this finding is identified by a line of "
        "code that was never flagged")


@pytest.mark.skipif(_RUFF_BIN is None, reason=_SKIP_RUFF)
def test_a_suppression_cannot_be_inherited_by_a_line_it_never_adjudicated(
        tmp_path, monkeypatch, live_ruff_path_env):
    """The consequence the test above exists to prevent, pinned separately.

    Under the skew, an unreviewed statement is reported under a SUPPRESSED
    finding's id and silently downgraded to INFO -- a suppression written for
    one line covering a different one. Measured before the fix with a firing
    control (the same suppression bound correctly with no skew), so this is the
    security direction, not a hypothetical.
    """
    root = _init_repo_with_upstream(tmp_path)
    _no_user_config(tmp_path, monkeypatch)
    monkeypatch.setitem(pipeline.RUNNERS, "gitleaks", _gitleaks_clean())

    cfg = config_mod.load_config(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        _staged(root, _EXEC_SRC)
        adjudicated = _s102(pipeline.run_gate(root, Gate.PRE_COMMIT, "staged",
                                               cfg, ledger, run_id="d-1").findings)
        (root / ".aramid-suppressions.toml").write_text(
            "[[suppress]]\n"
            f'id = "{adjudicated.id}"\n'
            'tool = "ruff"\nrule = "S102"\npath = "danger.py"\n'
            'reason = "reviewed: exec(x) is fed from an internal allowlist"\n',
            encoding="utf-8")

        # Control: with no skew the suppression binds, so a later INFO cannot
        # be mistaken for "suppressions never work here".
        _staged(root, _EXEC_SRC)
        bound = _s102(pipeline.run_gate(root, Gate.PRE_COMMIT, "staged", cfg,
                                         ledger, run_id="d-2").findings)
        assert bound.verdict is Verdict.INFO, \
            "control: the suppression must bind when nothing is skewed"

        # Treatment: index still exec(x) (the adjudicated line); disk is
        # exec(y), which nobody reviewed.
        _staged(root, _EXEC_SRC)
        (root / "danger.py").write_text(_EXEC_SRC_EDITED, encoding="utf-8")
        unreviewed = _s102(pipeline.run_gate(root, Gate.PRE_COMMIT, "staged",
                                              cfg, ledger, run_id="d-3").findings)
    finally:
        ledger.close()

    assert unreviewed.id != adjudicated.id, \
        "an unreviewed line must not inherit an adjudicated line's identity"
    assert unreviewed.verdict is Verdict.BLOCK, \
        "an unreviewed exec() must not be suppressed by a decision made about a different line"
