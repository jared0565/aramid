"""Guard on THIS repo's own ruff configuration (pyproject.toml).

aramid runs ruff with `--extend-select S` (the bandit-derived security family)
against every repo it gates, including itself. Its own test tree spawns `git`
and `python` by design, which trips two of those rules:

  S603  `subprocess` call: check for execution of untrusted input
  S607  Starting a process with a partial executable path

`pyproject.toml` already exempts the other deliberate-in-tests members of the S
family -- S101 (bare `assert`, which pytest requires) and S105/S106/S107 (fake
secret fixtures that exercise the secret-handling paths). S603/S607 are the
same shape of finding and were simply never added alongside them.

Left unexempted they produced 68 permanently-open findings against aramid's own
test tree -- the single largest source of noise in its own ledger, and exactly
the noise that teaches an operator to ignore a security tool.

This guards the exemption rather than the count: the S family stays fully armed
for `src/`, so a real subprocess risk in shipped code still blocks.
"""
from pathlib import Path

from aramid.runners import ruff
from aramid.runners.base import RunContext, ToolState

# A file that genuinely spawns processes, so the rules have something to fire
# on. If this ever stops using subprocess the test goes vacuous, so the run
# below asserts the finding set is non-empty overall before checking codes.
SUBPROCESS_USING_TEST = "tests/e2e/test_hook_fires.py"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_repo_config_exempts_deliberate_subprocess_use_in_tests():
    """Fails if the per-file-ignores entry for `tests/**` loses S603/S607:
    aramid's own gate then reports them against its own test tree."""
    root = _repo_root()
    assert (root / SUBPROCESS_USING_TEST).exists(), (
        f"{SUBPROCESS_USING_TEST} moved -- repoint this guard at another "
        "subprocess-using test or it silently stops testing anything")

    ctx = RunContext(root=root, files=[SUBPROCESS_USING_TEST])
    result = ruff.run(ctx)
    assert result.state is ToolState.OK, (
        f"ruff did not run cleanly (state={result.state}); a crashed run "
        "reports no findings and would make this test vacuously pass")

    codes = {f.rule for f in ruff.parse(result, ctx)}
    assert not ({"S603", "S607"} & codes), (
        f"ruff reports {sorted({'S603', 'S607'} & codes)} against "
        f"{SUBPROCESS_USING_TEST}. Add them to [tool.ruff.lint.per-file-ignores] "
        'for "tests/**" in pyproject.toml, alongside S101/S105/S106/S107.')


def test_security_family_stays_armed_for_src():
    """The companion guarantee: exempting tests/ must not disarm the S family
    for shipped code. Fails if a blanket ignore is added at the top level."""
    root = _repo_root()
    ctx = RunContext(root=root, files=["src/aramid/red_proof.py"])
    result = ruff.run(ctx)
    assert result.state is ToolState.OK

    codes = {f.rule for f in ruff.parse(result, ctx)}
    assert any(c.startswith("S") for c in codes), (
        "no S-family finding in src/aramid/red_proof.py -- it carries a known "
        "S112 (try-except-continue). If that was fixed, repoint this at "
        "another src file with a live S finding; do not delete the guard.")
