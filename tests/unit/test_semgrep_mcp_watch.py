"""The daily watch for the semgrep release that lets mcp past 1.29.0.

semgrep pins `mcp==1.29.0`, so the mcp advisories against 1.29.0 stay open for
every install of aramid until a semgrep release admits a newer mcp and this
repo raises its semgrep floor to that release (the operator's plan of
2026-10-30). `.github/scripts/semgrep_mcp_watch.py` reads the newest semgrep's
own wheel metadata on PyPI each day and goes red when the floor can move.

Run as a subprocess against a `--snapshot` of what it would read from PyPI, so
the CLI contract the workflow invokes is what is pinned. Exit codes: 0 still
blocked, 1 act (raise the floor), 2 could not tell. Every red outcome below is
asserted by its exit code, so a script that always says "blocked" fails them.
The one exception is the fetch itself (`_get`), driven in-process near the end
with the network and the clock stubbed.
"""
import contextlib
import importlib.util
import json
import subprocess
import sys
import types
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "semgrep_mcp_watch.py"
WORKFLOW = ROOT / ".github" / "workflows" / "semgrep-mcp-watch.yml"
SCRIPT_REL = ".github/scripts/semgrep_mcp_watch.py"

PYPROJECT = '[project]\nname = "x"\ndependencies = ["click>=8", "semgrep>=1.137,<2"]\n'
WHEELS = ("semgrep-{v}-py3-none-manylinux_2_34_x86_64.whl",
          "semgrep-{v}-py3-none-win_amd64.whl")


def _snapshot(mcp_line="mcp==1.29.0", version="1.183.0",
              mcp_versions=("1.28.1", "1.29.0", "1.30.0", "1.31.0"), wheels=None):
    if wheels is None:
        requires = ["click~=8.1"] + ([mcp_line] if mcp_line is not None else [])
        wheels = {name.format(v=version): requires for name in WHEELS}
    return {"semgrep_version": version, "wheels": wheels,
            "mcp_versions": list(mcp_versions)}


def _run(tmp_path, snapshot, pyproject=PYPROJECT, extra=()):
    snap = tmp_path / "snapshot.json"
    snap.write_text(snapshot if isinstance(snapshot, str) else json.dumps(snapshot),
                    encoding="utf-8")
    args = [sys.executable, str(SCRIPT), "--snapshot", str(snap)]
    if pyproject is not None:
        pp = tmp_path / "pyproject.toml"
        pp.write_text(pyproject, encoding="utf-8")
        args += ["--pyproject", str(pp)]
    r = subprocess.run([*args, *extra], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=60, check=False)
    return r, r.stdout + r.stderr


def _verdict(r, out, code):
    """The script's OWN verdict, not Python's: `python missing.py` also exits 2
    and an uncaught exception exits 1, so the exit code alone cannot tell a
    "could not tell" or an "act" from a script that never ran its logic."""
    assert r.returncode == code, out
    assert "Traceback" not in out, out
    assert "semgrep-mcp-watch:" in out, out
    if code:
        assert "::error::" in out, out


def test_the_script_exists_where_the_workflow_calls_it():
    """Non-vacuity. Every other test here shells out to this path."""
    assert SCRIPT.is_file(), f"no watch script at {SCRIPT}"


# -- still blocked: green ---------------------------------------------------

def test_the_exact_pin_semgrep_ships_today_is_still_blocked(tmp_path):
    """What 1.183.0 says in every wheel (read from PyPI 2026-11-01)."""
    r, out = _run(tmp_path, _snapshot("mcp==1.29.0"))

    _verdict(r, out, 0)
    assert "1.183.0" in out                     # names the release it read
    assert "mcp==1.29.0" in out                 # and the line that blocks
    assert "all 2 wheels" in out                # and how many wheels said so


def test_a_pin_with_an_environment_marker_is_still_blocked(tmp_path):
    r, out = _run(tmp_path, _snapshot('mcp==1.29.0; python_version >= "3.10"'))

    _verdict(r, out, 0)


def test_a_range_capped_below_the_fix_is_still_blocked(tmp_path):
    r, out = _run(tmp_path, _snapshot("mcp>=1.29,<1.30"))

    _verdict(r, out, 0)


MCP_2X = ("1.29.0", "2.0.0", "2.1.0", "2.2.0", "2.3.0")


def test_a_range_inside_the_affected_2x_line_is_still_blocked(tmp_path):
    """OSV (2026-11-01): mcp 2.0.0 and 2.1.0 carry all four advisories again,
    fixed in 2.2.0. A floor raised to a semgrep that admits only those would
    clear nothing, so `>= 1.30.0` alone is the wrong test."""
    r, out = _run(tmp_path, _snapshot("mcp>=2.0,<2.2", mcp_versions=MCP_2X))

    _verdict(r, out, 0)


def test_a_2x_range_past_its_fix_unblocks(tmp_path):
    r, out = _run(tmp_path, _snapshot("mcp>=2.0", version="1.190.0", mcp_versions=MCP_2X))

    _verdict(r, out, 1)
    assert "2.3.0" in out


def test_a_release_candidate_alone_does_not_unblock(tmp_path):
    """A floor can only move to a final mcp release; an rc is not one. The rc
    sits ABOVE 1.30.0: `1.30.0rc1` sorts below 1.30.0, so the threshold alone
    rejected it and this test passed with the rc filter removed (2026-11-01)."""
    r, out = _run(tmp_path, _snapshot("mcp>=1.29", mcp_versions=("1.29.0", "1.31.0rc1")))

    _verdict(r, out, 0)


# -- the floor can move: red, act --------------------------------------------

def test_an_open_range_names_the_newest_mcp_it_allows(tmp_path):
    r, out = _run(tmp_path, _snapshot("mcp>=1.29", version="1.190.0"))

    _verdict(r, out, 1)
    assert "::error::" in out
    assert "1.31.0" in out                      # the newest allowed mcp
    assert "semgrep>=1.190.0" in out            # the floor to raise to
    assert "outside" not in out                 # 1.190.0 fits the current bounds


def test_an_exact_pin_to_the_fixed_release_unblocks(tmp_path):
    r, out = _run(tmp_path, _snapshot("mcp==1.30.0", version="1.190.0"))

    _verdict(r, out, 1)
    assert "1.30.0" in out


def test_a_minimum_above_the_fix_unblocks(tmp_path):
    r, out = _run(tmp_path, _snapshot("mcp>=1.31", version="1.190.0"))

    _verdict(r, out, 1)
    assert "1.31.0" in out


def test_dropping_mcp_altogether_unblocks(tmp_path):
    """No mcp at all clears the advisories just as surely as a newer one."""
    r, out = _run(tmp_path, _snapshot(None, version="1.190.0"))

    _verdict(r, out, 1)
    assert "no longer depends on mcp" in out
    assert "semgrep>=1.190.0" in out


def test_an_mcp_line_behind_an_extra_is_no_dependency_at_all(tmp_path):
    """`mcp==1.29.0; extra == "mcp"` reaches only `pip install semgrep[mcp]`.
    A plain `semgrep>=X` then installs no mcp, which clears the advisories."""
    r, out = _run(tmp_path, _snapshot('mcp==1.29.0; extra == "mcp"', version="1.190.0"))

    _verdict(r, out, 1)
    assert "no longer depends on mcp" in out


def test_a_release_outside_the_current_bounds_says_to_widen_them(tmp_path):
    """pyproject.toml caps semgrep at <2; a 2.x release that admits the fix
    needs the cap widened as well as the floor raised."""
    r, out = _run(tmp_path, _snapshot("mcp>=1.29", version="2.0.0"))

    _verdict(r, out, 1)
    assert "outside" in out
    assert "<2" in out


# -- could not tell: red, never green ------------------------------------------

def test_wheels_that_disagree_are_not_guessed_at(tmp_path):
    wheels = {"semgrep-1.190.0-py3-none-win_amd64.whl": ["mcp==1.29.0"],
              "semgrep-1.190.0-py3-none-macosx_11_0_arm64.whl": ["mcp>=1.29"]}
    r, out = _run(tmp_path, _snapshot(version="1.190.0", wheels=wheels))

    _verdict(r, out, 2)
    assert "disagree" in out


def test_two_mcp_lines_in_one_wheel_are_left_to_a_human(tmp_path):
    """Split by environment, one line may unblock while the other does not;
    judging only the last (or first) line read would guess."""
    requires = ['mcp==1.29.0; python_version < "3.12"', 'mcp>=1.30; python_version >= "3.12"']
    wheels = {name.format(v="1.190.0"): requires for name in WHEELS}
    r, out = _run(tmp_path, _snapshot(version="1.190.0", wheels=wheels))

    _verdict(r, out, 2)
    assert "judge them by hand" in out


def test_a_release_with_no_wheels_is_not_a_pass(tmp_path):
    r, out = _run(tmp_path, _snapshot(wheels={}))

    _verdict(r, out, 2)
    assert "::error::" in out


def test_no_mcp_release_list_is_not_a_pass(tmp_path):
    r, out = _run(tmp_path, _snapshot("mcp>=1.29", mcp_versions=()))

    _verdict(r, out, 2)


def test_an_unparseable_requirement_is_not_a_pass(tmp_path):
    # Not `mcp===!!1.29`: `===` is arbitrary equality, so packaging parses
    # that (checked 2026-11-01) and the test would read a green as a pass.
    r, out = _run(tmp_path, _snapshot("mcp>>=1.29"))
    assert "unparseable" in out

    _verdict(r, out, 2)


def test_an_unreadable_snapshot_is_not_a_pass(tmp_path):
    r, out = _run(tmp_path, "{not json")

    _verdict(r, out, 2)


def test_a_pyproject_without_semgrep_is_not_a_pass(tmp_path):
    r, out = _run(tmp_path, _snapshot("mcp>=1.29", version="1.190.0"),
                  pyproject='[project]\nname = "x"\ndependencies = ["click>=8"]\n')

    _verdict(r, out, 2)


def test_pypi_out_of_reach_is_not_a_pass(tmp_path):
    """The live path: nothing listens on port 9 here, so every read fails."""
    pp = tmp_path / "pyproject.toml"
    pp.write_text(PYPROJECT, encoding="utf-8")
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--pypi", "http://127.0.0.1:9",
         "--attempts", "1", "--pyproject", str(pp)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=120, check=False)

    _verdict(r, r.stdout + r.stderr, 2)
    assert "could not" in (r.stdout + r.stderr).lower()


def test_an_index_that_is_not_http_is_refused_before_it_is_read(tmp_path):
    """The script's S310 `noqa` rests on this check: no `file:` or custom
    scheme reaches urlopen. Without the check a `file:` URL is still read (and
    fails as a missing file), so the reason, not the exit code, is the test."""
    pp = tmp_path / "pyproject.toml"
    pp.write_text(PYPROJECT, encoding="utf-8")
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--pypi", (tmp_path / "index").as_uri(),
         "--attempts", "1", "--pyproject", str(pp)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=60, check=False)

    _verdict(r, r.stdout + r.stderr, 2)
    assert "scheme 'file' is not http(s)" in r.stdout + r.stderr


def test_the_default_pyproject_is_this_repos(tmp_path):
    """Without --pyproject the script reads the repo's own file; it must find
    the semgrep requirement there, or every real run is a 'could not tell'."""
    r, out = _run(tmp_path, _snapshot("mcp==1.29.0"), pyproject=None)

    _verdict(r, out, 0)


# -- the fetch: drain findings ----------------------------------------------
# The 15:00Z drain of 2026-11-01 mutated `_get` and three mutants survived
# (ledger rows 5d92cfec, 1444a9ba, 1f84bac7): the attempt floor, the wait
# between attempts and the request timeout. Every test above reads a snapshot,
# so none of them ever fetched. These drive `_get` in-process, in a freshly
# loaded copy of the script whose own `urllib` and `time` names are replaced:
# nothing global is patched, nothing touches the network and nothing waits.

def _offline(answer=None):
    """A fresh copy of the script whose fetches are recorded, not made. Each
    request's timeout is recorded in `calls`, each wait in `sleeps`; a request
    fails as an unreachable host would, unless `answer` is given."""
    spec = importlib.util.spec_from_file_location("semgrep_mcp_watch", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    calls, sleeps = [], []

    @contextlib.contextmanager
    def urlopen(request, timeout=None):
        calls.append(timeout)
        if answer is None:
            raise urllib.error.URLError("unreachable (stub)")
        yield types.SimpleNamespace(read=lambda: answer)

    mod.urllib = types.SimpleNamespace(
        parse=urllib.parse, error=urllib.error,
        request=types.SimpleNamespace(Request=urllib.request.Request,
                                      urlopen=urlopen))
    mod.time = types.SimpleNamespace(sleep=sleeps.append)
    return mod, calls, sleeps


def test_one_attempt_asked_for_is_one_request_and_no_wait():
    """Row 5d92cfec (`max(attempts, 1)` -> `max(attempts, 2)`). Zero asked for
    is still one request, so a mis-set --attempts cannot skip the read."""
    for asked in (1, 0):
        mod, calls, sleeps = _offline()

        with pytest.raises(mod.CouldNotTell, match="could not read"):
            mod._get("https://pypi.invalid/x", "application/json", asked)

        assert len(calls) == 1, f"--attempts {asked}: {len(calls)} requests"
        assert sleeps == [], f"--attempts {asked}: waited {sleeps}"


def test_each_retry_waits_five_seconds_more_than_the_one_before():
    """Row 1444a9ba (`5 * attempt` -> `6 * attempt`). Three attempts against an
    index that never answers: no wait before the first, 5 s, then 10 s."""
    mod, calls, sleeps = _offline()

    with pytest.raises(mod.CouldNotTell, match="could not read"):
        mod._get("https://pypi.invalid/x", "application/json", 3)

    assert len(calls) == 3
    assert sleeps == [5, 10]


def test_a_request_gives_up_after_thirty_seconds():
    """Row 1f84bac7 (`timeout=30` -> `timeout=31`). Without a timeout urlopen
    waits forever, and a hung PyPI would hold the job to its 10-minute limit.
    The exact 30 is a pinned number; no outcome depends on it being 30 and not
    31. Also the one path where the first request answers."""
    mod, calls, sleeps = _offline(answer=b'{"ok": true}')

    body = mod._get("https://pypi.invalid/x", "application/json", 3)

    assert body == b'{"ok": true}'
    assert calls == [30]
    assert sleeps == []


# -- the workflow -----------------------------------------------------------

def _workflow():
    assert WORKFLOW.is_file(), f"no workflow at {WORKFLOW}"
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_the_workflow_runs_daily_and_on_demand_only():
    wf = _workflow()
    triggers = wf.get("on", wf.get(True))     # YAML 1.1 reads a bare `on` as True

    assert set(triggers) == {"schedule", "workflow_dispatch"}, (
        "a network read of PyPI must not run on push or pull_request: it would "
        "turn every push red on a PyPI outage")
    assert triggers["schedule"] and triggers["schedule"][0]["cron"]


def test_the_workflow_can_only_read():
    assert _workflow()["permissions"] == {"contents": "read"}


def test_the_workflow_runs_the_script_and_lets_a_red_stay_red():
    jobs = _workflow()["jobs"]
    steps = [s for job in jobs.values() for s in job["steps"]]

    assert any(SCRIPT_REL in s.get("run", "") for s in steps), (
        f"no step runs {SCRIPT_REL}")
    assert not any("continue-on-error" in d
                   for d in [*jobs.values(), *steps]), (
        "continue-on-error would turn the alert into a green run")
