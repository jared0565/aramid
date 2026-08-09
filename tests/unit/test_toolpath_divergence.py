"""A tool aramid DECLARES AS A DEPENDENCY can be shadowed on PATH by an
unrelated copy, and aramid then runs the unrelated copy silently.

Measured on the published 0.2.0 artifact, in a clean venv, on the same file:

    ruff 0.15.18 (PATH, what aramid ran)  -> F401
    ruff 0.16.2  (venv, what pip installed) -> F401 + I001 + PLW1510

Same aramid, same input, different verdicts. That defeats the thing the
dependency pin is for, and it defeats `pre_push_match_ci` one layer down --
CI installs into a fresh environment with no global ruff and gets 0.16.2,
while a developer with an old user-scheme ruff gets 0.15.18, so the gate that
exists to make local match CI cannot.

PATH-first is NOT changed by any of this and these tests do not ask for that.
`toolpath`'s search order is deliberate ("the operator's own toolchain always
wins") and the one-resolution-path invariant is load-bearing. What was wrong
is that the divergence was SILENT. These pin that it is reported.
"""
import shutil
import sys

import pytest

from aramid import toolpath


@pytest.fixture
def two_copies(tmp_path, monkeypatch):
    """A PATH copy and an interpreter console-script copy that are genuinely
    DIFFERENT FILES.

    Deliberately not tested against this machine's real ruff: that setup
    happens to exist here today and would rot into a vacuous pass the moment
    someone uninstalls the global copy. Planted files make the divergence a
    property of the test, not of the host.
    """
    on_path = tmp_path / "path-bin" / toolpath.exe_name("ruff")
    in_venv = tmp_path / "venv-scripts" / toolpath.exe_name("ruff")
    for p, body in ((on_path, "#path copy"), (in_venv, "#venv copy")):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")

    monkeypatch.setattr(shutil, "which",
                        lambda name, *a, **k: str(on_path) if name == "ruff" else None)
    monkeypatch.setattr(toolpath, "scripts_dirs", lambda: [in_venv.parent])
    return on_path, in_venv


def test_divergence_names_both_paths_when_they_differ(two_copies):
    on_path, in_venv = two_copies

    div = toolpath.divergence("ruff")

    assert div is not None, "a shadowed dependency reported no divergence"
    assert div.resolved == on_path
    assert div.dependency_copy == in_venv


def test_resolution_itself_is_unchanged_path_still_wins(two_copies):
    # The whole point: report the divergence, do NOT reorder the search.
    on_path, _ = two_copies
    assert toolpath.resolve("ruff") == on_path


def test_no_divergence_when_path_resolves_to_the_dependency_copy(tmp_path, monkeypatch):
    same = tmp_path / "scripts" / toolpath.exe_name("ruff")
    same.parent.mkdir(parents=True)
    same.write_text("#the one copy", encoding="utf-8")
    monkeypatch.setattr(shutil, "which",
                        lambda name, *a, **k: str(same) if name == "ruff" else None)
    monkeypatch.setattr(toolpath, "scripts_dirs", lambda: [same.parent])

    assert toolpath.divergence("ruff") is None


def test_no_divergence_when_there_is_no_dependency_copy_at_all(tmp_path, monkeypatch):
    """The ordinary case for a user who installed the analyzers themselves and
    has no venv copy. Silence is correct here -- a notice on every run would
    train people to ignore it."""
    on_path = tmp_path / "path-bin" / toolpath.exe_name("ruff")
    on_path.parent.mkdir(parents=True)
    on_path.write_text("#only copy", encoding="utf-8")
    monkeypatch.setattr(shutil, "which",
                        lambda name, *a, **k: str(on_path) if name == "ruff" else None)
    monkeypatch.setattr(toolpath, "scripts_dirs", lambda: [tmp_path / "empty"])

    assert toolpath.divergence("ruff") is None


def test_gitleaks_is_not_a_declared_dependency_so_never_diverges(tmp_path, monkeypatch):
    """gitleaks is a downloaded binary in `~/.aramid/tools`, not a pip
    dependency. PATH beating aramid's managed copy is the documented,
    intended behaviour there -- exactly what the module docstring means by
    'aramid's managed copy is a fallback, never an override' -- so it must
    NOT be reported as drift."""
    on_path = tmp_path / "path-bin" / toolpath.exe_name("gitleaks")
    managed = tmp_path / "venv-scripts" / toolpath.exe_name("gitleaks")
    for p in (on_path, managed):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("#x", encoding="utf-8")
    monkeypatch.setattr(shutil, "which",
                        lambda name, *a, **k: str(on_path) if name == "gitleaks" else None)
    monkeypatch.setattr(toolpath, "scripts_dirs", lambda: [managed.parent])

    assert toolpath.divergence("gitleaks") is None


def test_the_dependency_list_matches_what_the_package_actually_declares():
    """A hand-maintained list of "tools aramid depends on" is exactly the kind
    of literal that goes stale silently -- add a dependency, forget the set,
    and its drift stops being reported with nothing failing. Checked against
    the INSTALLED metadata, which is what ships.
    """
    from importlib.metadata import PackageNotFoundError, requires
    try:
        declared = requires("aramid") or []
    except PackageNotFoundError:  # pragma: no cover - aramid is always installed here
        pytest.skip("aramid metadata unavailable")

    import re
    names = {re.split(r"[<>=!~;\[ ]", r.strip())[0] for r in declared}
    # Only the ones that actually ship an executable aramid shells out to.
    executable_deps = names & {"ruff", "semgrep", "pip-audit"}

    assert toolpath.DEPENDENCY_TOOLS <= names, (
        f"DEPENDENCY_TOOLS names something aramid does not depend on: "
        f"{toolpath.DEPENDENCY_TOOLS - names}")
    assert executable_deps <= toolpath.DEPENDENCY_TOOLS, (
        f"a declared executable dependency is missing from DEPENDENCY_TOOLS, so its "
        f"drift would go unreported: {executable_deps - toolpath.DEPENDENCY_TOOLS}")


def test_doctor_names_both_paths_and_both_versions(two_copies, monkeypatch):
    """Asserting merely that doctor "mentions ruff twice" would pass whether
    or not the two copies actually differ. The discriminating content is BOTH
    absolute paths -- that is what lets a reader tell which analyzer produced
    a finding set -- so that is what is asserted."""
    from aramid.commands import doctor
    on_path, in_venv = two_copies
    monkeypatch.setattr(doctor, "_version_of", lambda p: "0.16.2" if p == in_venv else "0.15.18")

    lines = doctor.divergence_lines()

    assert lines, "a shadowed dependency produced no doctor output"
    blob = "\n".join(lines)
    assert str(on_path) in blob
    assert str(in_venv) in blob
    assert "0.15.18" in blob and "0.16.2" in blob
    assert "ruff" in blob


def test_cmd_doctor_actually_prints_the_divergence(tmp_path, monkeypatch, capsys):
    """The helper being correct is worth nothing if `cmd_doctor` never calls
    it. Pinning the wiring separately, because a tested-but-uncalled helper
    passes every test above."""
    from aramid.commands import doctor
    monkeypatch.setattr(doctor, "divergence_lines",
                        lambda: ["  DRIFT    ruff         running 0.15.18"])
    try:
        doctor.cmd_doctor(tmp_path)
    except SystemExit:
        pass
    assert "DRIFT    ruff" in capsys.readouterr().out


def test_doctor_does_not_cry_drift_when_both_copies_are_the_same_version(two_copies, monkeypatch):
    """Two different FILES of the same VERSION cannot produce different
    findings, so reporting them teaches the reader to skip the notice. Found
    by rendering the real output rather than by the assertions above: on this
    machine `pip-audit` diverges by path with 2.10.1 on both sides, and the
    first version of this printed it as DRIFT.

    Version equality is judged HERE and not in `toolpath.divergence`, which
    deliberately runs no subprocess -- provenance in the gate JSON still
    records the differing paths as fact. This suppresses a WARNING, not a
    record."""
    from aramid.commands import doctor
    monkeypatch.setattr(doctor, "_version_of", lambda p: "2.10.1")

    assert doctor.divergence_lines() == []


def test_doctor_still_reports_drift_when_a_version_cannot_be_read(two_copies, monkeypatch):
    """Unknown is not the same as equal. If either copy will not answer
    `--version`, the safe report is to name both paths -- silence there would
    hide the case where the unreadable binary is the broken one."""
    from aramid.commands import doctor
    monkeypatch.setattr(doctor, "_version_of", lambda p: "")

    assert doctor.divergence_lines(), "unknown versions were treated as agreement"


def test_doctor_is_silent_when_nothing_diverges(monkeypatch):
    from aramid.commands import doctor
    monkeypatch.setattr(toolpath, "divergences", list)
    assert doctor.divergence_lines() == []


def test_gate_json_records_which_analyzer_binary_produced_the_findings():
    """A finding set is only comparable to another finding set if you know
    which analyzer produced it. `doctor` reporting drift is advisory and
    happens at a different time than the run; the run's OWN output is what
    someone reads when CI and local disagree, so provenance belongs there.
    """
    import json

    from aramid import reporter
    from aramid.pipeline import GateResult

    result = GateResult(exit_code=0, findings=[], degraded=[], new_ids=[],
                        stale_overrides=[], run_id="r1",
                        tool_provenance={"ruff": {"path": "/a/bin/ruff",
                                                   "dependency_copy": "/venv/bin/ruff"},
                                          "semgrep": {"path": "/venv/bin/semgrep"}})

    payload = json.loads(reporter.render_json(result))

    assert payload["tools"]["ruff"]["path"] == "/a/bin/ruff"
    # present ONLY when it differs -- that is what makes it worth reading
    assert payload["tools"]["ruff"]["dependency_copy"] == "/venv/bin/ruff"
    assert "dependency_copy" not in payload["tools"]["semgrep"]


def test_run_gate_populates_provenance_for_the_runners_that_ran(tmp_path, monkeypatch):
    """Recording provenance is worthless if `run_gate` never fills it in.
    Pinned separately from the serialization, because the reporter tests pass
    against a hand-built GateResult and would not notice a field that is
    always empty in real runs."""
    import sys as _sys
    _sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
    from unit.test_pipeline import _cfg, _ledger, _repo  # reuse the real harness

    from aramid import pipeline as pl
    from aramid.models import Gate

    root = _repo(tmp_path)
    cfg = _cfg(root, tmp_path, monkeypatch)
    ledger = _ledger(tmp_path)
    monkeypatch.setitem(pl.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, ["ruff"])
    monkeypatch.setattr(toolpath, "resolve",
                        lambda n: __import__("pathlib").Path(f"/fake/bin/{n}"))
    monkeypatch.setattr(toolpath, "divergence", lambda n, resolved=None: None)

    result = pl.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger, run_id="prov")
    ledger.close()

    assert "ruff" in result.tool_provenance, result.tool_provenance
    assert result.tool_provenance["ruff"]["path"].endswith("ruff")


def test_provenance_does_not_probe_runner_keys_that_are_not_binaries(monkeypatch):
    """`tests`, `deps`, `typecheck`, `eslint` and `clippy` are REGISTRY KEYS,
    not executables -- there is no `tests.exe`. The first version of this
    resolved every selected key, so on Windows (72 PATH entries x PATHEXT)
    each miss cost ~110ms to discover nothing, and the entry never appeared
    anyway. Measured: 1146ms per gate invocation, on the latency-sensitive
    pre-commit path.

    This is a CORRECTNESS assertion that happens to buy the speed: probing a
    name that cannot exist is not a slow success, it is a wrong question.
    """
    from aramid import pipeline as pl
    asked = []
    monkeypatch.setattr(pl.toolpath, "resolve", lambda n: asked.append(n) or None)
    monkeypatch.setattr(pl.toolpath, "divergence", lambda n, resolved=None: None)

    pl._tool_provenance({k: None for k in
                          ["gitleaks", "ruff", "semgrep", "eslint", "clippy",
                           "typecheck", "deps", "tests"]})

    assert set(asked) == {"gitleaks", "ruff", "semgrep"}, (
        f"probed names that are not binaries: {set(asked) - {'gitleaks','ruff','semgrep'}}")


def test_provenance_resolves_each_tool_exactly_once(monkeypatch):
    """`divergence()` called `resolve()` internally, so every dependency tool
    was looked up TWICE per gate run -- ~100ms of `shutil.which` each time,
    for an answer the caller already had."""
    from aramid import pipeline as pl
    from pathlib import Path as _P
    calls = []

    def counting_resolve(n):
        calls.append(n)
        return _P(f"/bin/{n}")

    monkeypatch.setattr(pl.toolpath, "resolve", counting_resolve)
    pl._tool_provenance({k: None for k in ["ruff", "semgrep"]})

    assert calls == sorted(calls) or True  # order is not the point
    assert len(calls) == 2, f"resolved {len(calls)} times for 2 tools: {calls}"


def test_divergence_uses_a_supplied_resolution_instead_of_redoing_it(two_copies, monkeypatch):
    """The seam that makes the above possible: a caller that has already
    resolved can hand the answer in. Must produce the same verdict as the
    self-resolving path."""
    on_path, in_venv = two_copies
    called = []
    real_resolve = toolpath.resolve
    monkeypatch.setattr(toolpath, "resolve",
                        lambda n: called.append(n) or real_resolve(n))

    div = toolpath.divergence("ruff", resolved=on_path)

    assert called == [], "divergence re-resolved despite being handed the path"
    assert div is not None and div.dependency_copy == in_venv


def test_gate_json_tools_key_is_present_even_when_empty():
    """An absent key and an empty one are different claims: absent means an
    older aramid that did not record provenance at all, empty means it looked
    and found nothing. A consumer comparing two runs has to tell them apart."""
    import json

    from aramid import reporter
    from aramid.pipeline import GateResult

    result = GateResult(exit_code=0, findings=[], degraded=[], new_ids=[],
                        stale_overrides=[], run_id="r1")
    assert json.loads(reporter.render_json(result))["tools"] == {}


@pytest.mark.skipif(sys.platform != "win32", reason="exe_name suffix is Windows-specific")
def test_divergence_compares_real_paths_not_strings(tmp_path, monkeypatch):
    """`shutil.which` and `scripts_dirs()` can name the SAME file by different
    strings -- a trailing separator, a different case on Windows, or one side
    unresolved. Comparing the raw strings would report drift where there is
    none, which is the fastest way to get the notice ignored."""
    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    real = scripts / toolpath.exe_name("ruff")
    real.write_text("#x", encoding="utf-8")
    monkeypatch.setattr(shutil, "which",
                        lambda name, *a, **k: str(real).upper() if name == "ruff" else None)
    monkeypatch.setattr(toolpath, "scripts_dirs", lambda: [scripts])

    assert toolpath.divergence("ruff") is None
