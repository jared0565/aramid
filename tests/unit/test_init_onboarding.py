"""`commands.init` at unit scope: the onboarding-date preservation, the two
agent-surface notices, the history scan's ref lookup and its four exits,
the shim validation, `_init_one`'s refusals and summary, and the
`--discover` walk -- every rendered line and every return asserted whole.

The drain confirms a mutant against the unit suite alone, and 28 of this
module's generator mutants sat on lines it never executed: both refusals'
`return 3`, the scope-subpath and scope-root comparisons that decide what
`aramid.toml` records and which tree the stack detector walks, the
history scan's skipped/empty/suppressed exits, the shim validation's two
composites (a missing shim that `or` would have read anyway; a foreign
trampoline with no relocated sibling), and the discovery walk's depth
bound -- tests/integration/test_init.py covers them and the drain never
runs that directory.

Seams: the ones the integration file uses (`doctor.probe_toolchain`,
`gitleaks_runner.run`/`parse`), plus `init.run_gate` and `init.cmd_doctor`
so an onboarding costs no tool run and prints nothing but its own lines;
`hooks.install`, the agent-file merges, the registry and the ledger stay
real on a tmp repo."""
import subprocess
import sys
from pathlib import Path

import pytest

from aramid import config as config_mod
from aramid import hooks as hooks_mod
from aramid.commands import doctor, init
from aramid.ledger import Ledger
from aramid.models import Gate
from aramid.normalizer import RawFinding
from aramid.pipeline import GateResult
from aramid.runners.base import RunnerResult, ToolState


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path, name="repo", *, seed="app.py"):
    r = tmp_path / name
    r.mkdir(parents=True)
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    if seed:
        (r / seed).write_text("def run(cmd):\n    exec(cmd)\n", encoding="utf-8")
        _git(r, "add", seed)
        _git(r, "commit", "-q", "-m", "seed")
    return r


def _outside_git(tmp_path):
    """A directory no git work tree encloses -- asserted, not assumed."""
    d = tmp_path / "outside"
    d.mkdir()
    assert init.gitutil._run(d, "rev-parse", "--is-inside-work-tree").returncode != 0
    return d


def _present(root):
    return {
        "gitleaks": doctor.ToolStatus("gitleaks", True, "8.21.2"),
        "semgrep": doctor.ToolStatus("semgrep", True, "1.100.0"),
        "ruff": doctor.ToolStatus("ruff", True, "0.6.0"),
        "pip-audit": doctor.ToolStatus("pip-audit", True, "2.7.0"),
        "interpreter": doctor.ToolStatus("interpreter", True, sys.executable),
    }


# ------------------------------------------------------- _existing_onboarded --

def test_existing_onboarded_reads_the_recorded_date_or_nothing(tmp_path):
    p = tmp_path / "ARAMID.md"
    assert init._existing_onboarded(p) is None, "no file"
    p.write_text("# x\n- **Onboarded:** 2026-07-30\n", encoding="utf-8")
    assert init._existing_onboarded(p) == "2026-07-30"
    p.write_text("# x\n- **Onboarded:** 2026-07-30 (moved)\n", encoding="utf-8")
    assert init._existing_onboarded(p) is None, "hand-mangled: no history to preserve"


def test_write_aramid_md_keeps_the_recorded_date_across_regeneration(tmp_path):
    init._write_aramid_md(tmp_path, {"python"}, None)
    first = (tmp_path / "ARAMID.md").read_text(encoding="utf-8")
    assert init._existing_onboarded(tmp_path / "ARAMID.md") == init.date.today().isoformat()

    (tmp_path / "ARAMID.md").write_text(
        first.replace(init.date.today().isoformat(), "2026-07-30", 1), encoding="utf-8")
    init._write_aramid_md(tmp_path, {"python"}, None)
    again = (tmp_path / "ARAMID.md").read_text(encoding="utf-8")
    assert init._existing_onboarded(tmp_path / "ARAMID.md") == "2026-07-30"
    assert again.replace("2026-07-30", init.date.today().isoformat(), 1) == first, \
        "only the date survives; everything else is the fresh template"


# ------------------------------------------------ render_agent_*_notice --

SETTINGS_NOTICE = (
    "aramid: init: registered aramid's agent hooks (SessionStart + PreToolUse) in "
    ".claude/settings.json -- sessions start with live gate posture and git bypass "
    "flags are screened:\n"
    'aramid: init:       git add .claude/settings.json && git commit -m "chore: aramid '
    'agent hooks"')
MCP_NOTICE = (
    "aramid: init: registered aramid's MCP server in .mcp.json -- MCP-capable agents "
    "get aramid_check/aramid_status/ledger tools:\n"
    'aramid: init:       git add .mcp.json && git commit -m "chore: aramid mcp server"')


@pytest.mark.parametrize("render, unparseable, notice", [
    (init.render_agent_settings_notice,
     "aramid: init: .claude/settings.json could not be parsed -- left untouched; fix "
     "the JSON and re-run `aramid init` to register aramid's agent hooks",
     SETTINGS_NOTICE),
    (init.render_agent_mcp_notice,
     "aramid: init: .mcp.json could not be parsed -- left untouched; fix the JSON and "
     "re-run `aramid init` to register aramid's MCP server",
     MCP_NOTICE),
])
def test_agent_notice_three_rules(tmp_path, render, unparseable, notice):
    r = _repo(tmp_path)
    out = _outside_git(tmp_path)
    assert render(r, "unparseable") == unparseable
    assert render(out, "unparseable") == unparseable, "a refused write prints anywhere"
    for action in ("ok", "stale", "absent", "damaged", ""):
        assert render(r, action) == "", action
    assert render(r, "created") == notice
    assert render(r, "updated") == notice
    assert render(out, "created") == "", "no work tree: nothing to commit"


# ------------------------------------------------------- _historical_ref_for --

def _raw(file, commit=None, secret="AKIAFAKEFAKEFAKEFAKE", line=1):
    return RawFinding(tool="gitleaks", rule="generic-api-key", severity_raw="high",
                      file=file, line=line, message="found a key", secret=secret,
                      commit=commit)


def test_historical_ref_for_pops_each_file_queue_in_raws_order():
    ref_for = init._historical_ref_for([
        _raw("a.py", "a" * 40), _raw("b.py"), _raw("a.py", "c" * 40, line=9)])
    assert ref_for("a.py") == "a" * 40
    assert ref_for("b.py") == "HEAD", "no commit recorded: HEAD, never None"
    assert ref_for("a.py") == "c" * 40
    with pytest.raises(IndexError):
        ref_for("a.py")


# ------------------------------------------------------------ _scan_history --

@pytest.fixture
def scan(tmp_path, monkeypatch):
    """A repo, its ledger and config, with the gitleaks runner answered by
    the arm: `scan(state, raws)` returns the count and leaves the ledger
    open for inspection (closed at teardown)."""
    r = _repo(tmp_path)
    ledger = Ledger(r / ".aramid" / "ledger.db")
    cfg = config_mod.load_config(r)

    def run(state=ToolState.OK, raws=()):
        monkeypatch.setattr(init.gitleaks_runner, "run",
                            lambda ctx: RunnerResult("gitleaks", state))
        monkeypatch.setattr(init.gitleaks_runner, "parse", lambda result, ctx: list(raws))
        return init._scan_history(r, ledger, cfg)
    run.root, run.ledger = r, ledger
    yield run
    ledger.close()


def _historical(ledger):
    return [e for e in ledger.events()
            if e.type.value == "finding_detected" and e.payload.get("historical")]


def test_scan_history_skips_a_degraded_runner_and_says_so(scan, capsys):
    assert scan(ToolState.MISSING, [_raw("src/config.py")]) == 0
    assert capsys.readouterr() == (
        "", "aramid: init: full-history gitleaks scan skipped (missing)\n")
    assert _historical(scan.ledger) == []


def test_scan_history_records_nothing_when_every_hit_is_under_an_ignored_path(scan, capsys):
    assert scan(raws=[_raw(".cache/x.py"), _raw("graph-out/graph.json")]) == 0
    assert capsys.readouterr() == ("", "")
    assert _historical(scan.ledger) == []


def test_scan_history_records_each_hit_once_as_historical(scan, capsys):
    raws = [_raw("src/config.py", "a" * 40), _raw("src/other.py", "b" * 40, secret="AKIAOTHER")]
    assert scan(raws=raws) == 2
    assert capsys.readouterr() == ("", "")
    events = _historical(scan.ledger)
    assert sorted(e.payload["file"] for e in events) == ["src/config.py", "src/other.py"]

    assert scan(raws=raws) == 2, "the count is this scan's, not the ledger's growth"
    assert len(_historical(scan.ledger)) == 2, "a repeat scan appends nothing"


def test_scan_history_honours_a_committed_suppression_and_prints_the_count(scan, capsys):
    raws = [_raw("tests/fixtures/creds.py", "a" * 40),
            _raw("src/config.py", "b" * 40, secret="AKIAOTHER")]
    (scan.root / ".aramid-suppressions.toml").write_text(
        "[[suppress]]\n"
        'id = "' + "0" * 64 + '"\n'
        'tool = "gitleaks"\nrule = "generic-api-key"\npath = "somewhere/else.py"\n'
        'reason = "unrelated"\n', encoding="utf-8")
    assert scan(raws=raws) == 2
    assert capsys.readouterr() == ("", ""), "an entry for another finding: silent"

    fixture_id = next(e.finding_id for e in _historical(scan.ledger)
                      if e.payload["file"] == "tests/fixtures/creds.py")
    (scan.root / ".aramid-suppressions.toml").write_text(
        "[[suppress]]\n"
        f'id = "{fixture_id}"\n'
        'tool = "gitleaks"\nrule = "generic-api-key"\npath = "tests/fixtures/creds.py"\n'
        'reason = "deliberate test fixture"\n', encoding="utf-8")
    assert scan(raws=raws) == 1
    assert capsys.readouterr() == (
        "aramid: init: 1 historical finding(s) suppressed by .aramid-suppressions.toml\n", "")


# ------------------------------------------------------- _validate_hook_shim --

def _shims(r):
    return hooks_mod.hooks_dir(r)


def _warning(r, hook):
    return (f"aramid: init: WARNING -- {_shims(r) / hook} missing or not aramid-managed "
            f"after install; hooks may not be armed\n")


def test_validate_hook_shim_after_a_real_install(tmp_path, capsys):
    r = _repo(tmp_path)
    hooks_mod.install(r, Path(sys.executable))
    assert init._validate_hook_shim(r) is True
    assert capsys.readouterr() == ("", "")


def test_validate_hook_shim_names_every_missing_or_foreign_slot(tmp_path, capsys):
    r = _repo(tmp_path)
    hooks_mod.install(r, Path(sys.executable))
    (_shims(r) / "pre-push").unlink()
    (_shims(r) / "post-commit").write_bytes(b"#!/bin/sh\n# a human wrote this\nexit 0\n")

    assert init._validate_hook_shim(r) is False
    assert capsys.readouterr() == ("", _warning(r, "pre-push") + _warning(r, "post-commit"))


def test_validate_hook_shim_accepts_a_foreign_trampoline_only_with_a_relocated_shim(
        tmp_path, capsys):
    r = _repo(tmp_path)
    hooks_mod.install(r, Path(sys.executable))
    hdir = _shims(r)
    (hdir / "pre-commit").rename(hdir / "pre-commit.local")
    (hdir / "pre-commit").write_bytes(
        b"#!/bin/sh\n# >>> graphite managed >>>\nexec .git/hooks/pre-commit.local\n")
    assert init._validate_hook_shim(r) is True
    assert capsys.readouterr() == ("", "")

    trampoline = (hdir / "pre-commit").read_bytes()
    (hdir / "pre-commit").unlink()
    assert init._validate_hook_shim(r) is False, \
        "a relocated sibling with no slot: git never dispatches to it"
    assert capsys.readouterr() == ("", _warning(r, "pre-commit"))

    (hdir / "pre-commit").write_bytes(trampoline)
    (hdir / "pre-commit.local").unlink()
    assert init._validate_hook_shim(r) is False, "a trampoline chaining to nothing is a gap"
    assert capsys.readouterr() == ("", _warning(r, "pre-commit"))


# ---------------------------------------------------------------- _init_one --

@pytest.fixture
def onboard(monkeypatch):
    """Every tool run answered: the toolchain present, the history scan
    degraded (skipped), the baseline gate empty, doctor's report silent."""
    calls = {"gate": [], "doctor": []}
    monkeypatch.setattr(doctor, "probe_toolchain", _present)
    monkeypatch.setattr(init, "cmd_doctor",
                        lambda root, fix=False, during_init=False:
                        calls["doctor"].append((root, during_init)) or 0)
    monkeypatch.setattr(init.gitleaks_runner, "run",
                        lambda ctx: RunnerResult("gitleaks", ToolState.MISSING))

    def run_gate(root, gate, mode, cfg, ledger, *a, **kw):
        calls["gate"].append((gate, mode))
        return GateResult(0, [], [], [], [], "f" * 32)
    monkeypatch.setattr(init, "run_gate", run_gate)
    return calls


def _summary(out):
    """The summary block, from its heading to the done line."""
    return out[out.index("aramid: init: summary\n"):]


def test_init_one_refuses_outside_a_git_repository(tmp_path, capsys, onboard):
    target = tmp_path / "plain"
    target.mkdir()
    assert init._init_one(target) == 3
    assert capsys.readouterr() == ("", (
        f"aramid: init: {target.resolve()} is not inside a git repository (`git rev-parse "
        f"--show-toplevel` failed) -- refusing to half-initialize.\n"))
    assert onboard["doctor"] == [] and not (target / "aramid.toml").exists()


def test_init_one_refuses_to_arm_without_the_block_tier_tools(tmp_path, capsys, onboard,
                                                              monkeypatch):
    r = _repo(tmp_path)
    statuses = _present(r)
    statuses["semgrep"] = doctor.ToolStatus("semgrep", False, detail="not found")
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: statuses)

    assert init._init_one(r) == 3
    out, err = capsys.readouterr()
    assert out == f"aramid: init: {r}\n"
    assert err == ("aramid: init: refusing to arm hooks -- BLOCK-tier tool(s) missing: "
                   "semgrep; run `aramid doctor` (or `aramid doctor --fix`) and re-run init.\n")
    assert onboard["doctor"] == [(r, True)], "the report printed first, keyed on during_init"
    assert not (r / "aramid.toml").exists() and not (_shims(r) / "pre-commit").exists()


def test_init_one_onboards_a_fresh_repo_and_summarises_it(tmp_path, capsys, onboard):
    r = _repo(tmp_path)
    assert init._init_one(r) == 0
    out, err = capsys.readouterr()

    assert out.startswith(f"aramid: init: {r}\naramid: init: wrote {r / 'aramid.toml'}\n")
    assert "aramid: init: baseline written (0 finding(s))\n" in out
    assert _summary(out) == (
        "aramid: init: summary\n"
        f"  root:              {r}\n"
        "  stack:             python\n"
        "  hooks armed:       yes\n"
        "  baseline findings: 0\n"
        "  historical secrets:0\n"
        "aramid: init: done. Run `aramid status` any time to see open findings.\n")
    assert "aramid: init: full-history gitleaks scan skipped (missing)\n" in err
    assert onboard["gate"] == [(Gate.ALL, "all")]
    assert "scope_subpath" not in (r / "aramid.toml").read_text(encoding="utf-8")
    for hook in ("pre-commit", "pre-push", "post-commit"):
        assert hooks_mod.MARKER_START.encode() in (_shims(r) / hook).read_bytes()
    ledger = Ledger(r / ".aramid" / "ledger.db")
    try:
        assert ledger.has_baseline()
    finally:
        ledger.close()


def test_init_one_on_a_subdirectory_onboards_the_whole_repository(tmp_path, capsys, onboard):
    """The gate scans the root, so init says so: the stack comes from the
    root's app.py (nothing under sub/ is code) and no `scope_subpath` is
    written -- before 0.19.0 both were scoped to sub/ and nothing applied it."""
    r = _repo(tmp_path)                       # app.py at the root, nothing under sub/
    sub = r / "sub"
    sub.mkdir()
    (sub / "README").write_text("no code here\n", encoding="utf-8")

    assert init._init_one(sub) == 0
    out, _ = capsys.readouterr()
    assert _summary(out) == (
        "aramid: init: summary\n"
        f"  root:              {r}\n"
        "  scan scope:        whole repository (init ran in sub)\n"
        "  stack:             python\n"
        "  hooks armed:       yes\n"
        "  baseline findings: 0\n"
        "  historical secrets:0\n"
        "aramid: init: done. Run `aramid status` any time to see open findings.\n")
    assert "scope_subpath" not in (r / "aramid.toml").read_text(encoding="utf-8")


def test_init_one_re_run_leaves_toml_and_baseline_alone(tmp_path, capsys, onboard):
    r = _repo(tmp_path)
    assert init._init_one(r) == 0
    capsys.readouterr()
    (r / "aramid.toml").write_text('schema_version = 1\n[timeouts]\npre_push = 900\n',
                                   encoding="utf-8")

    assert init._init_one(r) == 0
    out, _ = capsys.readouterr()
    assert f"aramid: init: {r / 'aramid.toml'} already exists -- left untouched\n" in out
    assert "aramid: init: baseline already exists -- left untouched\n" in out
    assert onboard["gate"] == [(Gate.ALL, "all")], "the baseline gate ran once, on the first init"
    assert "pre_push = 900" in (r / "aramid.toml").read_text(encoding="utf-8")


def test_init_one_reports_unarmed_hooks_in_the_summary(tmp_path, capsys, onboard, monkeypatch):
    r = _repo(tmp_path)
    monkeypatch.setattr(init, "_validate_hook_shim", lambda root: False)
    assert init._init_one(r) == 0
    out, _ = capsys.readouterr()
    assert "  hooks armed:       NO -- see warning above\n" in out


# ------------------------------------------------------------- discovery --

def test_skip_discover_dir_names_and_globs():
    for name in ("node_modules", "_tools", ".venv", ".git", "__pycache__", ".aramid",
                 ".cache", "graph-out", ".graphite", ".graphite-cache"):
        assert init._skip_discover_dir(name), name
    for name in ("src", "graphite", "tools", ".github", "node_modules2"):
        assert not init._skip_discover_dir(name), name


def _mark_repo(d):
    d.mkdir(parents=True, exist_ok=True)
    (d / ".git").mkdir()
    return d


def test_find_repos_walks_to_depth_three_skips_tooling_dirs_and_stops_at_a_repo(tmp_path):
    base = tmp_path / "base"
    shallow = _mark_repo(base / "one")
    deep = _mark_repo(base / "a" / "b" / "c")                  # depth 3: found
    _mark_repo(base / "a" / "b" / "c" / "nested")               # inside a repo: not walked
    _mark_repo(base / "x" / "y" / "z" / "w")                    # depth 4: beyond the bound
    _mark_repo(base / "node_modules" / "pkg")                   # under a skipped name
    _mark_repo(base / ".graphite-cache" / "pkg")                # under a skipped glob
    (base / "file.txt").write_text("not a dir\n", encoding="utf-8")

    assert init._find_repos(base) == [deep, shallow]
    assert init._find_repos(base, max_depth=4) == [deep, shallow, base / "x" / "y" / "z" / "w"]
    assert init._find_repos(base / "file.txt") == []
    assert init._find_repos(base / "missing") == []


def test_discover_onboards_each_repo_and_returns_the_worst_exit(tmp_path, capsys, monkeypatch):
    base = tmp_path / "base"
    r1 = _mark_repo(base / "r1")
    r2 = _mark_repo(base / "r2")
    seen = []
    monkeypatch.setattr(init, "_init_one", lambda r: seen.append(r) or {r1: 0, r2: 3}[r])

    assert init._discover(base) == 3
    assert seen == [r1, r2]
    assert capsys.readouterr().out == (
        f"aramid: init --discover: found 2 repo(s) under {base}:\n"
        f"  - {r1}\n  - {r2}\n"
        f"\naramid: init --discover: onboarding {r1}\n"
        f"\naramid: init --discover: onboarding {r2}\n")

    (tmp_path / "empty").mkdir()
    assert init._discover(tmp_path / "empty") == 0
    assert capsys.readouterr().out == (
        f"aramid: init --discover: found 0 repo(s) under {tmp_path / 'empty'}:\n")


def test_cmd_init_routes_on_the_discover_flag(monkeypatch):
    monkeypatch.setattr(init, "_discover", lambda t: ("discover", t))
    monkeypatch.setattr(init, "_init_one", lambda t: ("one", t))
    assert init.cmd_init(Path("p"), discover=True) == ("discover", Path("p"))
    assert init.cmd_init(Path("p")) == ("one", Path("p"))
