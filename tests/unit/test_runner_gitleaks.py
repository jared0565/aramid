import json
import os
from pathlib import Path


from aramid.runners import gitleaks
from aramid.runners.base import RunContext, RunnerResult, ToolState

FIXTURE = Path(__file__).parent.parent / "fixtures" / "gitleaks.json"


def test_parse_fixture_produces_finding_with_secret():
    result = RunnerResult(tool="gitleaks", state=ToolState.OK, raw=FIXTURE.read_text())
    ctx = RunContext(root=Path("."))

    findings = gitleaks.parse(result, ctx)

    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "gitleaks"
    assert f.rule == "aws-access-token"
    assert f.file == "src/config.py"
    assert f.line == 3
    assert f.secret == "AKIAIOSFODNN7EXAMPLE"


def test_parse_empty_report_is_no_findings():
    result = RunnerResult(tool="gitleaks", state=ToolState.OK, raw="[]")
    assert gitleaks.parse(result, RunContext(root=Path("."))) == []


def test_parse_skips_non_ok_state():
    result = RunnerResult(tool="gitleaks", state=ToolState.MISSING)
    assert gitleaks.parse(result, RunContext(root=Path("."))) == []


def test_staged_argv_uses_git_staged(tmp_path):
    # protect is deprecated in gitleaks 8.19+ (removed in a future major ->
    # unknown-command -> CRASHED -> pre-commit fail-open lets secrets pass).
    # git --staged is the non-deprecated equivalent (verified vs v8.21.2
    # cmd/git.go), and matches the history path's `gitleaks git`.
    ctx = RunContext(root=tmp_path)
    report_path = tmp_path / "report.json"
    argv = gitleaks._build_argv(ctx, report_path)
    assert argv[:3] == ["gitleaks", "git", "--staged"]
    assert "protect" not in argv
    assert "--report-format" in argv and "json" in argv
    assert "--report-path" in argv and str(report_path) in argv
    assert "-" not in argv  # never pass "-" as a report-path sentinel


def test_range_argv_uses_git_log_opts(tmp_path):
    ctx = RunContext(root=tmp_path, rng="HEAD~5..HEAD")
    report_path = tmp_path / "report.json"
    argv = gitleaks._build_argv(ctx, report_path)
    assert argv[:2] == ["gitleaks", "git"]
    assert "--log-opts" in argv
    assert argv[argv.index("--log-opts") + 1] == "HEAD~5..HEAD"
    assert "--report-path" in argv and str(report_path) in argv


def test_full_history_sentinel_argv_uses_git_log_not_staged_fallback(tmp_path):
    """MUST-FIX 1 (final-review.md): `pipeline.FULL_HISTORY_RNG` ("") is a
    deliberately falsy-but-not-None sentinel `pipeline._discover_files` now
    hands back for range mode when there is no @{u}/origin/HEAD yet (a
    brand-new repo's first push, spec §3: "scan every commit reachable from
    HEAD"). `_build_argv` must branch on `ctx.rng is not None`, NOT
    truthiness -- pre-fix, `if ctx.rng:` treated "" exactly like None and
    fell back to `protect --staged`, which only sees the currently-staged
    diff and silently scans nothing on a clean working tree. An empty
    `--log-opts` value is itself gitleaks/`git log`'s own "no revision
    given -> walk everything reachable from HEAD" default."""
    ctx = RunContext(root=tmp_path, rng="")
    report_path = tmp_path / "report.json"
    argv = gitleaks._build_argv(ctx, report_path)
    assert argv[:2] == ["gitleaks", "git"]
    assert "--log-opts" in argv
    assert argv[argv.index("--log-opts") + 1] == ""
    assert "protect" not in argv
    assert "--staged" not in argv


def test_run_reads_back_the_report_file_gitleaks_wrote(tmp_path, monkeypatch):
    """gitleaks writes its report to a FILE path, not stdout -- run() must
    write to a temp file and read it back, never pass "-" as a stdout
    sentinel (that would create a literal file named "-")."""
    fixture_text = FIXTURE.read_text()

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        report_path = Path(argv[argv.index("--report-path") + 1])
        report_path.write_text(fixture_text)
        return RunnerResult(tool="gitleaks", state=ToolState.OK, raw="", stderr="",
                             duration_s=0.05, returncode=1)

    monkeypatch.setattr(gitleaks, "run_subprocess", fake_run_subprocess)

    ctx = RunContext(root=tmp_path)
    result = gitleaks.run(ctx)

    assert result.state is ToolState.OK
    findings = gitleaks.parse(result, ctx)
    assert len(findings) == 1
    assert findings[0].secret == "AKIAIOSFODNN7EXAMPLE"


def test_run_nonzero_exit_with_leaks_is_not_crashed(tmp_path, monkeypatch):
    """gitleaks exits 1 (its documented "leaks found" code) when it finds
    leaks -- that must be treated as OK, not CRASHED."""
    fixture_text = FIXTURE.read_text()

    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        report_path = Path(argv[argv.index("--report-path") + 1])
        report_path.write_text(fixture_text)
        return RunnerResult(tool="gitleaks", state=ToolState.OK, raw="", stderr="",
                             duration_s=0.05, returncode=1)

    monkeypatch.setattr(gitleaks, "run_subprocess", fake_run_subprocess)
    result = gitleaks.run(RunContext(root=tmp_path))
    assert result.state is ToolState.OK


def test_run_missing_binary_passes_through(tmp_path, monkeypatch):
    monkeypatch.setattr(
        gitleaks, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="gitleaks", state=ToolState.MISSING),
    )
    result = gitleaks.run(RunContext(root=tmp_path))
    assert result.state is ToolState.MISSING


def test_run_unparseable_report_is_crashed(tmp_path, monkeypatch):
    def fake_run_subprocess(argv, cwd, timeout_s, env=None):
        report_path = Path(argv[argv.index("--report-path") + 1])
        report_path.write_text("not json{{{")
        return RunnerResult(tool="gitleaks", state=ToolState.OK, raw="", stderr="boom", duration_s=0.01)

    monkeypatch.setattr(gitleaks, "run_subprocess", fake_run_subprocess)
    result = gitleaks.run(RunContext(root=tmp_path))
    assert result.state is ToolState.CRASHED


def test_run_errored_before_report_written_is_crashed_not_clean(tmp_path, monkeypatch):
    """CRITICAL: gitleaks can error before writing a report at all (bad
    --log-opts range, not-a-git-repo, permission error, ...) -- the report
    file never exists, so text is "" and json.loads("[]") succeeds. Without
    checking the returncode, that reads as ToolState.OK with zero findings
    -- a broken BLOCK-tier secrets scanner would silently "pass". The real
    exit code (anything outside gitleaks' documented {0, 1}) must surface
    as CRASHED, never as a clean empty scan."""
    monkeypatch.setattr(
        gitleaks, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="gitleaks", state=ToolState.OK, raw="", stderr="fatal: not a git repository",
            duration_s=0.01, returncode=2),
    )
    result = gitleaks.run(RunContext(root=tmp_path))
    assert result.state is ToolState.CRASHED
    # Even though state is CRASHED, parse() itself still yields zero
    # findings for a non-OK state -- proving why a future pipeline (Task
    # 5.3) MUST inspect RunnerResult.state directly and cannot rely on
    # parse() output alone to detect this failure.
    assert gitleaks.parse(result, RunContext(root=tmp_path)) == []


def test_run_clean_exit_with_missing_report_file_is_ok(tmp_path, monkeypatch):
    """Distinct from the CRASHED case above: if gitleaks exits with its
    documented "no leaks" code (0) but happens to write nothing, that is
    still a clean run -- treat as []. The discriminator is the returncode,
    not merely "was there a report file"."""
    monkeypatch.setattr(
        gitleaks, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="gitleaks", state=ToolState.OK, raw="", stderr="", duration_s=0.01, returncode=0),
    )
    result = gitleaks.run(RunContext(root=tmp_path))
    assert result.state is ToolState.OK
    assert gitleaks.parse(result, RunContext(root=tmp_path)) == []


def test_full_tree_mode_scans_the_tree_not_the_empty_index():
    """`--all` must not route the secret scanner to `git --staged`.

    MEASURED against the published 0.2.0 wheel on a synthetic repo. `--all`
    sets `rng = None` (pipeline._discover_files), and `None` meant "staged"
    -- the one value that also meant "not range-based". So under `--all`,
    with nothing staged, gitleaks scanned NOTHING and reported ToolState.OK.

    Reporting OK is what made it dangerous rather than merely useless. OK
    puts gitleaks in `scope_tools`, and `record_run` then resolves any open
    gitleaks finding whose file is in scope -- which under `--all` is the
    whole tracked tree. Observed end to end: two committed secrets that
    gitleaks finds when run directly, `aramid check --all` reporting "no
    findings", and both prior BLOCK findings written `finding_resolved` in
    the ledger. Committing a secret is what marked it fixed, permanently,
    into an append-only audit trail.

    `--all` is the CI-parity mode `[hooks].pre_push_match_ci` runs on every
    push, and gitleaks is the BLOCK tier."""
    ctx = RunContext(root=Path("."), rng=None, full_tree=True)

    argv = gitleaks._build_argv(ctx, Path("r.json"))

    assert argv[1] == "dir", f"expected a working-tree scan, got {argv[:3]}"
    assert "--staged" not in argv


def test_staged_mode_is_unchanged_when_not_full_tree():
    """The pre-commit path still scans the index, and must: that is the only
    place a secret can be caught BEFORE it enters history."""
    ctx = RunContext(root=Path("."), rng=None)

    argv = gitleaks._build_argv(ctx, Path("r.json"))

    assert argv[1] == "git"
    assert "--staged" in argv


def test_a_range_still_wins_over_full_tree():
    """Range mode is the pre-push path and scans real commits. `full_tree`
    must not shadow it -- a range scan attributes a leak to the commit that
    introduced it, which a directory scan cannot do."""
    ctx = RunContext(root=Path("."), rng="@{u}..HEAD", full_tree=True)

    argv = gitleaks._build_argv(ctx, Path("r.json"))

    assert argv[1] == "git"
    assert "--log-opts" in argv


# ------------------------------------ --all scans a COPY of the tracked files ---
# Measured 2026-09-04 on aramid's own repo: `gitleaks dir <root>` walked the
# gitignored `.cache/` (15,388 files, 418 MB) for 63 s of a 68 s scan against
# a 120 s budget. Under load from a concurrent drain it timed out, the
# pre-push gate reported gitleaks degraded, and `--strict` refused a push
# whose gate had blocking 0 -- twice in one morning. The 381 tracked files
# scan in 1.4 s. `gitleaks dir` takes one path and cannot exclude anything,
# so `--all` hands it a directory holding exactly `ctx.files`.

def _fake_dir_scan(seen: dict, leak: bool = True):
    """A gitleaks double for `dir` mode: records the directory it was pointed
    at and what was in it AT CALL TIME (the copy is gone once run() returns),
    and reports one leak in <dir>/src/a.py the way gitleaks does -- as an
    absolute path under the directory it scanned."""
    def fake(argv, cwd, timeout_s, env=None):
        scanned = Path(argv[argv.index("dir") + 1])
        seen["dir"] = scanned
        seen["files"] = sorted(p.relative_to(scanned).as_posix()
                               for p in scanned.rglob("*") if p.is_file())
        report = Path(argv[argv.index("--report-path") + 1])
        items = [{"RuleID": "generic-api-key", "File": str(scanned / "src" / "a.py"),
                  "StartLine": 1, "Secret": "s", "Description": "d"}] if leak else []
        report.write_text(json.dumps(items))
        return RunnerResult("gitleaks", ToolState.OK, "", "", 0.1, 1 if leak else 0)
    return fake


def test_full_tree_scans_a_copy_holding_only_the_tracked_files(tmp_path, monkeypatch):
    root = tmp_path / "r"
    (root / "src").mkdir(parents=True)
    (root / ".cache").mkdir()
    (root / "src" / "a.py").write_text("key = 'x'\n")
    (root / ".cache" / "blob.json").write_text("{}")          # gitignored: never staged
    (root / "untracked.txt").write_text("not in ctx.files\n")
    seen = {}
    monkeypatch.setattr(gitleaks, "run_subprocess", _fake_dir_scan(seen))
    ctx = RunContext(root=root, files=["src/a.py"], rng=None, full_tree=True)

    result = gitleaks.run(ctx)

    assert seen["dir"] != root and root not in seen["dir"].parents, "the repo itself is not walked"
    assert seen["files"] == ["src/a.py"]
    assert not seen["dir"].exists(), "the copy is gone once the scan returns"
    assert result.state is ToolState.OK
    [finding] = gitleaks.parse(result, ctx)
    assert finding.file == "src/a.py", "the leak is reported at its REPO path, not the copy's"
    assert json.loads(result.raw)[0]["File"] == str(root / "src" / "a.py")


def test_full_tree_copies_only_regular_files(tmp_path, monkeypatch):
    """`git ls-files` also lists a submodule (a directory), a path deleted in
    the working tree, and -- on POSIX, where the test can make one -- a
    symlink. gitleaks skips symlinks itself; none of the three may abort the
    scan."""
    root = tmp_path / "r"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("x = 1\n")
    (root / "sub").mkdir()                                     # a gitlink
    (root / ".cache").mkdir()
    (root / ".cache" / "blob").write_text("ignored; would show up in a root walk")
    files = ["src/a.py", "sub", "gone.py"]
    if os.name != "nt":
        os.symlink(root / "src" / "a.py", root / "link.py")
        files.append("link.py")
    seen = {}
    monkeypatch.setattr(gitleaks, "run_subprocess", _fake_dir_scan(seen))
    ctx = RunContext(root=root, files=files, rng=None, full_tree=True)

    result = gitleaks.run(ctx)

    assert result.state is ToolState.OK
    assert seen["files"] == ["src/a.py"]


def test_full_tree_with_nothing_tracked_scans_an_empty_directory(tmp_path, monkeypatch):
    """Zero tracked files is zero files to scan -- not a fall-back to walking
    the whole tree, which would report leaks in files nobody can commit."""
    root = tmp_path / "r"
    root.mkdir()
    (root / "junk.txt").write_text("untracked\n")
    seen = {}
    monkeypatch.setattr(gitleaks, "run_subprocess", _fake_dir_scan(seen, leak=False))
    ctx = RunContext(root=root, files=[], rng=None, full_tree=True)

    result = gitleaks.run(ctx)

    assert seen["dir"] != root
    assert seen["files"] == []
    assert result.state is ToolState.OK
    assert gitleaks.parse(result, ctx) == []
