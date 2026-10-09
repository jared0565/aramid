from pathlib import Path

from aramid.runners import ruff
from aramid.runners.base import RunContext, RunnerResult, ToolState

FIXTURE = Path(__file__).parent.parent / "fixtures" / "ruff.json"


def test_parse_fixture_yields_s_rule_finding():
    """A no-ruff-config repo containing `exec(x)` must still produce an S102
    finding -- proves aramid enforces the security (S) family itself via
    --extend-select, independent of the target repo's own ruff config."""
    result = RunnerResult(tool="ruff", state=ToolState.OK, raw=FIXTURE.read_text())
    ctx = RunContext(root=Path("."), files=["app.py"])

    findings = ruff.parse(result, ctx)

    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "ruff"
    assert f.rule == "S102"
    assert f.file == "app.py"
    assert f.line == 3
    assert f.severity_raw == "error"
    assert "exec" in f.message


def test_parse_empty_is_no_findings():
    result = RunnerResult(tool="ruff", state=ToolState.OK, raw="[]")
    assert ruff.parse(result, RunContext(root=Path("."))) == []


def test_parse_skips_non_ok_state():
    result = RunnerResult(tool="ruff", state=ToolState.CRASHED)
    assert ruff.parse(result, RunContext(root=Path("."))) == []


def test_argv_mandates_extend_select_s(tmp_path):
    """--extend-select S is mandatory: ruff's default rule set excludes the
    bandit-derived S family, so without this flag the security rules never
    fire regardless of the target repo's own config."""
    ctx = RunContext(root=tmp_path, files=["app.py", "b.py"])
    argv = ruff._build_argv(ctx)
    assert argv[0] == "ruff"
    assert argv[1] == "check"
    assert "--output-format" in argv and argv[argv.index("--output-format") + 1] == "json"
    assert "--force-exclude" in argv
    assert "--extend-select" in argv and argv[argv.index("--extend-select") + 1] == "S"
    assert argv[-2:] == ["app.py", "b.py"] or "--" in argv
    sep = argv.index("--")
    assert argv[sep + 1:] == ["app.py", "b.py"]


def test_argv_filters_to_python_files_only(tmp_path):
    """ctx.files is the gate's WHOLE file set; ruff parses whatever explicit
    paths it is handed as Python, so non-.py files (YAML, templates, ...)
    must never reach its argv -- live-CI bug: 958 invalid-syntax findings
    from owasp.yml / ARAMID.md.tmpl / the workflow YAML."""
    ctx = RunContext(root=tmp_path, files=[
        "app.py", "rules/owasp.yml", "data/ARAMID.md.tmpl",
        ".github/workflows/aramid.yml", "typed.pyi", "README.md",
    ])
    argv = ruff._build_argv(ctx)
    sep = argv.index("--")
    assert argv[sep + 1:] == ["app.py", "typed.pyi"]


def test_run_no_python_files_is_clean_noop(tmp_path, monkeypatch):
    """Zero paths after filtering must NOT invoke ruff at all -- ruff given
    no explicit paths falls back to scanning the whole cwd."""
    def _boom(*a, **k):
        raise AssertionError("run_subprocess must not be called")
    monkeypatch.setattr(ruff, "run_subprocess", _boom)
    result = ruff.run(RunContext(root=tmp_path, files=["rules/owasp.yml", "README.md"]))
    assert result.state is ToolState.OK
    assert ruff.parse(result, RunContext(root=tmp_path)) == []


def test_run_missing_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(
        ruff, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="ruff", state=ToolState.MISSING),
    )
    result = ruff.run(RunContext(root=tmp_path, files=["a.py"]))
    assert result.state is ToolState.MISSING


def test_run_ok_roundtrips_fixture(tmp_path, monkeypatch):
    fixture_text = FIXTURE.read_text()
    monkeypatch.setattr(
        ruff, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="ruff", state=ToolState.OK, raw=fixture_text),
    )
    ctx = RunContext(root=tmp_path, files=["app.py"])
    result = ruff.run(ctx)
    assert result.state is ToolState.OK
    findings = ruff.parse(result, ctx)
    assert findings[0].rule == "S102"


def test_run_unparseable_output_is_crashed(tmp_path, monkeypatch):
    monkeypatch.setattr(
        ruff, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="ruff", state=ToolState.OK, raw="not json", stderr="boom"),
    )
    result = ruff.run(RunContext(root=tmp_path, files=["a.py"]))
    assert result.state is ToolState.CRASHED


def test_run_empty_output_with_error_returncode_is_crashed(tmp_path, monkeypatch):
    """Empty stdout parses fine as '[]' -- without a returncode check this
    would silently read as a clean 'zero findings' run even though ruff
    errored (bad args, internal error, ...) with a returncode outside its
    documented {0, 1}."""
    monkeypatch.setattr(
        ruff, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="ruff", state=ToolState.OK, raw="", stderr="error: bad argument", returncode=2),
    )
    result = ruff.run(RunContext(root=tmp_path, files=["a.py"]))
    assert result.state is ToolState.CRASHED


# --- FN-38: the inline-marker second pass ----------------------------------

import json  # noqa: E402
import time  # noqa: E402

from aramid.runners import inline  # noqa: E402


def _item(path, row, code="S105", message="Possible hardcoded password"):
    return {"code": code, "name": code, "filename": str(path), "message": message,
            "location": {"row": row, "column": 1}, "severity": "error"}


class _FakeRuff:
    """Answers the three ruff invocations by shape: the gate's own check, the
    `--show-files` probe, and the `--isolated` second pass."""

    def __init__(self, root, own, examined, second, second_rc=0):
        self.root, self.own, self.examined = root, own, examined
        self.second, self.second_rc = second, second_rc
        self.calls = []

    def __call__(self, argv, cwd, timeout_s, env=None):
        self.calls.append((list(argv), timeout_s))
        if "--show-files" in argv:
            raw = "\n".join(str(self.root / f) for f in self.examined)
            return RunnerResult("ruff", ToolState.OK, raw=raw, returncode=0)
        if "--isolated" in argv:
            return RunnerResult("ruff", ToolState.OK, raw=json.dumps(self.second),
                                returncode=self.second_rc)
        return RunnerResult("ruff", ToolState.OK, raw=json.dumps(self.own), returncode=1)

    def second_calls(self):
        return [c for c in self.calls if "--isolated" in c[0]]


def _marked_tree(tmp_path):
    (tmp_path / "a.py").write_text(
        'password = "hunter2hunter2"  # noqa: S105\nVALUE = 2\n',
        encoding="utf-8")
    (tmp_path / "t.py").write_text('password = "hunter2hunter2"\n', encoding="utf-8")


def _inline_ctx(tmp_path, **kw):
    return RunContext(root=tmp_path, files=["a.py", "t.py"], inline_pass=True,
                      ruff_block_rules=("S105", "S106"), **kw)


def test_without_the_inline_pass_ruff_runs_exactly_as_before(tmp_path, monkeypatch):
    _marked_tree(tmp_path)
    fake = _FakeRuff(tmp_path, own=[], examined=["a.py"], second=[])
    monkeypatch.setattr(ruff, "run_subprocess", fake)
    result = ruff.run(RunContext(root=tmp_path, files=["a.py", "t.py"]))
    assert fake.second_calls() == []
    assert getattr(result, "sub_results", None) is None


def test_the_inline_pass_reports_only_hits_the_markers_hid(tmp_path, monkeypatch):
    _marked_tree(tmp_path)
    own = [_item(tmp_path / "a.py", 2)]
    second = [_item(tmp_path / "a.py", 1), _item(tmp_path / "a.py", 2),
              _item(tmp_path / "t.py", 1)]
    fake = _FakeRuff(tmp_path, own=own, examined=["a.py", "t.py"], second=second)
    monkeypatch.setattr(ruff, "run_subprocess", fake)
    ctx = _inline_ctx(tmp_path)

    result = ruff.run(ctx)

    [(argv, _)] = fake.second_calls()
    assert argv[:3] == ["ruff", "check", "--isolated"]
    assert "--ignore-noqa" in argv
    assert argv[argv.index("--select") + 1] == "S105,S106"
    assert argv[argv.index("--") + 1:] == ["a.py", "t.py"]
    assert [r.tool for r in result.sub_results] == ["ruff", inline.RUFF]
    assert result.state is ToolState.OK
    findings = ruff.parse(result, ctx)
    assert [(f.tool, f.rule, f.file, f.line, f.subject) for f in findings] == [
        ("ruff", "S105", "a.py", 2, None),
        (inline.RUFF, inline.RULE, "a.py", 1, ("ruff", "S105")),
        (inline.RUFF, inline.RULE, "t.py", 1, ("ruff", "S105")),
    ]


def test_an_inline_finding_names_the_kind_of_marker(tmp_path, monkeypatch):
    _marked_tree(tmp_path)
    fake = _FakeRuff(tmp_path, own=[], examined=["a.py", "t.py"],
                     second=[_item(tmp_path / "a.py", 1), _item(tmp_path / "t.py", 1)])
    monkeypatch.setattr(ruff, "run_subprocess", fake)
    ctx = _inline_ctx(tmp_path)
    noqa, config = ruff.parse(ruff.run(ctx), ctx)
    assert "`# noqa`" in noqa.message and "S105" in noqa.message
    assert "per-file-ignores" in config.message and "S105" in config.message


def test_the_inline_pass_examines_only_what_ruff_itself_examined(tmp_path, monkeypatch):
    # `--isolated` drops the repo's `exclude` too; a file the repo excludes
    # must never come back as "hidden".
    _marked_tree(tmp_path)
    fake = _FakeRuff(tmp_path, own=[], examined=["a.py"], second=[])
    monkeypatch.setattr(ruff, "run_subprocess", fake)
    result = ruff.run(_inline_ctx(tmp_path))
    [(argv, _)] = fake.second_calls()
    assert argv[argv.index("--") + 1:] == ["a.py"]
    assert result.sub_results[1].examined == frozenset({"a.py"})


def test_a_failed_inline_pass_degrades_only_its_own_label(tmp_path, monkeypatch):
    _marked_tree(tmp_path)
    fake = _FakeRuff(tmp_path, own=[_item(tmp_path / "a.py", 2)], examined=["a.py"],
                     second=[], second_rc=2)
    monkeypatch.setattr(ruff, "run_subprocess", fake)
    ctx = _inline_ctx(tmp_path)
    result = ruff.run(ctx)
    own, second = result.sub_results
    assert (own.tool, own.state) == ("ruff", ToolState.OK)
    assert (second.tool, second.state) == (inline.RUFF, ToolState.CRASHED)
    assert result.state is ToolState.OK
    assert [(f.tool, f.line) for f in ruff.parse(result, ctx)] == [("ruff", 2)]


def test_no_time_left_skips_the_inline_pass_and_leaves_ruffs_own_result(tmp_path, monkeypatch):
    # The gate abandons a whole registry key at its budget. A second pass that
    # ran past it would turn ruff's own finished result into a TIMEOUT.
    _marked_tree(tmp_path)
    fake = _FakeRuff(tmp_path, own=[_item(tmp_path / "a.py", 2)], examined=["a.py"],
                     second=[_item(tmp_path / "a.py", 1)])
    monkeypatch.setattr(ruff, "run_subprocess", fake)
    ctx = _inline_ctx(tmp_path, gate_deadline=time.monotonic())
    result = ruff.run(ctx)
    assert fake.second_calls() == []
    own, second = result.sub_results
    assert own.state is ToolState.OK
    assert (second.tool, second.state) == (inline.RUFF, ToolState.TIMEOUT)


def test_the_inline_pass_never_outlives_the_gate_deadline(tmp_path, monkeypatch):
    _marked_tree(tmp_path)
    fake = _FakeRuff(tmp_path, own=[], examined=["a.py"], second=[])
    monkeypatch.setattr(ruff, "run_subprocess", fake)
    ruff.run(_inline_ctx(tmp_path, gate_deadline=time.monotonic() + 10.0))
    [(_, timeout_s)] = fake.second_calls()
    assert timeout_s < 10.0


class _HungSecondPass(_FakeRuff):
    """A second pass that ignores its timeout, standing in for the up-to-5 s
    reap `run_subprocess` spends on a killed tree after the timeout."""

    def __call__(self, argv, cwd, timeout_s, env=None):
        if "--isolated" in argv:
            self.calls.append((list(argv), timeout_s))
            time.sleep(timeout_s + 6.0)
            return RunnerResult("ruff", ToolState.TIMEOUT, duration_s=timeout_s + 6.0)
        return super().__call__(argv, cwd, timeout_s, env)


def test_a_second_pass_whose_kill_hangs_never_costs_ruff_its_own_result(tmp_path, monkeypatch):
    # The gate drops a whole registry key that returns after its budget,
    # finished results and all, so ruff's own result must come back before
    # the deadline however long the second pass takes to die.
    _marked_tree(tmp_path)
    fake = _HungSecondPass(tmp_path, own=[_item(tmp_path / "t.py", 1)], examined=["a.py", "t.py"],
                           second=[])
    monkeypatch.setattr(ruff, "run_subprocess", fake)
    deadline = time.monotonic() + 4.0
    result = ruff.run(_inline_ctx(tmp_path, gate_deadline=deadline))
    returned = time.monotonic()

    assert returned < deadline, f"returned {returned - deadline:.1f} s after the deadline"
    own, second = result.sub_results
    assert own.state is ToolState.OK
    assert (second.tool, second.state) == (inline.RUFF, ToolState.TIMEOUT)
    assert [f.tool for f in ruff.parse(result, _inline_ctx(tmp_path))] == ["ruff"]


def test_no_python_in_scope_still_reports_the_inline_label_ok_and_empty(tmp_path, monkeypatch):
    # The label is in each gate's expected set; ruff reports OK-with-nothing
    # here, so its inline label must too, or status counts a skip.
    fake = _FakeRuff(tmp_path, own=[], examined=[], second=[])
    monkeypatch.setattr(ruff, "run_subprocess", fake)
    result = ruff.run(RunContext(root=tmp_path, files=["README.md"], inline_pass=True,
                                 ruff_block_rules=("S105",)))
    assert fake.calls == []
    own, second = result.sub_results
    assert (own.state, own.examined) == (ToolState.OK, frozenset())
    assert (second.tool, second.state, second.examined) == (
        inline.RUFF, ToolState.OK, frozenset())


def test_a_code_this_ruff_does_not_know_is_dropped_not_fatal(tmp_path, monkeypatch):
    # ruff exits 2 on an unknown `--select` code. A typo in a repo's
    # `block_rules` additions, or a curated code a future ruff removes, would
    # otherwise degrade the inline label on every run -- and `--strict` would
    # refuse every push. A code ruff does not know is one it can never report,
    # so there is nothing for a marker to hide under it.
    _marked_tree(tmp_path)
    fake = _FakeRuff(tmp_path, own=[], examined=["a.py"], second=[_item(tmp_path / "a.py", 1)])

    def picky(argv, cwd, timeout_s, env=None):
        if "--isolated" in argv and "S9999" in argv[argv.index("--select") + 1]:
            fake.calls.append((list(argv), timeout_s))
            return RunnerResult("ruff", ToolState.OK, raw="", returncode=2, stderr=(
                "ruff failed\n  Cause: Unknown rule selector `S9999` in `select` "
                "from the CLI\n"))
        return fake(argv, cwd, timeout_s, env)

    monkeypatch.setattr(ruff, "run_subprocess", picky)
    ctx = RunContext(root=tmp_path, files=["a.py"], inline_pass=True,
                     ruff_block_rules=("S105", "S9999"))
    result = ruff.run(ctx)
    second = result.sub_results[1]
    assert second.state is ToolState.OK
    first_try, retry = fake.second_calls()
    assert retry[0][retry[0].index("--select") + 1] == "S105"
    assert "S9999" in second.stderr
    assert [(f.tool, f.line) for f in ruff.parse(result, ctx)] == [(inline.RUFF, 1)]
