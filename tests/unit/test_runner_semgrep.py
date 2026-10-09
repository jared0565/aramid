import json
from pathlib import Path

from aramid.runners import semgrep
from aramid.runners.base import RunContext, RunnerResult, ToolState

FIXTURE = Path(__file__).parent.parent / "fixtures" / "semgrep.json"


def test_parse_fixture_yields_finding():
    result = RunnerResult(tool="semgrep", state=ToolState.OK, raw=FIXTURE.read_text())
    ctx = RunContext(root=Path("."), files=["app.py"])

    findings = semgrep.parse(result, ctx)

    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "semgrep"
    assert f.rule == "python.lang.security.audit.exec-detected.exec-detected"
    assert f.file == "app.py"
    assert f.line == 3
    assert f.severity_raw == "ERROR"
    assert "exec" in f.message


def test_parse_normalizes_live_prefixed_check_id_to_canonical_rule_id():
    """Task 81b regression test. Real semgrep (observed LIVE, v1.169.0
    against this repo's own vendored config at
    src/aramid/rules/owasp.yml) does not report the bare rule `id:` as
    `check_id` -- it prefixes it with the `--config` file's *directory*
    path, dot-joined (drive letter and every path separator become '.'):

        F.Projects.aramid.src.aramid.rules.owasp-top-ten.a03-injection.python-sqli-string-concat

    for the vendored rule whose `id:` in owasp.yml is
    `owasp-top-ten.a03-injection.python-sqli-string-concat`.
    block_rules.toml's `[semgrep] block` list matches rule ids with the
    fnmatch pattern "owasp-top-ten.*", which anchors at the START of the
    string -- against the raw, prefixed check_id above it NEVER matches,
    so `parse()` must normalize `check_id` back to the canonical form
    before it becomes RawFinding.rule."""
    raw_check_id = (
        "F.Projects.aramid.src.aramid.rules."
        "owasp-top-ten.a03-injection.python-sqli-string-concat"
    )
    raw_json = json.dumps({
        "errors": [],
        "results": [{
            "check_id": raw_check_id,
            "path": "vuln.py",
            "start": {"line": 2, "col": 1, "offset": 0},
            "end": {"line": 2, "col": 60, "offset": 60},
            "extra": {
                "message": "SQL injection via string concatenation.",
                "severity": "ERROR",
            },
        }],
    })
    result = RunnerResult(tool="semgrep", state=ToolState.OK, raw=raw_json)
    ctx = RunContext(root=Path("."), files=["vuln.py"])

    findings = semgrep.parse(result, ctx)

    assert len(findings) == 1
    assert findings[0].rule == "owasp-top-ten.a03-injection.python-sqli-string-concat"


def test_parse_leaves_non_vendored_check_id_unchanged():
    """Fallback path: a check_id with no 'owasp-top-ten.' substring at all
    (a future non-vendored/registry rule) has no vendored-config prefix to
    strip, so it passes through unchanged -- exactly today's fixture,
    which is a real (non-vendored) semgrep registry rule id."""
    findings = semgrep.parse(
        RunnerResult(tool="semgrep", state=ToolState.OK, raw=FIXTURE.read_text()),
        RunContext(root=Path("."), files=["app.py"]),
    )
    assert findings[0].rule == "python.lang.security.audit.exec-detected.exec-detected"


def test_parse_no_results_is_empty():
    result = RunnerResult(tool="semgrep", state=ToolState.OK, raw='{"results": [], "errors": []}')
    assert semgrep.parse(result, RunContext(root=Path("."))) == []


def test_parse_skips_non_ok_state():
    result = RunnerResult(tool="semgrep", state=ToolState.MISSING)
    assert semgrep.parse(result, RunContext(root=Path("."))) == []


def test_argv_uses_vendored_config_and_offline_flags(tmp_path):
    ctx = RunContext(root=tmp_path, files=["app.py"])
    argv = semgrep._build_argv(ctx)
    assert argv[0] == "semgrep"
    assert "--config" in argv
    assert argv[argv.index("--config") + 1] == str(semgrep.VENDORED_RULES_PATH)
    assert "--json" in argv
    assert "--metrics=off" in argv
    assert "--quiet" in argv
    sep = argv.index("--")
    assert argv[sep + 1:] == ["app.py"]


def test_run_missing_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(
        semgrep, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="semgrep", state=ToolState.MISSING),
    )
    result = semgrep.run(RunContext(root=tmp_path, files=["a.py"]))
    assert result.state is ToolState.MISSING


def test_run_ok_roundtrips_fixture(tmp_path, monkeypatch):
    fixture_text = FIXTURE.read_text()
    monkeypatch.setattr(
        semgrep, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="semgrep", state=ToolState.OK, raw=fixture_text),
    )
    ctx = RunContext(root=tmp_path, files=["app.py"])
    result = semgrep.run(ctx)
    assert result.state is ToolState.OK
    findings = semgrep.parse(result, ctx)
    assert findings[0].rule.endswith("exec-detected")


def test_run_unparseable_output_is_crashed(tmp_path, monkeypatch):
    monkeypatch.setattr(
        semgrep, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(tool="semgrep", state=ToolState.OK, raw="not json", stderr="boom"),
    )
    result = semgrep.run(RunContext(root=tmp_path, files=["a.py"]))
    assert result.state is ToolState.CRASHED


def test_argv_includes_extra_configs(tmp_path):
    ctx = RunContext(root=tmp_path, files=["a.py"],
                     extra_semgrep_configs=(str(tmp_path / "regression.yml"),))
    argv = semgrep._build_argv(ctx)
    assert argv.count("--config") == 2
    assert str(tmp_path / "regression.yml") in argv


def test_canonical_rule_id_strips_prefix_for_pack_rules():
    live = "repo.aramid-rules.regression.aramid-regression.block.deadbeef"
    assert semgrep._canonical_rule_id(live) == "aramid-regression.block.deadbeef"
    # owasp behavior unchanged
    assert semgrep._canonical_rule_id("x.y.owasp-top-ten.a01") == "owasp-top-ten.a01"


def test_run_empty_output_with_error_returncode_is_crashed(tmp_path, monkeypatch):
    """CRITICAL: empty stdout parses fine as '{}' -- without a returncode
    check this would silently read as a clean 'zero findings' run even
    though semgrep exited 2 (its documented fatal-error code, e.g. a bad
    --config) before producing a report. A broken BLOCK-tier SAST scanner
    must not silently 'pass'."""
    monkeypatch.setattr(
        semgrep, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="semgrep", state=ToolState.OK, raw="", stderr="invalid config", returncode=2),
    )
    result = semgrep.run(RunContext(root=tmp_path, files=["a.py"]))
    assert result.state is ToolState.CRASHED


def test_canonical_rule_id_uses_rightmost_prefix_occurrence():
    from aramid.runners.semgrep import _CANONICAL_RULE_PREFIX, _canonical_rule_id
    # A checkout path that itself embeds the literal prefix must not truncate
    # the id early -- the REAL canonical id is the rightmost occurrence.
    cid = f"/src/{_CANONICAL_RULE_PREFIX}junk/config/{_CANONICAL_RULE_PREFIX}sqli"
    assert _canonical_rule_id(cid) == f"{_CANONICAL_RULE_PREFIX}sqli"


# --- vendored rule namespaces beyond owasp-top-ten --------------------------
#
# The semgrep tier is rule-id driven: `block_rules.toml`'s
# `[semgrep] block = ["owasp-top-ten.*", ...]` means EVERY id under that
# namespace blocks. Rust memory-safety lints (transmute, get_unchecked,
# set_len) are worth surfacing but have legitimate uses and must not block a
# push by default, so they need a namespace outside the block list. That only
# works if `_canonical_rule_id` also strips the config-path prefix off them --
# otherwise the id keeps a machine-dependent absolute path, which would make
# fingerprints, overrides and suppressions differ per checkout.

def test_canonical_rule_id_strips_every_vendored_namespace():
    from aramid.runners.semgrep import VENDORED_RULE_PREFIXES, _canonical_rule_id

    assert "owasp-top-ten." in VENDORED_RULE_PREFIXES
    assert "rust-memory-safety." in VENDORED_RULE_PREFIXES

    for prefix in VENDORED_RULE_PREFIXES:
        live = f"F.Projects.aramid.src.aramid.rules.{prefix}some-rule"
        assert _canonical_rule_id(live) == f"{prefix}some-rule", (
            f"{prefix} must normalise, or its findings carry a per-machine id")


def test_every_namespace_in_the_shipped_ruleset_is_registered():
    """The test above cannot catch a MISSING namespace -- it iterates the very
    tuple it is checking, so it validates the list against itself and passes
    whatever the list happens to say.

    That gap shipped a real defect. `injection-dataflow.` was added to
    owasp.yml without being registered here, so `_canonical_rule_id` left
    semgrep's config-path prefix attached and every finding from the new rule
    carried an id namespaced with the ABSOLUTE PATH of the rules file. A
    consumer repo hit it querying `ledger filter --rule <documented id>` and
    got a clean, confident `[]`.

    The blast radius is wider than a wrong report: `compute_fingerprint` takes
    the RULE as an ingredient, so an unstripped id makes the FINDING ID itself
    machine-dependent -- suppressions and overrides written on one checkout
    bind nothing on another, silently.

    So this test derives the namespaces from the shipped YAML, which is the
    source of truth for which rules exist, and asserts each is registered.
    Adding a rule under a new namespace fails here until it is.
    """
    import re

    from aramid.runners.semgrep import (
        VENDORED_RULES_PATH,
        VENDORED_RULE_PREFIXES,
        _canonical_rule_id,
    )

    ids = re.findall(r"^\s*-\s*id:\s*(\S+)\s*$",
                     VENDORED_RULES_PATH.read_text(encoding="utf-8"), re.MULTILINE)
    assert ids, "no rule ids parsed -- the regex, not the ruleset, is what broke"

    namespaces = {rid.split(".", 1)[0] + "." for rid in ids}
    unregistered = sorted(ns for ns in namespaces if ns not in VENDORED_RULE_PREFIXES)
    assert not unregistered, (
        f"namespace(s) {unregistered} ship in owasp.yml but are absent from "
        f"VENDORED_RULE_PREFIXES -- their findings will carry a machine-dependent "
        f"id built from the rules file's absolute path")

    # And prove the consequence is actually gone, not merely that the tuple was
    # edited: every shipped id must survive a round trip through a realistic
    # live check_id.
    for rid in ids:
        live = f"F.Projects.aramid.src.aramid.rules.{rid}"
        assert _canonical_rule_id(live) == rid, f"{rid} keeps a per-machine prefix"


def test_canonical_rule_id_still_prefers_the_rightmost_occurrence():
    """Unchanged guarantee: a checkout path that itself embeds a namespace
    literal must not truncate the real id early."""
    from aramid.runners.semgrep import _canonical_rule_id

    cid = "/src/rust-memory-safety.junk/config/rust-memory-safety.transmute"
    assert _canonical_rule_id(cid) == "rust-memory-safety.transmute"


# --- examined set -----------------------------------------------------------
#
# Shapes below are copied from a live `semgrep --json` capture (1.169.0,
# 2026-08-06) against the vendored OWASP ruleset. Three behaviours were
# measured rather than assumed, and two of them say there is NO hole here:
#   - `.semgrepignore` is BYPASSED for explicitly-passed paths (an ignored
#     file was scanned and did produce a finding), so it is not ruff's
#     `--force-exclude` hole in disguise;
#   - so is the default 1MB `--max-target-bytes` limit (a 1,224,024-byte file
#     was scanned and did produce a finding);
#   - but a file with a syntax error IS listed under `paths.scanned`, yields
#     no findings, and semgrep still exits 0. That one is real.

def _payload(scanned, results=(), errors=()) -> str:
    return json.dumps({"paths": {"scanned": list(scanned)},
                       "results": list(results), "errors": list(errors)})


_SYNTAX_ERROR = {
    "type": ["PartialParsing", [{"path": "src/syntaxerr.py",
                                 "start": {"line": 2, "col": 5, "offset": 0},
                                 "end": {"line": 2, "col": 10, "offset": 5}}]],
    "path": "src/syntaxerr.py",
    "message": "Syntax error at line src/syntaxerr.py:2:\n `eval(` was unexpected",
}


def _ok(raw, tmp_path, monkeypatch, files):
    monkeypatch.setattr(
        semgrep, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult("semgrep", ToolState.OK, raw=raw, returncode=1))
    return semgrep.run(RunContext(root=tmp_path, files=files))


def test_examined_excludes_a_file_semgrep_could_not_parse(tmp_path, monkeypatch):
    """semgrep lists an unparseable file as `scanned` and exits 0 having found
    nothing in it -- so resolution recorded every open semgrep finding in that
    file as fixed the moment a syntax error was introduced."""
    raw = _payload(["src/bad.py", "src/syntaxerr.py"], errors=[_SYNTAX_ERROR])

    result = _ok(raw, tmp_path, monkeypatch, ["src/bad.py", "src/syntaxerr.py"])

    assert result.examined == frozenset({"src/bad.py"})


def test_examined_excludes_files_semgrep_has_no_rules_for(tmp_path, monkeypatch):
    """The adapter passes ctx.files UNFILTERED -- unlike ruff/eslint there is
    no suffix screen -- so semgrep is handed `.md`, `.bin`, images and all.
    Measured: those never appear in `paths.scanned`, so they must not be
    vouched for either."""
    raw = _payload(["src/bad.py"])

    result = _ok(raw, tmp_path, monkeypatch,
                 ["src/bad.py", "src/blob.bin", "README.md"])

    assert result.examined == frozenset({"src/bad.py"})


def test_examined_normalizes_windows_separators(tmp_path, monkeypatch):
    """`paths.scanned` comes back with the host's separators; resolution
    matches against ledger paths, which are forward-slash."""
    raw = _payload([r"src\aramid\ledger.py"])

    result = _ok(raw, tmp_path, monkeypatch, ["src/aramid/ledger.py"])

    assert result.examined == frozenset({"src/aramid/ledger.py"})


def test_missing_paths_key_cannot_report_rather_than_vouching_for_nothing(
        tmp_path, monkeypatch):
    """A semgrep old enough to omit `paths` must fall back to the previous
    behaviour, not block every resolution forever. That is exactly what the
    None/empty-set distinction on RunnerResult.examined is for."""
    raw = json.dumps({"results": [], "errors": []})

    result = _ok(raw, tmp_path, monkeypatch, ["src/bad.py"])

    assert result.examined is None


def test_no_output_at_all_vouches_for_nothing_rather_than_for_everything(
        tmp_path, monkeypatch):
    """Empty stdout is NOT an old semgrep, and must not reach the fallback
    above.

    `json_or_crashed(..., empty="{}")` substitutes `{}` for empty stdout while
    keeping ToolState.OK. `{}` has no `paths`, so `_examined` returned None --
    "cannot vouch" -- and None keeps the tool out of
    `pipeline._examined_by_tool`, so `ledger.record_run` falls back to
    `scope_files`: the gate's ENTIRE file set. Every open semgrep finding
    would be written `fixed` into an append-only ledger on a run that produced
    no report at all. Since a2e101f semgrep is BLOCK-armed, so those are
    findings that now stop a push.

    The two cases are cleanly separable and the distinction is not a judgement
    call: an old semgrep still emits a real JSON report (see the test above),
    it just omits `paths`. `{}` is aramid's own placeholder, never semgrep's
    output. eslint, clippy and tsc all return the empty set for their
    equivalent no-usable-output case; semgrep was the lone hold-out."""
    result = _ok("", tmp_path, monkeypatch, ["src/bad.py"])

    assert result.state is ToolState.OK
    assert result.examined == frozenset(), (
        "a semgrep run that reported nothing must vouch for nothing -- "
        "None here credits it with the whole gate file set")


def test_whitespace_only_output_is_no_output(tmp_path, monkeypatch):
    """`json_or_crashed` only substitutes on a falsy `raw`, so a lone newline
    survives as `"\\n"` -- which json.loads rejects, taking the run to CRASHED.
    Pin it anyway: the check must key on emptiness after stripping, so that a
    future loosening of either side cannot reopen the hole quietly."""
    result = _ok("   \n  ", tmp_path, monkeypatch, ["src/bad.py"])

    assert result.examined == frozenset()


def test_degraded_run_vouches_for_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(
        semgrep, "run_subprocess",
        lambda argv, cwd, t, env=None: RunnerResult("semgrep", ToolState.TIMEOUT))

    result = semgrep.run(RunContext(root=tmp_path, files=["a.py"]))

    assert result.state is ToolState.TIMEOUT
    assert result.examined is not None and not result.examined


# --- FN-38: the `--disable-nosem` second pass and the inline label -----------
#
# semgrep's own run keeps its pre-FN-38 argv exactly. A second pass with
# `--disable-nosem` over the examined files that mention `nosem` reports what
# a marker hid, as the hits it has and the own run does not. It never reads
# `extra.is_ignored`: semgrep marks that only on some engine paths (logged in,
# yes; fresh, as on every CI runner, absent), and FN-38's first build relied
# on it and went red on all 7 CI legs while passing on a logged-in machine.

import time  # noqa: E402

from aramid.runners import inline  # noqa: E402

_SQLI = "F.x.rules.owasp-top-ten.a03-injection.python-sqli-string-concat"
_CANONICAL = "owasp-top-ten.a03-injection.python-sqli-string-concat"


def _sem_item(line, col=5, path="q.py"):
    return {"check_id": _SQLI, "path": path,
            "start": {"line": line, "col": col}, "end": {"line": line, "col": col + 20},
            "extra": {"severity": "ERROR", "message": "string-built SQL"}}


def _sem_report(*items, scanned=("q.py",), errors=()):
    return json.dumps({"results": list(items), "errors": list(errors),
                       "paths": {"scanned": list(scanned)}})


def _sem_tree(tmp_path, marker="  # nosemgrep"):
    (tmp_path / "q.py").write_text(
        "def f(cur, n):\n"
        f"    cur.execute('SELECT ' + n){marker}\n"
        "    cur.execute('SELECT ' + n)\n", encoding="utf-8")


class _FakeSemgrep:
    """Answers semgrep's own run and the `--disable-nosem` second pass, by
    shape. `second` is the second pass's stdout, or a RunnerResult."""

    def __init__(self, own, second=None, own_rc=1, second_rc=1, hang_s=0.0):
        self.own, self.second = own, second
        self.own_rc, self.second_rc, self.hang_s = own_rc, second_rc, hang_s
        self.calls = []

    def __call__(self, argv, cwd, timeout_s, env=None):
        self.calls.append((list(argv), timeout_s))
        if "--disable-nosem" not in argv:
            return RunnerResult("semgrep", ToolState.OK, raw=self.own, returncode=self.own_rc)
        if self.hang_s:
            time.sleep(timeout_s + self.hang_s)
            return RunnerResult("semgrep", ToolState.TIMEOUT, duration_s=timeout_s + self.hang_s)
        if isinstance(self.second, RunnerResult):
            return self.second
        return RunnerResult("semgrep", ToolState.OK, raw=self.second, returncode=self.second_rc)

    def second_calls(self):
        return [argv for argv, _ in self.calls if "--disable-nosem" in argv]


def _inline_run(tmp_path, monkeypatch, fake, files=("q.py",), **kw):
    monkeypatch.setattr(semgrep, "run_subprocess", fake)
    ctx = RunContext(root=tmp_path, files=list(files), inline_pass=True, **kw)
    return semgrep.run(ctx), ctx


def test_without_the_inline_pass_semgrep_runs_exactly_as_before(tmp_path, monkeypatch):
    _sem_tree(tmp_path)
    fake = _FakeSemgrep(_sem_report(_sem_item(3)))
    monkeypatch.setattr(semgrep, "run_subprocess", fake)
    result = semgrep.run(RunContext(root=tmp_path, files=["q.py"]))
    assert [argv for argv, _ in fake.calls] == [semgrep._build_argv(
        RunContext(root=tmp_path, files=["q.py"]))]
    assert "--disable-nosem" not in fake.calls[0][0]
    assert getattr(result, "sub_results", None) is None


def test_semgreps_own_run_never_carries_disable_nosem(tmp_path, monkeypatch):
    # The BLOCK-tier result is semgrep's own, with its markers honoured by
    # semgrep itself: nothing FN-38 does can change it.
    _sem_tree(tmp_path)
    fake = _FakeSemgrep(_sem_report(_sem_item(3)), _sem_report(_sem_item(2), _sem_item(3)))
    _inline_run(tmp_path, monkeypatch, fake)
    own_argv, second_argv = (argv for argv, _ in fake.calls)
    assert "--disable-nosem" not in own_argv
    assert second_argv.index("--disable-nosem") < second_argv.index("--")
    assert second_argv[second_argv.index("--") + 1:] == ["q.py"]


def test_the_second_pass_reports_what_the_own_run_did_not(tmp_path, monkeypatch):
    _sem_tree(tmp_path)
    fake = _FakeSemgrep(_sem_report(_sem_item(3)), _sem_report(_sem_item(2), _sem_item(3)))
    result, ctx = _inline_run(tmp_path, monkeypatch, fake)

    own, second = result.sub_results
    assert (own.tool, second.tool, second.state) == ("semgrep", inline.SEMGREP, ToolState.OK)
    assert second.examined == own.examined == frozenset({"q.py"})
    assert [(f.tool, f.rule, f.line, f.subject) for f in semgrep.parse(result, ctx)] == [
        ("semgrep", _CANONICAL, 3, None),
        (inline.SEMGREP, inline.RULE, 2, ("semgrep", _CANONICAL)),
    ]


def test_two_hits_on_one_line_are_told_apart_by_column(tmp_path, monkeypatch):
    _sem_tree(tmp_path)
    fake = _FakeSemgrep(_sem_report(_sem_item(2, col=5)),
                        _sem_report(_sem_item(2, col=5), _sem_item(2, col=40)))
    result, ctx = _inline_run(tmp_path, monkeypatch, fake)
    assert [(f.tool, f.line) for f in semgrep.parse(result, ctx)] == [
        ("semgrep", 2), (inline.SEMGREP, 2)]


def test_no_file_that_mentions_nosem_starts_no_second_process(tmp_path, monkeypatch):
    _sem_tree(tmp_path, marker="")
    fake = _FakeSemgrep(_sem_report(_sem_item(2), _sem_item(3)))
    result, ctx = _inline_run(tmp_path, monkeypatch, fake)
    assert fake.second_calls() == []
    own, second = result.sub_results
    assert (second.tool, second.state, second.examined) == (
        inline.SEMGREP, ToolState.OK, own.examined)
    assert [f.tool for f in semgrep.parse(result, ctx)] == ["semgrep", "semgrep"]


def test_the_nosem_screen_ignores_case(tmp_path, monkeypatch):
    _sem_tree(tmp_path, marker="  # NoSemGrep")
    fake = _FakeSemgrep(_sem_report(_sem_item(3)), _sem_report(_sem_item(2), _sem_item(3)))
    _inline_run(tmp_path, monkeypatch, fake)
    assert len(fake.second_calls()) == 1


def test_only_files_that_mention_nosem_are_scanned_again(tmp_path, monkeypatch):
    _sem_tree(tmp_path)
    (tmp_path / "plain.py").write_text("X = 1\n", encoding="utf-8")
    fake = _FakeSemgrep(_sem_report(_sem_item(3), scanned=("q.py", "plain.py")),
                        _sem_report(_sem_item(2), _sem_item(3)))
    result, _ = _inline_run(tmp_path, monkeypatch, fake, files=("q.py", "plain.py"))
    [argv] = fake.second_calls()
    assert argv[argv.index("--") + 1:] == ["q.py"]
    # plain.py has no marker to hide anything, so the label vouches for it too.
    assert result.sub_results[1].examined == frozenset({"q.py", "plain.py"})


def test_a_file_the_screen_cannot_read_is_scanned_again(tmp_path, monkeypatch):
    # Unread is not "no marker": a file skipped here could hide one.
    fake = _FakeSemgrep(_sem_report(scanned=("gone.py",)), _sem_report(scanned=("gone.py",)))
    _inline_run(tmp_path, monkeypatch, fake, files=("gone.py",))
    [argv] = fake.second_calls()
    assert argv[argv.index("--") + 1:] == ["gone.py"]


def test_a_degraded_semgrep_starts_no_second_pass(tmp_path, monkeypatch):
    _sem_tree(tmp_path)
    fake = _FakeSemgrep("", own_rc=2)
    result, _ = _inline_run(tmp_path, monkeypatch, fake)
    assert result.state is ToolState.CRASHED
    assert len(fake.calls) == 1
    assert getattr(result, "sub_results", None) is None


def test_an_empty_report_reports_the_label_ok_and_examining_nothing(tmp_path, monkeypatch):
    # The label is in each gate's expected set. semgrep reports OK-vouching-
    # for-nothing on an empty stdout, so its inline label must say the same,
    # or status counts a skip for a run that skipped nothing.
    _sem_tree(tmp_path)
    fake = _FakeSemgrep("", own_rc=0)
    result, _ = _inline_run(tmp_path, monkeypatch, fake)
    own, second = result.sub_results
    assert (own.state, own.examined) == (ToolState.OK, frozenset())
    assert (second.tool, second.state, second.examined) == (
        inline.SEMGREP, ToolState.OK, frozenset())
    assert fake.second_calls() == []


def test_a_crashed_second_pass_is_degraded_under_its_label_only(tmp_path, monkeypatch):
    _sem_tree(tmp_path)
    fake = _FakeSemgrep(_sem_report(_sem_item(3)), "", second_rc=2)
    result, ctx = _inline_run(tmp_path, monkeypatch, fake)
    own, second = result.sub_results
    assert (own.state, own.examined) == (ToolState.OK, frozenset({"q.py"}))
    assert (second.tool, second.state, second.examined) == (
        inline.SEMGREP, ToolState.CRASHED, frozenset())
    assert [f.tool for f in semgrep.parse(result, ctx)] == ["semgrep"]


def test_a_second_pass_with_no_report_vouches_for_nothing(tmp_path, monkeypatch):
    _sem_tree(tmp_path)
    fake = _FakeSemgrep(_sem_report(_sem_item(3)), "", second_rc=0)
    result, ctx = _inline_run(tmp_path, monkeypatch, fake)
    second = result.sub_results[1]
    assert (second.state, second.examined) == (ToolState.OK, frozenset())
    assert [f.tool for f in semgrep.parse(result, ctx)] == ["semgrep"]


def test_a_file_the_second_pass_could_not_parse_is_not_vouched_for(tmp_path, monkeypatch):
    _sem_tree(tmp_path)
    fake = _FakeSemgrep(_sem_report(_sem_item(3)),
                        _sem_report(errors=[{"path": "q.py", "message": "boom"}]))
    result, _ = _inline_run(tmp_path, monkeypatch, fake)
    assert result.sub_results[1].examined == frozenset()


def test_an_old_semgrep_without_paths_screens_the_gate_files(tmp_path, monkeypatch):
    # No `paths` in a real report: semgrep's own result falls back to the
    # gate's file set (examined None), and so does its label.
    _sem_tree(tmp_path)
    old = json.dumps({"results": [_sem_item(3)], "errors": []})
    fake = _FakeSemgrep(old, json.dumps({"results": [_sem_item(2), _sem_item(3)], "errors": []}))
    result, ctx = _inline_run(tmp_path, monkeypatch, fake)
    own, second = result.sub_results
    assert own.examined is None and second.examined is None
    assert [(f.tool, f.line) for f in semgrep.parse(result, ctx)] == [
        ("semgrep", 3), (inline.SEMGREP, 2)]


def test_the_second_pass_never_outlives_the_gate_deadline(tmp_path, monkeypatch):
    _sem_tree(tmp_path)
    fake = _FakeSemgrep(_sem_report(_sem_item(3)), _sem_report(_sem_item(3)))
    _inline_run(tmp_path, monkeypatch, fake, gate_deadline=time.monotonic() + 10.0)
    [(_, timeout_s)] = [c for c in fake.calls if "--disable-nosem" in c[0]]
    assert timeout_s < 10.0


def test_a_second_pass_whose_kill_hangs_never_costs_semgrep_its_own_result(
        tmp_path, monkeypatch):
    _sem_tree(tmp_path)
    fake = _FakeSemgrep(_sem_report(_sem_item(3)), hang_s=6.0)
    deadline = time.monotonic() + 4.0
    result, ctx = _inline_run(tmp_path, monkeypatch, fake, gate_deadline=deadline)
    returned = time.monotonic()

    assert returned < deadline, f"returned {returned - deadline:.1f} s after the deadline"
    own, second = result.sub_results
    assert own.state is ToolState.OK
    assert (second.tool, second.state) == (inline.SEMGREP, ToolState.TIMEOUT)
    assert [f.tool for f in semgrep.parse(result, ctx)] == ["semgrep"]
