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
