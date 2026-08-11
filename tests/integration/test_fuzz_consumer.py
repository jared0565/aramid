"""Integration: the fuzz consumer against real git worktrees + the real
driver subprocess on tiny fixture repos."""
import subprocess

import pytest

from aramid import config as config_mod
from aramid.consumers import fuzz as fuzz_consumer
from aramid.consumers.base import DrainContext
from aramid.ledger import Ledger
from aramid.models import Event, EventType
from aramid.queue import QueueItem
from aramid.runners.base import RunnerResult, ToolState


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _sha(root) -> str:
    cp = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                         capture_output=True, text=True)
    return cp.stdout.strip()


BUGGY = ("def head(xs: list[int]) -> int:\n"
         "    return xs[0]\n")            # IndexError on []
CONTRACT = ("def validate(a: int) -> int:\n"
            "    if a < 0:\n"
            "        raise ValueError('neg')\n"
            "    return a\n")
SCARY = ("def delete_everything(target: str) -> None:\n"
         "    return None\n")


def _repo(tmp_path, body, filename="lib.py", extra_toml=""):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[fuzz]\nmax_functions = 5\ncases_per_function = 40\n"
        "wall_budget_s = 200\nbatch_timeout_s = 90\n" + extra_toml, encoding="utf-8")
    (r / filename).write_text("def placeholder() -> None:\n    return None\n",
                              encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    (r / filename).write_text(body, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "feature")
    return r, base, _sha(r)


def _consume(r, base, head, monkeypatch, tmp_path):
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    item = QueueItem(id="q1", base=base, head=head, score=55, reasons=("t",),
                     state="queued", created_at="t", updated_at="t")
    try:
        return fuzz_consumer.consume(item, DrainContext(root=r, cfg=cfg,
                                                        ledger=led, clock=lambda: "t"))
    finally:
        led.close()


def _no_worktrees(r):
    cp = subprocess.run(["git", "worktree", "list"], cwd=r, check=True,
                         capture_output=True, text=True)
    return len([ln for ln in cp.stdout.splitlines() if ln.strip()]) == 1


def test_deep_crash_reported(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, BUGGY)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings, "IndexError crash must be reported"
    f = res.findings[0]
    assert f.tool == "fuzz" and f.file == "lib.py"
    assert f.rule == "crash-indexerror"
    assert "raised IndexError" in f.message
    assert res.extra["crashes"] >= 1
    assert _no_worktrees(r)


def test_contract_exception_not_reported(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, CONTRACT)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings == []
    assert res.extra["contract_exceptions"] >= 1
    assert _no_worktrees(r)


def test_scary_name_skipped(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, SCARY)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.extra["skipped_name"] >= 1
    assert res.extra["functions_fuzzed"] == 0


def test_unhinted_function_fuzzes_zero_cases_ok(tmp_path, monkeypatch):
    # An unhinted function is a candidate by AST but the driver's
    # supported_params finds it unfuzzable -> zero cases run, zero findings,
    # OK (never DEGRADED). functions_seen counts it; cases_run stays 0.
    r, base, head = _repo(tmp_path, "def f(a):\n    return a\n")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings == []
    assert res.extra["cases_run"] == 0
    assert res.extra["functions_seen"] >= 1


def test_no_python_files_ok_noop(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, BUGGY)
    (r / "notes.md").write_text("hi\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "docs")
    res = _consume(r, head, _sha(r), monkeypatch, tmp_path)
    assert res.state == "ok" and res.findings == []
    assert "no python files" in res.note


def test_truncation_visible(tmp_path, monkeypatch):
    body = BUGGY + "\ndef head2(xs: list[int]) -> int:\n    return xs[0]\n"
    r, base, head = _repo(tmp_path, body, extra_toml="")
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[fuzz]\nmax_functions = 1\ncases_per_function = 20\n",
        encoding="utf-8")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.extra["truncated"] is True
    assert "truncated" in res.note


def test_worktree_removed_on_midloop_exception(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, BUGGY)
    monkeypatch.setattr(fuzz_consumer.gitutil, "diff_new_lines",
                        lambda *a, **kw: {"lib.py": {1}})
    monkeypatch.setattr(fuzz_consumer, "_candidate_functions",
                        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        _consume(r, base, head, monkeypatch, tmp_path)
    assert _no_worktrees(r)


def test_fuzz_findings_classify_warn_never_block(tmp_path, monkeypatch):
    from aramid.models import Gate
    from aramid import policy
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(tmp_path)
    _sev, verdict = policy.classify("fuzz", "crash-indexerror", "medium",
                                    Gate.ALL, cfg=cfg)
    assert str(verdict) != "block"
    assert not any("fuzz" in key for key in cfg.block_rules)


def test_determinism_same_findings_twice(tmp_path, monkeypatch):
    r, base, head = _repo(tmp_path, BUGGY)
    a = _consume(r, base, head, monkeypatch, tmp_path)
    b = _consume(r, base, head, monkeypatch, tmp_path)
    assert [(f.rule, f.file, f.line) for f in a.findings] == \
           [(f.rule, f.file, f.line) for f in b.findings]


def test_import_failure_not_counted_as_fuzzed(tmp_path, monkeypatch):
    # A target file that import-fails must NOT inflate functions_fuzzed --
    # only lib.py's genuinely-run function counts. Two files, both diff-
    # touched in the feature commit.
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[fuzz]\nmax_functions = 5\ncases_per_function = 20\n",
        encoding="utf-8")
    (r / "lib.py").write_text("def p() -> None:\n    return None\n", encoding="utf-8")
    (r / "bad.py").write_text("def q() -> None:\n    return None\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    (r / "lib.py").write_text(BUGGY, encoding="utf-8")
    (r / "bad.py").write_text(
        "import totally_nonexistent_xyz\n"
        "def g(a: int) -> int:\n    return a\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "feature")
    head = _sha(r)

    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.extra["import_failures"] == 1
    # head (lib.py) ran; g (bad.py) was never reached -> fuzzed count is 1, not 2
    assert res.extra["functions_fuzzed"] == 1
    assert any(f.file == "lib.py" for f in res.findings)


def test_drain_e2e_records_fuzz_run(tmp_path, monkeypatch):
    from aramid import registry
    from aramid.commands import drain as drain_mod
    from aramid.commands.drain import cmd_drain
    from aramid.models import EventType
    from aramid import queue as queue_mod

    r, base, head = _repo(tmp_path, BUGGY)
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "repos.toml")
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: tmp_path / "drain.lock")
    monkeypatch.setattr(config_mod, "_user_config_path",
                         lambda: tmp_path / "no-user.toml")
    registry.register(r, "2026-07-20T10:00:00+00:00")
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        queue_mod.enqueue(led, "2026-07-20T10:00:00+00:00", base, head, 55, ["seed"])
    finally:
        led.close()

    rc = cmd_drain([str(r)])
    assert rc in (0, 2)

    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        runs = [e for e in led.events()
                if e.type is EventType.CONSUMER_RUN_FINISHED
                and e.payload.get("consumer") == "fuzz"]
        assert runs, "drain must have run the fuzz consumer"
        assert "crashes" in runs[-1].payload   # extra payload merged
        state = led.open_findings()
        assert any(rec.get("tool") == "fuzz" for rec in state.values()), \
            "deep-crash finding must land in the ledger"
    finally:
        led.close()

OK_FN = ("def ok(a: int) -> int:\n"
         "    return a\n")


def _two_file_repo(tmp_path, second_feature_body):
    # Two changed .py files; [fuzz] budget of exactly ONE function so the
    # second file is reached with budget 0. cases kept tiny for speed.
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[fuzz]\nmax_functions = 1\ncases_per_function = 5\n"
        "wall_budget_s = 200\nbatch_timeout_s = 90\n", encoding="utf-8")
    (r / "lib.py").write_text("def placeholder() -> None:\n    return None\n",
                              encoding="utf-8")
    (r / "other.py").write_text("Y = 0\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    (r / "lib.py").write_text(OK_FN, encoding="utf-8")          # 1 candidate
    (r / "other.py").write_text(second_feature_body, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "feature")
    return r, base, _sha(r)


def test_exact_fit_budget_not_flagged_truncated(tmp_path, monkeypatch):
    # Budget exactly consumed and the remaining changed file has NO
    # candidates: claiming truncation is an over-report (fuzz M4).
    r, base, head = _two_file_repo(tmp_path, "X = 1\n")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.extra["truncated"] is False
    assert "truncated" not in res.note


def test_dropped_candidate_flagged_truncated(tmp_path, monkeypatch):
    # The remaining changed file DOES have a candidate that the budget
    # dropped: the flag must be set.
    r, base, head = _two_file_repo(
        tmp_path, "def also(b: int) -> int:\n    return b\n")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.extra["truncated"] is True
    assert "truncated" in res.note


# --- fuzz can prove a repair ------------------------------------------------
#
# fuzz had no resolver of ANY kind. Nothing matched tool="fuzz", record_run
# cannot reach it (runner labels only) and drain._consume_item passes empty
# scopes, so a crash finding stayed open forever -- even after the crash was
# fixed and the very same seeded case ran clean.
#
# What makes resolution safe here is DETERMINISM: `fuzzgen.case_seed(file,
# func, i)` means re-fuzzing a function replays exactly the corpus that found
# the crash. So for a function that was actually called, "no crash this time"
# is a real re-examination rather than a gap in coverage.
#
# "Actually called" is the hard part, and it is why the driver now reports
# `fuzzed`. A function whose type hints were removed is silently skipped as
# unfuzzable, and a file that fails to import is skipped whole -- both produce
# exactly the same evidence as "ran clean": nothing. Scoping by what was
# ATTEMPTED would resolve findings in code that was never executed.

def _seed_from(r, raw, head):
    """Record the finding the DRAIN would have recorded, and return its id.

    Normalized through the drain's own `normalize` call rather than through the
    consumer's fingerprint helper -- the equality of those two is the property
    the loop depends on, so a test must not assume it on both sides.
    """
    import functools

    from aramid import policy
    from aramid.models import Gate
    from aramid.normalizer import normalize

    cfg = config_mod.load_config(r)
    fs = normalize([raw], r, lambda f: head, b"salt-fixed-16byt", Gate.ALL,
                   functools.partial(policy.classify, cfg=cfg), pin_occurrence=True)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.record_run("seed", "2026-08-10T00:00:00+00:00", "drain",
                       set(), set(), fs)
    finally:
        led.close()
    return fs[0].id


# Crashes on an out-of-range index; the fixed version guards it. Same function
# name and same file both times, so the seeded corpus is identical.
_CRASHY = ("def pick(i: int) -> int:\n"
           "    data = [1, 2, 3]\n"
           "    return data[i]\n")
_FIXED = ("def pick(i: int) -> int:\n"
          "    data = [1, 2, 3]\n"
          "    if not 0 <= i < len(data):\n"
          "        return 0\n"
          "    return data[i]\n")
_UNHINTED = ("def pick(i):\n"
             "    data = [1, 2, 3]\n"
             "    return data[i]\n")


def test_the_driver_vouches_for_the_functions_it_actually_called(tmp_path):
    """A function that cannot be fuzzed must not appear in `fuzzed`. Without
    this an unhinted function looks exactly like a clean one -- both produce no
    records -- and its open findings would resolve on no evidence at all."""
    from aramid.fuzzdriver import run_spec

    (tmp_path / "m.py").write_text(
        "def hinted(x: int) -> int:\n    return x\n"
        "def unhinted(x):\n    return x\n", encoding="utf-8")
    out = run_spec({"root": str(tmp_path),
                    "targets": [{"file": "m.py",
                                 "functions": ["hinted", "unhinted"], "cases": 3}]})

    fuzzed = {tuple(x) for x in out["fuzzed"]}
    assert ("m.py", "hinted") in fuzzed
    assert ("m.py", "unhinted") not in fuzzed, \
        "an unfuzzable function was vouched for as examined"


def test_a_file_that_fails_to_import_vouches_for_nothing(tmp_path):
    from aramid.fuzzdriver import run_spec

    (tmp_path / "bad.py").write_text("import definitely_not_a_module_xyz\n",
                                     encoding="utf-8")
    out = run_spec({"root": str(tmp_path),
                    "targets": [{"file": "bad.py", "functions": ["anything"],
                                 "cases": 3}]})

    assert out["fuzzed"] == []
    assert "bad.py" in out["import_failures"]


def test_the_crash_message_names_its_function_in_the_form_scoping_reads(
        tmp_path, monkeypatch):
    """Scope is matched on the function named in the message, so the message
    FORMAT is load-bearing. Pinned here so changing it breaks loudly instead of
    silently narrowing every future repair claim to nothing."""
    r, base, head = _repo(tmp_path, _CRASHY, filename="mod.py")
    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.findings, f"fixture produced no crash: {res.note}"
    assert res.findings[0].message.startswith("fuzz crash: pick(")
    assert fuzz_consumer._names_function(res.findings[0].message, "pick")
    assert not fuzz_consumer._names_function(res.findings[0].message, "pic")


def test_a_crash_that_was_fixed_is_claimed_repaired(tmp_path, monkeypatch):
    """The whole loop, real driver in a real worktree: the crashy version
    reports a finding, the fix lands, and the next run proves that exact
    identity gone."""
    r, base, head = _repo(tmp_path, _CRASHY, filename="mod.py")
    first = _consume(r, base, head, monkeypatch, tmp_path)
    assert first.findings, f"fixture produced no crash: {first.note}"
    fid = _seed_from(r, first.findings[0], head)

    (r / "mod.py").write_text(_FIXED, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "guard the index")
    res = _consume(r, base, _sha(r), monkeypatch, tmp_path)

    assert res.findings == [], f"the fix did not stop the crash: {res.findings}"
    assert res.repaired is not None, "a fixed crash proved nothing"
    assert res.repaired.tool == "fuzz"
    assert res.repaired.reason == "crash_not_reproduced"
    assert fid in set(res.repaired.ids)


def test_a_crash_that_still_reproduces_is_never_claimed(tmp_path, monkeypatch):
    """The counterfactual: same seeded corpus, still crashing. Claiming repair
    for a finding being reported in the same breath is the worst thing this
    mechanism could do."""
    r, base, head = _repo(tmp_path, _CRASHY, filename="mod.py")
    first = _consume(r, base, head, monkeypatch, tmp_path)
    assert first.findings
    fid = _seed_from(r, first.findings[0], head)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.findings, "fixture stopped crashing; the test would be vacuous"
    assert fid not in set(res.repaired.ids if res.repaired else ())


def test_a_finding_in_a_function_this_run_never_fuzzed_stays_open(
        tmp_path, monkeypatch):
    """THE ATTACK. The type hints come off, so the driver silently skips the
    function -- no records, exactly like a clean run. Resolving here would
    clear a live crash finding because the code stopped being CHECKABLE, not
    because anything was fixed."""
    r, base, head = _repo(tmp_path, _CRASHY, filename="mod.py")
    first = _consume(r, base, head, monkeypatch, tmp_path)
    assert first.findings
    fid = _seed_from(r, first.findings[0], head)

    (r / "mod.py").write_text(_UNHINTED, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "drop the hints")
    res = _consume(r, base, _sha(r), monkeypatch, tmp_path)

    assert res.findings == [], "an unhinted function cannot be fuzzed at all"
    assert fid not in set(res.repaired.ids if res.repaired else ()), \
        "removing type hints resolved a live crash finding"


def test_a_driver_that_never_produced_a_verdict_claims_nothing(
        tmp_path, monkeypatch):
    """A timed-out driver produces no records -- indistinguishable from a clean
    sweep in the output alone."""
    from aramid.runners.base import RunnerResult, ToolState

    r, base, head = _repo(tmp_path, _CRASHY, filename="mod.py")
    first = _consume(r, base, head, monkeypatch, tmp_path)
    assert first.findings
    fid = _seed_from(r, first.findings[0], head)

    monkeypatch.setattr(fuzz_consumer, "run_subprocess",
                        lambda *a, **k: RunnerResult(tool="python",
                                                     state=ToolState.TIMEOUT,
                                                     returncode=0))
    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert fid not in set(res.repaired.ids if res.repaired else ()), \
        "a driver that never produced a verdict resolved findings anyway"


def test_a_drained_fuzz_repair_flips_the_open_finding_to_fixed(tmp_path, monkeypatch):
    """End to end through the REAL drain with the real driver subprocess: the
    crash is recorded as a finding (id computed by `normalize`), the guard is
    added, and the ledger says `fixed`.

    The consumer never re-derives the id it resolves -- it names open findings
    within a re-examined scope -- so what this holds is the whole chain:
    detection, scoping, the drain's `present_ids` subtraction, and the ledger
    write. None of the consumer-level tests reach past the return value.
    """
    from aramid.commands import drain as drain_mod

    r, base, head = _repo(tmp_path, _CRASHY, filename="mod.py")
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"fuzz": fuzz_consumer})
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(r)

    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        drain_mod._consume_item(
            r, cfg, led,
            QueueItem(id="q1", base=base, head=head, score=55, reasons=("t",),
                      state="queued", created_at="t", updated_at="t"),
            lambda: "2026-08-10T00:00:00+00:00")

        opened = {fid for fid, rec in led.open_findings().items()
                  if rec.get("tool") == "fuzz" and rec["status"] == "open"}
        assert opened, "the crashy version recorded no open fuzz finding"

        (r / "mod.py").write_text(_FIXED, encoding="utf-8")
        _git(r, "add", "-A")
        _git(r, "commit", "-q", "-m", "guard the index")
        drain_mod._consume_item(
            r, cfg, led,
            QueueItem(id="q2", base=base, head=_sha(r), score=55, reasons=("t",),
                      state="queued", created_at="t", updated_at="t"),
            lambda: "2026-08-10T01:00:00+00:00")

        after = led.open_findings()
        assert all(after[fid]["status"] == "fixed" for fid in opened), (
            "a fixed crash stayed open: "
            f"{ {fid: after[fid]['status'] for fid in opened} }")
    finally:
        led.close()


# ------------------------------------- a broken driver must not read as ok --

def _broken_driver(monkeypatch, *, state=ToolState.OK, returncode=0, raw="not json",
                   stderr=""):
    """Force the driver subprocess to fail in a chosen way."""
    monkeypatch.setattr(fuzz_consumer, "run_subprocess",
                        lambda *a, **k: RunnerResult(
                            "fuzzdriver", state, raw=raw, returncode=returncode,
                            stderr=stderr))


def _seed_broken_runs(r, head, n, item_id="q1"):
    """n prior CONSUMER_RUN_FINISHED events recording a broken driver at `head`."""
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        for i in range(n):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"r{i}", "t",
                             payload={"consumer": "fuzz", "item_id": item_id,
                                      "note": f"{fuzz_consumer._DRIVER_BROKEN}"
                                              f"{head[:12]}: no parseable output"}))
    finally:
        led.close()


def test_an_unparseable_driver_degrades_so_the_item_retries(tmp_path, monkeypatch):
    """Measured on aramid's own ledger: 8 of 49 fuzz runs recorded
    `state: ok` with the note "driver produced no parseable output". The drain
    marks an item drained only when every consumer finished cleanly, so `ok`
    here CONSUMED the queue item and threw the fuzzing opportunity away --
    silently, and with a healthy-looking state. `degraded` is what the drain
    already understands (`ok = False`, item not marked drained, retried), and
    what the mutation consumer already uses for the same situation."""
    r, base, head = _repo(tmp_path, BUGGY)
    _broken_driver(monkeypatch, raw="<html>not json</html>")

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "degraded"
    assert res.note.startswith(fuzz_consumer._DRIVER_BROKEN)
    assert _no_worktrees(r)


def test_a_driver_that_errored_degrades_too(tmp_path, monkeypatch):
    """The adjacent return, and the same lie. A driver that exited non-zero
    produced no fuzzing at all."""
    r, base, head = _repo(tmp_path, BUGGY)
    _broken_driver(monkeypatch, state=ToolState.CRASHED, returncode=1,
                   stderr="ModuleNotFoundError: no such module")

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "degraded"
    assert "ModuleNotFoundError" in res.note


def test_a_persistently_broken_driver_gives_up_rather_than_pinning_the_queue(
        tmp_path, monkeypatch):
    """The other half of degrading, and it is not optional. A degraded
    consumer keeps its item in the queue, so a permanently broken driver would
    re-run every consumer on that item forever. Mirrors mutation's
    `_BASELINE_GIVE_UP`: after three honest degraded attempts the run reports
    `ok` with a permanent-skip note, letting the item drain."""
    r, base, head = _repo(tmp_path, BUGGY)
    _seed_broken_runs(r, head, fuzz_consumer._DRIVER_GIVE_UP)
    _broken_driver(monkeypatch)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "ok"
    assert res.note == "fuzz giving up: driver persistently broken"


def test_the_give_up_is_scoped_to_the_head_not_the_item(tmp_path, monkeypatch):
    """Queue coalescing advances `item.head` under a stable `item.id`, so a
    give-up counted per item would let new commits inherit an old head's
    verdict and never be fuzzed at all. Only the same code state failing three
    times gives up."""
    r, base, head = _repo(tmp_path, BUGGY)
    _seed_broken_runs(r, "0" * 40, fuzz_consumer._DRIVER_GIVE_UP)  # a DIFFERENT head
    _broken_driver(monkeypatch)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "degraded"


def test_a_timed_out_driver_stays_ok_because_the_budget_is_the_design(
        tmp_path, monkeypatch):
    """Deliberately NOT changed, and pinned so it is not swept up by the
    above. A timeout means the wall budget did its job; degrading it would put
    every budget-limited repo into a permanent retry loop. The lost coverage
    is visible as `timeouts` in the run's stats instead."""
    r, base, head = _repo(tmp_path, BUGGY)
    _broken_driver(monkeypatch, state=ToolState.TIMEOUT)

    res = _consume(r, base, head, monkeypatch, tmp_path)

    assert res.state == "ok"
    assert "timed out" in res.note
