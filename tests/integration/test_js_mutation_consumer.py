import shutil
import subprocess

import pytest

from aramid import config as config_mod
from aramid.consumers import js_mutation as jsc
from aramid.consumers.base import DrainContext
from aramid.ledger import Ledger
from aramid.queue import QueueItem
from aramid.runners.base import RunnerResult, ToolState


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _sha(root):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          capture_output=True, text=True).stdout.strip()


# A JS repo whose test SCRIPT exists (so detect_tests -> "npm"); the calc source
# has a mutable `>=` on the changed line.
def _js_repo(tmp_path, with_node_modules=True):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "package.json").write_text(
        '{"name":"x","scripts":{"test":"node test.js"}}\n', encoding="utf-8")
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[js_mutation]\nmax_mutants = 3\n"
        "wall_budget_s = 300\nmutant_timeout_s = 60\n", encoding="utf-8")
    (r / "calc.js").write_text("function isAdult(age) {\n  return true;\n}\n"
                               "module.exports = { isAdult };\n", encoding="utf-8")
    (r / "test.js").write_text("process.exit(0);\n", encoding="utf-8")
    # node_modules must never be a tracked path: `git worktree add` would then
    # check it out into the worktree, and a real `mklink /J` / os.symlink
    # cannot land on top of an already-existing (non-empty) directory.
    (r / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    if with_node_modules:
        (r / "node_modules").mkdir()
        (r / "node_modules" / ".marker").write_text("real deps", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    (r / "calc.js").write_text("function isAdult(age) {\n  return age >= 18;\n}\n"
                               "module.exports = { isAdult };\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "feature")
    return r, base, _sha(r)


def _consume(r, base, head, monkeypatch, tmp_path):
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(r)
    led = Ledger(r / ".aramid" / "ledger.db")
    item = QueueItem(id="q1", base=base, head=head, score=55, reasons=("t",),
                     state="queued", created_at="t", updated_at="t")
    try:
        return jsc.consume(item, DrainContext(root=r, cfg=cfg, ledger=led, clock=lambda: "t"))
    finally:
        led.close()


def test_disabled_returns_ok_note(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    (r / "aramid.toml").write_text("schema_version = 1\n[js_mutation]\nenabled = false\n",
                                   encoding="utf-8")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok" and res.note == "disabled"


def test_no_js_test_stack_ok_skip(tmp_path, monkeypatch):
    # package.json WITHOUT a test script -> detect_tests has no "npm" -> OK-skip,
    # never degraded (else the queue item pins forever).
    r, base, head = _js_repo(tmp_path)
    (r / "package.json").write_text('{"name":"x","scripts":{}}\n', encoding="utf-8")
    _git(r, "commit", "-q", "-am", "drop test script")
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert "no js test stack" in res.note


def test_node_modules_absent_ok_skip(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path, with_node_modules=False)
    # Force the pm gate to pass regardless of whether npm is on PATH (CI is
    # Node-free), so the node_modules check is the one that fires.
    monkeypatch.setattr(jsc, "_pm_test_argv", lambda pm: ["npm", "test"])
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert "node_modules not installed" in res.note


def test_link_and_unlink_node_modules_preserves_target(tmp_path):
    # Invariant #7: unlinking the junction/symlink must NEVER delete the real
    # node_modules it points at.
    src = tmp_path / "src"
    (src / "node_modules").mkdir(parents=True)
    (src / "node_modules" / "keep.txt").write_text("keep", encoding="utf-8")
    wt = tmp_path / "wt"
    wt.mkdir()
    linked = jsc._link_node_modules(src, wt)
    assert linked is True
    assert (wt / "node_modules" / "keep.txt").read_text() == "keep"
    jsc._unlink_node_modules(wt)
    assert not (wt / "node_modules").exists()
    assert (src / "node_modules" / "keep.txt").read_text() == "keep", \
        "the real node_modules must survive the unlink"


def _scripted(monkeypatch, seq):
    """Replace run_subprocess with a scripted sequence of (state, returncode).
    Also force the pm gate to pass (CI is Node-free, so shutil.which('npm') is
    None) and stub the junction helpers so no real link is created. call 0 is
    the baseline run; calls 1+ are the per-mutant runs."""
    calls = {"n": 0}

    def fake(argv, cwd, timeout, **kw):
        i = calls["n"]
        calls["n"] += 1
        state, rc = seq[i] if i < len(seq) else seq[-1]
        return RunnerResult(tool="npm", state=state, returncode=rc)

    monkeypatch.setattr(jsc, "run_subprocess", fake)
    monkeypatch.setattr(jsc, "_pm_test_argv", lambda pm: ["npm", "test"])
    monkeypatch.setattr(jsc, "_link_node_modules", lambda src, wt: True)
    monkeypatch.setattr(jsc, "_unlink_node_modules", lambda wt: None)
    return calls


def test_survivor_reported_when_suite_passes_the_mutant(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    # baseline green (rc 0), then every mutant run green (rc 0) -> survivor(s)
    _scripted(monkeypatch, [(ToolState.OK, 0)])
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings, "a mutant the suite cannot kill must be reported"
    f = res.findings[0]
    assert f.tool == "js-mutation" and f.file == "calc.js"
    assert "mutant survived" in f.message
    assert res.extra["survived"] >= 1


def test_killed_when_suite_fails_the_mutant(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    # baseline green, then every mutant fails (rc 1) -> killed, no findings
    _scripted(monkeypatch, [(ToolState.OK, 0), (ToolState.OK, 1)])
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings == []
    assert res.extra["killed"] >= 1


def test_baseline_red_degrades_with_loadbearing_note(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    _scripted(monkeypatch, [(ToolState.OK, 1)])   # baseline itself fails
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "degraded"
    assert res.note.startswith(f"baseline failing @ {head[:12]}")


def test_timeout_counts_not_killed_not_survived(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    _scripted(monkeypatch, [(ToolState.OK, 0), (ToolState.TIMEOUT, 0)])
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.extra["timeouts"] >= 1
    assert res.findings == []


def test_give_up_after_three_baseline_failures_head_scoped(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    from aramid.ledger import Ledger
    from aramid.models import Event, EventType
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        for i in range(3):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"r{i}", "t",
                             payload={"consumer": "js_mutation", "item_id": "q1",
                                      "note": f"baseline failing @ {head[:12]}"}))
    finally:
        led.close()
    _scripted(monkeypatch, [(ToolState.OK, 0)])   # would pass, but give-up first
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert "giving up" in res.note


def _link_raises(src, wt):
    raise OSError("mklink /J failed: simulated persistent link failure")


def test_node_modules_link_failure_degrades_with_head_scoped_prefix(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    _scripted(monkeypatch, [(ToolState.OK, 0)])          # pm gate + stubs
    monkeypatch.setattr(jsc, "_link_node_modules", _link_raises)   # link fails
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "degraded"
    # note must START with the head-scoped prefix so prior_note_count can match it
    assert res.note.startswith(f"node_modules link failing @ {head[:12]}")


def test_give_up_after_three_node_modules_link_failures_head_scoped(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    from aramid.ledger import Ledger
    from aramid.models import Event, EventType
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        for i in range(3):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"r{i}", "t",
                             payload={"consumer": "js_mutation", "item_id": "q1",
                                      "note": f"node_modules link failing @ {head[:12]}"}))
    finally:
        led.close()
    _scripted(monkeypatch, [(ToolState.OK, 0)])
    monkeypatch.setattr(jsc, "_link_node_modules", _link_raises)   # would fail, but give-up first
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert "giving up" in res.note


_HAS_NODE = shutil.which("node") is not None and shutil.which("npm") is not None


def _no_worktrees(r):
    cp = subprocess.run(["git", "worktree", "list"], cwd=r, check=True,
                        capture_output=True, text=True)
    return len([ln for ln in cp.stdout.splitlines() if ln.strip()]) == 1


@pytest.mark.skipif(not _HAS_NODE, reason="node+npm not on PATH (Python-only CI)")
def test_real_npm_weak_suite_reports_survivor(tmp_path, monkeypatch):
    # End-to-end with a REAL `npm test`: a weak test (exit 0 regardless) cannot
    # kill the `>= -> >` mutant on the changed line, so it must be reported.
    r, base, head = _js_repo(tmp_path)   # test.js is `process.exit(0)` = weak
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings, "the weak suite cannot kill the mutant -> survivor"
    assert res.findings[0].tool == "js-mutation"
    assert _no_worktrees(r)


def test_is_test_file_case_insensitive():
    # `.test.`/`.spec.` detection must be case-insensitive so an uppercase
    # `Foo.TEST.JS` is treated as a test file, not mutated as production code.
    assert jsc._is_test_file("src/Foo.TEST.JS")
    assert jsc._is_test_file("src/Bar.Spec.ts")
    assert jsc._is_test_file("__tests__/x.js")
    assert not jsc._is_test_file("src/calc.js")


def test_consumer_is_registered():
    # Importing the module must register it in the consumer registry (the drain
    # loop dispatches via base.CONSUMERS).
    from aramid.consumers import base
    assert base.CONSUMERS["js_mutation"] is jsc
