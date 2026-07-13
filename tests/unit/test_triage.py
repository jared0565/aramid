import json
from pathlib import Path

from aramid import queue, triage
from aramid.ledger import Ledger


# --- path signal -----------------------------------------------------------

def test_path_signal_fires_on_security_tokens():
    score, reasons = triage.path_signal(["src/auth/login.py", "README.md"], [])
    assert score == 30
    assert any("auth" in r for r in reasons)


def test_path_signal_zero_on_benign_paths():
    assert triage.path_signal(["docs/notes.md", "src/util/math.py"], []) == (0, [])


def test_path_signal_honors_extra_patterns():
    score, reasons = triage.path_signal(["billing/charge.py"], ["billing/*"])
    assert score == 30


# --- content signal --------------------------------------------------------

def test_content_signal_exec_class():
    score, reasons = triage.content_signal("+    exec(payload)\n", ["x.py"])
    assert score == 25 and any("exec" in r for r in reasons)


def test_content_signal_sql_class():
    diff = '+    cur.execute("SELECT * FROM t WHERE id=" + uid)\n'
    score, reasons = triage.content_signal(diff, ["db.py"])
    assert score == 25


def test_content_signal_manifest_path():
    score, reasons = triage.content_signal("+requests==2.99.0\n", ["requirements.txt"])
    assert score == 25 and any("manifest" in r for r in reasons)


def test_content_signal_ignores_removed_lines():
    assert triage.content_signal("-    exec(payload)\n", ["x.py"]) == (0, [])


# --- novelty signal --------------------------------------------------------

def test_novelty_signal_new_vs_seen():
    assert triage.novelty_signal({"a.py"}, ["a.py"]) == (0, [])
    score, reasons = triage.novelty_signal({"a.py"}, ["a.py", "brand_new.py"])
    assert score == 20 and "brand_new.py" in reasons[0]


# --- blast radius ----------------------------------------------------------

def _write_graph(root: Path, edges: list[tuple[str, str]], files: dict[str, str]):
    (root / "graph-out").mkdir()
    nodes = [{"id": nid, "kind": "file", "source_file": sf} for nid, sf in files.items()]
    payload = {"nodes": nodes,
               "edges": [{"source": s, "target": t, "relation": "imports"}
                          for s, t in edges]}
    (root / "graph-out" / "graph.json").write_text(json.dumps(payload), encoding="utf-8")


def test_blast_radius_absent_graph_is_zero(tmp_path):
    assert triage.blast_radius_signal(tmp_path, ["core.py"]) == (0, [])


def test_blast_radius_scales_with_dependents(tmp_path):
    files = {"core": "core.py", **{f"d{i}": f"d{i}.py" for i in range(12)}}
    _write_graph(tmp_path, [(f"d{i}", "core") for i in range(12)], files)
    score, reasons = triage.blast_radius_signal(tmp_path, ["core.py"])
    assert score == 25  # >= 10 dependents
    score2, _ = triage.blast_radius_signal(tmp_path, ["d3.py"])  # nothing depends on d3
    assert score2 == 0


def test_blast_radius_thresholds(tmp_path):
    files = {"core": "core.py", "a": "a.py", "b": "b.py", "c": "c.py", "d": "d.py"}
    _write_graph(tmp_path, [("a", "core"), ("b", "core")], files)
    assert triage.blast_radius_signal(tmp_path, ["core.py"])[0] == 10  # 1-2 dependents


# --- combined scorer + budget ---------------------------------------------

def _fake_git(monkeypatch, paths, diff):
    from aramid import triage as t
    monkeypatch.setattr(t.gitutil, "diff_paths", lambda root, base, head: paths)
    monkeypatch.setattr(t.gitutil, "diff_text", lambda root, base, head, max_bytes=400_000: diff)


def test_score_combines_and_clamps(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "l.db")
    _fake_git(monkeypatch, ["src/auth/handler.py"], "+exec(x)\n")
    cfg_triage = {"min_score": 40, "extra_security_paths": []}
    cfg = type("C", (), {"triage": cfg_triage})()
    result = triage.score(tmp_path, "a", "b", cfg, led)
    # path 30 + content 25 + novelty 20 (+ blast 0, no graph) = 75
    assert result.score == 75
    assert result.paths == ("src/auth/handler.py",)
    led.close()


def test_score_budget_stops_early(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "l.db")
    _fake_git(monkeypatch, ["src/auth/handler.py"], "+exec(x)\n")
    cfg = type("C", (), {"triage": {"min_score": 40, "extra_security_paths": []}})()
    clock = iter([0.0, 0.1, 99.0, 99.0, 99.0, 99.0]).__next__  # budget blown after 1st signal
    result = triage.score(tmp_path, "a", "b", cfg, led, budget_s=2.0, monotonic=clock)
    assert result.score == 30  # only the path signal ran
    assert any("budget" in r for r in result.reasons)
    led.close()


def test_run_triage_records_and_enqueues(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "l.db")
    _fake_git(monkeypatch, ["src/auth/handler.py"], "+exec(x)\n")
    cfg = type("C", (), {"triage": {"min_score": 40, "extra_security_paths": []}})()
    result, queued = triage.run_triage(tmp_path, cfg, led, "a", "b", "2026-07-13T12:00:00+00:00")
    assert queued is True
    assert queue.last_triaged_head(led) == "b"
    item = queue.queued_item(queue.materialize_queue(led.events()))
    assert item is not None and item.score == result.score
    led.close()


def test_run_triage_below_threshold_records_but_does_not_enqueue(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "l.db")
    _fake_git(monkeypatch, ["docs/notes.md"], "+hello\n")
    cfg = type("C", (), {"triage": {"min_score": 40, "extra_security_paths": []}})()
    result, queued = triage.run_triage(tmp_path, cfg, led, "a", "b", "2026-07-13T12:00:00+00:00")
    assert queued is False and result.score == 20  # novelty only
    assert queue.queued_item(queue.materialize_queue(led.events())) is None
    assert queue.last_triaged_head(led) == "b"  # still recorded
    led.close()
