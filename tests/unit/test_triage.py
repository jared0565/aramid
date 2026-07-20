import json
from pathlib import Path

import pytest

from aramid import config as config_mod
from aramid import queue, triage
from aramid.ledger import Ledger

REPO_ROOT = Path(__file__).resolve().parents[2]


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


def test_novelty_signal_normalizes_paths():
    # seen ledger paths are stored normalized (forward-slash, casefolded);
    # a Windows-style diff path must not read as "unseen"
    assert triage.novelty_signal({"src/auth/x.py"}, ["src\\auth\\X.py"]) == (0, [])


# --- blast radius ----------------------------------------------------------
#
# Fixture mirrors graphite's REAL graph-out/graph.json schema: file nodes
# carry source_file; "imports" edges resolve to PLACEHOLDER module-name
# nodes ({"id": "queue", "kind": "unknown"} -- no source_file) and carry
# the IMPORTER's source_file. Edges never target file-node ids.

def _write_graph(root: Path, file_nodes: dict[str, str],
                 placeholders: list[str],
                 edges: list[tuple[str, str, str]]):
    nodes = [{"id": nid, "kind": "file", "name": sf.rsplit("/", 1)[-1],
              "source_file": sf} for nid, sf in file_nodes.items()]
    nodes += [{"id": pid, "kind": "unknown", "name": pid} for pid in placeholders]
    payload = {"nodes": nodes,
               "edges": [{"source": s, "target": t, "relation": "imports",
                          "source_file": sf} for s, t, sf in edges]}
    (root / "graph-out").mkdir(exist_ok=True)
    (root / "graph-out" / "graph.json").write_text(json.dumps(payload), encoding="utf-8")


def test_blast_radius_absent_graph_is_zero(tmp_path):
    assert triage.blast_radius_signal(tmp_path, ["core.py"]) == (0, [])


def test_blast_radius_resolves_placeholder_targets(tmp_path):
    # 12 modules import "queue" via its placeholder node; the file node id
    # (src_aramid_queue) is never an edge target. A self-import edge from
    # queue.py itself must not count as a dependent.
    file_nodes = {"src_aramid_queue": "src/aramid/queue.py",
                  **{f"dep{i}": f"deps/dep{i}.py" for i in range(12)}}
    edges = [(f"dep{i}", "queue", f"deps/dep{i}.py") for i in range(12)]
    edges.append(("src_aramid_queue", "queue", "src/aramid/queue.py"))  # self
    _write_graph(tmp_path, file_nodes, ["queue"], edges)
    score, reasons = triage.blast_radius_signal(tmp_path, ["src/aramid/queue.py"])
    assert score == 25  # >= 10 dependents
    assert "12 dependents" in reasons[0]
    # nothing imports dep3 -> no dependents
    assert triage.blast_radius_signal(tmp_path, ["deps/dep3.py"]) == (0, [])


def test_blast_radius_thresholds(tmp_path):
    # 2 external dependents + 1 self-import edge -> self excluded -> 10
    file_nodes = {"src_aramid_queue": "src/aramid/queue.py",
                  "a": "a.py", "b": "b.py", "c": "c.py"}
    edges = [("a", "queue", "a.py"), ("b", "queue", "b.py"),
             ("src_aramid_queue", "queue", "src/aramid/queue.py")]
    _write_graph(tmp_path, file_nodes, ["queue"], edges)
    assert triage.blast_radius_signal(tmp_path, ["src/aramid/queue.py"])[0] == 10
    # 3 dependents -> 18
    edges.append(("c", "queue", "c.py"))
    _write_graph(tmp_path, file_nodes, ["queue"], edges)
    assert triage.blast_radius_signal(tmp_path, ["src/aramid/queue.py"])[0] == 18


@pytest.mark.skipif(not (REPO_ROOT / "graph-out" / "graph.json").exists(),
                    reason="no graphite graph in this checkout")
def test_blast_radius_real_graph_smoke():
    # Against this repo's ACTUAL graphite output: queue.py is imported by
    # several modules on this branch, so the signal must find dependents.
    # This is the test that would have caught the placeholder-schema bug.
    score, reasons = triage.blast_radius_signal(REPO_ROOT, ["src/aramid/queue.py"])
    assert score > 0
    assert reasons and "dependents" in reasons[0]


def test_blast_radius_corrupt_graph_is_zero(tmp_path):
    (tmp_path / "graph-out").mkdir()
    graph = tmp_path / "graph-out" / "graph.json"
    graph.write_text("[]", encoding="utf-8")  # valid JSON, wrong shape
    assert triage.blast_radius_signal(tmp_path, ["core.py"]) == (0, [])
    graph.write_bytes(b"\xff\xfe{")  # invalid UTF-8
    assert triage.blast_radius_signal(tmp_path, ["core.py"]) == (0, [])


# --- combined scorer + budget ---------------------------------------------

def _fake_git(monkeypatch, paths, diff):
    from aramid import triage as t
    monkeypatch.setattr(t.gitutil, "diff_paths", lambda root, base, head: paths)
    # score() now scopes the diff to the filtered paths (diff_text(..., paths=)),
    # so the mock must accept the paths kwarg. It ignores the value and returns
    # the same body -- the scoping behavior itself is exercised by
    # test_content_signal_ignores_filtered_graphite_diff_body below.
    monkeypatch.setattr(t.gitutil, "diff_text",
                        lambda root, base, head, max_bytes=400_000, paths=None: diff)


def test_score_combines_and_clamps(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "l.db")
    _fake_git(monkeypatch, ["src/auth/handler.py"], "+exec(x)\n")
    cfg_triage = {"min_score": 40, "extra_security_paths": []}
    cfg = type("C", (), {"triage": cfg_triage, "ignore_paths": []})()
    result = triage.score(tmp_path, "a", "b", cfg, led)
    # path 30 + content 25 + novelty 20 (+ blast 0, no graph) = 75
    assert result.score == 75
    assert result.paths == ("src/auth/handler.py",)
    led.close()


def test_score_budget_stops_early(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "l.db")
    _fake_git(monkeypatch, ["src/auth/handler.py"], "+exec(x)\n")
    cfg = type("C", (), {"triage": {"min_score": 40, "extra_security_paths": []},
                         "ignore_paths": []})()
    clock = iter([0.0, 0.1, 99.0, 99.0, 99.0, 99.0]).__next__  # budget blown after 1st signal
    result = triage.score(tmp_path, "a", "b", cfg, led, budget_s=2.0, monotonic=clock)
    assert result.score == 30  # only the path signal ran
    assert any("budget" in r for r in result.reasons)
    led.close()


def test_run_triage_records_and_enqueues(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "l.db")
    _fake_git(monkeypatch, ["src/auth/handler.py"], "+exec(x)\n")
    cfg = type("C", (), {"triage": {"min_score": 40, "extra_security_paths": []},
                         "ignore_paths": []})()
    result, queued = triage.run_triage(tmp_path, cfg, led, "a", "b", "2026-07-13T12:00:00+00:00")
    assert queued is True
    assert queue.last_triaged_head(led) == "b"
    item = queue.queued_item(queue.materialize_queue(led.events()))
    assert item is not None and item.score == result.score
    led.close()


def test_run_triage_below_threshold_records_but_does_not_enqueue(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "l.db")
    _fake_git(monkeypatch, ["docs/notes.md"], "+hello\n")
    cfg = type("C", (), {"triage": {"min_score": 40, "extra_security_paths": []},
                         "ignore_paths": []})()
    result, queued = triage.run_triage(tmp_path, cfg, led, "a", "b", "2026-07-13T12:00:00+00:00")
    assert queued is False and result.score == 20  # novelty only
    assert queue.queued_item(queue.materialize_queue(led.events())) is None
    assert queue.last_triaged_head(led) == "b"  # still recorded
    led.close()


# --- FIX 4: score()/run_triage() must filter_paths() before feeding paths
#     into path/novelty/blast-radius signals and record_triage (spec 8b:
#     tracked graphite artifacts must never be triaged as targets). Uses a
#     REAL load_config (not the minimal test double above) because
#     filter_paths needs cfg.ignore_paths, which only a real load_config
#     populates with the built-in graphite entries. -------------------------

def _real_cfg(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-such-user-config" / "config.toml")
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    return repo, config_mod.load_config(repo)


def test_score_filters_graphite_artifacts_from_signals(tmp_path, monkeypatch):
    repo, cfg = _real_cfg(tmp_path, monkeypatch)
    led = Ledger(tmp_path / "l.db")
    _fake_git(monkeypatch, ["graph-out/graph.json", "src/auth.py"], "")
    result = triage.score(repo, "a", "b", cfg, led)
    assert "graph-out/graph.json" not in result.paths
    assert "src/auth.py" in result.paths
    led.close()


def test_content_signal_ignores_filtered_graphite_diff_body(tmp_path, monkeypatch):
    # A tracked graphite artifact (filtered out of `paths`) must not feed
    # content_signal. When EVERY changed file is a graphite artifact, the
    # post-filter path set is empty and the diff must be "" -- NOT a fallback
    # to the full (risky) diff body. Discriminating mock: an unscoped/empty
    # pathspec returns a risky body (the bug); a scoped call returns nothing.
    from aramid import triage as t
    repo, cfg = _real_cfg(tmp_path, monkeypatch)
    led = Ledger(tmp_path / "l.db")
    monkeypatch.setattr(t.gitutil, "diff_paths",
                        lambda root, base, head: ["graph-out/graph.json"])

    def fake_diff_text(root, base, head, max_bytes=400_000, paths=None):
        if not paths:
            return "+exec(payload)\n"   # the dangerous full-diff fallback
        return ""                        # scoped to a real path set -> nothing

    monkeypatch.setattr(t.gitutil, "diff_text", fake_diff_text)
    result = triage.score(repo, "a", "b", cfg, led)
    assert not any("risky-content" in r for r in result.reasons)
    led.close()


def test_run_triage_filters_graphite_artifacts_from_triaged_paths(tmp_path, monkeypatch):
    repo, cfg = _real_cfg(tmp_path, monkeypatch)
    led = Ledger(tmp_path / "l.db")
    _fake_git(monkeypatch, ["graph-out/graph.json", "src/auth.py"], "")
    result, queued = triage.run_triage(repo, cfg, led, "a", "b",
                                       "2026-07-13T12:00:00+00:00")
    recorded = queue.triaged_paths(led)
    assert "src/auth.py" in recorded
    assert "graph-out/graph.json" not in recorded
    # novelty must not have counted the graphite path either
    assert any("novelty: 1 unseen" in r for r in result.reasons)
    assert not any("graph-out" in r for r in result.reasons)
    led.close()
