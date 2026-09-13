"""`consumers.regression_pack.consume` at unit scope: the two skips, the
argv, the degrade and the parse, each exact.

The drain confirms a mutant against the unit suite alone, and until this
file nothing in it reached `consume`; its 2 generated mutants were held by
tests/integration/test_regression_pack_consumer.py, which the drain never
runs. Seams: `_changed_paths` (git) and `run_subprocess` (semgrep), the
same two that file replaces."""
import json

from aramid import pack
from aramid.consumers import regression_pack as rp
from aramid.consumers.base import DrainContext
from aramid.queue import QueueItem
from aramid.runners.base import RunnerResult, ToolState


def _item():
    return QueueItem(id="i1", base="b" * 40, head="h" * 40, score=50, reasons=("r",),
                     state="queued", created_at="t", updated_at="t")


def _ctx(root):
    return DrainContext(root=root, cfg=None, ledger=None, clock=lambda: "t")


def _pack(root):
    p = root / pack.RULES_REL_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("rules: []\n", encoding="utf-8")
    return p


class Semgrep:
    def __init__(self, out):
        self.out = out
        self.calls = []

    def __call__(self, argv, cwd, timeout_s, env=None):
        self.calls.append((list(argv), cwd, timeout_s))
        return self.out


def _run(root, monkeypatch, changed, out):
    monkeypatch.setattr(rp, "_changed_paths", lambda r, item: list(changed))
    sg = Semgrep(out)
    monkeypatch.setattr(rp, "run_subprocess", sg)
    return rp.consume(_item(), _ctx(root)), sg


def test_no_pack_file_is_an_ok_noop_before_git_is_asked(tmp_path, monkeypatch):
    def never(*a):
        raise AssertionError("diff_paths must not run without a pack")
    monkeypatch.setattr(rp, "_changed_paths", never)

    res = rp.consume(_item(), _ctx(tmp_path))

    assert (res.state, res.note, res.findings, res.cost) == ("ok", "no pack file", [], 0.0)


def test_a_range_whose_files_are_gone_is_an_ok_noop_before_semgrep_runs(
        tmp_path, monkeypatch):
    _pack(tmp_path)

    res, sg = _run(tmp_path, monkeypatch, ["deleted.py"], None)

    assert (res.state, res.note, res.findings) == ("ok", "no files in range", [])
    assert sg.calls == []


def test_semgrep_runs_the_pack_only_against_the_surviving_files(tmp_path, monkeypatch):
    p = _pack(tmp_path)
    (tmp_path / "a.py").write_text("x\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("x\n", encoding="utf-8")

    res, sg = _run(tmp_path, monkeypatch, ["a.py", "gone.py", "b.py"],
                   RunnerResult(tool="semgrep", state=ToolState.OK, raw='{"results": []}'))

    assert sg.calls == [(["semgrep", "--config", str(p), "--json", "--metrics=off",
                          "--quiet", "--", "a.py", "b.py"], tmp_path, 120.0)]
    assert (res.state, res.findings, res.cost) == ("ok", [], 0.0)


def test_a_semgrep_that_did_not_finish_degrades_with_its_state(tmp_path, monkeypatch):
    _pack(tmp_path)
    (tmp_path / "a.py").write_text("x\n", encoding="utf-8")

    res, _ = _run(tmp_path, monkeypatch, ["a.py"],
                  RunnerResult(tool="semgrep", state=ToolState.TIMEOUT, raw=""))

    assert (res.state, res.note, res.findings) == ("degraded", "semgrep timeout", [])


def test_a_hit_is_parsed_into_a_finding(tmp_path, monkeypatch):
    _pack(tmp_path)
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "prod.env").write_text("x\n", encoding="utf-8")
    payload = {"results": [{"check_id": "x.aramid-regression.block.deadbeef",
                            "path": "cfg/prod.env", "start": {"line": 3},
                            "extra": {"severity": "ERROR", "message": "reintroduction"}}]}

    res, _ = _run(tmp_path, monkeypatch, ["cfg/prod.env"],
                  RunnerResult(tool="semgrep", state=ToolState.OK, raw=json.dumps(payload)))

    assert res.state == "ok" and res.cost == 0.0
    assert [(f.rule, f.file, f.line, f.message) for f in res.findings] == [
        ("aramid-regression.block.deadbeef", "cfg/prod.env", 3, "reintroduction")]
