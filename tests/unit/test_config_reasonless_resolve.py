"""FN-39: the finding for a suppression entry with no reason resolves once the
entry has a reason, or is gone.

`config.load_suppressions` reports such an entry as a finding with `tool =
"aramid"`. `ledger.record_run` resolves only findings whose tool is the label
of a runner that ran, and no runner is `aramid`, so the finding stayed open
for good: measured 2026-10-13 through `run_gate`, open after the entry gained
a reason, under either gate, and after the file was deleted. Each case runs a
semgrep finding beside it as the CONTROL: it resolves when it goes away, so a
row left open is the tool gate's doing, not the harness's."""
import subprocess

from aramid import config, pipeline, yield_report
from aramid.ledger import Ledger
from aramid.models import EventType, Gate
from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState

ENTRY = '[[suppress]]\nid = "{fid}"\ntool = "semgrep"\nrule = "r"\npath = "a.py"\n'
REASON = 'reason = "reviewed: a fixture"\n'


def _git(r, *args):
    subprocess.run(["git", *args], cwd=r, check=True, capture_output=True)


class _Semgrep:
    """One semgrep hit on a.py while `hit` is set, a clean run otherwise."""
    hit = True

    @classmethod
    def run(cls, ctx):
        return RunnerResult("semgrep", ToolState.OK, raw="{}")

    @classmethod
    def parse(cls, result, ctx):
        if not cls.hit:
            return []
        return [RawFinding(tool="semgrep", rule="python.lang.correctness.x", severity_raw="low",
                           file="a.py", line=1, message="a control finding")]


def _setup(tmp_path, monkeypatch):
    r = tmp_path / "r"
    r.mkdir(parents=True)
    for args in (("init", "-b", "main"), ("config", "user.email", "t@t"),
                 ("config", "user.name", "t")):
        _git(r, *args)
    (r / "a.py").write_text("x = 1\n")
    _git(r, "add", "a.py")
    _git(r, "commit", "-m", "initial")
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "no-user-config.toml")
    monkeypatch.setattr(_Semgrep, "hit", True)
    monkeypatch.setitem(pipeline.RUNNERS, "semgrep", _Semgrep)
    for gate in (Gate.PRE_COMMIT, Gate.PRE_PUSH):
        monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, gate, ["semgrep"])
    return r, config.load_config(r), Ledger(tmp_path / "ledger.db")


def _status(ledger, tool):
    return {fid: rec["status"] for fid, rec in ledger.open_findings().items()
            if rec.get("tool") == tool}


def _first_run(r, cfg, ledger):
    (r / ".aramid-suppressions.toml").write_text(ENTRY.format(fid="a" * 64))
    pipeline.run_gate(r, Gate.PRE_PUSH, "all", cfg, ledger, run_id="g1")
    reasonless, control = _status(ledger, "aramid"), _status(ledger, "semgrep")
    assert list(reasonless.values()) == ["open"] and list(control.values()) == ["open"]
    return next(iter(reasonless))


def test_a_reason_given_resolves_the_finding_under_either_gate(tmp_path, monkeypatch):
    for gate in (Gate.PRE_PUSH, Gate.PRE_COMMIT):
        r, cfg, ledger = _setup(tmp_path / gate.value, monkeypatch)
        fid = _first_run(r, cfg, ledger)

        pipeline.run_gate(r, gate, "all", cfg, ledger, run_id="g2")
        assert _status(ledger, "aramid") == {fid: "open"}, "still without a reason: stays open"

        (r / ".aramid-suppressions.toml").write_text(ENTRY.format(fid="a" * 64) + REASON)
        _Semgrep.hit = False
        pipeline.run_gate(r, gate, "all", cfg, ledger, run_id="g3")
        assert set(_status(ledger, "semgrep").values()) == {"fixed"}, "control: the harness resolves"
        assert _status(ledger, "aramid") == {fid: "fixed"}
        resolved = [e for e in ledger.events() if e.type is EventType.FINDING_RESOLVED
                    and e.finding_id == fid]
        assert [e.payload for e in resolved] == [{"auto_resolved": "reasonless_entry_gone"}]
        ledger.close()


def test_a_removed_entry_or_file_resolves_the_finding(tmp_path, monkeypatch):
    for how in ("entry", "file"):
        r, cfg, ledger = _setup(tmp_path / how, monkeypatch)
        fid = _first_run(r, cfg, ledger)
        sup = r / ".aramid-suppressions.toml"
        if how == "entry":
            sup.write_text("# every entry reviewed and removed\n")
        else:
            sup.unlink()
        _Semgrep.hit = False
        pipeline.run_gate(r, Gate.PRE_PUSH, "all", cfg, ledger, run_id="g2")
        assert set(_status(ledger, "semgrep").values()) == {"fixed"}, "control: the harness resolves"
        assert _status(ledger, "aramid") == {fid: "fixed"}, how
        ledger.close()


def test_the_resolver_says_what_it_walked_and_registers_itself(tmp_path, monkeypatch):
    """Every gate run records the resolver's yield, a zero included, so its
    silence can mean only "never called" (`ledger.note_yield`); and the
    report grades the pair rather than calling it UNREGISTERED."""
    r, cfg, ledger = _setup(tmp_path, monkeypatch)
    _first_run(r, cfg, ledger)
    (r / ".aramid-suppressions.toml").write_text(
        ENTRY.format(fid="a" * 64) + REASON + "\n" + ENTRY.format(fid="b" * 64))
    pipeline.run_gate(r, Gate.PRE_PUSH, "all", cfg, ledger, run_id="g2")

    yields = [(e.run_id, e.payload) for e in ledger.events() if e.type is EventType.RESOLVER_YIELD
              and e.payload.get("resolver") == "reasonless_entry_gone"]
    assert yields == [
        ("g1", {"resolver": "reasonless_entry_gone", "tool": "aramid",
                "considered": 1, "resolved": 0}),
        ("g2", {"resolver": "reasonless_entry_gone", "tool": "aramid",
                "considered": 2, "resolved": 1}),
    ], "g1: walked and still reported; g2: the a-entry resolved, the new b-entry walked"
    assert ("reasonless_entry_gone", "aramid") in yield_report.EXPECTED
    ledger.close()


def test_an_entry_that_stays_without_a_reason_is_no_clears_not_blind(tmp_path, monkeypatch):
    """The report's other half: a standing entry is an outcome, not a broken
    resolver, so `aramid status` must not name it a resolver defect."""
    r, cfg, ledger = _setup(tmp_path, monkeypatch)
    _first_run(r, cfg, ledger)
    pipeline.run_gate(r, Gate.PRE_PUSH, "all", cfg, ledger, run_id="g2")
    rows = {(row.resolver, row.tool): row for row in yield_report.collect(ledger)}
    row = rows[("reasonless_entry_gone", "aramid")]
    assert (row.runs, row.verdict, row.flagged) == (2, yield_report.NO_CLEARS, False)
    ledger.close()
