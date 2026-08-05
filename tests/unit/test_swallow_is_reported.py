"""The fail-safe handlers must SAY when they swallowed something.

Eleven `except Exception: continue` guards across the gate and the drain were
silent. Each is correct to skip -- a malformed ledger record must never crash
a gate -- but a silent skip makes a corrupt ledger produce output identical to
a clean run.

test_diagnostics.py covers the helpers. This file covers the thing that
actually matters: that a REAL malformed record, fed to a REAL gate function,
produces both the fail-safe behaviour AND a report. A helper nothing calls is
worth nothing, and the eleven call sites are where the wiring can be wrong.

The malformed shape used throughout is `"line": None`. That is not invented:
`int(rec.get("line", 0))` returns None rather than the default when the key is
present-but-null, so `int(None)` raises TypeError -- the exact case the
original guards' comments cite.
"""
import pytest

from aramid import mutation_gate, review
from aramid.models import Gate


class _FakeLedger:
    """Only what the gate functions touch. A real Ledger cannot hold a
    malformed record -- record_run builds the payload from a Finding -- so
    corruption has to be injected at this seam."""

    def __init__(self, findings):
        self._findings = findings
        self.appended = []

    def open_findings(self):
        return dict(self._findings)

    def append(self, event):
        self.appended.append(event)


class _Cfg:
    def __init__(self, **sections):
        self.llm = sections.get("llm", {})
        self.mutation = sections.get("mutation", {})


def _llm_rec(**over):
    rec = {"source": "llm", "status": "open", "severity": "critical",
           "confirmed": True, "rule": "llm/a01", "file": "a.py", "line": 1,
           "message": "m", "evidence": "e"}
    rec.update(over)
    return rec


def _mutation_rec(**over):
    rec = {"tool": "mutation", "status": "open", "severity": "high",
           "rule": "survived", "file": "a.py", "line": 1, "message": "m",
           "evidence": "e"}
    rec.update(over)
    return rec


# --------------------------------------------------------------- llm gate ---
# The highest-stakes site: a rec skipped here never reaches the BLOCK gate.


def test_llm_gate_still_skips_a_malformed_record(capsys):
    """Behaviour unchanged -- the gate must not crash, and must not invent a
    finding from a record it could not read."""
    ledger = _FakeLedger({"a" * 64: _llm_rec(line=None)})
    out = review.llm_gate_findings(_Cfg(llm={"llm_block_armed": True}),
                                   ledger, Gate.PRE_PUSH)
    assert out == []


def test_llm_gate_reports_that_it_skipped(capsys):
    ledger = _FakeLedger({"a" * 64: _llm_rec(line=None)})
    review.llm_gate_findings(_Cfg(llm={"llm_block_armed": True}),
                             ledger, Gate.PRE_PUSH)
    err = capsys.readouterr().err
    assert "llm-gate" in err and "1" in err, err


def test_llm_gate_is_silent_when_every_record_is_well_formed(capsys):
    """The guard against chatter. If this fails, every push grows a line of
    noise and the operator learns to skip past the report."""
    ledger = _FakeLedger({"a" * 64: _llm_rec()})
    out = review.llm_gate_findings(_Cfg(llm={"llm_block_armed": True}),
                                   ledger, Gate.PRE_PUSH)
    assert len(out) == 1
    assert capsys.readouterr().err == ""


def test_a_good_record_alongside_a_bad_one_still_reaches_the_gate(capsys):
    """Skipping is per-record, not per-run: one corrupt row must not take a
    confirmed critical down with it."""
    ledger = _FakeLedger({"a" * 64: _llm_rec(line=None),
                          "b" * 64: _llm_rec(file="good.py")})
    out = review.llm_gate_findings(_Cfg(llm={"llm_block_armed": True}),
                                   ledger, Gate.PRE_PUSH)
    assert [f.file for f in out] == ["good.py"]
    assert "llm-gate" in capsys.readouterr().err


def test_the_count_is_reported_once_not_once_per_record(capsys):
    """Three bad rows, one line. A corrupted ledger must not flood the gate
    report -- that is why these are counters and not prints in the handler."""
    ledger = _FakeLedger({c * 64: _llm_rec(line=None) for c in "abc"})
    review.llm_gate_findings(_Cfg(llm={"llm_block_armed": True}),
                             ledger, Gate.PRE_PUSH)
    err = capsys.readouterr().err.strip()
    assert len(err.splitlines()) == 1, err
    assert "3" in err


# ---------------------------------------------------------- mutation gate ---


def test_mutation_gate_skips_and_reports(capsys):
    ledger = _FakeLedger({"a" * 64: _mutation_rec(line=None)})
    out = mutation_gate.mutation_gate_findings(
        _Cfg(mutation={"mutation_block_armed": True}), ledger, Gate.PRE_PUSH)
    assert out == []
    assert "mutation-gate" in capsys.readouterr().err


def test_mutation_gate_is_silent_on_clean_input(capsys):
    ledger = _FakeLedger({"a" * 64: _mutation_rec()})
    out = mutation_gate.mutation_gate_findings(
        _Cfg(mutation={"mutation_block_armed": True}), ledger, Gate.PRE_PUSH)
    assert len(out) == 1
    assert capsys.readouterr().err == ""


# ------------------------------------------------------------- providers ----


def test_a_provider_whose_probe_raises_is_named(capsys, monkeypatch):
    """A raising probe reads as "not configured", and the LLM half of the
    product then does nothing forever with no indication why. The provider's
    NAME is the whole value of this message."""
    from aramid.providers import base as providers_base

    class _Exploding:
        @staticmethod
        def available(cfg):
            raise RuntimeError("credentials file is corrupt")

    monkeypatch.setitem(providers_base.PROVIDERS, "wobbly", _Exploding)
    cfg = _Cfg(llm={"provider_order": ["wobbly"]})

    assert providers_base.chain(cfg) == []          # fail-open, unchanged
    err = capsys.readouterr().err
    assert "wobbly" in err
    assert "RuntimeError" in err
    assert "credentials file is corrupt" in err


def test_a_healthy_provider_chain_stays_quiet(capsys, monkeypatch):
    from aramid.providers import base as providers_base

    class _Fine:
        @staticmethod
        def available(cfg):
            return True

    monkeypatch.setitem(providers_base.PROVIDERS, "steady", _Fine)
    cfg = _Cfg(llm={"provider_order": ["steady"]})

    assert providers_base.chain(cfg) == [_Fine]
    assert capsys.readouterr().err == ""


# ----------------------------------------------------------------- mutant ---


def test_mutant_generation_stays_quiet_on_ordinary_code(capsys):
    """Counting unparseable mutants must not turn ordinary mutation into a
    chatty operation. Asserts mutants were actually produced first -- a run
    that generated nothing would be silent for the wrong reason."""
    from aramid import mutation

    mutants = mutation.generate_mutants("def f(x):\n    return x + 1\n", {2})

    assert mutants, "no mutants generated -- this check would pass vacuously"
    assert capsys.readouterr().err == ""
