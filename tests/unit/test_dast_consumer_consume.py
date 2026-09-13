"""`consumers.dast.consume` at unit scope: every branch, note, default and
claim, one exact assertion each.

The drain confirms a mutant against the unit suite alone, and until this
file nothing in it reached `consume` -- the 14 mutants the generator emits
for its body were held by tests/integration/test_dast_consumer.py (a real
HTTP server), which the drain never runs. The seam here is the one that
file already uses for the crash arm: `dast_probe.probe_scoped` replaced by
a fake that records what it was asked and answers a script."""
from types import SimpleNamespace

from aramid.consumers import dast as dc
from aramid.consumers.base import DrainContext
from aramid.dast_probe import DastFinding, DastUnreachable
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Finding, Gate, Severity, Verdict
from aramid.queue import QueueItem

HEAD = "0123456789abcdef0123456789abcdef01234567"
CSP = DastFinding(check="dast-header-csp", method="GET", path="/", severity="medium",
                  message="Content-Security-Policy missing", evidence="headers: 4")
GIT = DastFinding(check="dast-exposed-path", method="GET", path="/.git/config",
                  severity="high", message="exposed", evidence="status: 200")


def _ctx(root, dast, ledger=None):
    return DrainContext(root=root, cfg=SimpleNamespace(dast=dast), ledger=ledger,
                        clock=lambda: "t")


def _item(head=HEAD, item_id="q1"):
    return QueueItem(id=item_id, base="b" * 40, head=head, score=55, reasons=("t",),
                     state="queued", created_at="t", updated_at="t")


class Probe:
    """`probe_scoped` that records its arguments and answers `result` --
    a (findings, probed) pair, or an exception instance to raise."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def __call__(self, base_url, paths, timeout_s):
        self.calls.append((base_url, list(paths), timeout_s))
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def _run(tmp_path, monkeypatch, dast, probe=None, *, ledger=True, head=HEAD, item_id="q1"):
    probe = probe if probe is not None else Probe(([], set()))
    monkeypatch.setattr(dc.dast_probe, "probe_scoped", probe)
    led = Ledger(tmp_path / "ledger.db") if ledger else None
    try:
        res = dc.consume(_item(head, item_id), _ctx(tmp_path, dast, led))
    finally:
        if led is not None:
            led.close()
    return res, probe


def _seed_open(root, fid, file):
    led = Ledger(root / "ledger.db")
    try:
        led.record_run("seed", "2026-08-10T00:00:00+00:00", "drain", set(), set(),
                       [Finding(id=fid, tool="dast", rule="dast-header-csp",
                                severity_raw="medium", severity=Severity.MEDIUM,
                                verdict=Verdict.WARN, file=file, line=0,
                                message="header missing", evidence="", gate=Gate.ALL)])
    finally:
        led.close()


def _seed_notes(root, n, note, item_id="q1"):
    led = Ledger(root / "ledger.db")
    try:
        for k in range(n):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"d{k}",
                             f"2026-08-10T0{k}:00:00+00:00",
                             payload={"consumer": "dast", "item_id": item_id,
                                      "state": "degraded", "note": note, "duration_s": 1.0}))
    finally:
        led.close()


# ------------------------------------------------------- structural skips --

def test_a_config_with_no_dast_table_is_an_unconfigured_target(tmp_path, monkeypatch):
    res, probe = _run(tmp_path, monkeypatch, None, ledger=False)

    assert (res.state, res.note) == ("ok", "no dast target configured")
    assert probe.calls == []


def test_disabled_says_so_and_looks_no_further(tmp_path, monkeypatch):
    res, probe = _run(tmp_path, monkeypatch,
                      {"enabled": False, "base_url": "http://h/"}, ledger=False)

    assert (res.state, res.note) == ("ok", "disabled")
    assert probe.calls == []


def test_an_empty_base_url_is_unconfigured_not_invalid(tmp_path, monkeypatch):
    res, probe = _run(tmp_path, monkeypatch, {"base_url": "   "}, ledger=False)

    assert (res.state, res.note) == ("ok", "no dast target configured")
    assert probe.calls == []


def test_a_scheme_that_is_not_http_is_invalid_even_with_a_host(tmp_path, monkeypatch):
    res, probe = _run(tmp_path, monkeypatch, {"base_url": "ftp://h/"}, ledger=False)

    assert (res.state, res.note) == (
        "ok", "invalid dast base_url (need http(s)://host with a valid port)")
    assert probe.calls == []


def test_an_http_url_without_a_host_is_invalid(tmp_path, monkeypatch):
    res, probe = _run(tmp_path, monkeypatch, {"base_url": "http:///p"}, ledger=False)

    assert res.note == "invalid dast base_url (need http(s)://host with a valid port)"
    assert probe.calls == []


def test_a_port_out_of_range_is_invalid_not_a_crash(tmp_path, monkeypatch):
    res, probe = _run(tmp_path, monkeypatch, {"base_url": "http://h:99999/"}, ledger=False)

    assert res.note == "invalid dast base_url (need http(s)://host with a valid port)"
    assert probe.calls == []


# --------------------------------------------------------- a real probe --

def test_the_probe_gets_the_url_the_paths_and_a_10s_default_timeout(tmp_path, monkeypatch):
    res, probe = _run(tmp_path, monkeypatch, {"base_url": " http://h/ ", "paths": ["/a"]})

    assert probe.calls == [("http://h/", ["/a"], 10.0)]
    assert res.state == "ok"


def test_the_configured_timeout_is_passed_through(tmp_path, monkeypatch):
    _, probe = _run(tmp_path, monkeypatch, {"base_url": "http://h/", "timeout_s": 2})

    assert probe.calls == [("http://h/", [], 2.0)]


def test_findings_become_warn_raws_at_line_0_with_the_synthetic_file(tmp_path, monkeypatch):
    res, _ = _run(tmp_path, monkeypatch, {"base_url": "https://h:8443/x"},
                  Probe(([CSP, GIT], {"GET /", "GET /.git/config"})))

    assert res.state == "ok" and res.cost == 0.0
    assert res.note == "2 hygiene finding(s) on h"
    assert res.extra == {"target": "h", "found": 2, "probed": ["GET /", "GET /.git/config"]}
    assert [(f.tool, f.rule, f.severity_raw, f.file, f.line, f.message, f.evidence)
            for f in res.findings] == [
        ("dast", "dast-header-csp", "medium", "GET /", 0,
         "Content-Security-Policy missing", "headers: 4"),
        ("dast", "dast-exposed-path", "high", "GET /.git/config", 0, "exposed", "status: 200")]
    assert res.repaired is None, "nothing open, nothing to claim"


# --------------------------------------------------------- degradations --

def test_an_unreachable_target_degrades_with_the_head_scoped_prefix(tmp_path, monkeypatch):
    res, _ = _run(tmp_path, monkeypatch, {"base_url": "http://h/"}, Probe(DastUnreachable()))

    assert (res.state, res.note) == ("degraded", f"dast target unreachable (last seen @ {HEAD[:12]})")
    assert res.findings == [] and res.repaired is None


def test_a_probe_crash_degrades_with_120_chars_of_the_error(tmp_path, monkeypatch):
    res, _ = _run(tmp_path, monkeypatch, {"base_url": "http://h/"},
                  Probe(RuntimeError("x" * 150)))

    assert res.state == "degraded"
    assert res.note == f"dast probe error (last seen @ {HEAD[:12]}): " + "x" * 120
    assert res.repaired is None


def test_three_unreachable_notes_at_this_head_give_up_before_probing(tmp_path, monkeypatch):
    _seed_notes(tmp_path, 3, f"dast target unreachable (last seen @ {HEAD[:12]})")

    res, probe = _run(tmp_path, monkeypatch, {"base_url": "http://h/"})

    assert (res.state, res.note) == (
        "ok", "dast giving up: target persistently unreachable or erroring")
    assert probe.calls == []


def test_two_unreachable_notes_do_not(tmp_path, monkeypatch):
    _seed_notes(tmp_path, 2, f"dast target unreachable (last seen @ {HEAD[:12]})")

    res, probe = _run(tmp_path, monkeypatch, {"base_url": "http://h/"})

    assert res.state == "ok" and res.note == "0 hygiene finding(s) on h"
    assert len(probe.calls) == 1


def test_three_crash_notes_alone_give_up_too(tmp_path, monkeypatch):
    _seed_notes(tmp_path, 3, f"dast probe error (last seen @ {HEAD[:12]}): boom")

    res, probe = _run(tmp_path, monkeypatch, {"base_url": "http://h/"})

    assert res.note == "dast giving up: target persistently unreachable or erroring"
    assert probe.calls == []


def test_notes_from_another_head_or_item_do_not_count(tmp_path, monkeypatch):
    other = "f" * 40
    _seed_notes(tmp_path, 3, f"dast target unreachable (last seen @ {other[:12]})")
    _seed_notes(tmp_path, 3, f"dast target unreachable (last seen @ {HEAD[:12]})", item_id="q0")

    res, probe = _run(tmp_path, monkeypatch, {"base_url": "http://h/"})

    assert res.note == "0 hygiene finding(s) on h"
    assert len(probe.calls) == 1


# --------------------------------------------------------------- claims --

def test_an_open_finding_on_a_probed_endpoint_that_stopped_firing_is_claimed(
        tmp_path, monkeypatch):
    fid = dc._finding_fp("dast-header-csp", "GET", "/")
    _seed_open(tmp_path, fid, "GET /")

    res, _ = _run(tmp_path, monkeypatch, {"base_url": "http://h/"}, Probe(([], {"GET /"})))

    assert res.repaired is not None
    assert (res.repaired.tool, res.repaired.reason, res.repaired.ids) == (
        "dast", "endpoint_reprobed", (fid,))


def test_a_finding_that_still_fires_on_a_probed_endpoint_is_not_claimed(
        tmp_path, monkeypatch):
    fid = dc._finding_fp("dast-header-csp", "GET", "/")
    _seed_open(tmp_path, fid, "GET /")

    res, _ = _run(tmp_path, monkeypatch, {"base_url": "http://h/"}, Probe(([CSP], {"GET /"})))

    assert res.repaired is None
    assert [f.rule for f in res.findings] == ["dast-header-csp"]


def test_a_finding_on_an_endpoint_this_scan_did_not_reach_stays_open(tmp_path, monkeypatch):
    fid = dc._finding_fp("dast-header-csp", "GET", "/admin")
    _seed_open(tmp_path, fid, "GET /admin")

    res, _ = _run(tmp_path, monkeypatch, {"base_url": "http://h/"}, Probe(([], {"GET /"})))

    assert res.repaired is None


def test_a_claim_names_only_the_probed_and_silent_ids_sorted(tmp_path, monkeypatch):
    a = dc._finding_fp("dast-header-csp", "GET", "/")
    b = dc._finding_fp("dast-header-csp", "GET", "/login")
    c = dc._finding_fp("dast-header-csp", "GET", "/admin")
    for fid, file in ((a, "GET /"), (b, "GET /login"), (c, "GET /admin")):
        _seed_open(tmp_path, fid, file)

    res, _ = _run(tmp_path, monkeypatch, {"base_url": "http://h/"},
                  Probe(([], {"GET /", "GET /login"})))

    assert res.repaired is not None and res.repaired.ids == tuple(sorted((a, b)))
