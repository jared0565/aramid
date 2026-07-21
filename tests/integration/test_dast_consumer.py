import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from aramid import config as config_mod
from aramid.consumers import dast as dc
from aramid.consumers.base import DrainContext
from aramid.ledger import Ledger
from aramid.queue import QueueItem


# A distinct-char head (not "h"*40) so a wrong head[:12] slice length would break
# the give-up test's seeded-note prefix. 40 hex-ish chars, all distinct in [:12].
_HEAD = "0123456789abcdef0123456789abcdef01234567"


def _item():
    return QueueItem(id="q1", base="b" * 40, head=_HEAD, score=55,
                     reasons=("t",), state="queued", created_at="t", updated_at="t")


def _consume(root, cfg):
    led = Ledger(root / ".aramid" / "ledger.db")
    try:
        return dc.consume(_item(),
                          DrainContext(root=root, cfg=cfg, ledger=led, clock=lambda: "t"))
    finally:
        led.close()


def _cfg(tmp_path, monkeypatch, toml_body):
    r = tmp_path / "r"
    r.mkdir(exist_ok=True)
    (r / "aramid.toml").write_text(toml_body, encoding="utf-8")
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    return r, config_mod.load_config(r)


def test_disabled_returns_ok(tmp_path, monkeypatch):
    r, cfg = _cfg(tmp_path, monkeypatch, "schema_version = 1\n[dast]\nenabled = false\n")
    res = _consume(r, cfg)
    assert res.state == "ok" and res.note == "disabled"


def test_no_base_url_ok_skip(tmp_path, monkeypatch):
    r, cfg = _cfg(tmp_path, monkeypatch, "schema_version = 1\n[dast]\nbase_url = \"\"\n")
    res = _consume(r, cfg)
    assert res.state == "ok"
    assert "no dast target" in res.note


def test_registered_in_consumers():
    from aramid.consumers import base
    assert base.CONSUMERS["dast"] is dc
    assert dc.PIN_OCCURRENCE is True


class _Handler(BaseHTTPRequestHandler):
    routes: dict = {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        status, headers, body = self.routes.get(self.path,
                                                (404, [("Content-Type", "text/plain")], b"no"))
        self.send_response_only(status)   # NOT send_response: that auto-injects
        # its own Server/Date headers, which would shadow the route's headers and
        # break the banner checks. send_response_only writes only the status line.
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


def _server(routes):
    _Handler.routes = routes
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_findings_reported_and_shape(tmp_path, monkeypatch):
    srv, url = _server({"/": (200, [("Content-Type", "text/html")], b"<html></html>")})
    try:
        r, cfg = _cfg(tmp_path, monkeypatch,
                      f"schema_version = 1\n[dast]\nbase_url = \"{url}\"\n")
        res = _consume(r, cfg)
    finally:
        srv.shutdown()
        srv.server_close()
    assert res.state == "ok"
    assert res.cost == 0.0
    assert res.findings, "a bare http response has missing headers -> findings"
    f = res.findings[0]
    assert f.tool == "dast"
    assert f.file.startswith("GET ")
    assert f.line == 0


def test_unreachable_degrades_with_loadbearing_note(tmp_path, monkeypatch):
    # base_url points at a closed port -> DastUnreachable -> DEGRADED
    r, cfg = _cfg(tmp_path, monkeypatch,
                  "schema_version = 1\n[dast]\nbase_url = \"http://127.0.0.1:1/\"\ntimeout_s = 1\n")
    res = _consume(r, cfg)
    assert res.state == "degraded"
    assert res.note.startswith("dast target unreachable @ ")


def test_give_up_after_three_unreachable(tmp_path, monkeypatch):
    from aramid.models import Event, EventType
    r, cfg = _cfg(tmp_path, monkeypatch,
                  "schema_version = 1\n[dast]\nbase_url = \"http://127.0.0.1:1/\"\ntimeout_s = 1\n")
    led = Ledger(r / ".aramid" / "ledger.db")
    head12 = _HEAD[:12]
    try:
        for i in range(3):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"r{i}", "t",
                             payload={"consumer": "dast", "item_id": "q1",
                                      "note": f"dast target unreachable @ {head12}"}))
    finally:
        led.close()
    res = _consume(r, cfg)
    assert res.state == "ok"
    assert "giving up" in res.note


def test_bad_port_base_url_ok_skip(tmp_path, monkeypatch):
    # a port typo is a CONFIG mistake -> OK-skip, NOT degraded (degraded would pin
    # the queue item forever). Regression lock for the whole-branch Important fix.
    r, cfg = _cfg(tmp_path, monkeypatch,
                  "schema_version = 1\n[dast]\nbase_url = \"http://127.0.0.1:99999/\"\n")
    res = _consume(r, cfg)
    assert res.state == "ok"
    assert "invalid dast base_url" in res.note


def test_probe_crash_degrades_with_headscoped_note(tmp_path, monkeypatch):
    # a non-DastUnreachable crash degrades with a HEAD-SCOPED give-up prefix, so a
    # persistent crash can eventually give up (never pins forever).
    def _boom(*a, **k):
        raise RuntimeError("synthetic prober crash")
    monkeypatch.setattr("aramid.dast_probe.probe", _boom)
    r, cfg = _cfg(tmp_path, monkeypatch,
                  "schema_version = 1\n[dast]\nbase_url = \"http://127.0.0.1:1/\"\ntimeout_s = 1\n")
    res = _consume(r, cfg)
    assert res.state == "degraded"
    assert res.note.startswith("dast probe error @ ")


def test_dast_finding_fingerprint_stable_through_normalize(tmp_path, monkeypatch):
    # dast is the first PIN_OCCURRENCE consumer emitting a SYNTHETIC file="GET /path"
    # with line=0. Drive a dast RawFinding through the SAME normalize() call the drain
    # uses (see commands/drain.py) and assert: line=0 is safe (no IndexError), the
    # finding is WARN-tier, and the fingerprint is STABLE across two drains (no ghost
    # never-resolving re-detection).
    import functools
    import subprocess
    from aramid import policy
    from aramid.models import Gate
    from aramid.normalizer import RawFinding, normalize
    r, cfg = _cfg(tmp_path, monkeypatch, "schema_version = 1\n[dast]\nbase_url = \"http://x/\"\n")
    subprocess.run(["git", "init", "-q"], cwd=r, check=True, capture_output=True)
    raw = RawFinding(tool="dast", rule="dast-header-csp", severity_raw="medium",
                     file="GET /", line=0,
                     message="Content-Security-Policy response header is missing",
                     evidence="present headers: Content-Type")
    args = (r, lambda f: "deadbeefcafe", b"salt-fixed-16byt", Gate.ALL,
            functools.partial(policy.classify, cfg=cfg))
    a = normalize([raw], *args, pin_occurrence=True)
    b = normalize([raw], *args, pin_occurrence=True)
    assert len(a) == 1
    assert a[0].tool == "dast" and a[0].file == "GET /" and a[0].line == 0
    assert a[0].verdict.name == "WARN"          # dast rides the classify catch-all
    assert a[0].id == b[0].id                    # stable fingerprint -> no ghost re-detect
