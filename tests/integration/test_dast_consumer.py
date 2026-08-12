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
    assert res.note.startswith("dast target unreachable (last seen @ ")


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
                                      "note": f"dast target unreachable (last seen @ {head12})"}))
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
    # Patches `probe_scoped`, which is what the consumer calls -- `probe` is now
    # a thin delegator, and patching it would leave this guard pointing at a
    # function nothing on this path invokes. It failed loudly when the seam
    # moved, which is the only reason that was noticed.
    monkeypatch.setattr("aramid.dast_probe.probe_scoped", _boom)
    r, cfg = _cfg(tmp_path, monkeypatch,
                  "schema_version = 1\n[dast]\nbase_url = \"http://127.0.0.1:1/\"\ntimeout_s = 1\n")
    res = _consume(r, cfg)
    assert res.state == "degraded"
    assert res.note.startswith("dast probe error (last seen @ ")


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


# --- dast can prove a repair ------------------------------------------------
#
# dast had no resolver of ANY kind: nothing matched tool="dast", record_run
# cannot reach it (runner labels only), drain._consume_item passes empty
# scopes, and it is explicitly barred from departed-file resolution because its
# `file` is "GET /login" -- not a path, so "has it left the repo" has no
# answer. Fix the missing header and the finding stayed open forever.
#
# What makes resolution safe here is that a probe of a reachable endpoint is a
# COMPLETE re-examination of it: every check family runs against that one
# response. So absence really does mean clean -- but only for endpoints that
# ANSWERED, which is why the scope comes from `probe_scoped` and not from the
# configured path list.

_HARDENED = {"/": (200, [
    ("Content-Type", "text/html"),
    ("Content-Security-Policy", "default-src 'self'"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "geolocation=()"),
], b"<html></html>")}


def _seed_open(root, fid, file="GET /", rule="dast-header-csp"):
    from aramid.models import Finding, Gate, Severity, Verdict
    led = Ledger(root / ".aramid" / "ledger.db")
    try:
        led.record_run("seed", "2026-08-10T00:00:00+00:00", "drain", set(), set(),
                       [Finding(id=fid, tool="dast", rule=rule,
                                severity_raw="medium", severity=Severity.MEDIUM,
                                verdict=Verdict.WARN, file=file, line=0,
                                message="header missing", evidence="",
                                gate=Gate.ALL)])
    finally:
        led.close()


def test_the_consumer_derives_the_same_id_normalize_gives_the_finding(
        tmp_path, monkeypatch):
    """THE identity that makes every claim below mean anything, with one side
    from each computation -- `_finding_fp` here, `normalize` there. A test that
    read both sides from `_finding_fp` would only prove it is deterministic,
    which is not the property in question."""
    import functools
    import subprocess

    from aramid import policy
    from aramid.models import Gate
    from aramid.normalizer import RawFinding, normalize

    r, cfg = _cfg(tmp_path, monkeypatch,
                  "schema_version = 1\n[dast]\nbase_url = \"http://x/\"\n")
    subprocess.run(["git", "init", "-q"], cwd=r, check=True, capture_output=True)
    raw = RawFinding(tool="dast", rule="dast-header-csp", severity_raw="medium",
                     file="GET /", line=0, message="m", evidence="e")
    normalized = normalize([raw], r, lambda f: "deadbeefcafe", b"salt-fixed-16byt",
                           Gate.ALL, functools.partial(policy.classify, cfg=cfg),
                           pin_occurrence=True)

    assert dc._finding_fp("dast-header-csp", "GET", "/") == normalized[0].id


def test_a_fixed_hygiene_issue_on_a_probed_endpoint_is_claimed_repaired(
        tmp_path, monkeypatch):
    srv, url = _server(_HARDENED)
    try:
        r, cfg = _cfg(tmp_path, monkeypatch,
                      f"schema_version = 1\n[dast]\nbase_url = \"{url}\"\n")
        _seed_open(r, dc._finding_fp("dast-header-csp", "GET", "/"))
        res = _consume(r, cfg)
    finally:
        srv.shutdown()
        srv.server_close()

    assert res.repaired is not None, "a hardened endpoint proved nothing"
    assert res.repaired.tool == "dast"
    assert res.repaired.reason == "endpoint_reprobed"
    assert dc._finding_fp("dast-header-csp", "GET", "/") in set(res.repaired.ids)


def test_a_finding_that_still_fires_is_never_claimed(tmp_path, monkeypatch):
    """The counterfactual. A bare response still has no CSP header, so that
    finding re-fires -- and a producer must never claim repair for something it
    is reporting in the same breath."""
    srv, url = _server({"/": (200, [("Content-Type", "text/html")], b"<html></html>")})
    try:
        r, cfg = _cfg(tmp_path, monkeypatch,
                      f"schema_version = 1\n[dast]\nbase_url = \"{url}\"\n")
        fid = dc._finding_fp("dast-header-csp", "GET", "/")
        _seed_open(r, fid)
        res = _consume(r, cfg)
    finally:
        srv.shutdown()
        srv.server_close()

    assert any(f.rule == "dast-header-csp" for f in res.findings), \
        "fixture no longer re-fires the finding; the test would be vacuous"
    assert fid not in set(res.repaired.ids if res.repaired else ())


def test_a_finding_on_an_endpoint_this_scan_never_touched_stays_open(
        tmp_path, monkeypatch):
    """Scope, not tool. `/admin` is not configured, so it was never probed --
    and a finding nobody looked at cannot be repaired. This is also what makes
    SHRINKING the configured `paths` safe: dropping a path stops examining it,
    it does not clear it."""
    srv, url = _server(_HARDENED)
    try:
        r, cfg = _cfg(tmp_path, monkeypatch,
                      f"schema_version = 1\n[dast]\nbase_url = \"{url}\"\n")
        fid = dc._finding_fp("dast-exposed-custom", "GET", "/admin")
        _seed_open(r, fid, file="GET /admin", rule="dast-exposed-custom")
        res = _consume(r, cfg)
    finally:
        srv.shutdown()
        srv.server_close()

    assert fid not in set(res.repaired.ids if res.repaired else ())


def test_an_unreachable_target_claims_nothing(tmp_path, monkeypatch):
    """THE ATTACK, and the one that matters most. If a down app could resolve
    its own findings, every dast finding in the ledger clears the moment the
    target stops answering -- a security tool failing in the one direction it
    must never fail in."""
    r, cfg = _cfg(tmp_path, monkeypatch,
                  "schema_version = 1\n[dast]\nbase_url = \"http://127.0.0.1:9\"\n")
    _seed_open(r, dc._finding_fp("dast-header-csp", "GET", "/"))

    res = _consume(r, cfg)

    assert res.state == "degraded"
    assert not (res.repaired and res.repaired.ids), \
        "an unreachable target resolved its own findings"


def test_a_probe_crash_claims_nothing(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("prober bug")

    r, cfg = _cfg(tmp_path, monkeypatch,
                  "schema_version = 1\n[dast]\nbase_url = \"http://x/\"\n")
    _seed_open(r, dc._finding_fp("dast-header-csp", "GET", "/"))
    monkeypatch.setattr(dc.dast_probe, "probe_scoped", boom)

    res = _consume(r, cfg)

    assert res.state == "degraded"
    assert not (res.repaired and res.repaired.ids)


def test_a_drained_dast_repair_flips_the_open_finding_to_fixed(tmp_path, monkeypatch):
    """End to end through the REAL drain against a real local server: a bare
    response records header findings, the app is hardened, and the ledger says
    `fixed`.

    Both scans hit the SAME endpoint, so this also pins the half the consumer
    tests cannot reach -- that the ids `normalize` assigns at detection are the
    ids the claim later names. A drift there would leave every consumer-level
    test green and resolve nothing in practice.
    """
    import subprocess

    from aramid.commands import drain as drain_mod

    srv, url = _server({"/": (200, [("Content-Type", "text/html")], b"<html></html>")})
    r, cfg = _cfg(tmp_path, monkeypatch,
                  f"schema_version = 1\n[dast]\nbase_url = \"{url}\"\n")
    subprocess.run(["git", "init", "-q"], cwd=r, check=True, capture_output=True)
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"dast": dc})

    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        drain_mod._consume_item(r, cfg, led, _item(),
                                lambda: "2026-08-10T00:00:00+00:00")
        opened = {fid for fid, rec in led.open_findings().items()
                  if rec.get("tool") == "dast" and rec["status"] == "open"}
        assert opened, "the bare response recorded no open dast finding"

        # Harden the app: same endpoint, now serving every header.
        _Handler.routes = _HARDENED
        drain_mod._consume_item(r, cfg, led, _item(),
                                lambda: "2026-08-10T01:00:00+00:00")

        after = led.open_findings()
        header_findings = {fid for fid in opened
                           if str(after[fid].get("rule", "")).startswith("dast-header-")}
        assert header_findings, "fixture recorded no header finding to repair"
        assert all(after[fid]["status"] == "fixed" for fid in header_findings), (
            "a fixed header stayed open: "
            f"{ {fid: after[fid]['status'] for fid in header_findings} }")
        # The transport finding is NOT fixed -- the target is still plain http.
        transport = {fid for fid in opened
                     if str(after[fid].get("rule", "")) == "dast-transport-plaintext"}
        assert all(after[fid]["status"] == "open" for fid in transport), (
            "a finding that still fires was resolved by the same scan")
    finally:
        # `_Handler.routes` is CLASS state shared by every test in this file.
        # Nothing currently reads it stale (each test re-sets it through
        # `_server`), but leaving it dirty makes this test's position in the
        # file load-bearing, and a test whose correctness depends on running
        # last is a flake waiting for someone to append below it.
        _Handler.routes = {}
        led.close()
        srv.shutdown()
        srv.server_close()
