import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from aramid.dast_probe import (DastUnreachable, _Response, _all_headers,
                               _check_cookies, _check_transport, _fetch, _header,
                               _same_host, probe)


class _Handler(BaseHTTPRequestHandler):
    # routes: dict[path] -> (status, list[(header, value)], body_bytes)
    routes: dict = {}

    def log_message(self, *a):
        pass

    def _respond(self):
        status, headers, body = self.routes.get(
            self.path, (404, [("Content-Type", "text/plain")], b"nope"))
        self.send_response_only(status)   # NOT send_response: that auto-injects
        # its own Server/Date headers, which would shadow the route's headers and
        # break the banner checks. send_response_only writes only the status line.
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        if self.command == "GET":
            self.wfile.write(body)

    def do_GET(self):
        self._respond()

    def do_HEAD(self):
        self._respond()


@pytest.fixture
def harness():
    """Start a controllable local HTTP server in a thread; yield (base_url, set_routes)."""
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    def set_routes(routes):
        _Handler.routes = routes

    try:
        yield f"http://127.0.0.1:{port}", set_routes
    finally:
        srv.shutdown()
        srv.server_close()
        _Handler.routes = {}


def test_fetch_returns_status_headers_body(harness):
    base, set_routes = harness
    set_routes({"/": (200, [("X-Test", "yes"), ("Content-Type", "text/html")], b"hello")})
    resp = _fetch(base + "/", "GET", 5.0)
    assert resp.status == 200
    assert resp.body == "hello"
    assert _header(resp, "x-test") == "yes"          # case-insensitive
    assert resp.tls_error is None


def test_fetch_head_reads_no_body(harness):
    base, set_routes = harness
    set_routes({"/": (200, [("Content-Type", "text/html")], b"body-here")})
    resp = _fetch(base + "/", "HEAD", 5.0)
    assert resp.status == 200
    assert resp.body == ""


def test_fetch_preserves_duplicate_set_cookie(harness):
    base, set_routes = harness
    set_routes({"/": (200, [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")], b"")})
    resp = _fetch(base + "/", "GET", 5.0)
    assert _all_headers(resp, "set-cookie") == ["a=1", "b=2"]


def test_fetch_follows_same_host_redirect(harness):
    base, set_routes = harness
    set_routes({
        "/a": (302, [("Location", "/b")], b""),
        "/b": (200, [("Content-Type", "text/html")], b"landed"),
    })
    resp = _fetch(base + "/a", "GET", 5.0)
    assert resp.status == 200 and resp.body == "landed"


def test_fetch_does_not_chase_cross_host_redirect(harness):
    base, set_routes = harness
    set_routes({"/a": (302, [("Location", "http://example.com/evil")], b"")})
    resp = _fetch(base + "/a", "GET", 5.0)
    # cross-host redirect is NOT followed: we report the 302 against our host
    assert resp.status == 302
    assert "example.com" not in resp.final_url


def test_fetch_stops_at_redirect_budget(harness):
    base, set_routes = harness
    # a same-host chain LONGER than _MAX_REDIRECTS (2): /a -> /b -> /c -> /d.
    # The loop runs _MAX_REDIRECTS + 1 = 3 times (fetching /a, /b, /c); /c still
    # redirects to /d but the budget is exhausted -> return the last hop attempted
    # (a 302), never fetching /d.
    set_routes({
        "/a": (302, [("Location", "/b")], b""),
        "/b": (302, [("Location", "/c")], b""),
        "/c": (302, [("Location", "/d")], b""),
        "/d": (200, [("Content-Type", "text/html")], b"too-far"),
    })
    resp = _fetch(base + "/a", "GET", 5.0)
    assert resp.status == 302
    assert resp.final_url.endswith("/c")
    assert resp.body != "too-far"


def test_fetch_bounds_body_read(harness):
    base, set_routes = harness
    set_routes({"/big": (200, [("Content-Type", "text/plain")], b"x" * (200 * 1024))})
    resp = _fetch(base + "/big", "GET", 5.0)
    assert len(resp.body) <= 64 * 1024


def test_fetch_unreachable_raises(harness):
    base, _ = harness  # a valid host, but hit a port that is closed
    with pytest.raises(DastUnreachable):
        _fetch("http://127.0.0.1:1/", "GET", 1.0)


def test_same_host():
    assert _same_host("http://h:80/a", "http://h:80/b")
    assert not _same_host("http://h/a", "http://other/a")
    assert not _same_host("http://h/a", "https://h/a")   # scheme differs


def test_fetch_rejects_non_get_head_method(harness):
    base, _ = harness
    with pytest.raises(ValueError):
        _fetch(base + "/", "POST", 5.0)


def test_same_host_fails_closed_on_bad_port():
    # an out-of-range port must not raise; treat as cross-host (don't chase)
    assert _same_host("http://h:1/a", "http://h:99999/b") is False


def test_fetch_does_not_chase_bad_port_redirect(harness):
    base, set_routes = harness
    set_routes({"/a": (302, [("Location", "http://127.0.0.1:99999/b")], b"")})
    resp = _fetch(base + "/a", "GET", 5.0)
    # bad-port redirect Location -> _same_host False -> not chased -> return the 302
    assert resp.status == 302


_HTML = [("Content-Type", "text/html")]


def _checks(findings):
    return sorted(f.check for f in findings)


def test_headers_all_missing_flagged(harness):
    base, set_routes = harness
    set_routes({"/": (200, list(_HTML), b"<html></html>")})
    found = _checks(probe(base, [], 5.0))
    # http target -> no HSTS check; the other five header checks all fire
    assert "dast-header-csp" in found
    assert "dast-header-xfo" in found
    assert "dast-header-xcto" in found
    assert "dast-header-referrer" in found
    assert "dast-header-permissions" in found
    assert "dast-header-hsts" not in found        # HSTS is https-only


def test_headers_present_not_flagged(harness):
    base, set_routes = harness
    set_routes({"/": (200, _HTML + [
        ("Content-Security-Policy", "default-src 'self'"),
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "geolocation=()"),
    ], b"<html></html>")})
    found = _checks(probe(base, [], 5.0))
    assert not any(c.startswith("dast-header-") for c in found)


def test_header_finding_shape(harness):
    base, set_routes = harness
    set_routes({"/": (200, list(_HTML), b"x")})
    f = next(f for f in probe(base, [], 5.0) if f.check == "dast-header-csp")
    assert f.method == "GET" and f.path == "/" and f.severity in ("medium", "low")
    assert "Content-Security-Policy" in f.message
    # evidence is metadata, never the body
    assert "x" != f.evidence and f.evidence


def test_probe_findings_sorted(harness):
    base, set_routes = harness
    set_routes({"/": (200, list(_HTML), b"x")})
    fs = probe(base, [], 5.0)
    keys = [(f.path, f.check) for f in fs]
    assert keys == sorted(keys)


def test_cookie_missing_flags_flagged(harness):
    base, set_routes = harness
    set_routes({"/": (200, [("Content-Type", "text/html"),
                            ("Set-Cookie", "sid=abc123; Path=/")], b"x")})
    fs = probe(base, [], 5.0)
    checks = _checks(fs)
    assert "dast-cookie-httponly" in checks
    assert "dast-cookie-samesite" in checks
    # http target -> Secure is not required (can't set Secure over http meaningfully)
    # the cookie VALUE must never appear in any finding
    assert all("abc123" not in f.evidence and "abc123" not in f.message for f in fs)


def test_cookie_all_flags_present_not_flagged(harness):
    base, set_routes = harness
    set_routes({"/": (200, [("Content-Type", "text/html"),
                            ("Set-Cookie", "sid=x; HttpOnly; SameSite=Lax")], b"x")})
    fs = probe(base, [], 5.0)
    assert not any(c.startswith("dast-cookie-") for c in _checks(fs))


def _cookie_resp(*set_cookie_values):
    return _Response(200, [("Set-Cookie", v) for v in set_cookie_values], "", "http://h/")


def test_cookie_value_containing_httponly_still_flagged():
    # M-c: a VALUE that merely contains "httponly" must not suppress the finding.
    findings = _check_cookies(_cookie_resp("token=httponly-abc123; Path=/"), is_https=True)
    checks = {f.check for f in findings}
    assert "dast-cookie-httponly" in checks
    assert "dast-cookie-secure" in checks
    assert "dast-cookie-samesite" in checks


def test_cookie_value_containing_secure_still_flagged():
    findings = _check_cookies(_cookie_resp("sid=secure-value-1; HttpOnly; SameSite=Lax"),
                              is_https=True)
    checks = {f.check for f in findings}
    assert "dast-cookie-secure" in checks          # value contains "secure", no real Secure attr
    assert "dast-cookie-httponly" not in checks     # real HttpOnly attr present
    assert "dast-cookie-samesite" not in checks     # real SameSite attr present


def test_cookie_no_attributes_flags_all():
    findings = _check_cookies(_cookie_resp("sid=abc123"), is_https=True)
    assert {f.check for f in findings} == {
        "dast-cookie-secure", "dast-cookie-httponly", "dast-cookie-samesite"}


def test_cookie_all_flags_present_not_flagged_regression():
    findings = _check_cookies(_cookie_resp("sid=x; Secure; HttpOnly; SameSite=Lax"),
                              is_https=True)
    assert findings == []


def test_transport_plaintext_flagged(harness):
    base, set_routes = harness   # base is http://
    set_routes({"/": (200, [("Content-Type", "text/html")], b"x")})
    assert "dast-transport-plaintext" in _checks(probe(base, [], 5.0))


def test_transport_cert_expired_from_tls_error():
    resp = _Response(0, [], "", "https://h/", tls_error="certificate has expired (_ssl.c:1)")
    checks = [f.check for f in _check_transport("https://h/", resp)]
    assert "dast-transport-cert-expired" in checks


def test_transport_cert_invalid_from_tls_error():
    resp = _Response(0, [], "", "https://h/", tls_error="self signed certificate")
    checks = [f.check for f in _check_transport("https://h/", resp)]
    assert "dast-transport-cert-invalid" in checks


def test_exposed_git_config_flagged(harness):
    base, set_routes = harness
    set_routes({
        "/": (200, [("Content-Type", "text/html")], b"<html></html>"),
        "/.git/config": (200, [("Content-Type", "text/plain")],
                         b"[core]\n\trepositoryformatversion = 0\n"),
    })
    fs = probe(base, [], 5.0)
    hit = next(f for f in fs if f.check == "dast-exposed-git-config")
    assert hit.path == "/.git/config" and hit.severity == "high"


def test_exposed_signature_gated_no_false_positive_on_spa(harness):
    # an SPA that returns 200 + index.html for EVERY path must NOT trip exposed checks
    base, set_routes = harness
    _spa = (200, [("Content-Type", "text/html")], b"<!doctype html><html>app</html>")
    set_routes({"/": _spa, "/.git/config": _spa, "/.env": _spa})
    assert not any(c.startswith("dast-exposed-") for c in _checks(probe(base, [], 5.0)))


def test_exposed_custom_path_non_html_flagged(harness):
    base, set_routes = harness
    set_routes({
        "/": (200, [("Content-Type", "text/html")], b"<html></html>"),
        "/backup.sql": (200, [("Content-Type", "application/sql")], b"INSERT INTO users"),
    })
    fs = probe(base, ["/backup.sql"], 5.0)
    assert any(f.check == "dast-exposed-custom" and f.path == "/backup.sql" for f in fs)


def test_banner_version_leak_flagged(harness):
    base, set_routes = harness
    set_routes({"/": (200, [("Content-Type", "text/html"),
                            ("Server", "nginx/1.25.3"),
                            ("X-Powered-By", "PHP/8.1.2")], b"x")})
    checks = _checks(probe(base, [], 5.0))
    assert "dast-banner-server" in checks
    assert "dast-banner-powered-by" in checks


def test_banner_no_version_not_flagged(harness):
    base, set_routes = harness
    set_routes({"/": (200, [("Content-Type", "text/html"), ("Server", "nginx")], b"x")})
    assert "dast-banner-server" not in _checks(probe(base, [], 5.0))


def test_hardened_response_yields_nothing(harness):
    base, set_routes = harness
    # a fully-hardened http response (no cookies, all headers present, no banner)
    set_routes({"/": (200, [
        ("Content-Type", "text/html"),
        ("Content-Security-Policy", "default-src 'self'"),
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "geolocation=()"),
    ], b"<html></html>")}
    )
    # only the plaintext-transport finding may remain (base is http)
    checks = _checks(probe(base, [], 5.0))
    assert checks == ["dast-transport-plaintext"]


def test_probe_never_mutates_only_get_head(harness):
    base, set_routes = harness
    seen = {"methods": set()}

    class _Record(_Handler):
        def _respond(self):
            seen["methods"].add(self.command)
            super()._respond()

    # swap the harness handler to record methods
    import http.server
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Record)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    _Record.routes = {"/": (200, [("Content-Type", "text/html")], b"x")}
    try:
        probe(f"http://127.0.0.1:{port}", [], 5.0)
    finally:
        srv.shutdown()
        srv.server_close()
    assert seen["methods"] <= {"GET", "HEAD"}   # never POST/PUT/DELETE/etc


def test_evidence_never_contains_cookie_value(harness):
    base, set_routes = harness
    set_routes({"/": (200, [("Content-Type", "text/html"),
                            ("Set-Cookie", "session=SUPERSECRETVALUE")], b"x")})
    fs = probe(base, [], 5.0)
    assert all("SUPERSECRETVALUE" not in f.evidence
               and "SUPERSECRETVALUE" not in f.message for f in fs)


def test_probe_ordering_deterministic(harness):
    base, set_routes = harness
    set_routes({"/": (200, [("Content-Type", "text/html"),
                            ("Set-Cookie", "a=1"), ("Server", "nginx/1.2")], b"x")})
    a = [(f.path, f.check) for f in probe(base, [], 5.0)]
    b = [(f.path, f.check) for f in probe(base, [], 5.0)]
    assert a == b == sorted(a)


def test_fetch_maps_tls_cert_error_to_tls_error(monkeypatch):
    import http.client
    import ssl

    from aramid import dast_probe

    def _raise_cert_error(self, *a, **k):
        raise ssl.SSLCertVerificationError("self signed certificate")

    # Exercise _fetch's real `except ssl.SSLCertVerificationError` branch: the
    # request into the HTTPS connection fails validation -> _Response(status 0,
    # tls_error set), never a raise. Because SSLCertVerificationError subclasses
    # OSError, this ALSO locks the except ORDER (cert-error before the generic
    # OSError -> DastUnreachable): swap those two clauses and this goes red.
    monkeypatch.setattr(http.client.HTTPSConnection, "request", _raise_cert_error)
    resp = dast_probe._fetch("https://127.0.0.1:1/", "GET", 1.0)
    assert resp.status == 0
    assert resp.tls_error is not None
    assert "self signed" in resp.tls_error
