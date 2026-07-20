import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from aramid.dast_probe import (DastUnreachable, _all_headers, _fetch, _header,
                               _same_host)


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
