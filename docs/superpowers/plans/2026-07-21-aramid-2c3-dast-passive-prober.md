# 2c-3 DAST Passive Web-Hygiene Prober Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a drain consumer that scans a user-declared `base_url` for deterministic web-hygiene issues (security headers, cookie flags, transport, exposed sensitive paths, banner leak) with an owned stdlib prober and reports them as WARN-tier findings.

**Architecture:** Two new modules mirroring the `jsmutate.py`/`consumers/js_mutation.py` split — `dast_probe.py` (owned stdlib prober: one-shot `http.client`/`ssl` fetch + five check families, pure of ledger/config knowledge) and `consumers/dast.py` (drain orchestrator: read `[dast]` config, OK-skip / DEGRADED-with-give-up / run, map `DastFinding → RawFinding`). Builds **no** long-lived-process primitive; all I/O is one-shot HTTP.

**Tech Stack:** Python stdlib only (`http.client`, `ssl`, `urllib.parse`, `http.server` for tests). Tests via `python -m pytest` (Windows: never bare `pytest`).

**Spec:** `docs/superpowers/specs/2026-07-20-aramid-2c3-dast-passive-prober-design.md`

## Global Constraints

- Branch: `feat/2c3-dast` off main. Never implement on main.
- Ruff parity: `python -m ruff check .` must equal the baseline measured at branch creation (expected 43). Every task matches it.
- Full suite green before merge: `python -m pytest -q` (828 base + new).
- Commit trailer on every commit: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` (omitted below for brevity — always add; use `git commit -F -` with a quoted heredoc, NEVER `-m "..."` with backticks in the body).
- Consumer contract: a module exposing `NAME: str` + `consume(item, ctx: DrainContext) -> ConsumerResult`, registered `base.CONSUMERS[NAME] = sys.modules[__name__]`, imported in `commands/drain.py`.
- Findings are WARN-tier: `RawFinding(tool="dast", rule=<check-id>, severity_raw="high"/"medium"/"low", …)`; `cost=0.0`; `PIN_OCCURRENCE = True`.
- OK-not-DEGRADED for structural absence (disabled / no `base_url` / invalid `base_url`) — a degraded consumer pins the queue item forever. DEGRADED only for transient (`DastUnreachable`, probe crash), with head-scoped give-up after 3 on a persistently-unreachable target.
- **Non-mutating & bounded:** GET/HEAD only; same-host redirects ≤2; per-request timeout; body read ≤64 KiB. A scan never mutates the target and always terminates quickly.
- **No secret ever persisted verbatim:** every `DastFinding.evidence` is synthetic metadata (status, matched-signature name, header *names*, cookie *name* + missing flags) — NEVER the raw response body or a cookie/secret value.

## File Structure

- **Create** `src/aramid/dast_probe.py` — owned prober. `DastUnreachable`, `DastFinding`, `probe(base_url, paths, timeout_s) -> list[DastFinding]`. Pure network I/O; no subprocess, no ledger/config.
- **Create** `src/aramid/consumers/dast.py` — drain consumer. `NAME="dast"`, `consume`, `PIN_OCCURRENCE=True`, registration.
- **Modify** `src/aramid/config.py` — add `dast: dict` field + load wiring.
- **Modify** `src/aramid/data/defaults.toml` — add `[dast]` block.
- **Modify** `src/aramid/commands/drain.py` — import the consumer (registration side-effect).
- **Test** `tests/unit/test_dast_probe.py`, `tests/integration/test_dast_consumer.py`.

---

### Task 1: Fetch layer + response model + test harness

Establishes the whole prober's HTTP primitive (bounded, same-host-redirect-limited, GET/HEAD, `DastUnreachable`), the data model (`DastFinding`, `_Response`), and the reusable local-`http.server` test harness later tasks lean on. No check families yet — just a correct, safe fetch.

**Files:**
- Create: `src/aramid/dast_probe.py`
- Test: `tests/unit/test_dast_probe.py`

**Interfaces:**
- Produces: `dast_probe.DastUnreachable(Exception)`; `dast_probe.DastFinding(check: str, method: str, path: str, severity: str, message: str, evidence: str)`; `dast_probe._Response(status: int, headers: list[tuple[str,str]], body: str, final_url: str, tls_error: str | None = None)`; `dast_probe._fetch(url: str, method: str, timeout: float) -> _Response` (raises `DastUnreachable`); helpers `_header(resp, name) -> str | None`, `_all_headers(resp, name) -> list[str]`, `_same_host(u1, u2) -> bool`.

- [ ] **Step 0: Branch + ruff baseline**

```bash
git checkout -b feat/2c3-dast
python -m ruff check . 2>&1 | tail -1   # expect "Found 43 errors." — record it
```

- [ ] **Step 1: Write the failing fetch tests + harness**

Create `tests/unit/test_dast_probe.py`:

```python
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
```

- [ ] **Step 2: Run (red)**

Run: `python -m pytest tests/unit/test_dast_probe.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'aramid.dast_probe'`.

- [ ] **Step 3: Implement the fetch layer**

Create `src/aramid/dast_probe.py`:

```python
"""dast_probe -- owned stdlib passive web-hygiene prober (2c-3 spec).

One-shot HTTP only (no long-lived process): fetch a user-declared base_url with
http.client, follow at most a couple of SAME-HOST redirects, read a bounded body
prefix, and run five deterministic check families (headers/cookies/transport/
exposed-paths/banner). Every finding's `evidence` is synthetic metadata -- never
raw response body or a cookie/secret value -- so no secret is ever persisted
(spec invariant #2). Mirrors the owned-tool precedent (jsmutate/fuzzgen)."""
import http.client
import re
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

_MAX_BODY = 64 * 1024
_MAX_REDIRECTS = 2
_USER_AGENT = "aramid-dast/1"
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class DastUnreachable(Exception):
    """base_url could not be contacted at all (connection refused / DNS /
    timeout) -- distinct from a probe that returned a boring response. The
    consumer maps this to DEGRADED (transient)."""


@dataclass
class DastFinding:
    check: str      # stable rule id, e.g. "dast-header-hsts"
    method: str     # "GET" | "HEAD"
    path: str       # request path, e.g. "/" or "/.git/config"
    severity: str   # "high" | "medium" | "low"
    message: str
    evidence: str   # synthetic metadata only -- never raw body / secret values


@dataclass
class _Response:
    status: int
    headers: list                 # list[tuple[str, str]] -- preserves dup Set-Cookie
    body: str                     # decoded prefix, <= _MAX_BODY (empty for HEAD)
    final_url: str
    tls_error: str | None = None  # set when the https handshake failed validation


def _header(resp: _Response, name: str) -> str | None:
    """First header value matching `name` (case-insensitive), or None."""
    low = name.lower()
    for k, v in resp.headers:
        if k.lower() == low:
            return v
    return None


def _all_headers(resp: _Response, name: str) -> list:
    low = name.lower()
    return [v for k, v in resp.headers if k.lower() == low]


def _same_host(u1: str, u2: str) -> bool:
    a, b = urlsplit(u1), urlsplit(u2)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


def _fetch(url: str, method: str, timeout: float) -> _Response:
    """GET/HEAD `url`, following <= _MAX_REDIRECTS SAME-HOST redirects, reading
    <= _MAX_BODY bytes. Returns _Response. A TLS validation failure returns a
    _Response with tls_error set (status 0). A connection-level failure (refused/
    DNS/timeout) raises DastUnreachable."""
    cur = url
    last = None
    for _ in range(_MAX_REDIRECTS + 1):
        parts = urlsplit(cur)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        try:
            if parts.scheme == "https":
                conn = http.client.HTTPSConnection(
                    parts.hostname, parts.port, timeout=timeout,
                    context=ssl.create_default_context())
            else:
                conn = http.client.HTTPConnection(
                    parts.hostname, parts.port, timeout=timeout)
            try:
                conn.request(method, path,
                             headers={"User-Agent": _USER_AGENT, "Connection": "close"})
                r = conn.getresponse()
                status = r.status
                headers = r.getheaders()
                raw = r.read(_MAX_BODY) if method == "GET" else b""
            finally:
                conn.close()
        except ssl.SSLCertVerificationError as exc:
            return _Response(0, [], "", cur, tls_error=str(exc))
        except (OSError, socket.timeout, http.client.HTTPException) as exc:
            raise DastUnreachable(str(exc)) from exc
        body = raw.decode("utf-8", errors="replace")
        last = _Response(status, headers, body, cur)
        if status in _REDIRECT_STATUSES:
            loc = _header(last, "location")
            if not loc:
                return last
            nxt = urljoin(cur, loc)
            if not _same_host(cur, nxt):
                return last          # never chase a cross-host redirect
            cur = nxt
            continue
        return last
    return last                      # redirect budget exhausted -> last hop
```

Note: `ssl.SSLCertVerificationError` is a subclass of `OSError`, so it MUST be caught first (it is, above).

- [ ] **Step 4: Run (green)**

Run: `python -m pytest tests/unit/test_dast_probe.py -v`
Expected: all PASS.

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/dast_probe.py tests/unit/test_dast_probe.py
git commit -F - <<'EOF'
feat(dast_probe): stdlib fetch layer (bounded, same-host redirect, unreachable)

Owned one-shot HTTP primitive for the passive prober: GET/HEAD via http.client,
follow <=2 SAME-HOST redirects (never chase cross-host), read <=64KiB, cp1252-
safe decode. A TLS validation failure returns a tls_error response (status 0);
a connection-level failure raises DastUnreachable (consumer degrades). Adds the
DastFinding/_Response model and a reusable local http.server test harness.
EOF
```

---

### Task 2: `probe()` orchestration + security-headers check

**Files:**
- Modify: `src/aramid/dast_probe.py`
- Test: `tests/unit/test_dast_probe.py`

**Interfaces:**
- Consumes: `_fetch`, `_Response`, `_header`, `DastFinding` (Task 1).
- Produces: `dast_probe.probe(base_url: str, paths: list[str], timeout_s: float) -> list[DastFinding]`; helper `_check_headers(resp: _Response, is_https: bool) -> list[DastFinding]`. `probe` fetches `base_url` once (GET), runs the header check on a real response, and returns findings sorted by `(path, check)`. Later tasks add cookie/transport/exposed/banner checks into `probe`.

- [ ] **Step 1: Write the failing header tests**

First **edit the top-of-file import** in `tests/unit/test_dast_probe.py` to add `probe` (keep all imports at module top — a new mid-file `import` would trip ruff E402):

```python
from aramid.dast_probe import (DastUnreachable, _all_headers, _fetch, _header,
                               _same_host, probe)
```

Then append the helpers + tests (NOT a new import statement):

```python
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
```

- [ ] **Step 2: Run (red)**

Run: `python -m pytest tests/unit/test_dast_probe.py -k "header or sorted" -v`
Expected: FAIL — `probe` / `_check_headers` not defined.

- [ ] **Step 3: Implement `probe` + header check**

In `src/aramid/dast_probe.py`, add the header spec table near the top (after the constants):

```python
# (header canonical name, rule slug, severity, https_only)
_HEADER_CHECKS = (
    ("Strict-Transport-Security", "dast-header-hsts", "medium", True),
    ("Content-Security-Policy", "dast-header-csp", "medium", False),
    ("X-Frame-Options", "dast-header-xfo", "medium", False),
    ("X-Content-Type-Options", "dast-header-xcto", "low", False),
    ("Referrer-Policy", "dast-header-referrer", "low", False),
    ("Permissions-Policy", "dast-header-permissions", "low", False),
)
```

Add the header check + `probe` at the end of the file:

```python
def _present_header_names(resp: _Response) -> str:
    return ", ".join(sorted({k for k, _ in resp.headers})) or "(none)"


def _check_headers(resp: _Response, is_https: bool) -> list:
    out = []
    present = _present_header_names(resp)
    for name, rule, sev, https_only in _HEADER_CHECKS:
        if https_only and not is_https:
            continue
        val = _header(resp, name)
        if val is None or not val.strip():
            out.append(DastFinding(
                check=rule, method="GET", path="/", severity=sev,
                message=f"{name} response header is missing",
                evidence=f"present headers: {present}"))
    return out


def probe(base_url: str, paths: list, timeout_s: float) -> list:
    """Run all v1 check families against base_url. Raises DastUnreachable if the
    base_url itself cannot be contacted (the consumer degrades). Findings are
    returned sorted by (path, check) for stable truncation/fingerprints."""
    is_https = urlsplit(base_url).scheme == "https"
    resp = _fetch(base_url, "GET", timeout_s)          # may raise DastUnreachable
    findings: list = []
    if resp.tls_error is None and resp.status > 0:
        findings += _check_headers(resp, is_https)
    findings.sort(key=lambda f: (f.path, f.check))
    return findings
```

- [ ] **Step 4: Run (green)**

Run: `python -m pytest tests/unit/test_dast_probe.py -v`
Expected: all PASS.

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/dast_probe.py tests/unit/test_dast_probe.py
git commit -F - <<'EOF'
feat(dast_probe): probe() orchestration + security-headers check

probe(base_url, paths, timeout) fetches the target once and flags missing
security headers (CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/
Permissions-Policy always; HSTS on https only). Findings sorted by (path, check);
evidence lists PRESENT header names only (metadata, never the body).
EOF
```

---

### Task 3: cookie-flags + transport checks

**Files:**
- Modify: `src/aramid/dast_probe.py`
- Test: `tests/unit/test_dast_probe.py`

**Interfaces:**
- Consumes: `probe`, `_Response`, `_all_headers` (Tasks 1-2).
- Produces: `_check_cookies(resp, is_https) -> list[DastFinding]`, `_check_transport(base_url, resp) -> list[DastFinding]`, wired into `probe`. Rules: `dast-cookie-secure`/`-httponly`/`-samesite`; `dast-transport-plaintext`/`-cert-invalid`/`-cert-expired`.

- [ ] **Step 1: Write the failing tests**

First **edit the top-of-file import** to add `_Response` and `_check_transport` (still at module top — no E402):

```python
from aramid.dast_probe import (DastUnreachable, _Response, _all_headers,
                               _check_transport, _fetch, _header, _same_host, probe)
```

Then append the tests (NOT a new import statement):

```python
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
```

- [ ] **Step 2: Run (red)**

Run: `python -m pytest tests/unit/test_dast_probe.py -k "cookie or transport" -v`
Expected: FAIL — cookie/transport checks not emitted / `_check_transport` not defined.

- [ ] **Step 3: Implement cookie + transport checks**

In `src/aramid/dast_probe.py`, add both checks (after `_check_headers`):

```python
def _check_cookies(resp: _Response, is_https: bool) -> list:
    out = []
    for raw in _all_headers(resp, "set-cookie"):
        # cookie NAME is safe to show; the VALUE is never emitted
        name = raw.split("=", 1)[0].strip()
        attrs = raw.lower()
        if is_https and "secure" not in attrs:
            out.append(DastFinding("dast-cookie-secure", "GET", "/", "medium",
                                   f"cookie {name!r} set without Secure",
                                   evidence="Set-Cookie missing Secure"))
        if "httponly" not in attrs:
            out.append(DastFinding("dast-cookie-httponly", "GET", "/", "medium",
                                   f"cookie {name!r} set without HttpOnly",
                                   evidence="Set-Cookie missing HttpOnly"))
        if "samesite" not in attrs:
            out.append(DastFinding("dast-cookie-samesite", "GET", "/", "low",
                                   f"cookie {name!r} set without SameSite",
                                   evidence="Set-Cookie missing SameSite"))
    return out


def _check_transport(base_url: str, resp: _Response) -> list:
    out = []
    if urlsplit(base_url).scheme != "https":
        out.append(DastFinding("dast-transport-plaintext", "GET", "/", "medium",
                               "target served over plaintext http (no TLS)",
                               evidence="scheme=http"))
    if resp.tls_error:
        low = resp.tls_error.lower()
        if "expired" in low:
            rule, msg = "dast-transport-cert-expired", "TLS certificate has expired"
        else:
            rule, msg = "dast-transport-cert-invalid", "TLS certificate failed validation"
        out.append(DastFinding(rule, "GET", "/", "medium", msg,
                               evidence=f"tls: {resp.tls_error[:120]}"))
    return out
```

Wire both into `probe` — replace its body with:

```python
def probe(base_url: str, paths: list, timeout_s: float) -> list:
    """Run all v1 check families against base_url. Raises DastUnreachable if the
    base_url itself cannot be contacted (the consumer degrades). Findings are
    returned sorted by (path, check) for stable truncation/fingerprints."""
    is_https = urlsplit(base_url).scheme == "https"
    resp = _fetch(base_url, "GET", timeout_s)          # may raise DastUnreachable
    findings: list = []
    findings += _check_transport(base_url, resp)
    if resp.tls_error is None and resp.status > 0:
        findings += _check_headers(resp, is_https)
        findings += _check_cookies(resp, is_https)
    findings.sort(key=lambda f: (f.path, f.check))
    return findings
```

(A `tls_error` response has status 0 and no headers, so header/cookie checks are skipped — only the cert finding is emitted, avoiding a flood of phantom "missing header" findings over a failed handshake.)

- [ ] **Step 4: Run (green)**

Run: `python -m pytest tests/unit/test_dast_probe.py -v`
Expected: all PASS.

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/dast_probe.py tests/unit/test_dast_probe.py
git commit -F - <<'EOF'
feat(dast_probe): cookie-flag + transport checks

Flags Set-Cookie missing Secure(https)/HttpOnly/SameSite (cookie NAME shown,
VALUE never emitted) and plaintext-http / expired / invalid TLS certs. A cert
handshake failure emits ONLY the cert finding (header/cookie checks skip a
status-0 tls_error response, so no phantom missing-header flood).
EOF
```

---

### Task 4: exposed-paths + banner-leak checks

**Files:**
- Modify: `src/aramid/dast_probe.py`
- Test: `tests/unit/test_dast_probe.py`

**Interfaces:**
- Consumes: `probe`, `_fetch`, `DastUnreachable`, `_header` (Tasks 1-3).
- Produces: `_check_exposed(base_url, paths, timeout_s) -> list[DastFinding]`, `_check_banner(resp) -> list[DastFinding]`, wired into `probe`. Rules: `dast-exposed-<slug>` / `dast-exposed-custom`; `dast-banner-server`/`-powered-by`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_dast_probe.py`:

```python
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
```

- [ ] **Step 2: Run (red)**

Run: `python -m pytest tests/unit/test_dast_probe.py -k "exposed or banner" -v`
Expected: FAIL — exposed/banner checks not emitted.

- [ ] **Step 3: Implement exposed + banner checks**

In `src/aramid/dast_probe.py`, add the curated table + banner regex near the top (after `_HEADER_CHECKS`):

```python
# curated exposed-path probes: (path, rule slug, severity, body-signature regex).
# A finding requires status 200 AND a signature match, so an SPA catch-all 200
# (an HTML index) is never a false positive.
_EXPOSED_CHECKS = (
    ("/.git/config", "dast-exposed-git-config", "high", r"\[core\]"),
    ("/.git/HEAD", "dast-exposed-git-head", "high", r"^ref:\s|^[0-9a-f]{40}"),
    ("/.env", "dast-exposed-dotenv", "high", r"(?m)^[A-Za-z_][A-Za-z0-9_]*="),
    ("/server-status", "dast-exposed-server-status", "medium", r"Apache Server Status"),
)
_BANNER_VERSION = re.compile(r"\d+\.\d+")
```

Add both checks (after `_check_transport`):

```python
def _looks_like_html(resp: _Response) -> bool:
    ct = (_header(resp, "content-type") or "").lower()
    if "text/html" in ct:
        return True
    head = resp.body.lstrip()[:64].lower()
    return head.startswith("<!doctype html") or head.startswith("<html")


def _check_exposed(base_url: str, paths: list, timeout_s: float) -> list:
    out = []
    for path, rule, sev, sig in _EXPOSED_CHECKS:
        try:
            r = _fetch(urljoin(base_url, path), "GET", timeout_s)
        except DastUnreachable:
            continue                       # a closed/blocked path is not a finding
        if r.status == 200 and re.search(sig, r.body):
            out.append(DastFinding(rule, "GET", path, sev,
                                   f"sensitive path {path} is exposed",
                                   evidence=f"200, body matched /{sig}/"))
    for path in paths:                     # user-declared extra probes (generic gate)
        try:
            r = _fetch(urljoin(base_url, path), "GET", timeout_s)
        except DastUnreachable:
            continue
        if r.status == 200 and not _looks_like_html(r):
            out.append(DastFinding("dast-exposed-custom", "GET", path, "medium",
                                   f"configured path {path} returns non-HTML 200",
                                   evidence="200, content is not an HTML document"))
    return out


def _check_banner(resp: _Response) -> list:
    out = []
    for name, rule in (("Server", "dast-banner-server"),
                       ("X-Powered-By", "dast-banner-powered-by")):
        val = _header(resp, name)
        if val and _BANNER_VERSION.search(val):
            out.append(DastFinding(rule, "GET", "/", "low",
                                   f"{name} header leaks a version",
                                   evidence=f"{name}: {val[:80]}"))
    return out
```

Wire both into `probe` — replace its body with:

```python
def probe(base_url: str, paths: list, timeout_s: float) -> list:
    """Run all v1 check families against base_url. Raises DastUnreachable if the
    base_url itself cannot be contacted (the consumer degrades). Findings are
    returned sorted by (path, check) for stable truncation/fingerprints."""
    is_https = urlsplit(base_url).scheme == "https"
    resp = _fetch(base_url, "GET", timeout_s)          # may raise DastUnreachable
    findings: list = []
    findings += _check_transport(base_url, resp)
    if resp.tls_error is None and resp.status > 0:
        findings += _check_headers(resp, is_https)
        findings += _check_cookies(resp, is_https)
        findings += _check_banner(resp)
    findings += _check_exposed(base_url, list(paths), timeout_s)
    findings.sort(key=lambda f: (f.path, f.check))
    return findings
```

- [ ] **Step 4: Run (green)**

Run: `python -m pytest tests/unit/test_dast_probe.py -v`
Expected: all PASS.

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/dast_probe.py tests/unit/test_dast_probe.py
git commit -F - <<'EOF'
feat(dast_probe): exposed-path + banner-leak checks

Curated exposed probes (.git/config, .git/HEAD, .env, server-status) gated on
status-200 AND a body-signature match, so an SPA catch-all 200 is never a false
positive; user-configured paths use a generic 200-and-not-HTML gate. Banner leak
flags Server/X-Powered-By headers disclosing a version (\d+\.\d+).
EOF
```

---

### Task 5: safety & determinism invariants

**Files:**
- Test: `tests/unit/test_dast_probe.py` (behavior already implemented; this task pins the invariants). If a test fails, fix `dast_probe.py` minimally.

- [ ] **Step 1: Write the invariant tests**

Append to `tests/unit/test_dast_probe.py`:

```python
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
```

- [ ] **Step 2: Run**

Run: `python -m pytest tests/unit/test_dast_probe.py -v`
Expected: all PASS (Tasks 1-4 already satisfy these). If any fail, fix `dast_probe.py` minimally (never weaken a safety invariant), then re-run.

- [ ] **Step 3: Ruff + commit**

```bash
python -m ruff check .
git add tests/unit/test_dast_probe.py src/aramid/dast_probe.py
git commit -F - <<'EOF'
test(dast_probe): pin safety + determinism invariants

Locks: a fully-hardened response yields nothing (bar plaintext-transport); the
prober only ever issues GET/HEAD (never mutates the target); no cookie/secret
value ever reaches evidence or message; deterministic (path, check) ordering for
truncation-stable fingerprints.
EOF
```

---

### Task 6: config `[dast]` block

**Files:**
- Modify: `src/aramid/data/defaults.toml`, `src/aramid/config.py:46` (field) and `:110` (load)
- Test: `tests/unit/test_config.py` (append)

**Interfaces:**
- Produces: `Config.dast: dict` with defaults `{enabled: True, base_url: "", paths: [], timeout_s: 10, block_armed: False}`.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_config.py` (mirror the `test_js_mutation_defaults_present` monkeypatch of `_user_config_path`):

```python
def test_dast_defaults_present(tmp_path, monkeypatch):
    from aramid import config as config_mod
    monkeypatch.setattr(config_mod, "_user_config_path", lambda: tmp_path / "no-user.toml")
    cfg = config_mod.load_config(tmp_path)
    assert cfg.dast.get("enabled") is True
    assert cfg.dast.get("base_url") == ""
    assert cfg.dast.get("paths") == []
    assert cfg.dast.get("timeout_s") == 10
    assert cfg.dast.get("block_armed") is False
```

- [ ] **Step 2: Run (red)**

Run: `python -m pytest tests/unit/test_config.py -k dast -v`
Expected: FAIL — `Config` has no `dast` attribute.

- [ ] **Step 3: Implement**

`src/aramid/data/defaults.toml`, add after the `[fuzz]` block (its last line `batch_timeout_s = 120`):

```toml
# --- Phase 2c-3 (spec section 8): drain-time DAST passive web-hygiene prober ---
[dast]
enabled = true
base_url = ""            # e.g. "https://staging.example.com" -- empty => OK-skip
paths = []               # extra paths to probe on top of the curated exposed set
timeout_s = 10           # per-request timeout
block_armed = false      # RESERVED: inert in 2c-3 (WARN-only); unit-4 wires the BLOCK branch
# start_command = ""     # RESERVED for 2c-3b explicit-config auto-start; ignored here
```

`src/aramid/config.py`, add the field after `js_mutation` (line 46):

```python
    js_mutation: dict = field(default_factory=dict)
    dast: dict = field(default_factory=dict)
```

And add the load line after `js_mutation=merged.get(...)` (line 110):

```python
        js_mutation=merged.get("js_mutation", {}),
        dast=merged.get("dast", {}),
```

- [ ] **Step 4: Run (green)**

Run: `python -m pytest tests/unit/test_config.py -q`
Expected: all PASS.

- [ ] **Step 5: Ruff + commit**

```bash
python -m ruff check .
git add src/aramid/data/defaults.toml src/aramid/config.py tests/unit/test_config.py
git commit -F - <<'EOF'
feat(config): [dast] config block (base_url, paths, timeout, reserved block_armed)
EOF
```

---

### Task 7: the `dast` consumer + drain registration

**Files:**
- Create: `src/aramid/consumers/dast.py`
- Modify: `src/aramid/commands/drain.py:33` (register)
- Test: `tests/integration/test_dast_consumer.py`

**Interfaces:**
- Consumes: `dast_probe.probe`/`DastUnreachable`/`DastFinding`; `base.ConsumerResult`/`DrainContext`/`prior_note_count`; `normalizer.RawFinding`.
- Produces: `NAME="dast"`, `consume(item, ctx) -> ConsumerResult`, `PIN_OCCURRENCE=True`.

- [ ] **Step 1: Write the gate + scripted tests**

Create `tests/integration/test_dast_consumer.py`:

```python
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from aramid import config as config_mod
from aramid.consumers import dast as dc
from aramid.consumers.base import DrainContext
from aramid.ledger import Ledger
from aramid.queue import QueueItem


def _item():
    return QueueItem(id="q1", base="b" * 40, head="h" * 40, score=55,
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
        srv.shutdown(); srv.server_close()
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
    head12 = ("h" * 40)[:12]
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
```

- [ ] **Step 2: Run (red)**

Run: `python -m pytest tests/integration/test_dast_consumer.py -v`
Expected: FAIL — `No module named 'aramid.consumers.dast'`.

- [ ] **Step 3: Implement the consumer**

Create `src/aramid/consumers/dast.py`:

```python
"""Drain-time DAST passive web-hygiene consumer (2c-3 spec). Scan a user-declared
base_url with the owned stdlib prober and report web-hygiene issues (headers /
cookies / transport / exposed paths / banner) as WARN-tier findings.

OK-not-DEGRADED for structural absence (disabled / no base_url / invalid
base_url) so a non-web repo never pins the queue item. DEGRADED + head-scoped
give-up (after 3) when the configured target is persistently unreachable -- the
app may simply not be up at drain time (findings are opportunistic by design).
Zero tokens (cost 0.0); PIN_OCCURRENCE because a live target is membership-
variable across drains. WARN-tier via policy.classify's catch-all."""
import sys
from urllib.parse import urlsplit

from aramid import dast_probe
from aramid.consumers import base
from aramid.consumers.base import ConsumerResult, DrainContext
from aramid.normalizer import RawFinding

NAME = "dast"
_UNREACHABLE_GIVE_UP = 3

# Live-target scans are membership-variable across drains (an app up one drain,
# down the next), so pin occurrence 0 -- one finding per (tool, rule, file).
PIN_OCCURRENCE = True


def consume(item, ctx: DrainContext) -> ConsumerResult:
    mcfg = getattr(ctx.cfg, "dast", None) or {}
    if not mcfg.get("enabled", True):
        return ConsumerResult(consumer=NAME, state="ok", note="disabled")

    base_url = str(mcfg.get("base_url", "")).strip()
    if not base_url:
        return ConsumerResult(consumer=NAME, state="ok",
                              note="no dast target configured")
    if urlsplit(base_url).scheme not in ("http", "https") or not urlsplit(base_url).hostname:
        # malformed target is a config mistake, not a transient fault -> OK-skip
        return ConsumerResult(consumer=NAME, state="ok",
                              note="invalid dast base_url (need http(s)://host)")

    paths = list(mcfg.get("paths", []))
    timeout_s = float(mcfg.get("timeout_s", 10))

    give_up_prefix = f"dast target unreachable @ {item.head[:12]}"
    if base.prior_note_count(ctx.ledger, NAME, item.id, give_up_prefix) >= _UNREACHABLE_GIVE_UP:
        # A persistently-unreachable target must stop pinning the queue item:
        # after 3 honest DEGRADED retries AT THIS HEAD this becomes a permanent
        # skip. Head-scoped so new commits get a fresh try. Load-bearing prefix.
        return ConsumerResult(consumer=NAME, state="ok",
                              note="dast giving up: target persistently unreachable")

    try:
        findings = dast_probe.probe(base_url, paths, timeout_s)
    except dast_probe.DastUnreachable:
        return ConsumerResult(consumer=NAME, state="degraded", note=give_up_prefix)
    except Exception as exc:  # a probe crash is transient -> degrade, never kill the drain
        return ConsumerResult(consumer=NAME, state="degraded",
                              note=f"dast probe error: {str(exc)[:150]}")

    raws = [RawFinding(tool="dast", rule=f.check, severity_raw=f.severity,
                       file=f"{f.method} {f.path}", line=0,
                       message=f.message, evidence=f.evidence)
            for f in findings]
    host = urlsplit(base_url).hostname
    return ConsumerResult(consumer=NAME, state="ok", findings=raws, cost=0.0,
                          note=f"{len(raws)} hygiene finding(s) on {host}",
                          extra={"target": host, "found": len(raws)})


base.CONSUMERS[NAME] = sys.modules[__name__]
```

Register it in `src/aramid/commands/drain.py` after the `js_mutation` import (line 33):

```python
from aramid.consumers import js_mutation as _js_mutation  # noqa: F401  (registers itself)
from aramid.consumers import dast as _dast  # noqa: F401  (registers itself)
```

- [ ] **Step 4: Run (green)**

Run: `python -m pytest tests/integration/test_dast_consumer.py -v`
Expected: all PASS.

- [ ] **Step 5: Full suite + ruff**

Run: `python -m pytest -q` — expect 828 base + new, all green.
Run: `python -m ruff check .` — must equal the recorded baseline (43).

- [ ] **Step 6: Commit**

```bash
git add src/aramid/consumers/dast.py src/aramid/commands/drain.py tests/integration/test_dast_consumer.py
git commit -F - <<'EOF'
feat(consumers): dast passive web-hygiene consumer + drain registration

Scans a configured base_url with the owned stdlib prober; WARN-tier findings
(tool="dast", cost 0.0, PIN_OCCURRENCE, file="GET /path"). OK-skip for structural
absence (disabled / no base_url / invalid base_url); DEGRADED + head-scoped
give-up (3) when the target is persistently unreachable (opportunistic by
design). Registered in drain.py.
EOF
```

- [ ] **Step 7: Whole-branch review + finish**

Dispatch the whole-branch adversarial review (project convention), apply any fix wave, then use superpowers:finishing-a-development-branch.

---

## Self-Review notes (author)

- **Spec coverage:** §3 modules → Tasks 1-5 (dast_probe) + Task 7 (consumer). §4 target model → Task 7 (base_url / OK-skip / invalid-url). §5 check families → Task 2 (headers), Task 3 (cookies, transport), Task 4 (exposed, banner). §6 prober API → Tasks 1-4 (`DastFinding`, `DastUnreachable`, `probe`). §7 OK/DEGRADED/give-up → Task 7. §8 config → Task 6. §9 findings/anchoring → Task 7 (`RawFinding` mapping, `file="GET /path"`, line 0, `PIN_OCCURRENCE`, cost 0.0). §10 error handling → Tasks 1 (fetch), 3 (tls), 4 (per-path swallow), 7 (probe-crash degrade). §11 testing → Tasks 1-7 (local http.server, not skip-gated). §12 safety → Task 1 (bounded/same-host/GET-HEAD), Task 5 (invariants), evidence-metadata-only throughout. §13 out-of-scope → not implemented (correct). §15 invariants → Task 5 pins #1-#4/#6; #5 (WARN-only) holds by the classify catch-all (no BLOCK code added).
- **Placeholder scan:** every code step shows complete code; test bodies concrete; no TBD/TODO. The `start_command`/`block_armed` toml keys are intentionally reserved+documented, not placeholders.
- **Type consistency:** `DastFinding(check, method, path, severity, message, evidence)` and `probe(base_url, paths, timeout_s)` identical across Tasks 1-7. `_Response(status, headers, body, final_url, tls_error)` consistent. `probe`'s body is fully re-shown each time it grows (Tasks 2→3→4) so an out-of-order reader gets the whole function. Consumer maps to `RawFinding(tool="dast", rule=f.check, severity_raw=f.severity, file=f"{f.method} {f.path}", line=0, message=f.message, evidence=f.evidence)` — matches the normalizer.RawFinding signature (tool, rule, severity_raw, file, line, message, evidence).
- **Give-up note:** the DEGRADED note (`give_up_prefix`) and the `prior_note_count` prefix are the same variable — byte-identical by construction (mutation-consumer mirror). Head-scoped via `item.head[:12]`.
- **Ordering:** Task 6 (config) precedes Task 7 (consumer reads `cfg.dast`). Tasks 1-5 (prober) precede Task 7 (consumer imports `dast_probe`). Correct.
