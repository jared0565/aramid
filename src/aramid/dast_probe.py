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

# (header canonical name, rule slug, severity, https_only)
_HEADER_CHECKS = (
    ("Strict-Transport-Security", "dast-header-hsts", "medium", True),
    ("Content-Security-Policy", "dast-header-csp", "medium", False),
    ("X-Frame-Options", "dast-header-xfo", "medium", False),
    ("X-Content-Type-Options", "dast-header-xcto", "low", False),
    ("Referrer-Policy", "dast-header-referrer", "low", False),
    ("Permissions-Policy", "dast-header-permissions", "low", False),
)

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
