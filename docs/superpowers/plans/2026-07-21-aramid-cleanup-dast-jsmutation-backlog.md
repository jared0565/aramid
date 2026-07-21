# DAST + JS-mutation Deferred-Backlog Cleanup — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every verified-still-real defect and coverage gap from the 2c-1b / 2c-3 deferred backlog in one bounded pass.

**Architecture:** Small, surgical edits to two production files (`dast_probe.py`, `consumers/js_mutation.py`) plus one annotation (`jsmutate.py`), each locked by a test. No new module, config key, consumer, or dependency. Bugs first (red→green TDD), then hygiene, then a green-on-arrival coverage tail that pins already-correct behavior.

**Tech Stack:** Python 3.10+ (Windows-first), stdlib `http.client`/`ssl`/`http.server`, pytest, ruff.

## Global Constraints

- **Platform:** Windows-first. Run tools as `python -m pytest` / `python -m ruff`, never bare `pytest`/`ruff`.
- **Style gate:** `python -m ruff check` must show **no new findings** beyond the established baseline (43 pre-existing at 2c-3 merge; confirm current count and hold parity). pyproject enables ruff **E/F defaults only** (no ANN rules).
- **Full suite:** `python -m pytest` stays green (864 passed / 3 skipped at 2c-3 merge, plus the new tests). Focused tasks run focused tests only; the controller runs the full suite once at the final gate.
- **TDD shape is labeled per task.** Tasks 1–4 are **red-first** (a failing test is the proof). Tasks 5–9 are **green-on-arrival** — the test passes the moment it is written; the "watch it fail" step is impossible and MUST NOT be faked. Each such task states *Expected first run: PASS*.
- **Commits:** one commit per task; trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Author messages with `git commit -F -` and a quoted heredoc (`<<'EOF'`), **never** `-m "…"` with backticks (backticks are shell-executed and corrupt the message).
- **Never** bypass hooks or signing (`--no-verify`, `--no-gpg-sign`).
- **No new** module, config key, consumer, dependency, or public-API change.
- **Safety invariant (unchanged, must hold):** dast finding `evidence` is synthetic metadata only — never raw body or a cookie/secret value. M-c must not begin emitting the cookie value.

---

## Task 1: D1 — node_modules link-failure give-up valve (red-first)

**Bug:** `consumers/js_mutation.py`'s link-failure `except OSError` degrades with a free-text note (`f"could not link node_modules: {exc}"`) and has **no give-up check** — a persistent link failure re-degrades every drain and pins the queue item forever (same class as the dast M-a bug). `base.prior_note_count` matches with `.startswith(prefix)` (base.py:52), so the note must *start with* a head-scoped prefix.

**Files:**
- Modify: `src/aramid/consumers/js_mutation.py` (add `_LINK_GIVE_UP`; add a give-up check next to the baseline give-up check ~line 123; change the link-failure note ~line 143)
- Test: `tests/integration/test_js_mutation_consumer.py`

**Interfaces:**
- Consumes: `base.prior_note_count(ledger, consumer, item_id, prefix) -> int` (startswith match); `_BASELINE_GIVE_UP = 3` pattern already in the file.
- Produces: module constant `_LINK_GIVE_UP = 3`; DEGRADED note format `f"node_modules link failing @ {item.head[:12]}: {exc}"`; OK give-up note `"js mutation giving up: node_modules link persistently failing"`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/integration/test_js_mutation_consumer.py` (after `test_give_up_after_three_baseline_failures_head_scoped`, ~line 190). Add a small helper that raises, then two tests:

```python
def _link_raises(src, wt):
    raise OSError("mklink /J failed: simulated persistent link failure")


def test_node_modules_link_failure_degrades_with_head_scoped_prefix(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    _scripted(monkeypatch, [(ToolState.OK, 0)])          # pm gate + stubs
    monkeypatch.setattr(jsc, "_link_node_modules", _link_raises)   # link fails
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "degraded"
    # note must START with the head-scoped prefix so prior_note_count can match it
    assert res.note.startswith(f"node_modules link failing @ {head[:12]}")


def test_give_up_after_three_node_modules_link_failures_head_scoped(tmp_path, monkeypatch):
    r, base, head = _js_repo(tmp_path)
    from aramid.ledger import Ledger
    from aramid.models import Event, EventType
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        for i in range(3):
            led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"r{i}", "t",
                             payload={"consumer": "js_mutation", "item_id": "q1",
                                      "note": f"node_modules link failing @ {head[:12]}"}))
    finally:
        led.close()
    _scripted(monkeypatch, [(ToolState.OK, 0)])
    monkeypatch.setattr(jsc, "_link_node_modules", _link_raises)   # would fail, but give-up first
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert "giving up" in res.note
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/integration/test_js_mutation_consumer.py -k "link_failure or link_failures" -v`
Expected: FAIL — `test_...prefix` gets today's note `"could not link node_modules: …"` (doesn't start with the new prefix); `test_give_up...link_failures` gets DEGRADED (no give-up check exists), not OK.

- [ ] **Step 3: Add the module constant**

In `src/aramid/consumers/js_mutation.py`, after `_BASELINE_GIVE_UP = 3` (line 28):

```python
_BASELINE_GIVE_UP = 3
_LINK_GIVE_UP = 3
```

- [ ] **Step 4: Add the give-up check next to the baseline give-up check**

After the baseline give-up block (currently lines 123–126), add a second give-up check (it reads only prior ledger notes, so placing it before the worktree add avoids wasteful worktree churn once we've given up):

```python
    if base.prior_note_count(ctx.ledger, NAME, item.id,
                             f"baseline failing @ {item.head[:12]}") >= _BASELINE_GIVE_UP:
        return ConsumerResult(consumer=NAME, state="ok",
                              note="js mutation giving up: baseline persistently failing")

    if base.prior_note_count(ctx.ledger, NAME, item.id,
                             f"node_modules link failing @ {item.head[:12]}") >= _LINK_GIVE_UP:
        return ConsumerResult(consumer=NAME, state="ok",
                              note="js mutation giving up: node_modules link persistently failing")
```

- [ ] **Step 5: Change the link-failure DEGRADED note to start with the head-scoped prefix**

Replace the `except OSError` block (currently lines 142–145):

```python
        try:
            linked = _link_node_modules(ctx.root, wt)
        except OSError as exc:
            # Load-bearing prefix: the give-up counter matches note.startswith(prefix).
            return ConsumerResult(consumer=NAME, state="degraded",
                                  note=f"node_modules link failing @ {item.head[:12]}: {str(exc)[:150]}",
                                  duration_s=time.monotonic() - started)
```

- [ ] **Step 6: Run to verify they pass**

Run: `python -m pytest tests/integration/test_js_mutation_consumer.py -v`
Expected: PASS (all, including the two new tests and the untouched give-up/baseline tests).

- [ ] **Step 7: Commit**

```bash
git add src/aramid/consumers/js_mutation.py tests/integration/test_js_mutation_consumer.py
git commit -F - <<'EOF'
fix(js_mutation): head-scoped give-up valve for persistent node_modules link failure

The link-failure except degraded with a free-text note and no give-up check,
so a persistent mklink/symlink failure re-degraded every drain and pinned the
queue item forever (same class as the dast M-a fix). Add _LINK_GIVE_UP and a
head-scoped give-up check; the DEGRADED note now starts with the load-bearing
prefix "node_modules link failing @ <head12>" so prior_note_count matches it.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

## Task 2: M-c — cookie flags matched as attributes, not whole-line substrings (red-first)

**Bug:** `dast_probe.py:154-172` `_check_cookies` substring-tests `"secure"`/`"httponly"`/`"samesite"` against the whole lowercased `Set-Cookie` line **including the value**, so a cookie whose value contains e.g. `httponly` falsely looks flagged → a real missing-flag finding is silently suppressed (false negative).

**Files:**
- Modify: `src/aramid/dast_probe.py:154-172` (`_check_cookies`)
- Test: `tests/unit/test_dast_probe.py`

**Interfaces:**
- Consumes: `_Response`, `_all_headers`, `DastFinding` (unchanged signatures).
- Produces: `_check_cookies(resp, is_https)` unchanged signature; behavior now keys on delimited attribute tokens after the first `;`.

- [ ] **Step 1: Write the failing tests**

In `tests/unit/test_dast_probe.py`, add `_check_cookies` to the import on line 6-7:

```python
from aramid.dast_probe import (DastUnreachable, _Response, _all_headers,
                               _check_cookies, _check_transport, _fetch, _header,
                               _same_host, probe)
```

Then add these tests (near the other cookie tests):

```python
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
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/unit/test_dast_probe.py -k cookie -v`
Expected: FAIL — `..._httponly_still_flagged` (today `"httponly"` is found in the value → not flagged) and `..._secure_still_flagged` (today `"secure"` found in value → not flagged) both fail. The no-attributes and all-flags-present cases pass already.

- [ ] **Step 3: Rewrite `_check_cookies` to parse attributes**

Replace `_check_cookies` (lines 154–172):

```python
def _check_cookies(resp: _Response, is_https: bool) -> list:
    out = []
    for raw in _all_headers(resp, "set-cookie"):
        # cookie NAME is safe to show; the VALUE is never emitted
        name = raw.split("=", 1)[0].strip()
        # Match flags as delimited ATTRIBUTES (everything after the first ';'), NOT
        # as substrings of the whole line -- else a cookie whose VALUE contains
        # "secure"/"httponly"/"samesite" would falsely look flagged (M-c false
        # negative). A cookie with no ';' yields attrs {""} -> all flags reported.
        _, _, attr_str = raw.partition(";")
        attrs = {tok.split("=", 1)[0].strip().lower() for tok in attr_str.split(";")}
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
```

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest tests/unit/test_dast_probe.py -v`
Expected: PASS (all cookie tests, including any pre-existing ones — the fix is behavior-preserving for well-formed cookies).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/dast_probe.py tests/unit/test_dast_probe.py
git commit -F - <<'EOF'
fix(dast): match cookie flags as attributes, not whole-line substrings

_check_cookies substring-tested secure/httponly/samesite against the entire
Set-Cookie line including the VALUE, so a cookie whose value contained a flag
name falsely looked flagged and a real missing-flag finding was suppressed
(M-c false negative). Parse attributes after the first ';' and match delimited
tokens. A cookie with no attributes still reports all three flags missing.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

## Task 3: M-d#3 + M-d#6 — `_fetch` method guard + `_same_host` fail-closed (red-first)

**Bugs:** (#3) `dast_probe.py` `_fetch` passes any `method` straight to `conn.request` with no guard — the read-only-probe contract is caller-enforced only. (#6) `_same_host` (lines 82–84) compares `urlsplit(...).port` raw; an out-of-range port in a redirect `Location` raises a bare `ValueError` out of `probe()` (the call at `_fetch:127` is outside the try/except).

**Intentional asymmetry:** #3 **raises** (bad method = programmer error, never from the wire); #6 returns **False** (bad port = untrusted redirect input → fail closed). Comments state this so a reviewer does not "unify" them.

**Files:**
- Modify: `src/aramid/dast_probe.py:82-84` (`_same_host`) and the top of `_fetch` (~line 92)
- Test: `tests/unit/test_dast_probe.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_dast_probe.py`:

```python
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
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/unit/test_dast_probe.py -k "non_get_head or bad_port" -v`
Expected: FAIL — `..._non_get_head` gets no `ValueError` (POST is sent, harness returns 501); `..._same_host_fails_closed` raises `ValueError` (port 99999 out of range); `..._chase_bad_port_redirect` propagates that same `ValueError` out of `_fetch`.

- [ ] **Step 3: Add the `_fetch` method guard**

At the top of `_fetch`'s body (immediately after the docstring, before `cur = url` at line 92):

```python
    # GET/HEAD only: this is a read-only passive prober. A non-GET/HEAD method is a
    # PROGRAMMER error (never arrives from the wire) -> RAISE. Contrast _same_host,
    # which fails CLOSED on untrusted redirect input rather than raising.
    if method not in ("GET", "HEAD"):
        raise ValueError(f"unsupported dast method: {method!r}")
    cur = url
```

- [ ] **Step 4: Make `_same_host` fail closed on a bad port**

Replace `_same_host` (lines 82–84):

```python
def _same_host(u1: str, u2: str) -> bool:
    # A malformed port in a redirect Location is UNTRUSTED wire input -> fail CLOSED
    # (treat as cross-host, never chase). Contrast _fetch's method guard, which
    # RAISES because a bad method is a programmer error, not wire input.
    try:
        a, b = urlsplit(u1), urlsplit(u2)
        return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)
    except ValueError:
        return False
```

- [ ] **Step 5: Run to verify they pass**

Run: `python -m pytest tests/unit/test_dast_probe.py -v`
Expected: PASS (all, including the existing `test_same_host`, `test_fetch_*` redirect tests).

- [ ] **Step 6: Commit**

```bash
git add src/aramid/dast_probe.py tests/unit/test_dast_probe.py
git commit -F - <<'EOF'
fix(dast): _fetch method guard (raise) + _same_host fail-closed on bad port

_fetch now rejects any non-GET/HEAD method with ValueError, enforcing the
read-only-probe contract at the primitive instead of by caller discipline.
_same_host wraps the port comparison and returns False on an out-of-range
port in a redirect Location (untrusted input -> fail closed, never chase),
instead of letting a bare ValueError escape probe(). The raise-vs-fail-closed
asymmetry is intentional and commented.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

## Task 4: D2 — `_consume_number` return annotation (red-first via marker test)

**Gap:** `jsmutate.py:235` `def _consume_number(source: str, i: int):` has no return annotation though every return site yields `(int, bool, int)`. The project runtime is ≥3.10 (proven by existing eager `list[str] | None` annotations in `js_mutation.py` with no `from __future__ import annotations`), so `tuple[int, bool, int]` needs no `__future__` import.

**Files:**
- Modify: `src/aramid/jsmutate.py:235`
- Test: `tests/unit/test_jsmutate.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_jsmutate.py`:

```python
def test_consume_number_has_return_annotation():
    import typing

    from aramid.jsmutate import _consume_number
    hints = typing.get_type_hints(_consume_number)
    assert hints["return"] == tuple[int, bool, int]
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/unit/test_jsmutate.py -k consume_number_has_return -v`
Expected: FAIL — `KeyError: 'return'` (the function currently has no return annotation, so `get_type_hints` has no `"return"` key).

- [ ] **Step 3: Add the annotation**

In `src/aramid/jsmutate.py`, line 235:

```python
def _consume_number(source: str, i: int) -> tuple[int, bool, int]:
```

- [ ] **Step 4: Run to verify it passes**

Run: `python -m pytest tests/unit/test_jsmutate.py -k consume_number_has_return -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/jsmutate.py tests/unit/test_jsmutate.py
git commit -F - <<'EOF'
style(jsmutate): annotate _consume_number return type

Add the missing -> tuple[int, bool, int] return annotation (matches every
return site and the docstring). A get_type_hints marker test locks it. No
__future__ import needed: the runtime is >=3.10 (existing eager `X | None`
annotations already evaluate at import).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

## Task 5: D3 — int-bound test covers `0b`/`0o` literals (green-on-arrival)

**Gap:** `test_int_bound_skips_float_hex_and_bigint` (`tests/unit/test_jsmutate.py:128-132`) covers `0xff` but not binary/octal, which flow through the same `_consume_number` early-exit branch (`source[i+1] in "xXbBoO"`).

**Expected first run: PASS** (green-on-arrival — the shared branch already skips `0b`/`0o` identically to `0x`; do NOT try to force a red).

**Files:**
- Modify: `tests/unit/test_jsmutate.py:129`

- [ ] **Step 1: Extend the literal tuple**

Change line 129 from:

```python
    for lit in ("1.5", "0xff", "10n", "1e3"):
```

to:

```python
    for lit in ("1.5", "0xff", "0b101", "0o17", "10n", "1e3"):
```

- [ ] **Step 2: Run to verify it passes**

Run: `python -m pytest tests/unit/test_jsmutate.py -k int_bound_skips -v`
Expected: PASS (binary/octal literals are skipped by int-bound, same as hex).

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_jsmutate.py
git commit -F - <<'EOF'
test(jsmutate): int-bound skip covers 0b/0o literals

Binary/octal literals route through the same _consume_number early-exit branch
as hex (source[i+1] in "xXbBoO") but were untested. Locks that a future narrowing
of the char class would be caught.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

## Task 6: M-d#2 — distinct-char head in the dast give-up test (green-on-arrival)

**Gap:** `_item()` (`tests/integration/test_dast_consumer.py:11-13`) uses `head="h"*40`, so `head[:12]` is indistinguishable from any other zero-based slice length — a wrong slice in the consumer wouldn't fail the test.

**Expected first run: PASS** (green-on-arrival — the consumer already slices `item.head[:12]` correctly; this only hardens the test so a *future* wrong slice would fail. Do NOT try to force a red.)

**Files:**
- Modify: `tests/integration/test_dast_consumer.py` (introduce a module constant `_HEAD`; use it in `_item()` and in `test_give_up_after_three_unreachable`)

- [ ] **Step 1: Add a distinct-char head constant and use it**

Above `_item()` (after the imports, ~line 9), add:

```python
# A distinct-char head (not "h"*40) so a wrong head[:12] slice length would break
# the give-up test's seeded-note prefix. 40 hex-ish chars, all distinct in [:12].
_HEAD = "0123456789abcdef0123456789abcdef01234567"
```

Change `_item()` (line 12) `head="h" * 40` to `head=_HEAD`:

```python
def _item():
    return QueueItem(id="q1", base="b" * 40, head=_HEAD, score=55,
                     reasons=("t",), state="queued", created_at="t", updated_at="t")
```

- [ ] **Step 2: Update every derived head slice**

In `test_give_up_after_three_unreachable`, change line 109 `head12 = ("h" * 40)[:12]` to:

```python
    head12 = _HEAD[:12]
```

Also grep the file to confirm there is no other `"h" * 40` or hard-coded head slice that must change:

Run: `python -m pytest tests/integration/test_dast_consumer.py -v` (see Step 3) after grepping:
`grep -n '"h" \* 40\|\[:12\]' tests/integration/test_dast_consumer.py` → only the two spots above should remain, now referencing `_HEAD`.

- [ ] **Step 3: Run to verify it passes**

Run: `python -m pytest tests/integration/test_dast_consumer.py -v`
Expected: PASS (all — the give-up test's seeded note prefix now derives from `_HEAD[:12]`, matching what the consumer computes from `item.head[:12]`).

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_dast_consumer.py
git commit -F - <<'EOF'
test(dast): distinct-char head so give-up test pins the head[:12] slice

_item() used head="h"*40, so any zero-based slice length was indistinguishable
and a wrong head[:12] in the consumer would not fail the give-up test. Use a
distinct 40-char head via a module constant and derive the seeded-note prefix
from the same constant.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

## Task 7: M-d#4 — `_fetch` redirect-budget exhaustion (green-on-arrival)

**Gap:** no test drives more than `_MAX_REDIRECTS` (2) same-host redirects, so the trailing `return last` (`dast_probe.py:132`) is uncovered.

**Expected first run: PASS** (green-on-arrival — current code already returns the last hop when the budget is exhausted. Do NOT try to force a red.)

**Files:**
- Modify: `tests/unit/test_dast_probe.py`

- [ ] **Step 1: Write the test**

Add to `tests/unit/test_dast_probe.py`:

```python
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
```

- [ ] **Step 2: Run to verify it passes**

Run: `python -m pytest tests/unit/test_dast_probe.py -k redirect_budget -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_dast_probe.py
git commit -F - <<'EOF'
test(dast): cover _fetch redirect-budget exhaustion

Drive a same-host redirect chain longer than _MAX_REDIRECTS and assert _fetch
returns the last hop attempted (a 302) rather than following past the budget.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

## Task 8: M-d#5 — `_fetch` TLS-cert-error mapping (green-on-arrival)

**Gap:** `_fetch`'s real `except ssl.SSLCertVerificationError` branch (`dast_probe.py:116-117`), which maps a cert failure to `_Response(status=0, tls_error=…)`, is untested end-to-end. **Bonus:** `SSLCertVerificationError` subclasses `OSError`, so this test also locks the **except order** (cert-error must be caught before the generic `OSError → DastUnreachable`).

**Approach:** monkeypatch the connection seam `_fetch` reaches after constructing an HTTPS connection to raise `SSLCertVerificationError` — no live TLS server, no committed cert.

**Expected first run: PASS** (green-on-arrival — the branch already exists and is correct. Do NOT try to force a red.)

**Files:**
- Modify: `tests/unit/test_dast_probe.py`

- [ ] **Step 1: Write the test**

Add to `tests/unit/test_dast_probe.py`:

```python
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
```

- [ ] **Step 2: Run to verify it passes**

Run: `python -m pytest tests/unit/test_dast_probe.py -k tls_cert_error -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_dast_probe.py
git commit -F - <<'EOF'
test(dast): cover _fetch TLS-cert-error mapping and except order

Monkeypatch the HTTPS request seam to raise ssl.SSLCertVerificationError and
assert _fetch returns _Response(status=0, tls_error set) rather than raising.
Since SSLCertVerificationError subclasses OSError, this also locks that the
cert-error except precedes the generic OSError -> DastUnreachable handler.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

## Task 9: D4 — real-npm E2E resolves *through* the node_modules junction (green-on-arrival)

**Gap:** the only real-npm E2E (`test_real_npm_weak_suite_reports_survivor`, `tests/integration/test_js_mutation_consumer.py:201-210`) uses a fixture whose `test.js` is `process.exit(0)` — it never `require()`s anything, so it would pass even if `_link_node_modules` were a no-op. It does not prove the junction wires module resolution.

**Approach:** add a `wire_pkg` flag to `_js_repo` (default `False`, so the ~10 other callers are untouched) that (a) writes a hand-written package under `node_modules/` (no `npm install`, no network), (b) makes `calc.js` `require()` it in **both** base and feature commits (so the diff stays the `return` line), and (c) makes `test.js` `require('./calc.js')`. Then the mutant subprocess throws `MODULE_NOT_FOUND` if the junction is absent → the **baseline** fails → no survivor. So a green survivor result proves resolution went through the junction.

**Definition-of-done (acceptance criterion, not "test is green"):** during development, temporarily stub `_link_node_modules` to a no-op returning `True` and confirm the test goes **red** (baseline fails / no findings). If it stays green with the junction gone, `require()` resolved some other way and the test proves nothing. This is a manual dev step; the committed test keeps the junction live.

**Expected first run:** on a machine with node+npm, **PASS** (survivor reported, junction proven). On Python-only CI, **SKIPPED** (`@skipif(not _HAS_NODE)`). Do NOT try to force a red in the committed test.

**Files:**
- Modify: `tests/integration/test_js_mutation_consumer.py` (`_js_repo` gains `wire_pkg`; strengthen `test_real_npm_weak_suite_reports_survivor`)

- [ ] **Step 1: Add the `wire_pkg` branch to `_js_repo`**

Replace the calc.js / test.js / node_modules setup in `_js_repo` (lines 25–53) so the source strings are built once and the `wire_pkg` branch layers the require + package on top. The full function becomes:

```python
def _js_repo(tmp_path, with_node_modules=True, wire_pkg=False):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "package.json").write_text(
        '{"name":"x","scripts":{"test":"node test.js"}}\n', encoding="utf-8")
    (r / "aramid.toml").write_text(
        "schema_version = 1\n[js_mutation]\nmax_mutants = 3\n"
        "wall_budget_s = 300\nmutant_timeout_s = 60\n", encoding="utf-8")

    # calc.js has a mutable `>=` on the changed line. When wire_pkg is set, calc.js
    # also require()s a hand-written package that ONLY resolves through the
    # node_modules junction, and test.js require()s calc.js -- so if the junction is
    # not wired, `node test.js` throws MODULE_NOT_FOUND and the baseline fails
    # (never a survivor). The require line is in BOTH commits so the diff stays the
    # `return` line and the mutant target is unchanged. (D4)
    req = "const { bump } = require('isadult-helper');\n" if wire_pkg else ""
    calc_base = f"{req}function isAdult(age) {{\n  return true;\n}}\nmodule.exports = {{ isAdult }};\n"
    calc_feat = f"{req}function isAdult(age) {{\n  return age >= 18;\n}}\nmodule.exports = {{ isAdult }};\n"
    test_js = ("const { isAdult } = require('./calc.js');\nprocess.exit(0);\n"
               if wire_pkg else "process.exit(0);\n")
    (r / "calc.js").write_text(calc_base, encoding="utf-8")
    (r / "test.js").write_text(test_js, encoding="utf-8")
    # node_modules must never be a tracked path: `git worktree add` would then
    # check it out into the worktree, and a real `mklink /J` / os.symlink
    # cannot land on top of an already-existing (non-empty) directory.
    (r / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    if with_node_modules:
        (r / "node_modules").mkdir()
        (r / "node_modules" / ".marker").write_text("real deps", encoding="utf-8")
        if wire_pkg:
            pkg = r / "node_modules" / "isadult-helper"
            pkg.mkdir()
            (pkg / "package.json").write_text(
                '{"name":"isadult-helper","main":"index.js"}\n', encoding="utf-8")
            (pkg / "index.js").write_text(
                "module.exports = { bump: (n) => n + 1 };\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    base = _sha(r)
    (r / "calc.js").write_text(calc_feat, encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "feature")
    return r, base, _sha(r)
```

- [ ] **Step 2: Strengthen the real-npm E2E to use `wire_pkg`**

Replace `test_real_npm_weak_suite_reports_survivor` (lines 201–210):

```python
@pytest.mark.skipif(not _HAS_NODE, reason="node+npm not on PATH (Python-only CI)")
def test_real_npm_weak_suite_reports_survivor(tmp_path, monkeypatch):
    # End-to-end with a REAL `npm test`. wire_pkg=True makes test.js -> calc.js ->
    # require('isadult-helper'), which ONLY resolves through the node_modules
    # junction. So the baseline passing (and the weak suite then reporting the
    # `>= -> >` survivor) PROVES resolution went through the junction (D4).
    # DoD sanity check (manual, not committed): stub jsc._link_node_modules to a
    # no-op returning True and this test goes red (MODULE_NOT_FOUND -> baseline
    # fails -> no findings).
    r, base, head = _js_repo(tmp_path, wire_pkg=True)
    res = _consume(r, base, head, monkeypatch, tmp_path)
    assert res.state == "ok"
    assert res.findings, "the weak suite cannot kill the mutant -> survivor"
    assert res.findings[0].tool == "js-mutation"
    assert res.extra["survived"] >= 1
    assert _no_worktrees(r)
```

- [ ] **Step 3: Run to verify (pass if node present, else skipped)**

Run: `python -m pytest tests/integration/test_js_mutation_consumer.py -k real_npm -v`
Expected: PASS if node+npm are on PATH; SKIPPED otherwise. Also run the whole file to confirm the `wire_pkg` default did not perturb the other callers:
Run: `python -m pytest tests/integration/test_js_mutation_consumer.py -v` → all pass/skip, none newly failing.

- [ ] **Step 4 (if node present): perform the DoD sanity check**

Temporarily add `monkeypatch.setattr(jsc, "_link_node_modules", lambda src, wt: True)` to the test body, run it, and confirm it now FAILS (baseline errors on `MODULE_NOT_FOUND` → `res.findings` empty). Then **remove** that line before committing. If node is not present, record in the report that the sanity check could not be run locally (CI skips this test anyway).

- [ ] **Step 5: Commit**

```bash
git add tests/integration/test_js_mutation_consumer.py
git commit -F - <<'EOF'
test(js_mutation): real-npm E2E proves resolution through the node_modules junction

The weak-suite E2E used test.js=process.exit(0), which never require()s anything,
so it passed even if the junction were a no-op. Add a wire_pkg fixture flag
(default off, other callers untouched) that makes test.js -> calc.js ->
require('isadult-helper'), a hand-written package resolvable only through the
junction. A green survivor result now proves the junction wired module
resolution (baseline would fail with MODULE_NOT_FOUND otherwise).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

## Final gate (controller, after all 9 tasks)

- [ ] Full suite: `python -m pytest` → green (864 + new tests passing; D4 real-npm passes locally if node present, else skipped).
- [ ] Style parity: `python -m ruff check` → no new findings beyond the baseline (43).
- [ ] Whole-branch adversarial review (most-capable model) with the review package for the branch range, pointed at any Minor findings recorded during the tasks.
- [ ] `superpowers:finishing-a-development-branch`.

## Out of scope (recorded, not lost)

- **M-d#1** — invalid-`base_url` OK-skip already covered by `test_bad_port_base_url_ok_skip`. Dropped (stale).
- **Aggregate wall-budget** for dast (slow target → ~`(paths+5)×timeout_s`/drain) — deferred follow-up.
- **2c-3 epic tail** (2c-3b auto-start, 2c-3c nuclei, unit-4 armed-BLOCK) — each its own spec.
