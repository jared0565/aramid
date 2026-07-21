# aramid Cleanup Pass: DAST + JS-mutation deferred backlog — Design

**Status:** approved (design), pending spec review
**Date:** 2026-07-21
**Roadmap:** deferred-backlog cleanup (not a numbered roadmap feature). Bundles the
still-real deferred tickets from 2c-1b (D1–D4) and 2c-3 (M-c, M-d) into one pass.

## 1. Goal

Close every **verified-still-real** defect and coverage gap from the 2c-1b / 2c-3
deferred backlog in a single bounded pass, before the next DAST epic unit. Each
ticket was re-verified against the current tree (not trusted from the ledger) — one
was already fixed and is dropped.

## 2. Scope

Three source areas carry the changes:

- `src/aramid/consumers/js_mutation.py` — one production bug (D1).
- `src/aramid/dast_probe.py` — three production changes (M-c, M-d#6, M-d#3).
- `src/aramid/jsmutate.py` — one annotation (D2).

Everything else is tests. The pass is deliberately small and cohesive; it is **not**
a refactor and introduces no new module, config key, consumer, or dependency.

### In scope (verified still-real)

| ID | Class | File |
|----|-------|------|
| **D1** | Production bug — pin-forever | `consumers/js_mutation.py` |
| **M-c** | Production bug — false-negative | `dast_probe.py` `_check_cookies` |
| **M-d#6** | Production bug — latent crash | `dast_probe.py` `_same_host` |
| **M-d#3** | Defense-in-depth | `dast_probe.py` `_fetch` |
| **D2** | Hygiene — annotation | `jsmutate.py` `_consume_number` |
| **D3** | Test coverage | `tests/unit/test_jsmutate.py` |
| **M-d#2** | Test coverage | `tests/integration/test_dast_consumer.py` |
| **M-d#4** | Test coverage | `tests/unit/test_dast_probe.py` |
| **M-d#5** | Test coverage (TLS harness) | `tests/unit/test_dast_probe.py` |
| **D4** | Test coverage (real-npm E2E) | `tests/integration/test_js_mutation_consumer.py` |

### Out of scope (explicit, so nothing is silently lost)

- **M-d#1** — invalid-`base_url` OK-skip is **already** covered by
  `test_bad_port_base_url_ok_skip` (tests/integration/test_dast_consumer.py). Stale;
  dropped.
- **Aggregate wall-budget** for dast (a slow target costs ~`(paths+5)×timeout_s`
  per drain) — a leftover 2c-3 whole-branch recommendation. Not in the chosen set;
  remains a deferred follow-up.
- **2c-3 epic tail** (2c-3b auto-start runtime, 2c-3c nuclei, unit-4 armed-BLOCK) —
  each its own spec later.

## 3. Background: the give-up / note-prefix invariant

Two of the fixes (D1, and the already-shipped dast M-a) rely on the same mechanism,
so it is stated once here as a shared invariant.

`base.prior_note_count(ledger, consumer, item_id, prefix)` counts prior
`CONSUMER_RUN_FINISHED` events for this item whose note **`.startswith(prefix)`**
(verified: base.py:52). A consumer bounds a persistent transient failure by:

1. degrading with a note that **starts with** a head-scoped prefix
   (`f"<reason> @ {item.head[:12]}"`), and
2. before retrying, checking `prior_note_count(...) >= N` and flipping to a permanent
   **OK-skip** once the threshold is reached.

Head-scoping means a new commit gets a fresh set of retries. Because matching is
`startswith`, a note may carry a free-text suffix (e.g. `f"{prefix}: {exc}"`) and
still match — this is exactly how the shipped dast `crash_prefix` works
(`consumers/dast.py`). The prefix string is **load-bearing**: free text must never
precede it.

## 4. Production fixes (Group A — true TDD, red-first)

For each of these, the failing test written first **is the proof the bug is real**;
it fails against current `main` and passes only after the fix.

### 4.1 D1 — node_modules link-failure give-up valve

**Current behavior** (`consumers/js_mutation.py:140-145`):

```python
try:
    linked = _link_node_modules(ctx.root, wt)
except OSError as exc:
    return ConsumerResult(consumer=NAME, state="degraded",
                          note=f"could not link node_modules: {str(exc)[:150]}",
                          duration_s=time.monotonic() - started)
```

This DEGRADED path has **no head-scoped prefix and no give-up check**, unlike the
baseline-failing path immediately below it (:123-126, guarded by `_BASELINE_GIVE_UP`).
A *persistent* link failure (permissions, disk full, antivirus lock on the junction)
re-degrades on **every** drain forever, and the drain refuses to mark an item drained
while any consumer is degraded → the queue item is **pinned forever**. This is the
same pin-forever class as the dast M-a bug fixed in 2c-3.

**Fix:** mirror the baseline valve and the dast pattern exactly.

- Add module constant `_LINK_GIVE_UP = 3` (alongside `_BASELINE_GIVE_UP`).
- **Before** the `try: linked = _link_node_modules(...)` block, add:
  ```python
  if base.prior_note_count(ctx.ledger, NAME, item.id,
                           f"node_modules link failing @ {item.head[:12]}") >= _LINK_GIVE_UP:
      return ConsumerResult(consumer=NAME, state="ok",
                            note="js mutation giving up: node_modules link persistently failing")
  ```
- Change the DEGRADED note to **start with** the head-scoped prefix:
  `note=f"node_modules link failing @ {item.head[:12]}: {str(exc)[:150]}"`.

**Tests (both fail on current main):**
- give-up-after-3: seed 3 `CONSUMER_RUN_FINISHED` events with
  `note=f"node_modules link failing @ {head[:12]}"`, monkeypatch
  `_link_node_modules` to raise `OSError`, assert `state == "ok"` and `"giving up"`
  in the note.
- single-failure prefix lock: one link failure with no prior notes → `state ==
  "degraded"` and the note **starts with** `f"node_modules link failing @ {head[:12]}"`
  (fails today because the current note starts with `"could not link node_modules:"`).

### 4.2 M-c — cookie flag detection matches attributes, not the whole line

**Current behavior** (`dast_probe.py:154-172`): `_check_cookies` sets `attrs =
raw.lower()` where `raw` is the **entire** `Set-Cookie` line (`name=value; attr; …`),
then substring-tests `"secure"`/`"httponly"`/`"samesite"` against it. Because the
cookie **value** is part of `raw`, a cookie such as
`Set-Cookie: token=httponly-abc123; Path=/` makes `"httponly" not in attrs` false →
the real missing-HttpOnly finding is **suppressed** (false negative). A real defect
is silently missed.

**Fix:** ignore the value; match delimited attribute tokens after the first `;`.

- Split the value off with `raw.partition(";")`; the attribute string is everything
  after the first `;`.
- Build a set of lowercased attribute names:
  `{tok.split("=", 1)[0].strip().lower() for tok in attr_str.split(";")}`, and test
  `"secure"`/`"httponly"`/`"samesite"` for membership.
- **Edge case preserved:** a cookie with no `;` at all yields an attribute set of
  `{""}`, so all three flags are correctly reported missing (matching today's
  behavior for that case).
- The cookie **name** extraction (`raw.split("=", 1)[0].strip()`) is unchanged, and
  the value is still never emitted (evidence remains a fixed metadata string).

**Tests (fail on current main):**
- `Set-Cookie: token=httponly-abc123; Path=/` over HTTPS → still flags
  `dast-cookie-httponly` (plus secure + samesite, since only `Path` is set).
- `Set-Cookie: sid=secure-value-1; HttpOnly; SameSite=Lax` over HTTPS → still flags
  `dast-cookie-secure` (value contains `secure`, no real `Secure` attribute).
- `Set-Cookie: sid=abc123` (no attributes) over HTTPS → all three flagged.
- A correctly-flagged cookie (`sid=x; Secure; HttpOnly; SameSite=Lax`) → no findings
  (regression guard that the fix doesn't over-report).

### 4.3 M-d#6 — `_same_host` fails closed on a malformed redirect port

**Current behavior** (`dast_probe.py:82-84`):

```python
def _same_host(u1: str, u2: str) -> bool:
    a, b = urlsplit(u1), urlsplit(u2)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)
```

`urlsplit(...).port` raises `ValueError: Port out of range 0-65535` for an
out-of-range port. `_same_host` is called at `_fetch:127` **outside** `_fetch`'s
`try/except`, so a redirect whose `Location` carries an out-of-range port propagates
a bare `ValueError` out of `probe()`. Today this is only caught by the consumer's
broad `except Exception` (degraded, crash_prefix) — an *accidental*
exception-as-control-flow path, not a designed one.

**Fix:** wrap the comparison and **fail closed** — treat a malformed-port target as a
cross-host redirect (do not chase it):

```python
def _same_host(u1: str, u2: str) -> bool:
    try:
        a, b = urlsplit(u1), urlsplit(u2)
        return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)
    except ValueError:
        return False
```

This preserves the existing "never chase a cross-host redirect" invariant and turns
an accidental crash into a documented, tested decision.

**Tests (fail on current main — today they *error* rather than assert):**
- `_same_host("http://h:1/a", "http://h:99999/b")` is `False`.
- `_fetch` given a redirect whose `Location` has an out-of-range port returns the
  **pre-redirect** response (does not raise, does not chase).

### 4.4 M-d#3 — `_fetch` method guard (defense-in-depth)

**Current behavior** (`dast_probe.py:87-132`): `_fetch(url, method, timeout)` passes
`method` straight to `conn.request(method, …)` with no validation. All in-tree
callers pass `"GET"`/`"HEAD"` literals, and `_Response.body` is only populated for
`GET`; a future caller passing an unsafe method would silently violate the
read-only-probe contract.

**Fix:** enforce the contract at the primitive. At the top of `_fetch`:

```python
if method not in ("GET", "HEAD"):
    raise ValueError(f"unsupported dast method: {method!r}")
```

**Test (fails on current main):** `_fetch(base + "/", "POST", 5.0)` raises
`ValueError`.

> **Intentional raise-vs-fail-closed asymmetry** (one-line comments in the code):
> M-d#3 **raises** because a bad method is a *programmer* error that can never arrive
> from the wire; M-d#6 returns **False** because a bad port arrives in an *untrusted
> redirect Location* and must fail closed. A reviewer seeing both in the same file
> should not "unify" them.

## 5. Hygiene fix (Group B)

### 5.1 D2 — `_consume_number` return annotation

**Current** (`jsmutate.py:235`): `def _consume_number(source: str, i: int):` — no
return annotation, though sibling helpers are annotated and the docstring states the
`(end_index, is_plain_int, value)` shape. Every return site yields `(int, bool, int)`.

**Fix:** `def _consume_number(source: str, i: int) -> tuple[int, bool, int]:`.

**Pre-check (guards a <3.9 runtime-eval trap):** before applying, grep `jsmutate.py`
for an existing subscripted-generic runtime annotation (e.g. `-> tuple[...]`,
`list[...]`) or `from __future__ import annotations`. If neither is present and the
module could evaluate annotations at runtime on Python <3.9, add
`from __future__ import annotations` at the top. A sibling `-> bool` alone does **not**
prove `tuple[...]` is safe. (Expected: aramid targets modern Python; this is a
5-second confirmation, not a likely change.)

No runtime test (annotations are not behavior). Optionally lock with a one-line
`typing.get_type_hints(_consume_number)["return"] == tuple[int, bool, int]` marker
test; the plan decides whether that earns its keep.

## 6. Coverage tail (Group C — green-on-arrival)

**Critical execution note:** every task in this group **passes the moment it is
written** — it locks behavior that is already correct (or already present but
untested). The standard TDD "write the failing test, watch it fail" step is
**impossible** here and must not be attempted. Each task states **expected first-run
result = PASS**. An implementer must not fabricate a red state, and a reviewer must
not flag "the test never failed" as a defect for these tasks.

### 6.1 D3 — int-bound test covers `0b`/`0o`

`test_int_bound_skips_float_hex_and_bigint` (`tests/unit/test_jsmutate.py:128-132`)
parametrizes `("1.5", "0xff", "10n", "1e3")`. `_consume_number` routes `0b`/`0o`
through the *same* early-exit branch as `0x` (`source[i+1] in "xXbBoO"`), so they are
structurally skipped identically — but untested. Add `"0b101"` and `"0o17"` to the
tuple; the existing `all(m.op != "int-bound" …)` assertion already covers them. Pure
test addition; passes immediately.

### 6.2 M-d#2 — distinct-char head in the give-up test

`_item()` (`tests/integration/test_dast_consumer.py`) uses `head = "h" * 40`, so
`head[:12]` is indistinguishable from any other zero-based slice length — a wrong
slice wouldn't fail the test. Change `_item()`'s head to a distinct-char value (e.g.
`"abcdefghij0123456789"`) and update **every** derived `head[:12]` reference in that
test file (at minimum `test_give_up_after_three_unreachable`'s `head12`; grep the
file for other head-scoped prefixes so no sibling test breaks). Test-only; passes
immediately.

### 6.3 M-d#4 — redirect-budget exhaustion

No test exceeds `_MAX_REDIRECTS`. Add a harness route chain of >2 same-host redirects
(`/a → /b → /c → /d`, each 302). `_fetch(base + "/a", "GET", …)` runs the loop
`_MAX_REDIRECTS + 1` times and returns the **last hop actually attempted** (still a
redirect-status `_Response`, not followed past the budget) via the trailing
`return last` at `dast_probe.py:132`. Assert the returned response is that last hop.
Test-only; passes immediately.

### 6.4 M-d#5 — TLS-error mapping (design decision ②)

`_fetch`'s `except ssl.SSLCertVerificationError` branch (`dast_probe.py:116-117`),
which maps a cert failure to `_Response(status=0, tls_error=…)`, is untested end to
end (existing transport tests construct `_Response(tls_error=…)` directly).

**Approach — monkeypatch, not a committed cert.** Cross-platform self-signed cert
generation is a smell and a checked-in key/cert is worse. Monkeypatch the connection
seam `_fetch` reaches **after** constructing the HTTPS connection (e.g.
`http.client.HTTPSConnection.request` / `.getresponse`) to raise
`ssl.SSLCertVerificationError`, point `_fetch` at an `https://` URL, and assert it
returns a `_Response` with `status == 0` and `tls_error` set — no live TLS server.

**Bonus coverage the design intends:** `SSLCertVerificationError` **subclasses
`OSError`**, so this test also **locks the except order** — the cert-error handler
must precede the generic `(OSError, socket.timeout, HTTPException) → DastUnreachable`
handler. Reordering those two `except` clauses turns this test red. This makes the
test real coverage, not a tautology. Passes on arrival against current (correct) code.

### 6.5 D4 — real-npm E2E resolves *through* the junction (design decision ①)

**Current gap:** the only real-npm E2E, `test_real_npm_weak_suite_reports_survivor`
(`tests/integration/test_js_mutation_consumer.py`, `@skipif` on node/npm absence),
uses a fixture whose `test.js` is `process.exit(0)` — it never `require()`s anything.
The test would pass **identically if `_link_node_modules` were a no-op**, so it does
not prove the junction wires module resolution.

**Approach — hermetic hand-written package + a real definition-of-done.** Add a
minimal hand-written package under the fixture's `node_modules/` (a `package.json` +
`index.js`; **no `npm install`, no network** — keeps CI hermetic), and have the
fixture's `test.js` `require()` it (through `calc.js` or directly) so the mutant
subprocess throws `MODULE_NOT_FOUND` if the junction is absent. Keep the existing
assertions (`state == "ok"`, findings fire).

**Definition-of-done (this is the acceptance criterion, not "the test is green"):**
during development, temporarily stub `_link_node_modules` to a no-op and confirm the
test goes **red** (subprocess `MODULE_NOT_FOUND`). If it stays green with the junction
gone, `require()` is resolving some other way and the test proves nothing. This
sanity check is a manual dev step; the committed suite keeps the junction live and
passes. Still gated by `@skipif` (node/npm) → skipped on Python-only CI.

## 7. Global constraints

Copied verbatim into the plan's Global Constraints; every task inherits them.

- **Platform:** Windows-first. Run tools as `python -m pytest` / `python -m ruff`,
  never bare `pytest`/`ruff`.
- **Style gate:** `python -m ruff check` must show **no new findings** beyond the
  established repo baseline (43 pre-existing at 2c-3 merge; confirm the current count
  at execution and hold parity — the pass must not increase it). pyproject enables
  ruff **E/F defaults only** (no ANN rules) — D2's annotation is not ruff-enforced.
- **Tests:** full suite via `python -m pytest` must stay green (864 passed / 3
  skipped at 2c-3 merge, plus the new tests). Focused tasks run focused tests; the
  controller runs the full suite once at the gate, not per task.
- **TDD shape:** Group A tasks are red→green (failing test first = proof of bug).
  Group C tasks are green-on-arrival (expected first-run = PASS; do not force red).
- **Commits:** one commit per task; message trailer
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Author commit messages
  with `git commit -F -` and a quoted heredoc (`<<'EOF'`), **never** `-m "…"` with
  backticks (backticks are shell-executed and silently corrupt the message).
- **Never** bypass hooks or signing (`--no-verify`, `--no-gpg-sign`).
- **No new** module, config key, consumer, dependency, or public-API change. This is
  a fix pass only.

## 8. Testing strategy

- **Group A (bugs):** each fix is driven by a test that fails against current `main`;
  the red run is recorded as the proof. Regression cases lock both the fix and the
  guard against over-reporting (M-c) / the note-prefix format (D1).
- **Group C (coverage):** each test passes on arrival and pins an existing behavior
  so a future regression is caught. M-d#5 additionally pins the `except` ordering;
  D4 additionally proves resolution-through-junction via its no-op sanity check.
- **Fingerprint / safety invariants** established in 2c-3 (dast evidence is
  metadata-only; `tool="dast"` → WARN via `policy.classify` catch-all; PIN_OCCURRENCE)
  are unchanged by this pass and must remain intact — M-c must not begin emitting the
  cookie value in evidence.

## 9. Success criteria

- All 5 verified production/hygiene changes applied; D1's and M-c's red tests
  demonstrably fail on `main` and pass after.
- All 5 coverage tests added and passing (D4 skipped without node/npm).
- `python -m ruff check` at parity with the baseline; full `python -m pytest` green.
- No behavior change beyond the described fixes; no new public surface.
- Stale M-d#1 and the deferred wall-budget item explicitly recorded as out of scope.

## 10. Decomposition (informative — finalized in the plan)

Roughly bugs → hygiene → coverage:

1. D1 give-up valve (js_mutation) — red-first
2. M-c cookie attribute parsing (dast_probe) — red-first
3. M-d#6 `_same_host` fail-closed (dast_probe) — red-first
4. M-d#3 `_fetch` method guard (dast_probe) — red-first *(the plan may merge #3+#4 —
   both tiny, same function region, but independently rejectable)*
5. D2 annotation (jsmutate) — trivial
6. D3 `0b`/`0o` test — green-on-arrival
7. M-d#2 distinct-head test — green-on-arrival
8. M-d#4 redirect-exhaustion test — green-on-arrival
9. M-d#5 TLS-error injection test — green-on-arrival
10. D4 real-npm junction E2E — green-on-arrival
