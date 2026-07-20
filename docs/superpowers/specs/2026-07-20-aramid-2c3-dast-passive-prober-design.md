# 2c-3 DAST — Passive Web-Hygiene Prober (design)

**Status:** approved design (brainstorming), pre-plan.
**Author:** aramid controller + subagent understand-phase (4 parallel researchers → opus synthesis).
**Roadmap:** Phase 2c "heavy adversarial tier" — mutation (2c-1), fuzz (2c-2), **DAST (2c-3)**. Each is a drain consumer.

## 0. TL;DR

2c-3 is the first unit of a decomposed **DAST epic**. This spec covers the **owned, stdlib-only passive web-hygiene prober** that scans a user-declared `base_url` for deterministic web-hygiene issues (security headers, cookie flags, transport, exposed sensitive paths, banner leak) and reports them as WARN-tier drain findings. It builds **no** new runtime machinery and exercises the entire findings → anchor → config → PIN → drain path end-to-end. Auto-start (a long-lived-process runtime), nuclei enrichment, and the live armed-BLOCK path are committed to the epic but **out of scope here** (2c-3b / 2c-3c / unit-4).

## 1. Why this shape (the design rationale)

DAST fundamentally differs from every existing consumer: the others analyze **static code** in a git worktree, but dynamic testing needs a **running application**. The understand phase confirmed aramid has *zero* machinery for that — `detectors.py` sniffs lockfiles only; there is **no long-lived-process primitive** (`runners.base.run_subprocess` is one-shot `communicate()`-and-reap), no port/URL/route notion.

Two design forces follow:

1. **Target acquisition is the user's job, not aramid's.** The modal repo has no reachable target → that is the cheap, silent **OK-skip default**. A target is the special case, declared by the user. This keeps the consumer entirely inside existing one-shot patterns and builds none of the missing primitive.
2. **Auto-start measures the wrong thing for hygiene checks.** An app cold-started from a clean worktree at `item.head` runs in **dev mode with no DB/env/secrets** — it frequently won't bind the port at all (→ no findings), and when it does, dev servers *legitimately* omit HSTS/CSP, run plain HTTP, and ship permissive CORS. Header/cookie/TLS checks against dev posture are **noise, not findings**. The production hygiene that matters lives only on the user's real/staging deployment. Therefore auto-start (2c-3b) is layered *under* URL-first and gated on **explicit** per-repo config — never guessed from `package.json` — and is deferred out of this spec.

**Precedent:** this is the direct analogue of 2c-1 choosing an owned stdlib `ast` mutator over heavy Stryker, and 2c-2 choosing an owned seeded generator over atheris/Hypothesis: owned/stdlib-first, zero-config, low-false-positive, Windows-native, graceful OK-skip.

## 2. Epic decomposition (build order)

| Unit | Deliverable | Size | Status |
|------|-------------|------|--------|
| **2c-3 (this spec)** | Owned passive prober vs a configured `base_url`, WARN-tier | M | designing |
| 2c-3b | Long-lived-process runtime (explicit-config auto-start: start → readiness-poll → Windows tree-kill teardown), layered under URL-first | L | own spec later |
| 2c-3c | nuclei enrichment (external binary when present; doctor download/version wiring; JSON parse) | M | own spec later |
| unit-4 | Wire the armed-BLOCK path (`policy.classify` `dast` branch + `block_rules[dast]`), gated on `[dast].block_armed` | S | folds into 2c-3b or its own follow-up |

Each unit is independently testable. This spec's prober ships value and de-risks the findings/anchor/config/PIN contract before any runtime exists.

## 3. Architecture & modules

Mirrors the `jsmutate.py` / `consumers/js_mutation.py` split (pure core + orchestrating consumer):

- **Create `src/aramid/dast_probe.py`** — the owned prober. Pure-ish: given a `base_url`, extra `paths`, and a `timeout_s`, it performs the check families via stdlib `http.client` / `urllib.request` / `ssl` and returns a `list[DastFinding]`. Network I/O is confined here; no subprocess, no long-lived process, no ledger/config knowledge. This is the unit-tested core.
- **Create `src/aramid/consumers/dast.py`** — `NAME = "dast"`, `consume(item, ctx) -> ConsumerResult`, `PIN_OCCURRENCE = True`, self-registers `base.CONSUMERS[NAME] = sys.modules[__name__]`. Reads `[dast]` config, decides OK-skip / DEGRADED / run, calls `dast_probe`, maps `DastFinding → RawFinding`, returns `ConsumerResult(cost=0.0, ...)`.
- **Modify `src/aramid/config.py`** — add `dast: dict = field(default_factory=dict)` and `dast=merged.get("dast", {})` (mirrors the `js_mutation` field/load pair).
- **Modify `src/aramid/data/defaults.toml`** — add a `[dast]` table.
- **Modify `src/aramid/commands/drain.py`** — add `from aramid.consumers import dast as _dast  # noqa: F401` (registration side-effect; **without this import the consumer never runs**).

## 4. Target model (this spec: `base_url` only)

- `consume` reads `mcfg = getattr(ctx.cfg, "dast", None) or {}`.
- If `not mcfg.get("enabled", True)` → `ConsumerResult(state="ok", note="disabled")`.
- `base_url = mcfg.get("base_url", "").strip()`. If empty → `ConsumerResult(state="ok", note="no dast target configured")` (permanent structural absence — OK, never DEGRADED, so the item still drains).
- Otherwise probe `base_url` (+ configured `paths` + the curated exposed-path set). Reachability failure is handled per §7.
- **Explicitly out of scope here:** `[dast].start_command` auto-start. The config schema (§8) reserves the key with a comment so 2c-3b is additive, but this spec ignores it.

## 5. Check families (v1)

All deterministic and near-zero-FP (a missing header/flag is a boolean fact, not a heuristic). Each check has a stable `rule` id (the fingerprint anchor) and a severity.

1. **Security headers** (`rule="dast-header-<name>"`, severity `medium`, `low` for the softer ones) — flag *missing or empty*:
   - `Strict-Transport-Security` (only on `https://` targets), `Content-Security-Policy`, `X-Frame-Options` (or CSP `frame-ancestors`), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`.
2. **Cookie flags** (`rule="dast-cookie-<flag>"`, severity `medium`) — for each `Set-Cookie` on the base response: missing `Secure` (https only), missing `HttpOnly`, missing/weak `SameSite`. The cookie **name** goes in the message; the cookie **value is never emitted** (secret hygiene, §12).
3. **Transport** (`rule="dast-transport-*"`) — `dast-transport-plaintext` (`medium`): target is `http://`. `dast-transport-cert-invalid` / `dast-transport-cert-expired` (`medium`): TLS handshake to an `https://` target fails validation / cert past `notAfter`.
4. **Exposed sensitive paths** (`rule="dast-exposed-<slug>"`, severity `high` for secrets, `medium` for info) — GET a curated fixed set and flag a revealing `200` (with a content sanity check to avoid SPA catch-all `200`s): `/.git/config`, `/.git/HEAD`, `/.env`, `/.env.local`, `/server-status`, common framework debug endpoints (e.g. `/actuator/env`). A finding requires both `200` **and** a content signature match (e.g. `/.git/config` body contains `[core]`), so a catch-all 200 index page is not a false positive.
5. **Banner leak** (`rule="dast-banner-<header>"`, severity `low`) — `Server` / `X-Powered-By` disclosing a product **version** (regex `\d+\.\d+`), not just a product name.

**Methods:** GET and HEAD only — never a mutating method. **Redirects:** follow at most 2, and only to the **same host** as `base_url` (no cross-host redirect chasing — SSRF hygiene, §12). **Response bodies:** read at most a bounded prefix (e.g. 64 KiB) for content-signature checks.

## 6. The prober API (`dast_probe.py`)

```python
@dataclass
class DastFinding:
    check: str      # stable rule id, e.g. "dast-header-hsts"
    method: str     # "GET" | "HEAD"
    path: str       # request path, e.g. "/" or "/.git/config"
    severity: str   # "high" | "medium" | "low"
    message: str    # human text, no secrets
    evidence: str   # short response excerpt, secret-scrubbed

def probe(base_url: str, paths: list[str], timeout_s: float) -> list[DastFinding]:
    """Run all v1 check families against base_url (+ paths + the curated
    exposed-path set). Pure network I/O; deterministic ordering (sorted by
    (path, check)) so truncation/fingerprints are stable. Raises
    DastUnreachable on a connection-level failure to base_url (so the
    consumer can DEGRADE); per-path errors on the exposed-path set are
    swallowed (a 404/closed path is simply not a finding)."""
```

`DastUnreachable` is a module exception distinguishing "the target isn't up" (→ DEGRADED) from "a probe returned a boring response" (→ no finding).

## 7. Consumer behavior — OK / DEGRADED / give-up

Direct mirror of `consumers/mutation.py`'s baseline give-up:

- **OK-skip (permanent, structural):** disabled; no `base_url`. Item drains.
- **Run:** call `probe(base_url, paths, timeout_s)`.
  - Success → `ConsumerResult(state="ok", findings=[...], cost=0.0, note=f"{len(findings)} hygiene finding(s) on {host}")`.
  - `DastUnreachable` → **DEGRADED**, `note = f"dast target unreachable @ {item.head[:12]}"`. Before running, compute that **exact** string as `give_up_prefix` and check `base.prior_note_count(ctx.ledger, NAME, item.id, give_up_prefix) >= _UNREACHABLE_GIVE_UP` (=3) → OK-skip with `note="dast giving up: target persistently unreachable"`. The DEGRADED note and the `prior_note_count` prefix must be byte-identical (load-bearing, exactly as `mutation`'s `f"baseline failing @ {item.head[:12]}"`); embedding `item.head[:12]` head-scopes the counter so it resets when new commits land.
  - Unexpected probe crash → DEGRADED (transient), no give-up prefix.

Rationale: a configured-but-unreachable target is the **opportunistic** case (the app happens not to be up at drain time). DEGRADED-with-give-up retries a few drains, then OK-skips so the queue item is never pinned forever (the load-bearing OK-not-DEGRADED invariant every 2c consumer honors).

## 8. Config `[dast]` schema (`defaults.toml`)

```toml
[dast]
enabled = true
base_url = ""            # e.g. "https://staging.example.com" -- empty => OK-skip
paths = []               # extra paths to probe on top of the curated exposed set
timeout_s = 10           # per-request timeout
block_armed = false      # RESERVED: inert in 2c-3 (WARN-only); unit-4 wires the
                         # policy.classify dast BLOCK branch to gate on this flag
# start_command = ""     # RESERVED for 2c-3b explicit-config auto-start; ignored here
```

Three-layer merge (`defaults.toml` ← user config ← repo `aramid.toml`) lets any repo point at its own target without editing defaults. Read via `getattr(ctx.cfg, "dast", None) or {}` and honor `enabled`.

## 9. Findings, anchoring & verdict

Consumer maps each `DastFinding` → `RawFinding`:

```python
RawFinding(tool="dast", rule=f.check, severity_raw=f.severity,
           file=f"{f.method} {f.path}", line=0,
           message=f.message, evidence=f.evidence)
```

- **Anchoring:** a URL finding has no repo file, so in `normalizer.normalize` `read_for_fingerprint` fails open to `""` and `line_content` collapses to empty. The fingerprint therefore keys on `(tool="dast", rule, file="GET /path")` — stable because v1 probes a **fixed** path set (no volatile path segments). (Volatile-path normalization becomes relevant only when 2c-3c/route-crawling introduces dynamic paths; noted, not needed here.)
- **`evidence`** is stored as `Finding.evidence` (normalizer.py:76) and does **not** enter the fingerprint, but it MUST still be secret-scrubbed (§12) because it is persisted and displayed.
- **`cost=0.0`** — CPU/network-bound, zero tokens (follow fuzz/mutation, not llm_review's spend path).
- **`PIN_OCCURRENCE = True`** — a live target is membership-variable across drains; pinning collapses to one finding per `(tool, rule, file)` so a probe that finds 3 issues one drain and 2 the next doesn't mint ghost never-resolving findings.
- **Verdict (WARN in MVP):** `tool="dast"` is not gitleaks/llm-review/ruff/semgrep/deps, so `policy.classify` (policy.py:119) returns `Verdict.WARN` with **zero new code**. This matches every 2c consumer being WARN-tier. The armed-BLOCK path is unit-4: a `if tool == "dast":` branch gating on `cfg.dast.get("block_armed", False)` + `block_rules.get("dast", {}).get("block", [])`, deliberately **separate** from `semgrep_block_armed` (the pack/semgrep split exists precisely to avoid conflating unrelated bakes). Shipping WARN-only keeps the one trust-torching failure — a false live-target finding blocking a push — impossible before an explicit bake.

## 10. Error handling & edge cases

- **base_url unreachable / timeout** → `DastUnreachable` → DEGRADED + give-up (§7).
- **TLS handshake failure** → distinguish "cert invalid/expired" (a *finding*, `dast-transport-cert-*`) from "connection refused" (DEGRADED). A hostname/CA validation failure is a finding; a socket-level refusal is unreachable.
- **Non-HTML / binary / huge responses** → bounded read (64 KiB prefix); content-signature checks only run on the prefix.
- **Redirects** → follow ≤2, same-host only; a redirect to another host is not chased (report against the configured host).
- **Malformed headers / duplicate `Set-Cookie`** → parse defensively; a parse failure on one header never aborts the whole probe (per-check try/except, count as an internal error, continue).
- **cp1252 host** → decode response bodies with `errors="replace"`; never raise on decode.

## 11. Testing strategy

The passive-vs-URL model's big win: **fully CI-testable with no external dependency** (unlike the js_mutation real-npm test, which is skip-gated on Node).

- **Unit (`tests/unit/test_dast_probe.py`):** feed `dast_probe` canned responses (monkeypatch the http layer, or point it at a local `http.server.BaseHTTPRequestHandler` serving controlled headers/cookies/status/body). Assert each check family fires on the bad case and stays silent on the good case (a fully-hardened response → `[]`). Determinism/ordering pinned. TLS-cert cases via a self-signed local https server or a mocked `ssl` path.
- **Integration (`tests/integration/test_dast_consumer.py`, NOT skip-gated):** stand up a local stdlib `http.server` in a thread serving a controlled app; run `consume` end-to-end. Cover: OK-skip when no `base_url`; findings shape + `tool="dast"` + `file="GET /path"` + `PIN_OCCURRENCE`/`cost=0.0`; DEGRADED + give-up when `base_url` points at a closed port (mirror the mutation baseline give-up test with a seeded ledger); exposed-path finding on a served `/.git/config`; no-false-positive on a hardened response.
- **Full suite + ruff parity** gate before merge; whole-branch adversarial review; finishing skill.

## 12. Security & safety

- **Outbound request safety (SSRF hygiene):** aramid only requests the user-configured `base_url` + curated/configured paths on the **same host**; no cross-host redirect chasing; GET/HEAD only (never a mutating method). The target is operator-declared, so this is not arbitrary SSRF, but same-host confinement prevents a redirect from turning a scan into a probe of an unintended host.
- **Secret scrubbing:** `evidence` and `message` MUST be run through aramid's `redact`/`scrub` before emission — a `Set-Cookie` value, `Authorization` echo, or token in a response body must never be persisted verbatim. Cookie **names** are safe to show; cookie **values** are never emitted.
- **Bounded work:** per-request `timeout_s`; bounded body read; a bounded total path set (curated + configured) so a scan is always short and predictable.
- **No credentials:** v1 sends no auth; it probes the target as an anonymous client. (Authenticated scanning is a future concern, not this spec.)

## 13. Out of scope (committed to the epic, not here)

- **2c-3b** — explicit-config auto-start runtime (start command + readiness poll + Windows tree-kill). Layered under URL-first; gated on explicit `[dast].start_command`, never `package.json` discovery.
- **2c-3c** — nuclei enrichment (active/CVE/template probing) as an external binary when present, with doctor download/version wiring.
- **unit-4** — wire the `policy.classify` `dast` BLOCK branch + `block_rules[dast]`, gated on `[dast].block_armed`.
- Active injection probing (SQLi/XSS payloads), route crawling/discovery, authenticated scans.

## 14. Key decisions (log)

- **D1 owned vs off-the-shelf:** owned prober now (2c-3) + nuclei staged (2c-3c). Same call as 2c-1's owned mutator over Stryker.
- **D2 target model:** URL-first; auto-start only on *explicit* config (2c-3b), never guessed; else OK-skip. Resolved after the **validity** insight — auto-start measures cold dev-mode posture, the wrong instrument for hygiene checks; URL-first scans the user's real/staging deployment.
- **D3 passive vs active:** passive/hygiene owned now; active delegated to nuclei (2c-3c).
- **D4 WARN vs BLOCK:** WARN-only MVP via the classify catch-all; arming hook designed (`block_armed` reserved) but the classify BLOCK branch is unit-4.
- **D5 scope/name:** decomposed epic, prober-vs-URL first. Consumer `NAME="dast"` is the umbrella; honest because the active half (2c-3c nuclei) is committed to the roadmap.

## 15. Invariants

1. **OK-not-DEGRADED for structural absence** — disabled / no `base_url` returns `state="ok"`; a degraded consumer pins the queue item forever. DEGRADED only for a transient unreachable/crash, with give-up after 3.
2. **No secret ever persisted verbatim** — all `evidence`/`message` scrubbed; cookie values never emitted.
3. **Bounded & non-mutating** — GET/HEAD only, same-host, per-request timeout, bounded body, bounded path set. A scan never mutates the target and always terminates quickly.
4. **Deterministic findings** — sorted, fixed path set → stable fingerprints across drains; `PIN_OCCURRENCE` collapses variable-membership batches.
5. **WARN-tier only** — no DAST finding can block a push in this spec; the BLOCK path is inert until unit-4 + an explicit bake.
6. **Zero new runtime primitive** — this spec builds no long-lived process; all I/O is one-shot stdlib HTTP.
