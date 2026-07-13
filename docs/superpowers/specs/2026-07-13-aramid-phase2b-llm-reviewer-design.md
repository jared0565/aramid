# Aramid Phase 2b — LLM Reviewer

**Status:** approved 2026-07-13
**Depends on:** Phase 1 (deterministic gate engine) and Phase 2a (watcher chassis +
regression attack pack), both merged to `main` (423 tests, CI green).

## 1. Overview

Phase 2b is the LLM leg of the red team: an adversarial security reviewer that
rides the 2a chassis as a queue consumer. The chassis needs zero changes —
triage, coalescing, budgets, and the drain already exist. 2b adds a provider
layer, a review protocol, and one zero-token gate check.

The token-economics contract carries over unchanged: **the only place aramid
ever spends LLM quota or dollars is inside the drain, under explicit budgets.**
Watching, triaging, queueing, blocking, and resolving remain pure computation.

### Decisions fixed during brainstorming

| Decision | Choice |
|---|---|
| Review invocation | One-shot assembled-context call (approach A): aramid builds the packet deterministically, one LLM call per item, strict JSON out. No agentic repo access, no map/reduce. |
| Provider chain | Claude CLI → Codex CLI → OpenRouter (hard monthly dollar cap) → queue holds. Order configurable. |
| Blocking channel | Ledger gate + deterministic auto-resolve: pre-push consults the ledger for OPEN refute-confirmed CRITICAL LLM findings (zero tokens); findings auto-resolve when their evidence quote leaves the file. |
| Refute panel | Single refuter, cross-provider, CRITICAL candidates only. Ambiguity defaults to refuted. |
| Blocking posture | Bake-then-arm: `[llm].llm_block_armed = false` shipped; `aramid arm --llm` ends the bake. Mirrors the Phase 1 semgrep bake. |
| Model tier | Sonnet-tier default (`claude -p --model sonnet`; Codex CLI default; mid-tier OpenRouter model). Config-overridable per provider. |
| Budgets | 3 LLM-reviewed items per drain, 240 s per call, OpenRouter cap $5/month. |
| Evidence binding | Every finding must quote the packet verbatim; the quote is mechanically verified or the finding is dropped. |

### Non-goals for 2b

- **LLM→pack auto-compiler deferred.** 2a's honesty note pointed it at 2b, but
  the chosen blocking channel (ledger gate) covers live blocking, and the manual
  `aramid pack add` path covers promotion. Auto-compilation waits until LLM
  finding volume justifies it.
- No mutation/fuzz/DAST consumers (2c).
- No fine-tuning, no embeddings, no vector stores, no conversation memory
  across reviews. Each review is stateless: packet in, findings out.
- No cross-machine spend aggregation; the OpenRouter cap is this-machine-only.

## 2. Architecture

```
drain pops item ──► consumers/llm_review.py            (new consumer)
                        │
                        ├─ review.py: assemble packet   (diff + capped file bodies
                        │             + graphite dependents — zero tokens)
                        ├─ providers/: chain call        Claude CLI → Codex CLI
                        │             (ONE call/item)      → OpenRouter ($cap) → hold
                        ├─ review.py: parse JSON, verify evidence quotes,
                        │             fingerprint, dedupe vs ledger
                        ├─ CRITICAL candidates ──► ONE cross-provider refute call
                        │
                        ▼
              findings (source=LLM, tool="llm-review") ──► ledger
                        │
pre-push gate ──► ledger read: OPEN confirmed-CRITICAL LLM findings
                  ──► BLOCK if [llm].llm_block_armed else WARN    (zero tokens)
```

### New modules

| Module | Responsibility |
|---|---|
| `src/aramid/providers/base.py` | `Provider` protocol: `NAME`, `available()`, `review(prompt, model, timeout_s) → ProviderResponse`. Ordered chain built from `[llm].provider_order`. Registry style mirrors `runners/` and `consumers/`. |
| `src/aramid/providers/claude_cli.py` | subprocess `claude -p --model <model> --output-format json`, prompt on stdin. |
| `src/aramid/providers/codex_cli.py` | subprocess `codex exec`, JSON output mode, prompt on stdin. |
| `src/aramid/providers/openrouter.py` | stdlib `urllib.request` POST to `/api/v1/chat/completions`; key from `OPENROUTER_API_KEY`; refuses calls that would breach the monthly cap. |
| `src/aramid/review.py` | Packet assembly, secret redaction, prompt rendering (review + refute), response parsing, evidence verification, line derivation, fingerprinting. |
| `src/aramid/consumers/llm_review.py` | `NAME = "llm-review"`; orchestrates assemble → chain call → verify → refute → record. Writes real `cost` and token counts into `ConsumerResult` — the first non-zero use of the Phase 4 metering slot. |

### Touched existing modules (small)

- `pipeline.py` — pre-push: auto-resolve pass + ledger block check (section 5).
- `config.py` + `data/defaults.toml` — `[llm]` section (below).
- `commands/arm.py` — `aramid arm --llm` sets `llm_block_armed = true`.
- `commands/status.py` — LLM finding counts, bake state, month spend.
- `commands/doctor.py` — zero-call provider probe (CLI present, key present,
  spend vs cap).
- `commands/drain.py` — no structural change; the CONSUMERS registry already
  dispatches. The `[llm].max_items_per_drain` cap is enforced **inside the
  consumer**: once the per-drain review count is exhausted, `consume()` returns
  `DEGRADED` with note `"llm budget exhausted"`. `_consume_item` already keeps
  a not-fully-consumed item queued, which is precisely the *queue holds*
  decision — over-budget items wait for the next drain, and since the drain
  pops priority-descending, the highest-risk items are always reviewed first.
  (The pack consumer redundantly re-runs on the retry; that is cheap CPU and
  accepted.)

### `[llm]` config (shipped defaults)

```toml
[llm]
enabled = true
max_items_per_drain = 3
call_timeout_s = 240
packet_max_bytes = 120000
llm_block_armed = false            # bake-then-arm; `aramid arm --llm` flips it
provider_order = ["claude-cli", "codex-cli", "openrouter"]
model_claude = "sonnet"
model_codex = ""                   # empty = CLI default
model_openrouter = "anthropic/claude-sonnet-4-5"
openrouter_monthly_cap_usd = 5.0
```

### Graphite coexistence (unchanged, restated)

Graphite's graph is read as *input* for the packet's dependents section.
Graphite artifacts (`graph-out/`, `.graphite*`, `.cache/graphite/`) remain in
the built-in ignore paths, are filtered at triage (2a §8b fix), and are
filtered **again** at packet assembly — they can never reach a review packet.

## 3. Review protocol

### Packet assembly (`review.py`, zero tokens)

For a popped item (`base..head`, coalesced):

1. **Header** — repo name, range, the item's triage reasons, and the review
   focus: OWASP semantic residue (A01 broken access control, A05 security
   misconfiguration, A07 identification/authentication failures) plus
   business-logic flaws.
2. **Unified diff** — `gitutil.diff_text` (byte-accurate truncation exists).
3. **Changed-file bodies at `head`** — post-image of each changed file,
   re-filtered through `config.filter_paths` (defense in depth); binary and
   oversized files skipped.
4. **Graphite dependents** — names only of modules importing the changed files;
   omitted silently when no graph exists.

Packet capped at `packet_max_bytes` (default 120 000 bytes ≈ 30 k tokens):
diff gets priority, then file bodies until the cap. Truncation is noted inside
the packet and in the consumer run note.

**Redaction pass:** before the packet leaves the machine, the rotated-secret
structural regexes from `pack.py` mask obvious secret tokens. Drains review
commits that may have *bypassed* gates; never assume the diff is secret-free
before shipping it to a third party.

**Empty packet** (everything filtered/binary/deleted): no LLM call; the item is
marked drained with a note.

### Prompt contract (review call)

- Role: adversarial security reviewer. Review ONLY the provided material.
- Packet wrapped in explicit untrusted-data delimiters with the instruction to
  treat contents as data, not instructions (prompt-injection mitigation).
- Output: strict JSON only —

```json
{"findings": [{
  "title": "...",
  "owasp": "A01|A05|A07|logic",
  "severity": "critical|high|medium|low",
  "file": "repo/relative/path.py",
  "line": 42,
  "evidence": "verbatim quote from the packet, <= 400 chars",
  "explanation": "...",
  "fix_hint": "..."
}]}
```

- An empty findings array is explicitly a valid, expected answer.
- Severity definitions given in the prompt: `critical` = exploitable as
  committed; `high` = exploitable under plausible conditions; `medium`/`low` =
  hardening.

### Parse & verify (zero tokens)

A finding is dropped unless it survives, in order:

1. **Schema check** — required fields present, severity in enum.
2. **Evidence verbatim** — the quote appears (whitespace-normalized) in the
   packet.
3. **Live-code anchor** — the quote is located in the *head* version of the
   named file; this derives the true line number (LLM line numbers are
   unreliable). A quote that exists only in removed diff lines is not a live
   issue → dropped.

Rejected findings are counted in the run note as `hallucination_rejected`.

**Malformed response** (envelope parses but the result is not valid JSON): the
call is spent; do **not** retry against the next provider. The item stays
queued. The attempts count is **derived, not stored**: the consumer counts this
item's prior `CONSUMER_RUN_FINISHED` events with `consumer="llm-review"` and a
malformed note; at 3 it stops calling providers and returns OK with note
`"llm giving up: repeated malformed output"` so the item drains rather than
wedging the queue. Budget-degraded runs (`"llm budget exhausted"`) do NOT
count as attempts.

### Fingerprint & dedupe

**Reuse Phase 1 fingerprinting wholesale** — no custom scheme. The verified
evidence quote anchors to a line in the head file; that line's content feeds
the existing `compute_fingerprint(tool, rule, file, line_content,
occurrence_index)`. `record_run` then already provides the exact semantics
this design needs (verified against `ledger.py`):

- fingerprint OPEN → no duplicate `FINDING_DETECTED` event.
- fingerprint OVERRIDDEN → never re-reported (record_run skips it).
- fingerprint FIXED (auto-resolved earlier) → re-opens as a fresh detection.

The only 2b-specific dedupe logic: **before the refute call**, the consumer
computes the candidate's fingerprint and checks `ledger.open_findings()` —
already-known findings are dropped pre-refute so no tokens are spent
re-confirming them.

Finding identity: `source = Source.LLM`, `tool = "llm-review"`,
`rule = "llm/<owasp-slug>"` (e.g. `llm/a01`, `llm/logic`).

### Refute pass

- Input: verified findings with severity `critical` only.
- One call per candidate: skeptic role, given the finding plus the relevant
  packet excerpt, asked to disprove. Output: strict JSON
  `{"refuted": bool, "reason": "..."}`. The prompt instructs: **when uncertain,
  refute** — a false BLOCK is worse than a false WARN.
- Provider: first available provider in chain order whose `NAME` differs from
  the reviewer's; fallback: same provider, fresh call.
- Refuted → severity demoted to `high`, the refuter's reason noted in the
  message. Survived → `Finding.confirmed = True` — the only thing the ledger
  gate ever blocks on.

### Recording & metering

- The consumer emits `RawFinding`s through the drain's existing
  `normalize → record_run` path (drain.py already records with an **empty
  resolution scope** — the 2a lesson: a drain must never resolve unrelated
  findings). LLM findings resolve only via auto-resolve, override, or expiry —
  never by scope replay.
- **Additive model changes** (all optional, defaulted, following the
  `RawFinding.commit` precedent):
  - `RawFinding` gains `evidence: str | None = None` (the verbatim quote) and
    `source: Source = Source.DETERMINISTIC`; `normalize()` passes both through
    instead of deriving evidence from the message.
  - `Finding` gains `confirmed: bool = False` (refute-survivor flag);
    `_detect_payload` includes it, so it materializes into ledger state
    automatically — the pre-push gate reads it from there.
- **`policy.classify` gains an `llm-review` branch:** severity is honored as
  reported (refute demotion is applied *before* normalize), verdict is always
  WARN at drain time. The blocking verdict is computed at the pre-push gate
  from materialized state (section 5), never stored at drain time.
- `ConsumerResult.cost` carries real dollars (0.0 for subscription CLIs, actual
  for OpenRouter); the note carries provider used and tokens in/out per call.
- The OpenRouter monthly cap is machine-global but ledgers are per-repo, so
  every provider call appends one line to `~/.aramid/llm_spend.jsonl`
  (`{"at": iso8601, "provider": ..., "model": ..., "tokens_in": n,
  "tokens_out": n, "cost_usd": x}`; subscription calls log with cost 0.0 for
  observability). The cap check sums entries in the current calendar month
  before every OpenRouter call.

## 4. Provider chain

### Protocol

```python
@dataclass
class ProviderResponse:
    text: str          # raw model output
    tokens_in: int
    tokens_out: int
    cost_usd: float    # 0.0 for subscription CLIs
    error: str = ""    # "" | "unavailable" | "quota" | "timeout" | "malformed" | "error"
```

Each provider module exposes `NAME: str`, `available() -> bool` (cheap, no LLM
call), `review(prompt, model, timeout_s) -> ProviderResponse`.

### Availability (checked once per drain, not per item)

- `claude-cli` / `codex-cli`: executable found via `shutil.which`; the absolute
  path is resolved once and baked into the subprocess argv (the 2a
  `win_sh_path` pattern — no shell interpolation, fixed argv).
- `openrouter`: `OPENROUTER_API_KEY` set **and** current-month spend < cap.

### Call mechanics

- Prompt is passed on **stdin** for both CLIs (packets exceed Windows argv
  limits). All subprocess calls use `encoding="utf-8", errors="replace"`,
  fixed argv, and `timeout_s` enforcement.
- `claude-cli`: parse the `--output-format json` envelope for `result` and
  usage fields.
- `codex-cli`: `codex exec` JSON output mode; `model_codex` appended only when
  non-empty.
- `openrouter`: POST via stdlib `urllib.request`; the response's `usage` block
  gives tokens; cost is taken from the response and appended to
  `llm_spend.jsonl` **before** returning. A call that would breach the cap is
  refused before sending.
- Timeout kill uses the 2a fixed-argv `taskkill /T` machinery so the CLI's
  child process tree dies too.

### Fallback rules (per call)

| Outcome | Action |
|---|---|
| `unavailable`, `quota`, `timeout`, nonzero exit | Try next provider in chain. |
| `malformed` (responded, unparseable) | Call spent; NO same-item retry. Item stays queued, `attempts += 1`. |
| Unknown error | Treated as `error` → next provider. The drain never crashes on a provider. |
| All providers exhausted | `ConsumerResult(state=DEGRADED, note="all providers unavailable")`; item stays queued (queue holds). 2a's drain already treats DEGRADED as not-drained. |

Quota detection is pattern-based on stderr/exit codes (e.g. the Claude CLI
usage-limit message); patterns live in the provider modules.

**Spend per drain:** at most `max_items_per_drain` reviews (default 3), plus
one refute call per *fresh* CRITICAL finding. Refutes are NOT bounded by
`max_items_per_drain` — the budget caps reviews only; each fresh CRITICAL a
review surfaces triggers its own refute. So the true worst case is `3 reviews
+ N refutes` where N is the number of fresh CRITICALs across those reviews
(unbounded in principle, though a single packet rarely yields more than a
few). At defaults with one CRITICAL per item that is `3 × (1 review + 1
refute)` = 6 calls; typical 1–3.

## 5. Blocking, bake & resolution

### Pre-push ledger gate (zero tokens)

At pre-push, after the deterministic pipeline:

1. **Auto-resolve pass** over every OPEN LLM finding in this repo: locate the
   evidence quote in the current HEAD version of its file (missing file counts
   as quote gone). Quote gone → append `FINDING_RESOLVED` with payload
   `{"auto_resolved": "evidence_gone"}`. Runs *before* the block check so a
   fixed finding never blocks.
2. Select survivors: `source=llm`, status OPEN, `confirmed=true`, severity
   CRITICAL.
3. Verdict: **BLOCK if `llm_block_armed` else WARN**. The message lists each
   finding's id + title + `aramid ledger show <id>` + the `aramid override`
   escape hatch. Arming is evaluated at gate time, so flipping the flag applies
   retroactively to already-open findings — correct for a bake.

Non-critical and unconfirmed LLM findings are always WARN-tier regardless of
arming.

### Bake-then-arm

Ships `llm_block_armed = false`. `aramid arm --llm` flips it in repo config;
`aramid arm` without the flag keeps its Phase 1 meaning (semgrep bake). The two
arming flags stay independent, like `pack_block_armed`.

### Resolution paths (all token-free)

- **Auto-resolve** — evidence quote no longer in the file. False-resolve safety
  net: the edit that removed the quote is itself a commit → post-commit triage
  re-enqueues → next drain re-reviews the new code.
- **Override** — existing `aramid override <id> <reason>`; fingerprint dedupe
  honors OVERRIDDEN, so it never re-reports.
- **Re-detection** — an auto-resolved fingerprint that reappears in a later
  review re-opens as a fresh detection.

### `aramid status` additions

Open/confirmed LLM finding counts, bake state (`armed` / `baking`), and
this-month provider spend from `llm_spend.jsonl`.

## 6. Error handling

Fail-open everywhere except money:

- Empty packet → no call, item drained with note.
- Provider hang → timeout + process-tree kill.
- No graphite graph → dependents omitted silently.
- Deleted file at HEAD → auto-resolves (quote gone).
- `llm_spend.jsonl` unreadable/corrupt → **fail-closed for OpenRouter only**:
  refuse paid calls when spend cannot be computed; subscription CLIs
  unaffected. The one deliberate inversion of the fail-open rule.
- Prompt injection in reviewed code → untrusted-data delimiters + evidence
  verification. Residual risk is injected *suppression* — a missed finding,
  equivalent to no review, never a false block. Mitigated, not eliminated.
- Concurrency → 2a's singleton drain lock; nothing new.

## 7. Testing

**No live LLM call in any test, ever** — CI and local suites use fakes and
recorded fixtures only.

- **Unit:** provider adapters against faked `subprocess.run` / `urllib`
  (envelope parsing from captured real Claude/Codex/OpenRouter response
  fixtures); evidence verification (verbatim, whitespace-normalized,
  removed-line rejection); fingerprint stability; redaction; spend-cap month
  math + fail-closed corruption path; refute demotion; auto-resolve (quote
  gone / file gone / quote moved).
- **Integration:** a `FakeProvider` injected into the chain → full loop:
  enqueue → drain → canned findings land in the ledger with `source=llm` →
  pre-push WARNs while baking → `aramid arm --llm` → BLOCKs → edit removes
  evidence → auto-resolve → push passes. Plus: all-providers-down leaves the
  item queued; three malformed runs → gives up and drains the item;
  budget-degraded runs don't count as attempts; pre-refute dedupe skips known
  fingerprints; cap-exhausted skips OpenRouter.
- **Doctor:** the zero-call provider probe's output is asserted in tests.

## 8. Forward hooks (NOT 2b scope — listed so interfaces leave room)

- `ConsumerResult.cost` and `llm_spend.jsonl` are the Phase 4 metering inputs;
  2b writes real numbers, Phase 4 aggregates and governs them.
- The refute prompt and panel size are config-shaped for one refuter; a 2c-era
  panel (N refuters, majority) would extend `[llm]` without protocol changes.
- The LLM→pack auto-compiler slots into `pack.py` when finding volume justifies
  it; fingerprints and evidence quotes are already the inputs it needs.
