# Aramid Reviewer Model-Selection Substrate + Deterministic Ladder — Design

**Status:** approved (brainstormed 2026-07-14)
**Repo:** `F:\Projects\aramid` · builds on Phases 1 + 2a + 2b (`main` @ `e8548e4`, CI green, 553 tests)
**Predecessor:** `2026-07-13-aramid-phase2b-llm-reviewer-design.md` (the LLM reviewer this modifies)

## 1. Goal & scope

Reconcile aramid's Phase 2b LLM-reviewer provider chain with the user's
**model-source policy** — dev-time tooling uses flat-rate sources (Claude
subscription, ChatGPT/Codex subscription, **Ollama Cloud**); **OpenRouter is
reserved for in-app LLM features only** — and lay the mechanical substrate for
a future adaptive model-selection engine by making any `(provider, model,
effort)` **arm** invocable and selecting arms **deterministically by risk
tier**.

**In scope**
1. A new `ollama-cloud` provider (direct Ollama Cloud HTTP API).
2. Drop `openrouter` from the **default** provider chain (module kept in-tree, opt-in).
3. Per-provider reasoning-**effort** plumbing (`claude --effort`, `codex -c
   model_reasoning_effort`, `ollama "think"`).
4. An **arm** abstraction + a config-defined **ladder** of arms across tiers.
5. **Deterministic risk-tiered selection**: `triage score → tier → arm`, with
   graceful degrade; refuter picks a cross-provider arm.

**Explicitly OUT of scope (deferred to the auto-learn engine spec)**
- Any *learning* / probabilistic arm selection, reward signal, bandit, or
  outcome feedback loop.
- Redesigning the **escalation signal**. This spec uses the triage score as a
  **provisional** tier signal (see §6.4) — a known-imperfect proxy the
  auto-learn engine will replace.

**Non-negotiable invariant (unchanged from Phase 2b):** nothing in this change
may cause a finding to be marked `confirmed=True` that would not otherwise be
confirmed. Selection changes *which model* reviews/refutes; it never touches
the evidence-binding, refute contract, or the `confirmed` gate.

## 2. Decisions

| Question | Decision |
|---|---|
| Ollama Cloud transport | Direct cloud HTTP API: `POST https://ollama.com/api/chat`, `Authorization: Bearer $OLLAMA_API_KEY`, `urllib` (mirror of `openrouter.py` minus the money cap). |
| OpenRouter | Removed from default `provider_order`/ladder; `openrouter.py` + its config keys + spend-cap code stay in-tree, reachable only if a repo opts in. |
| Effort surface | Normalized enum `low\|medium\|high\|""(unset)`; each provider maps to its native mechanism; `""` omits the flag. |
| Effort default values | Ship **unset (`""`)** until a one-time live CLI verification (plan step) confirms each provider accepts the value; verified values become the shipped defaults. |
| Selection unit | An **arm** `{tier, provider, model, effort, min_score}`, defined in `[[llm.ladder]]`. |
| Reviewer selection | Highest-`min_score` arm with `min_score ≤ item.score` whose provider is available; else **degrade to nearest lower-tier available** arm. |
| Refuter selection | Highest-tier available arm whose provider ≠ reviewer's; fallback = reviewer's own arm (self-refute, existing semantics). |
| Tier signal | Triage score — **provisional**, documented as imperfect; the auto-learn engine owns the real signal. |
| Cost | All default arms are flat-rate → `cost_usd = 0.0` across the whole dev chain; the OpenRouter cap machinery is never exercised by default. |

## 3. The `ollama-cloud` provider

New module `src/aramid/providers/ollama_cloud.py`, peer of `openrouter.py`,
stdlib `urllib` only.

```
NAME = "ollama-cloud"
_URL = "https://ollama.com/api/chat"

installed()    -> bool(os.environ.get("OLLAMA_API_KEY"))
available(cfg) -> installed()          # key present; no live probe, no cap
review(prompt, model, timeout_s, *, effort="") -> ProviderResponse
```

`review()` behaviour:
- If `OLLAMA_API_KEY` missing → `ERR_UNAVAILABLE`.
- Body: `{"model": model, "messages": [{"role":"user","content":prompt}],
  "stream": false}`; add `"think": true` iff `effort` is non-empty (see §4).
  Header `Authorization: Bearer $OLLAMA_API_KEY`.
- Parse **strictly** (mirror `openrouter.py`): `data` must be a dict;
  `text = data["message"]["content"]` must be `str` else `ERR_MALFORMED` — a
  body with no `message` must raise into the except and surface as
  `ERR_MALFORMED`, never a silent empty review.
- Tokens (best-effort, observability only): `prompt_eval_count` /
  `eval_count`. `cost_usd = 0.0` (flat-rate).
- Log tokens via `spend.append_spend(...)` like `claude_cli`/`codex_cli`
  (`_log` helper; never fail a successful call over logging).

Error map (fail-open, matches the chain contract):

| Condition | `error` |
|---|---|
| key missing | `ERR_UNAVAILABLE` |
| `TimeoutError` | `ERR_TIMEOUT` |
| `HTTPError` 429 | `ERR_QUOTA` |
| `HTTPError` 401/403 | `ERR_UNAVAILABLE` |
| other `HTTPError` / `OSError` / `ValueError` | `ERR_ERROR` |
| unexpected body shape | `ERR_MALFORMED` |

Registers into `PROVIDERS` at import (`base.PROVIDERS[NAME] = sys.modules[__name__]`).

## 4. Effort plumbing

aramid normalizes effort to `low | medium | high | ""` where `""` means
**unset → omit the flag entirely**. Each provider's `review()` gains a
keyword arg `effort: str = ""` and maps it:

| Provider | Mechanism | Mapping |
|---|---|---|
| `claude-cli` | CLI flag | append `--effort <effort>` iff non-empty |
| `codex-cli` | config override | append `-c model_reasoning_effort=<effort>` iff non-empty |
| `ollama-cloud` | request body | set `"think": true` iff non-empty (level-aware refinement deferred) |
| `openrouter` (opt-in) | request body | set `"reasoning": {"effort": <effort>}` iff non-empty |

**Silent-tier-death safety (advisor-mandated).** Flag *existence* is verified
against the installed CLIs (`claude 2.1.207`, `codex 0.144.1`); accepted
*values* are NOT verifiable under the no-live-calls test rule. Therefore:
1. Default arm efforts ship as `""` (flag omitted) — a wrong value can never
   kill a tier out of the box.
2. The **plan includes a one-time live verification step**: run each CLI once
   per intended effort value, confirm exit 0. Only verified values become the
   shipped defaults (intended: `cheap=low`, `mid=medium`, `frontier=high`).
   Any value that fails verification ships as `""` with a note.
3. Runtime visibility (§6.5): the consumer run note records the selected
   arm/tier and any degrade, so a dead tier surfaces in the ledger rather than
   silently downgrading every high-risk item.

## 5. The arm abstraction

An **arm** is the selectable unit: `Arm{tier: str, provider: str, model: str,
effort: str, min_score: int}`. Arms are defined in config as an array of
tables and parsed into `Arm` dataclasses. This is the substrate the future
auto-learn engine consumes unchanged — it will vary selection *policy* over
the same arm set.

Default ladder (`src/aramid/data/defaults.toml`):

```toml
# Reviewer model ladder (deterministic risk-tiered selection). Each arm binds a
# provider+model+effort to a tier; the arm whose min_score band contains the
# item's triage score is chosen (degrade to nearest available -- see design 6.3).
# effort ships "" (flag omitted) until the plan's live CLI check verifies values.
[[llm.ladder]]
tier = "cheap"
provider = "ollama-cloud"
model = "deepseek-v4-flash"
effort = ""            # intended: low  (set after live verification)
min_score = 40

[[llm.ladder]]
tier = "mid"
provider = "codex-cli"
model = "gpt-5.6"
effort = ""            # intended: medium
min_score = 60

[[llm.ladder]]
tier = "frontier"
provider = "claude-cli"
model = "opus"
effort = ""            # intended: high
min_score = 80
```

Rationale for the default assignment: capability rises with the tier
(fast open cloud model → GPT-5.6 → Opus 4.8), each tier is a **different
provider** so the cross-provider refuter always differs in model family from
the reviewer, and load naturally spreads across the three flat-rate quotas
(high-volume cheap → Ollama, rare frontier → Claude). `deepseek-v4-flash` is
the least-certain default and is expected to be user-tuned.

Config merge: a repo's `[[llm.ladder]]` **replaces** the default array
(list-replace semantics of `_deep_merge`), which is the correct whole-ladder
override behaviour.

## 6. Deterministic risk-tiered selection

Pure functions in `src/aramid/review.py` (testable without live calls). The
consumer computes available provider names (impure `available()` probes) and
passes them in.

### 6.1 Parse
`build_arms(cfg) -> list[Arm]`: parse `cfg.llm["ladder"]`; drop malformed
entries (fail-open); sort by `min_score` ascending. Empty/absent ladder → `[]`
(consumer treats as "no arms" → skip, same as no providers).

### 6.2 Reviewer
`select_reviewer(arms, score, available_names) -> Arm | None`:
- Target = the highest-`min_score` arm with `min_score ≤ score`.
- If the target arm's provider is available, return it.
- Else **degrade**: among available arms with `min_score ≤ target.min_score`,
  return the highest-`min_score`; if none, return the lowest-`min_score`
  available arm; if no arm is available, `None`.

### 6.3 Refuter
`select_refuter(arms, reviewer_arm, available_names) -> Arm`:
- Return the highest-tier (highest `min_score`) available arm whose
  `provider != reviewer_arm.provider` (max skeptical power + family diversity).
- Fallback: `reviewer_arm` itself (self-refute — preserves Phase 2b's
  single-provider fallback).

### 6.4 Provisional tier signal (documented limitation)
The triage score measures *how many admission signals fired* (security path,
risky content, novelty, blast radius), **not how much reasoning a review
needs**. A subtle access-control flaw can score low; a noisy rename can score
high. So `score → tier` is a **provisional** heuristic that may mis-route
frontier-worthy items to a cheaper arm. This is accepted for the deterministic
substrate; designing the real escalation signal is the core work of the
**auto-learn engine spec** (§8), which will replace this mapping.

### 6.5 Runtime visibility
The consumer run note gains `tier=<tier> arm=<provider>/<model>` and, when the
selected arm is not the target tier, `degraded_from=<target_tier>`. This makes
a provider outage / dead tier observable in the ledger instead of silently
downgrading.

## 7. Consumer integration (`consumers/llm_review.py`)

`consume()` replaces today's "first-available provider + `_model_for` static
model" with arm selection. No change to verify/refute/dedupe/budget logic or
the `confirmed` path.

- `arms = review.build_arms(cfg)`; `avail = {m.NAME for m in
  providers_base.chain(cfg)}` (available provider names).
- `reviewer_arm = review.select_reviewer(arms, item.score, avail)`; if `None`
  → the existing "no providers" / "unavailable" result branches apply
  (skip if none installed, degrade+hold if installed-but-unavailable).
- Review call: `_call(PROVIDERS[reviewer_arm.provider], prompt, cfg,
  timeout_s, effort=reviewer_arm.effort)`.
- Refute call (per fresh critical, within the existing refute budget/dedupe):
  `refuter_arm = review.select_refuter(arms, reviewer_arm, avail)`; call with
  `effort=refuter_arm.effort`.
- `_model_for` is removed; the arm supplies the model. `_call` gains an
  `effort` kwarg, passed to every provider; `cfg` is still passed only to
  `openrouter`.

## 8. OpenRouter reconciliation

- Remove `openrouter` from the default `provider_order` and from the default
  ladder. New default `provider_order = ["claude-cli", "codex-cli",
  "ollama-cloud"]`.
- `openrouter.py`, its config keys (`model_openrouter`,
  `openrouter_monthly_cap_usd`), its `PROVIDERS` registration, `spend.py`'s
  cap logic, and all its tests stay unchanged and green. A repo may opt in by
  adding `openrouter` to its `provider_order` and an `openrouter` arm to its
  ladder.
- `defaults.toml` comments `openrouter`'s keys as "opt-in / in-app only — not
  part of the dev-time default chain (model-source policy)."

## 9. Config schema & migration

- Add `[[llm.ladder]]` (array of arm tables, §5).
- `provider_order` default loses `openrouter`, gains `ollama-cloud`.
- Remove `model_claude` / `model_codex` / `model_ollama` from the selection
  path — arms carry the model now. (`model_openrouter` stays for the opt-in
  provider.) Legacy `model_*` keys, if present in a user config, are ignored
  by selection.
- `config.load_config` already passes the whole `[llm]` table through
  `_deep_merge` with no key allowlist, so `ladder` reads through unchanged.

## 10. Error handling

- Provider errors: unchanged fail-open chain contract; `ollama-cloud` error
  map per §3.
- Selection: malformed ladder entries dropped (fail-open); empty arm set →
  same as "no providers"; no available arm → degrade or hold (§6.2), never
  crash.
- Effort: unknown/unset → flag omitted; an effort-flag rejection is an ordinary
  provider error (chain falls through / item held) and is visible via the run
  note (§6.5).

## 11. Testing (no live LLM calls)

- `tests/unit/test_provider_ollama.py`: monkeypatch `urllib.request.urlopen`
  with canned JSON → assert text/token parse; key-missing→UNAVAILABLE;
  timeout→TIMEOUT; `HTTPError` 429→QUOTA, 401→UNAVAILABLE; malformed
  body→MALFORMED; `effort` non-empty sets `"think": true` in the sent body.
- `tests/unit/test_effort_passthrough.py`: monkeypatch each provider's
  transport; assert `claude` argv contains `--effort high` when set and does
  NOT when `effort=""`; `codex` argv contains `-c model_reasoning_effort=...`;
  `ollama` body sets/omits `think`.
- `tests/unit/test_arm_selection.py`: `select_reviewer` picks tier by score;
  degrades to nearest available when the target provider is out; returns
  `None` when nothing is available; `select_refuter` picks a different
  provider and falls back to self when only one provider is available;
  `build_arms` drops malformed entries and sorts by `min_score`.
- `tests/unit/test_llm_consumer.py`: extend — reviewer uses the score-selected
  arm's model; refuter uses a different provider; run note carries
  `tier=`/`arm=` and `degraded_from=` on degrade. Existing refute-budget /
  dedupe / confirmed tests must stay green unchanged.
- `tests/unit/test_config.py`: default `provider_order` no longer contains
  `openrouter` and contains `ollama-cloud`; default ladder has the three tiers
  with the documented providers and `min_score`s.
- `status` / `doctor`: a line enumerating ladder arms + provider availability
  (zero-call).

## 12. Forward hooks — what this hands the auto-learn engine

- A stable **arm** set and pure `select_*` functions the engine can wrap with a
  learned policy (swap the deterministic `select_reviewer` for a
  reward-driven one over the same arms).
- The run note already records `tier`/`arm`/`degraded_from`; the engine adds
  the outcome join (refute-survival, hallucination-reject rate, later
  override/fix/expiry) as the **reward signal** — the piece deliberately not
  designed here.
- `cost_usd`/token metering per arm already flows to the ledger (the Phase 4
  metering slot), giving the engine a cost axis for free.

## 13. Files touched

- **Create** `src/aramid/providers/ollama_cloud.py`
- **Create** `tests/unit/test_provider_ollama.py`, `test_effort_passthrough.py`,
  `test_arm_selection.py`
- **Modify** `src/aramid/providers/{claude_cli,codex_cli,openrouter}.py` (effort arg)
- **Modify** `src/aramid/review.py` (`Arm`, `build_arms`, `select_reviewer`,
  `select_refuter`)
- **Modify** `src/aramid/consumers/llm_review.py` (arm-based selection; `_call`
  effort; drop `_model_for`)
- **Modify** `src/aramid/data/defaults.toml` (ladder, `provider_order`,
  openrouter comments)
- **Modify** `src/aramid/commands/{status,doctor}.py` (arm/provider lines)
- **Modify** `tests/unit/test_config.py`, `tests/unit/test_llm_consumer.py`
- **Modify** README + this spec's predecessor references
