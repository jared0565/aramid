# Aramid Auto-Learn Model Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the auto-learn model-selection engine per the approved spec `docs/superpowers/specs/2026-07-18-aramid-autolearn-model-selection-design.md`: structured selection telemetry, machine-global Beta-posterior state, escalate-only Thompson **uplift** (shadow until `aramid arm --autolearn`), cascade re-review, and audit sampling.

**Architecture:** One new pure module `src/aramid/autolearn.py` (policy math + state serde + ledger rollup) consulted by `consumers/llm_review.py` around the existing, unmodified `review.reviewer_order` selection; telemetry rides a new `ConsumerResult.extra` dict merged into `CONSUMER_RUN_FINISHED` payloads; state lives at `~/.aramid/autolearn_state.json` (derived, rebuildable). Uplift is applied by calling `reviewer_order(arms, max(item.score, uplift_arm.min_score), avail)` — `review.py`'s selection functions are reused, not replaced.

**Tech Stack:** Python 3.14 stdlib only (hashlib, json, random, sqlite via existing Ledger). Tests: `python -m pytest` (pytest is NOT on PATH — always `python -m pytest`).

## Global Constraints

- **Block path untouchable (spec §3.1):** in `consumers/llm_review.py` the verify → confirmed-strip → pre-refute-dedupe → refute-cap → `apply_refute` code stays byte-identical except the *enumerated* additions in Tasks 3 and 6 (the `out["refuted"] = True` marker in `review.apply_refute`, the `refuted=` kwarg on `RawFinding`, the `refute_infos.append(...)` lines, and latency capture from `_call`). `reviewer_order`, `target_arm`, `select_refuter`, `verify_findings`, `auto_resolve_llm`, `llm_gate_findings` are NOT modified.
- **Cold start ≡ shipped ladder (spec §3.2):** with `enabled=true, armed=false` (the defaults) and no state file, behavior is identical to today. Every pre-existing test — especially `tests/unit/test_arm_selection.py` and the existing tests in `tests/unit/test_llm_consumer.py` — must pass **unchanged**. Do not edit an existing test to make it pass. Sole sanctioned fixture edit: Task 9 Step 4 appends `[llm.autolearn] audit_every = 0` to `test_llm_review.py`'s `_setup_repo` aramid.toml (hermeticity against hash-random shadow audits); no assertion changes.
- **Escalate-only (spec §3.3):** the ladder tier is a floor. No code path may serve an arm with `min_score` below the deterministic target's.
- **No live LLM calls in any test.** Providers are faked (`_Fake` pattern in `test_llm_consumer.py`) or monkeypatched.
- **No test touches the real `~/.aramid`:** `tests/conftest.py` (created in Task 1) autouse-patches `autolearn.state_path`; existing seams (`registry.registry_path`, `spend.spend_path`, `drain._lock_path`, `config._user_config_path`) are patched per existing fixture patterns where used.
- **Terminology:** the learned tier-raise is **uplift**. Never call it "escalation" (`policy.escalate_degraded` owns that word).
- **Constants (spec §8.2):** `PRIOR_CLEAN = 9`, `STATE_VERSION = 1`, default `uplift_threshold = 0.15`, `audit_every = 8`, `max_audits_per_drain = 1`, `cascade_hallucination_min = 3`.
- Run tests via `python -m pytest` from `F:\Projects\aramid`. Full suite ~6 min; run per-task targeted files, full suite only in Task 14.
- Commit prefix per repo convention: `feat(autolearn): ...` / `test(autolearn): ...` / `docs: ...`.

---

### Task 1: `autolearn.py` core — state, buckets, decisions

**Files:**
- Create: `src/aramid/autolearn.py`
- Create: `tests/conftest.py`
- Test: `tests/unit/test_autolearn.py`

**Interfaces:**
- Consumes: `review.target_arm(arms, score)`, `review.llm_fingerprint(rule, file, line_content)`, `review.Arm` (frozen dataclass: tier/provider/model/effort/min_score).
- Produces (later tasks rely on these exact names/signatures):
  - `PRIOR_CLEAN: int = 9`, `STATE_VERSION: int = 1`
  - `state_path() -> Path`
  - `empty_state() -> dict`
  - `load_state(path: Path | None = None) -> dict`
  - `save_state(state: dict, now_iso: str, path: Path | None = None) -> None`
  - `bucket_for(reasons) -> str` (`"sec"` | `"plain"`)
  - `posterior_key(arm, band: str, bucket: str) -> str`
  - `decision_rng(item_id: str, state: dict) -> random.Random`
  - `uplift_pick(arms, score, bucket, state, threshold, rng) -> tuple[Arm, float] | None`
  - `next_arm_above(arms, served_arm) -> Arm | None`
  - `audit_arm(arms, available: set[str]) -> Arm | None`
  - `should_audit(item_id: str, served_arm, arms, audit_every: int) -> bool`
  - `cascade_trigger(served_arm, arms, verified: list, rejected: int, truncated: bool, halluc_min: int) -> str | None`
  - `audit_diff(served_verified: list, audit_verified: list) -> tuple[int, int]`

- [ ] **Step 1: Create `tests/conftest.py`** (root-level, applies suite-wide — mirrors `tests/integration/conftest.py`'s registry isolation):

```python
"""Suite-wide fixtures.

`autolearn.load_state`/`save_state` default to `autolearn.state_path()`
(`Path.home() / ".aramid" / "autolearn_state.json"`). The llm-review
consumer READS it on every consume() and the drain WRITES it at rollup
time, so without isolation the suite would read/write real machine state
(the same concern tests/integration/conftest.py documents for the
registry). Autouse-patch the seam to a per-test tmp_path; individual tests
that seed state simply call autolearn.save_state(...) and hit the same
patched location.
"""
import pytest

from aramid import autolearn


@pytest.fixture(autouse=True)
def _isolated_autolearn_state(tmp_path, monkeypatch):
    monkeypatch.setattr(autolearn, "state_path",
                        lambda: tmp_path / "autolearn_state.json")
```

- [ ] **Step 2: Write the failing tests** — `tests/unit/test_autolearn.py`:

```python
"""autolearn core: state serde, buckets, Thompson uplift, cascade/audit
predicates, audit diff. Pure functions -- no providers, no ledger."""
import json

from aramid import autolearn
from aramid.review import Arm

CHEAP = Arm(tier="cheap", provider="fake-a", model="ma", effort="", min_score=40)
MID = Arm(tier="mid", provider="fake-c", model="mc", effort="", min_score=60)
FRONTIER = Arm(tier="frontier", provider="fake-b", model="mb", effort="", min_score=80)
ARMS = [CHEAP, MID, FRONTIER]


# --- state serde ------------------------------------------------------------

def test_empty_state_shape():
    st = autolearn.empty_state()
    assert st["version"] == autolearn.STATE_VERSION
    assert st["cursors"] == {} and st["posteriors"] == {}
    assert st["shadow"] == {"decisions": 0, "would_uplift": 0}
    assert st["audits"] == {"performed": 0, "missed_criticals": 0}


def test_load_state_missing_file_is_empty(tmp_path):
    assert autolearn.load_state(tmp_path / "nope.json") == autolearn.empty_state()


def test_load_state_corrupt_is_empty(tmp_path):
    p = tmp_path / "s.json"
    p.write_text("{not json", encoding="utf-8")
    assert autolearn.load_state(p) == autolearn.empty_state()


def test_load_state_foreign_version_is_empty(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"version": 99, "posteriors": {"x": {}}}),
                 encoding="utf-8")
    assert autolearn.load_state(p) == autolearn.empty_state()


def test_save_then_load_roundtrip(tmp_path):
    p = tmp_path / "s.json"
    st = autolearn.empty_state()
    st["posteriors"]["fake-a/ma|cheap|plain"] = {"misses": 2, "clean": 5}
    autolearn.save_state(st, "2026-07-18T00:00:00+00:00", p)
    got = autolearn.load_state(p)
    assert got["posteriors"]["fake-a/ma|cheap|plain"]["misses"] == 2
    assert got["updated_at"] == "2026-07-18T00:00:00+00:00"
    assert not p.with_name(p.name + ".tmp").exists()   # atomic write cleaned up


def test_default_path_uses_state_path_seam(tmp_path):
    # conftest patched state_path() into tmp_path -- default-arg calls hit it.
    autolearn.save_state(autolearn.empty_state(), "2026-07-18T00:00:00+00:00")
    assert autolearn.load_state()["version"] == autolearn.STATE_VERSION


# --- buckets ----------------------------------------------------------------

def test_bucket_for_security_reasons():
    assert autolearn.bucket_for(("risky-content: eval",)) == "sec"
    assert autolearn.bucket_for(("security-path: src/auth.py",)) == "sec"
    assert autolearn.bucket_for(("novel-path: x", "big-diff")) == "plain"
    assert autolearn.bucket_for(()) == "plain"


def test_posterior_key():
    assert autolearn.posterior_key(CHEAP, "cheap", "sec") == "fake-a/ma|cheap|sec"


# --- uplift decision --------------------------------------------------------

def test_uplift_cold_start_serves_floor():
    """No data: floor q ~ Beta(1, 1+... wait, Beta(1, PRIOR_CLEAN)) has mean
    0.10 <= 0.15 -- the floor arm qualifies. THE load-bearing invariant:
    cold start == deterministic ladder."""
    st = autolearn.empty_state()
    rng = autolearn.decision_rng("item-1", st)
    picked = autolearn.uplift_pick(ARMS, 45, "plain", st, 0.15, rng)
    assert picked is not None
    arm, floor_q = picked
    assert arm == CHEAP
    assert 0.0 <= floor_q <= 1.0


def test_uplift_cold_start_is_deterministic_per_item_and_state():
    st = autolearn.empty_state()
    a1 = autolearn.uplift_pick(ARMS, 45, "plain", st,
                               0.15, autolearn.decision_rng("i", st))
    a2 = autolearn.uplift_pick(ARMS, 45, "plain", st,
                               0.15, autolearn.decision_rng("i", st))
    assert a1 == a2


def test_uplift_high_miss_floor_escalates():
    """Overwhelming miss evidence on the floor arm at (band, bucket) pushes
    q far above threshold -> a higher arm serves. misses=500 makes the
    Thompson sample > 0.15 with probability ~1 and the seeded rng makes the
    single outcome fully deterministic."""
    st = autolearn.empty_state()
    st["posteriors"]["fake-a/ma|cheap|plain"] = {"misses": 500, "clean": 0}
    rng = autolearn.decision_rng("item-1", st)
    arm, floor_q = autolearn.uplift_pick(ARMS, 45, "plain", st, 0.15, rng)
    assert arm.min_score > CHEAP.min_score
    assert floor_q > 0.15


def test_uplift_other_bucket_evidence_does_not_leak():
    st = autolearn.empty_state()
    st["posteriors"]["fake-a/ma|cheap|sec"] = {"misses": 500, "clean": 0}
    rng = autolearn.decision_rng("item-1", st)
    arm, _ = autolearn.uplift_pick(ARMS, 45, "plain", st, 0.15, rng)
    assert arm == CHEAP    # 'plain' bucket has no data -> prior -> floor


def test_uplift_top_arm_always_qualifies():
    st = autolearn.empty_state()
    for key in ("fake-a/ma|cheap|plain", "fake-c/mc|cheap|plain",
                "fake-b/mb|cheap|plain"):
        st["posteriors"][key] = {"misses": 500, "clean": 0}
    rng = autolearn.decision_rng("item-1", st)
    arm, _ = autolearn.uplift_pick(ARMS, 45, "plain", st, 0.15, rng)
    assert arm == FRONTIER   # ceiling serves even with bad numbers everywhere


def test_uplift_frontier_floor_serves_frontier():
    st = autolearn.empty_state()
    rng = autolearn.decision_rng("item-1", st)
    arm, floor_q = autolearn.uplift_pick(ARMS, 95, "plain", st, 0.15, rng)
    assert arm == FRONTIER and floor_q == 0.0


def test_uplift_empty_arms_returns_none():
    st = autolearn.empty_state()
    assert autolearn.uplift_pick([], 45, "plain", st, 0.15,
                                 autolearn.decision_rng("i", st)) is None


# --- cascade / audit predicates --------------------------------------------

def test_cascade_trigger_matrix():
    crit = [{"severity": "critical"}]
    high = [{"severity": "high"}]
    t = autolearn.cascade_trigger
    assert t(CHEAP, ARMS, crit, 0, False, 3) == "critical"
    assert t(CHEAP, ARMS, high, 3, False, 3) == "hallucination"
    assert t(CHEAP, ARMS, high, 2, True, 3) == "truncated"
    assert t(CHEAP, ARMS, high, 2, False, 3) is None
    assert t(FRONTIER, ARMS, crit, 9, True, 3) is None   # top tier never cascades


def test_next_arm_above():
    assert autolearn.next_arm_above(ARMS, CHEAP) == MID
    assert autolearn.next_arm_above(ARMS, MID) == FRONTIER
    assert autolearn.next_arm_above(ARMS, FRONTIER) is None


def test_audit_arm_highest_available():
    assert autolearn.audit_arm(ARMS, {"fake-a", "fake-b", "fake-c"}) == FRONTIER
    assert autolearn.audit_arm(ARMS, {"fake-a", "fake-c"}) == MID
    assert autolearn.audit_arm(ARMS, set()) is None


def test_should_audit_hash_sampling():
    # audit_every=1: every below-top item samples; top-tier service never does.
    assert autolearn.should_audit("any-id", CHEAP, ARMS, 1) is True
    assert autolearn.should_audit("any-id", FRONTIER, ARMS, 1) is False
    assert autolearn.should_audit("any-id", CHEAP, ARMS, 0) is False
    assert autolearn.should_audit("any-id", CHEAP, [], 1) is False
    # Deterministic: same id -> same answer; distribution: over 200 ids at
    # audit_every=8, roughly 1/8 sample (loose bounds, no flake).
    hits = sum(autolearn.should_audit(f"id-{i}", CHEAP, ARMS, 8)
               for i in range(200))
    assert 10 <= hits <= 45
    assert autolearn.should_audit("id-0", CHEAP, ARMS, 8) == \
        autolearn.should_audit("id-0", CHEAP, ARMS, 8)


# --- audit diff -------------------------------------------------------------

def _cand(owasp, file, line_content, severity):
    return {"owasp": owasp, "file": file, "line_content": line_content,
            "severity": severity}


def test_audit_diff_counts_new_and_missed_criticals():
    served = [_cand("a01", "src/x.py", "y = 1", "high")]
    audit = [_cand("a01", "src/x.py", "y = 1", "critical"),   # same fingerprint
             _cand("a03", "src/x.py", "z = 2", "critical"),   # new critical
             _cand("a05", "src/y.py", "w = 3", "high")]       # new non-critical
    new_n, missed = autolearn.audit_diff(served, audit)
    assert (new_n, missed) == (2, 1)


def test_audit_diff_malformed_candidate_skipped():
    new_n, missed = autolearn.audit_diff([], [{"severity": "critical"}])
    assert (new_n, missed) == (0, 0)
```

- [ ] **Step 3: Run to verify failure**

Run: `python -m pytest tests/unit/test_autolearn.py -x -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'aramid.autolearn'` (or ImportError from conftest).

- [ ] **Step 4: Implement `src/aramid/autolearn.py`:**

```python
"""autolearn -- the learned model-selection engine (spec
2026-07-18-aramid-autolearn-model-selection-design.md): feature bucketing,
Beta-posterior math, the escalate-only Thompson UPLIFT decision, cascade
trigger rules, audit sampling, the machine-global state file, and the
ledger->state rollup. Pure computation except the two explicit state I/O
functions; provider calls and drain wiring live in consumers.llm_review
and commands.drain.

Terminology: the learned tier-raise is an UPLIFT -- "escalation" already
means policy.escalate_degraded's gate-exit behavior and is never used for
arm selection.

Fail-open contract (spec section 11): consumers wrap every call here in
try/except; load_state additionally degrades any unreadable or
foreign-version state to empty_state(). Cold start == shipped deterministic
ladder: with no data the floor arm's sampled miss-probability is
Beta(1, PRIOR_CLEAN) with mean 1/(1+PRIOR_CLEAN) = 0.10, under the 0.15
default threshold, so the floor qualifies and no uplift happens.
"""
import hashlib
import json
import os
import random
from pathlib import Path

from aramid import review as review_mod
from aramid.models import EventType

STATE_VERSION = 1
# Trust-the-ladder prior (spec section 8.2): Beta(1, PRIOR_CLEAN) keeps the
# no-data mean at 0.10 <= the 0.15 default threshold -- absence of evidence
# reproduces the deterministic ladder exactly.
PRIOR_CLEAN = 9


# --- state ------------------------------------------------------------------

def state_path() -> Path:
    """Seam for tests -- monkeypatch this rather than touching the real
    ~/.aramid (mirrors spend.spend_path / registry.registry_path)."""
    return Path.home() / ".aramid" / "autolearn_state.json"


def empty_state() -> dict:
    return {"version": STATE_VERSION, "updated_at": "", "cursors": {},
            "posteriors": {},
            "shadow": {"decisions": 0, "would_uplift": 0},
            "audits": {"performed": 0, "missed_criticals": 0}}


def load_state(path: Path | None = None) -> dict:
    """Unreadable, malformed, or foreign-version state degrades to
    empty_state() -- cold start, never a crash (spec section 11)."""
    p = path if path is not None else state_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return empty_state()
    if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
        return empty_state()
    out = empty_state()
    for key, default in list(out.items()):
        val = data.get(key, default)
        out[key] = val if isinstance(val, type(default)) else default
    return out


def save_state(state: dict, now_iso: str, path: Path | None = None) -> None:
    """Atomic write (tmp + os.replace): a torn write can never corrupt the
    previous state (spec section 11)."""
    p = path if path is not None else state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {**state, "updated_at": now_iso}
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    os.replace(tmp, p)


# --- features ---------------------------------------------------------------

def bucket_for(reasons) -> str:
    """Coarse feature bucket (spec section 8.1): 'sec' iff any triage reason
    names a security signal, else 'plain'. Deliberately 2-valued -- ~18
    reviews/day cannot support finer cells."""
    for r in reasons:
        if "security-path" in r or "risky-content" in r:
            return "sec"
    return "plain"


def posterior_key(arm, band: str, bucket: str) -> str:
    return f"{arm.provider}/{arm.model}|{band}|{bucket}"


def _counts(state: dict, key: str) -> dict:
    rec = state.get("posteriors", {}).get(key)
    return rec if isinstance(rec, dict) else {}


# --- uplift decision --------------------------------------------------------

def decision_rng(item_id: str, state: dict) -> random.Random:
    """Deterministic per-(item, state-generation) RNG (spec section 8.2):
    reproducible in tests, varies across state updates in production."""
    seed = hashlib.sha256(
        f"{item_id}|{state.get('updated_at', '')}".encode()).hexdigest()
    return random.Random(int(seed, 16))


def uplift_pick(arms, score: int, bucket: str, state: dict,
                threshold: float, rng: random.Random):
    """Escalate-only Thompson decision (spec section 8.2). Walk arms from
    the deterministic floor upward; for each, sample its miss-probability
    q ~ Beta(1+misses, PRIOR_CLEAN+clean); serve the lowest arm with
    q <= threshold. The top arm always qualifies (it is the measuring
    ceiling). Returns (arm, floor_q) where floor_q is the q sampled for the
    floor arm -- the number that explains the decision -- or None when
    there are no arms."""
    tgt = review_mod.target_arm(arms, score)
    if tgt is None:
        return None
    band = tgt.tier
    ladder_up = [a for a in arms if a.min_score >= tgt.min_score]
    floor_q = None
    for a in ladder_up[:-1]:
        c = _counts(state, posterior_key(a, band, bucket))
        q = rng.betavariate(1 + int(c.get("misses", 0)),
                            PRIOR_CLEAN + int(c.get("clean", 0)))
        if floor_q is None:
            floor_q = q
        if q <= threshold:
            return a, floor_q
    return ladder_up[-1], (floor_q if floor_q is not None else 0.0)


def next_arm_above(arms, served_arm):
    """The next-higher tier for a cascade re-review, or None at the top."""
    for a in arms:
        if a.min_score > served_arm.min_score:
            return a
    return None


# --- audit sampling ---------------------------------------------------------

def audit_arm(arms, available: set[str]):
    """The audit reviewer (spec section 10): the highest-min_score available
    arm, or None when nothing is available."""
    avail = [a for a in arms if a.provider in available]
    return avail[-1] if avail else None


def should_audit(item_id: str, served_arm, arms, audit_every: int) -> bool:
    """Deterministic 1-in-N sampling (spec section 10): hash the item id --
    no RNG state, reproducible in tests. Only items served BELOW the top
    arm are auditable (self-audit measures nothing)."""
    if audit_every <= 0 or not arms:
        return False
    if served_arm.min_score >= arms[-1].min_score:
        return False
    digest = int(hashlib.sha256(item_id.encode()).hexdigest(), 16)
    return digest % audit_every == 0


def _fid(cand: dict) -> str | None:
    try:
        return review_mod.llm_fingerprint(
            f"llm/{cand['owasp']}", cand["file"], cand["line_content"])
    except (KeyError, TypeError):
        return None


def audit_diff(served_verified: list, audit_verified: list) -> tuple[int, int]:
    """(new_findings, missed_criticals): audit candidates whose fingerprint
    the served review did not produce (spec section 10). Malformed
    candidates are skipped, never counted."""
    served = {f for f in (_fid(c) for c in served_verified) if f}
    new_findings = 0
    missed_criticals = 0
    for c in audit_verified:
        fid = _fid(c)
        if fid is None or fid in served:
            continue
        new_findings += 1
        if c.get("severity") == "critical":
            missed_criticals += 1
    return new_findings, missed_criticals


# --- cascade ----------------------------------------------------------------

def cascade_trigger(served_arm, arms, verified: list, rejected: int,
                    truncated: bool, halluc_min: int) -> str | None:
    """Deterministic danger signs after the served review (spec section 9).
    Returns 'critical' | 'hallucination' | 'truncated' or None. Never fires
    for a top-tier review."""
    if not arms or served_arm.min_score >= arms[-1].min_score:
        return None
    if any(c.get("severity") == "critical" for c in verified):
        return "critical"
    if rejected >= halluc_min:
        return "hallucination"
    if truncated:
        return "truncated"
    return None
```

(The `EventType` import is used by Task 2's `rollup`; leaving it now avoids a
second import churn — ruff will not flag it once Task 2 lands, but if the
Task 1 lint run complains, add `# noqa: F401` and remove it in Task 2.)

- [ ] **Step 5: Run to verify pass**

Run: `python -m pytest tests/unit/test_autolearn.py -q`
Expected: all PASS.

- [ ] **Step 6: Regression check** — the new root conftest must not disturb the existing suite:

Run: `python -m pytest tests/unit/test_llm_consumer.py tests/unit/test_arm_selection.py -q`
Expected: all PASS, unchanged.

- [ ] **Step 7: Commit**

```bash
git add src/aramid/autolearn.py tests/conftest.py tests/unit/test_autolearn.py
git commit -m "feat(autolearn): core policy module -- state serde, buckets, Thompson uplift, cascade/audit predicates"
```

---

### Task 2: `autolearn.rollup` — ledger events → posterior counts

**Files:**
- Modify: `src/aramid/autolearn.py` (append at end)
- Test: `tests/unit/test_autolearn_rollup.py`

**Interfaces:**
- Consumes: `aramid.models.Event`/`EventType`; the `selection` payload schema produced by Task 6 (`{"target_tier", "bucket", "served": {"provider","model",...}, "uplift": {"mode","pick",...}, "audit": {"performed","missed_criticals",...} | None, "refutes": [{"outcome"...}], "hallucination_rejected": int, "malformed"?: bool}`).
- Produces: `rollup(state: dict, events: list, repo_key: str) -> dict` — pure, returns a NEW state; cursor = event COUNT per repo_key (append-only ledger ⇒ count-based cursor is stable; a shrunken list resets to 0).

- [ ] **Step 1: Write the failing tests** — `tests/unit/test_autolearn_rollup.py`:

```python
"""rollup: fold CONSUMER_RUN_FINISHED selection payloads (and llm finding
overrides) into posterior counts. Pure -- events are built in-memory."""
from aramid import autolearn
from aramid.models import Event, EventType

AT = "2026-07-18T00:00:00+00:00"
KEY = "fake-a/ma|cheap|plain"


def _sel(**over):
    base = {"target_tier": "cheap", "bucket": "plain",
            "served": {"tier": "cheap", "provider": "fake-a", "model": "ma",
                       "effort": ""},
            "attempts": [], "uplift": {"mode": "shadow", "pick": "cheap",
                                       "applied": False, "sampled_q": 0.1},
            "cascade": {"triggered": False, "trigger": None, "applied": False},
            "audit": None, "refutes": [], "hallucination_rejected": 0,
            "tokens": {"in": 1, "out": 1}}
    base.update(over)
    return base


def _run_ev(run_id, sel):
    return Event(EventType.CONSUMER_RUN_FINISHED, run_id, AT,
                 payload={"consumer": "llm-review", "item_id": "q1",
                          "state": "ok", "duration_s": 1.0, "cost": 0.0,
                          "finding_count": 0, "note": "x", "selection": sel})


def test_rollup_clean_audit_counts_clean():
    ev = [_run_ev("r1", _sel(audit={"performed": True, "tier": "frontier",
                                    "new_findings": 0, "missed_criticals": 0}))]
    st = autolearn.rollup(autolearn.empty_state(), ev, "repo1")
    assert st["posteriors"][KEY]["clean"] == 1
    assert st["posteriors"][KEY]["misses"] == 0
    assert st["audits"] == {"performed": 1, "missed_criticals": 0}
    assert st["cursors"]["repo1"] == 1


def test_rollup_missed_critical_counts_misses():
    ev = [_run_ev("r1", _sel(audit={"performed": True, "tier": "frontier",
                                    "new_findings": 2, "missed_criticals": 2}))]
    st = autolearn.rollup(autolearn.empty_state(), ev, "repo1")
    assert st["posteriors"][KEY]["misses"] == 2
    assert st["posteriors"][KEY]["clean"] == 0
    assert st["audits"] == {"performed": 1, "missed_criticals": 2}


def test_rollup_secondary_counters_and_shadow():
    sel = _sel(hallucination_rejected=3,
               refutes=[{"refuter_provider": "fake-b", "refuter_tier": "frontier",
                         "outcome": "refuted", "latency_s": 1.0},
                        {"refuter_provider": "fake-b", "refuter_tier": "frontier",
                         "outcome": "survived", "latency_s": 1.0}],
               uplift={"mode": "shadow", "pick": "frontier", "applied": False,
                       "sampled_q": 0.4})
    st = autolearn.rollup(autolearn.empty_state(), [_run_ev("r1", sel)], "repo1")
    c = st["posteriors"][KEY]
    assert c["halluc"] == 3 and c["refuted"] == 1 and c["survived"] == 1
    assert st["shadow"] == {"decisions": 1, "would_uplift": 1}


def test_rollup_shadow_agree_not_would_uplift():
    st = autolearn.rollup(autolearn.empty_state(),
                          [_run_ev("r1", _sel())], "repo1")
    assert st["shadow"] == {"decisions": 1, "would_uplift": 0}


def test_rollup_malformed_counts():
    st = autolearn.rollup(autolearn.empty_state(),
                          [_run_ev("r1", _sel(malformed=True))], "repo1")
    assert st["posteriors"][KEY]["malformed"] == 1


def test_rollup_override_joins_via_run_id():
    detect = Event(EventType.FINDING_DETECTED, "r1", AT, finding_id="f1",
                   payload={"source": "llm", "tool": "llm-review"})
    override = Event(EventType.FINDING_OVERRIDDEN, "other-run", AT,
                     finding_id="f1", payload={"reason": "fp"})
    st = autolearn.rollup(autolearn.empty_state(),
                          [_run_ev("r1", _sel()), detect, override], "repo1")
    assert st["posteriors"][KEY]["overridden"] == 1


def test_rollup_cursor_makes_replay_idempotent():
    ev = [_run_ev("r1", _sel(audit={"performed": True, "tier": "frontier",
                                    "new_findings": 0, "missed_criticals": 0}))]
    st1 = autolearn.rollup(autolearn.empty_state(), ev, "repo1")
    st2 = autolearn.rollup(st1, ev, "repo1")          # nothing new
    assert st2["posteriors"][KEY]["clean"] == 1
    assert st2["audits"]["performed"] == 1


def test_rollup_shrunken_ledger_resets_cursor():
    st = autolearn.empty_state()
    st["cursors"]["repo1"] = 99
    got = autolearn.rollup(st, [_run_ev("r1", _sel())], "repo1")
    assert got["shadow"]["decisions"] == 1      # replayed from 0
    assert got["cursors"]["repo1"] == 1


def test_rollup_ignores_events_without_selection():
    ev = [Event(EventType.CONSUMER_RUN_FINISHED, "r1", AT,
                payload={"consumer": "regression-pack", "note": "x"})]
    st = autolearn.rollup(autolearn.empty_state(), ev, "repo1")
    assert st["posteriors"] == {} and st["cursors"]["repo1"] == 1


def test_rollup_does_not_mutate_input_state():
    base = autolearn.empty_state()
    autolearn.rollup(base, [_run_ev("r1", _sel())], "repo1")
    assert base == autolearn.empty_state()
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/unit/test_autolearn_rollup.py -x -q`
Expected: FAIL with `AttributeError: ... no attribute 'rollup'`.

- [ ] **Step 3: Append `rollup` to `src/aramid/autolearn.py`:**

```python
# --- reward rollup ----------------------------------------------------------

def rollup(state: dict, events: list, repo_key: str) -> dict:
    """Fold ledger events past this repo's cursor into posterior counts
    (spec section 8.3). Pure: returns a NEW state dict; the caller saves.
    The cursor is an event COUNT (the ledger is append-only and
    seq-ordered), so replaying the same list twice is a no-op; a shorter
    list than the cursor (rebuilt/compacted ledger) restarts from 0.

    Primary reward: audit outcomes -> misses/clean on the SERVED arm's
    (band, bucket) cell. Secondary counters (halluc/malformed/refuted/
    survived/overridden) are recorded for reporting but NOT read by
    uplift_pick (spec section 8.3)."""
    out = json.loads(json.dumps(state))     # deep copy; state is JSON-shaped
    cursor = int(out.get("cursors", {}).get(repo_key, 0))
    if cursor > len(events):
        cursor = 0

    # Join maps from the FULL stream (a finding's detect event may precede
    # the cursor): llm finding -> its drain run_id -> the served-arm cell.
    run_key: dict[str, str] = {}
    fid_run: dict[str, str] = {}
    for e in events:
        if e.type is EventType.CONSUMER_RUN_FINISHED:
            sel = e.payload.get("selection")
            if isinstance(sel, dict):
                served = sel.get("served") or {}
                band, bucket = sel.get("target_tier"), sel.get("bucket")
                if served.get("provider") and band and bucket:
                    run_key[e.run_id] = (f"{served['provider']}/"
                                         f"{served.get('model', '')}"
                                         f"|{band}|{bucket}")
        elif (e.type is EventType.FINDING_DETECTED
              and e.payload.get("source") == "llm" and e.finding_id):
            fid_run[e.finding_id] = e.run_id

    posts = out.setdefault("posteriors", {})

    def bump(key: str | None, field: str, n: int = 1) -> None:
        if not key or n <= 0:
            return
        rec = posts.setdefault(key, {"misses": 0, "clean": 0, "halluc": 0,
                                     "malformed": 0, "refuted": 0,
                                     "survived": 0, "overridden": 0})
        rec[field] = int(rec.get(field, 0)) + n

    for e in events[cursor:]:
        if e.type is EventType.CONSUMER_RUN_FINISHED:
            sel = e.payload.get("selection")
            if not isinstance(sel, dict):
                continue
            key = run_key.get(e.run_id)
            audit = sel.get("audit")
            if isinstance(audit, dict) and audit.get("performed"):
                out["audits"]["performed"] += 1
                missed = int(audit.get("missed_criticals", 0))
                out["audits"]["missed_criticals"] += missed
                if missed:
                    bump(key, "misses", missed)
                else:
                    bump(key, "clean")
            bump(key, "halluc", int(sel.get("hallucination_rejected", 0)))
            if sel.get("malformed"):
                bump(key, "malformed")
            for r in sel.get("refutes") or []:
                if not isinstance(r, dict):
                    continue
                if r.get("outcome") == "refuted":
                    bump(key, "refuted")
                elif r.get("outcome") == "survived":
                    bump(key, "survived")
            up = sel.get("uplift")
            if isinstance(up, dict) and up.get("mode") == "shadow":
                out["shadow"]["decisions"] += 1
                if up.get("pick") and up.get("pick") != sel.get("target_tier"):
                    out["shadow"]["would_uplift"] += 1
        elif e.type is EventType.FINDING_OVERRIDDEN and e.finding_id in fid_run:
            bump(run_key.get(fid_run[e.finding_id]), "overridden")

    out.setdefault("cursors", {})[repo_key] = len(events)
    return out
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/unit/test_autolearn_rollup.py tests/unit/test_autolearn.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/autolearn.py tests/unit/test_autolearn_rollup.py
git commit -m "feat(autolearn): ledger->posterior rollup with count-based cursors"
```

---

### Task 3: structured `refuted` flag end-to-end

**Files:**
- Modify: `src/aramid/models.py` (Finding)
- Modify: `src/aramid/normalizer.py` (RawFinding + normalize)
- Modify: `src/aramid/ledger.py` (`_detect_payload`)
- Modify: `src/aramid/review.py` (`apply_refute` — the SOLE permitted block-path edit)
- Modify: `src/aramid/consumers/llm_review.py` (one kwarg in the `RawFinding(...)` construction)
- Test: `tests/unit/test_review_refute.py` (append), `tests/unit/test_ledger_events.py` (append)

**Interfaces:**
- Produces: `Finding.refuted: bool = False`, `RawFinding.refuted: bool = False`, `_detect_payload` carries `"refuted"`, `apply_refute` sets `out["refuted"] = True` on the refuted branch only.
- **Block-path rule:** in `apply_refute` and the consumer, `confirmed` handling stays byte-identical; the additions are strictly the marker and its passthrough.

- [ ] **Step 1: Write the failing tests.** Append to `tests/unit/test_review_refute.py`:

```python
def test_apply_refute_sets_refuted_marker_only_on_refuted_branch():
    """Auto-learn telemetry marker (autolearn spec section 6): structured
    refute outcome. The gate reads `confirmed`, never this."""
    refuted = review.apply_refute({"severity": "critical", "explanation": "e"},
                                  True, "nope")
    assert refuted["refuted"] is True
    assert refuted["confirmed"] is False and refuted["severity"] == "high"
    survived = review.apply_refute({"severity": "critical", "explanation": "e"},
                                   False, "ok")
    assert "refuted" not in survived
    assert survived["confirmed"] is True
```

(Match the file's existing import name for the module under test — it imports `from aramid import review`.)

Append to `tests/unit/test_ledger_events.py`:

```python
def test_detect_payload_carries_refuted_flag():
    from aramid.ledger import _detect_payload
    from aramid.models import Finding, Gate, Severity, Source, Verdict
    f = Finding(id="x", tool="llm-review", rule="llm/a01", severity_raw="high",
                severity=Severity.HIGH, verdict=Verdict.WARN, file="a.py",
                line=1, message="m", evidence="e", gate=Gate.ALL,
                source=Source.LLM, refuted=True)
    assert _detect_payload(f)["refuted"] is True
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/unit/test_review_refute.py tests/unit/test_ledger_events.py -q`
Expected: new tests FAIL (`KeyError: 'refuted'` / unexpected kwarg).

- [ ] **Step 3: Implement.** In `src/aramid/models.py`, after the `confirmed` field of `Finding`:

```python
    # Auto-learn (autolearn spec section 6): structured refute outcome --
    # True iff apply_refute demoted this finding (critical -> high). The
    # gate reads `confirmed`, never this.
    refuted: bool = False
```

In `src/aramid/normalizer.py`, add to `RawFinding` after `confirmed: bool = False`:

```python
    refuted: bool = False
```

and in `normalize(...)`'s `Finding(` construction change the final line to:

```python
            source=raw.source, confirmed=raw.confirmed, refuted=raw.refuted))
```

In `src/aramid/ledger.py`, `_detect_payload` return gains one key:

```python
            "source": str(f.source), "confirmed": f.confirmed,
            "refuted": f.refuted}
```

In `src/aramid/review.py`, `apply_refute`'s refuted branch gains ONE line (everything else byte-identical):

```python
    if refuted:
        out["severity"] = "high"
        out["explanation"] = f"{out.get('explanation', '')} [refuted: {reason}]".strip()
        out["confirmed"] = False
        out["refuted"] = True   # autolearn telemetry marker; the gate reads `confirmed`, never this
```

In `src/aramid/consumers/llm_review.py`, the `RawFinding(...)` list-comprehension gains one kwarg after `confirmed=`:

```python
        confirmed=bool(cand.get("confirmed", False)),
        refuted=bool(cand.get("refuted", False)),
```

- [ ] **Step 4: Run to verify pass + block-path regression**

Run: `python -m pytest tests/unit/test_review_refute.py tests/unit/test_ledger_events.py tests/unit/test_llm_consumer.py tests/unit/test_llm_gate.py tests/unit/test_normalizer.py -q`
Expected: all PASS (existing tests unchanged).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/models.py src/aramid/normalizer.py src/aramid/ledger.py src/aramid/review.py src/aramid/consumers/llm_review.py tests/unit/test_review_refute.py tests/unit/test_ledger_events.py
git commit -m "feat(autolearn): structured refuted flag through apply_refute -> RawFinding -> ledger payload"
```

---

### Task 4: `ConsumerResult.extra` + drain payload merge

**Files:**
- Modify: `src/aramid/consumers/base.py`
- Modify: `src/aramid/commands/drain.py` (`_consume_item` payload construction only)
- Test: `tests/unit/test_consumers_base.py` (append), `tests/integration/test_drain.py` (append)

**Interfaces:**
- Produces: `ConsumerResult.extra: dict = field(default_factory=dict)`; drain merges `extra` into the `CONSUMER_RUN_FINISHED` payload with `setdefault` (core keys always win).

- [ ] **Step 1: Write the failing tests.** Append to `tests/unit/test_consumers_base.py`:

```python
def test_consumer_result_extra_defaults_empty():
    from aramid.consumers.base import ConsumerResult
    r = ConsumerResult(consumer="x", state="ok")
    assert r.extra == {}
```

Append to `tests/integration/test_drain.py` (follow the file's existing imports; it already imports `drain` internals — add what is missing at top: `from aramid.consumers.base import ConsumerResult` and `from types import SimpleNamespace` if absent):

```python
def test_consumer_extra_merged_into_event_payload(tmp_path, monkeypatch):
    """ConsumerResult.extra rides into the CONSUMER_RUN_FINISHED payload;
    core keys are never overridden by extra."""
    from aramid.commands import drain as drain_mod
    from aramid.ledger import Ledger
    from aramid.models import EventType
    from aramid.queue import QueueItem

    led = Ledger(tmp_path / "l.db")
    fake = SimpleNamespace(consume=lambda item, ctx: ConsumerResult(
        consumer="fake", state="ok",
        extra={"selection": {"served": {"provider": "p"}},
               "note": "MUST NOT WIN"}))
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"fake": fake})
    item = QueueItem(id="q1", base=None, head="h", score=50, reasons=(),
                     state="queued", created_at="2026-07-18T00:00:00+00:00",
                     updated_at="2026-07-18T00:00:00+00:00")
    try:
        ok = drain_mod._consume_item(tmp_path, SimpleNamespace(llm={}), led,
                                     item, lambda: "2026-07-18T00:00:00+00:00")
        assert ok is True
        evs = [e for e in led.events()
               if e.type is EventType.CONSUMER_RUN_FINISHED]
    finally:
        led.close()
    assert evs[0].payload["selection"] == {"served": {"provider": "p"}}
    assert evs[0].payload["note"] == ""          # core key wins over extra
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/unit/test_consumers_base.py tests/integration/test_drain.py::test_consumer_extra_merged_into_event_payload -q`
Expected: FAIL (`extra` attribute missing / payload missing `selection`).

- [ ] **Step 3: Implement.** In `src/aramid/consumers/base.py`, add to `ConsumerResult` after `note: str = ""`:

```python
    # Auto-learn (autolearn spec section 6): structured payload merged into
    # the CONSUMER_RUN_FINISHED event by the drain (setdefault -- core keys
    # always win). llm_review puts its `selection` telemetry dict here.
    extra: dict = field(default_factory=dict)
```

In `src/aramid/commands/drain.py` `_consume_item`, replace the `ledger.append(Event(...))` call with:

```python
        payload = {"consumer": name, "item_id": item.id,
                   "state": result.state,
                   "duration_s": round(duration, 3),
                   "cost": result.cost,
                   "finding_count": len(findings),
                   "note": result.note}
        for key, value in (result.extra or {}).items():
            payload.setdefault(key, value)
        ledger.append(Event(EventType.CONSUMER_RUN_FINISHED, run_id, clock(),
                            payload=payload))
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/unit/test_consumers_base.py tests/integration/test_drain.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/consumers/base.py src/aramid/commands/drain.py tests/unit/test_consumers_base.py tests/integration/test_drain.py
git commit -m "feat(autolearn): ConsumerResult.extra merged into consumer-run event payloads"
```

---

### Task 5: `[llm.autolearn]` config defaults (+ stale cheap-arm comment fix)

**Files:**
- Modify: `src/aramid/data/defaults.toml`
- Test: `tests/unit/test_config.py` (append one test; update two stale comments)

- [ ] **Step 1: Write the failing test.** Append to `tests/unit/test_config.py`:

```python
def test_autolearn_defaults_present(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: _no_user_config(tmp_path))
    cfg = config.load_config(tmp_path)
    al = cfg.llm["autolearn"]
    assert al["enabled"] is True
    assert al["armed"] is False
    assert al["uplift_threshold"] == 0.15
    assert al["audit_every"] == 8
    assert al["max_audits_per_drain"] == 1
    assert al["cascade_hallucination_min"] == 3


def test_autolearn_repo_override_deep_merges(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: _no_user_config(tmp_path))
    (tmp_path / "aramid.toml").write_text(
        "[llm.autolearn]\narmed = true\n", encoding="utf-8")
    cfg = config.load_config(tmp_path)
    assert cfg.llm["autolearn"]["armed"] is True
    assert cfg.llm["autolearn"]["enabled"] is True   # sibling default survives
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/unit/test_config.py -q -k autolearn`
Expected: FAIL with `KeyError: 'autolearn'`.

- [ ] **Step 3: Implement.** In `src/aramid/data/defaults.toml`, append after the last `[[llm.ladder]]` table:

```toml
# --- Auto-learn (autolearn spec sections 7-10): learned UPLIFT over the ladder ---
# Shadow-first, bake-then-arm: with the defaults below the engine records
# telemetry, computes shadow decisions, and runs audit double-reviews, but
# NEVER changes which arm serves. `aramid arm --autolearn` flips `armed`
# per-repo. Escalate-only either way: the ladder tier is a floor.
[llm.autolearn]
enabled = true
armed = false
# Serve the lowest arm whose Thompson-sampled miss probability is <= this.
# No-data prior Beta(1, 9) has mean 0.10 <= 0.15, so cold start == ladder.
uplift_threshold = 0.15
# Audit 1 in N below-frontier reviews with a frontier double-review
# (deterministic hash of the item id) -- the miss-rate measurement, active
# in shadow too; costs flat-rate quota only.
audit_every = 8
max_audits_per_drain = 1
# Cascade re-review (armed only) when the served review shows danger signs:
# a verified CRITICAL, hallucination_rejected >= this, or a truncated packet.
cascade_hallucination_min = 3
```

Also fix the now-stale ladder comments (the cheap arm was live-verified 2026-07-14 after the key was set). Replace these two comment lines above `[[llm.ladder]]`:

```toml
# cheap/ollama effort stays "" -- no OLLAMA_API_KEY was available to verify, and
# `think` is structural; unset is the fail-safe (a wrong value can't kill a tier).
```

with:

```toml
# cheap/ollama effort stays "" DELIBERATELY: any non-empty effort maps to
# `think: true` (slower reasoning mode) -- wrong for the high-volume cheap
# tier. The cheap arm itself was live-verified 2026-07-14 (deepseek-v4-flash,
# 200 OK end-to-end).
```

and change the cheap-arm model line comment:

```toml
model = "deepseek-v4-flash"   # live-verified 2026-07-14; tune per your account
```

In `tests/unit/test_config.py`, update the stale comment inside `test_llm_defaults_present` (assertions unchanged):

```python
    # effort: all three tiers live-verified 2026-07-14; cheap/ollama stays ""
    # deliberately (non-empty effort => think:true, wrong for the cheap tier).
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/unit/test_config.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/data/defaults.toml tests/unit/test_config.py
git commit -m "feat(autolearn): [llm.autolearn] defaults; un-stale the live-verified cheap-arm comments"
```

---

### Task 6: consumer telemetry + shadow policy (NO behavior change)

**Files:**
- Modify: `src/aramid/consumers/llm_review.py`
- Test: `tests/unit/test_llm_consumer.py` (append new tests ONLY — existing tests must pass unchanged)

**Interfaces:**
- Consumes: everything Task 1 produced; `cfg.llm["autolearn"]` (Task 5).
- Produces: `ConsumerResult.extra = {"selection": {...}}` with the spec §6 schema (`target_tier`, `bucket`, `served`, `attempts`, `uplift`, `cascade` placeholder, `audit: None`, `refutes`, `hallucination_rejected`, `tokens`); `_call` now returns `(ProviderResponse, latency_s)`; module global `_audits_used` reset by `begin_drain()`; module helper `_selection(...)`. Tasks 7–9 extend exactly these.
- **Behavior invariant:** with `armed=false` (default), the served arm, note string, findings, and all return states are byte-identical to before this task.

- [ ] **Step 1: Write the failing tests.** Append to `tests/unit/test_llm_consumer.py`:

```python
# --- auto-learn Task 6: selection telemetry + shadow ------------------------

def test_selection_payload_recorded_shadow(tmp_path, monkeypatch):
    """extra['selection'] carries served arm, bucket, attempts, and a shadow
    uplift record; shadow never changes the served arm."""
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"))])
    b = _Fake("fake-b", [])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45),
                                 _ctx_ladder(r, led, _LADDER_AB))
    finally:
        led.close()
    sel = got.extra["selection"]
    assert sel["served"] == {"tier": "cheap", "provider": "fake-a",
                             "model": "ma", "effort": ""}
    assert sel["target_tier"] == "cheap" and sel["bucket"] == "plain"
    assert sel["uplift"]["mode"] == "shadow"
    assert sel["uplift"]["applied"] is False
    assert sel["audit"] is None
    assert sel["cascade"] == {"triggered": False, "trigger": None,
                              "applied": False}
    assert sel["attempts"][0]["provider"] == "fake-a"
    assert sel["attempts"][0]["error"] == ""
    assert isinstance(sel["attempts"][0]["latency_s"], float)
    assert sel["tokens"] == {"in": 0, "out": 0}


def test_attempts_record_fallthrough_errors(tmp_path, monkeypatch):
    """Failed arms finally leave a trace (autolearn spec section 6)."""
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"))])
    b = _Fake("fake-b", [ProviderResponse(text="",
                                          error=providers_base.ERR_QUOTA)])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 90),
                                 _ctx_ladder(r, led, _LADDER_AB))
    finally:
        led.close()
    sel = got.extra["selection"]
    assert [(x["provider"], x["error"]) for x in sel["attempts"]] == \
        [("fake-b", "quota"), ("fake-a", "")]
    assert sel["served"]["provider"] == "fake-a"


def test_refute_outcome_recorded(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("critical"))])
    b = _Fake("fake-b", [ProviderResponse(text=json.dumps(
        {"refuted": False, "reason": "verified"}))])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45),
                                 _ctx_ladder(r, led, _LADDER_AB))
    finally:
        led.close()
    (ref,) = got.extra["selection"]["refutes"]
    assert ref["refuter_provider"] == "fake-b"
    assert ref["refuter_tier"] == "frontier"
    assert ref["outcome"] == "survived"


def test_refute_clipped_outcome_unavailable(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("critical"))])
    b = _Fake("fake-b", [])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r, cfg=_cfg(ladder=_LADDER_AB,
                                        max_refutes_per_drain=0),
                       ledger=led, clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45), ctx)
    finally:
        led.close()
    (ref,) = got.extra["selection"]["refutes"]
    assert ref["outcome"] == "unavailable" and ref["refuter_provider"] is None


def test_malformed_response_selection_flagged(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text="not json at all {{{")])
    b = _Fake("fake-b", [])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45),
                                 _ctx_ladder(r, led, _LADDER_AB))
    finally:
        led.close()
    assert got.state == "degraded"
    sel = got.extra["selection"]
    assert sel["malformed"] is True
    assert sel["served"]["provider"] == "fake-a"


def test_sec_bucket_from_reasons(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"))])
    b = _Fake("fake-b", [])
    _wire(monkeypatch, a, b)
    item = QueueItem(id="q1", base=base_sha, head=head_sha, score=45,
                     reasons=("risky-content: eval",), state="queued",
                     created_at=NOW.isoformat(), updated_at=NOW.isoformat())
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(item, _ctx_ladder(r, led, _LADDER_AB))
    finally:
        led.close()
    assert got.extra["selection"]["bucket"] == "sec"


def test_policy_error_fails_open_to_ladder(tmp_path, monkeypatch):
    """Any autolearn exception -> deterministic ladder, mode='error'
    (spec section 11)."""
    from aramid import autolearn
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"))])
    b = _Fake("fake-b", [])
    _wire(monkeypatch, a, b)
    monkeypatch.setattr(autolearn, "load_state",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError()))
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45),
                                 _ctx_ladder(r, led, _LADDER_AB))
    finally:
        led.close()
    assert got.state == "ok"
    assert "tier=cheap" in got.note
    assert got.extra["selection"]["uplift"]["mode"] == "error"


def test_autolearn_disabled_mode_off(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"))])
    b = _Fake("fake-b", [])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r, cfg=_cfg(ladder=_LADDER_AB,
                                        autolearn={"enabled": False}),
                       ledger=led, clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45), ctx)
    finally:
        led.close()
    assert got.extra["selection"]["uplift"]["mode"] == "off"
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/unit/test_llm_consumer.py -q -k "selection or attempts_record or refute_outcome or refute_clipped or malformed_response_selection or sec_bucket or policy_error or mode_off"`
Expected: new tests FAIL (`AttributeError: 'ConsumerResult' object has no attribute 'extra'` is NOT possible after Task 4 — they fail on missing `selection` key).

- [ ] **Step 3: Implement in `src/aramid/consumers/llm_review.py`.**

3a. Imports and module state — add `import time` after `import sys`; add `from aramid import autolearn` after `from aramid import review`; add the third counter:

```python
_reviews_used = 0
_refutes_used = 0
_audits_used = 0


def begin_drain() -> None:
    """Reset per-drain state. Called by cmd_drain once per invocation."""
    global _reviews_used, _refutes_used, _audits_used
    _reviews_used = 0
    _refutes_used = 0
    _audits_used = 0
```

3b. `_call` returns latency (update BOTH existing call sites in this step):

```python
def _call(module, prompt: str, model: str, cfg, timeout_s: float, *, effort: str = ""):
    """Returns (ProviderResponse, latency_s)."""
    kwargs = {"effort": effort}
    if module.NAME == "openrouter":
        kwargs["cfg"] = cfg
    started = time.monotonic()
    try:
        resp = module.review(prompt, model, timeout_s, **kwargs)
    except Exception:
        resp = providers_base.ProviderResponse(text="", error=providers_base.ERR_ERROR)
    return resp, round(time.monotonic() - started, 3)
```

3c. Add the module-level selection builder (before `consume`):

```python
def _selection(tgt, reviewer_arm, bucket, attempts, uplift_info, cascade_info,
               audit_info, refute_infos, rejected, tokens_in, tokens_out):
    """The structured telemetry payload (autolearn spec section 6), merged
    into the CONSUMER_RUN_FINISHED event via ConsumerResult.extra.
    `bucket` is required by the rollup's posterior key; `target_tier` doubles
    as the band."""
    return {
        "target_tier": tgt.tier if tgt is not None else None,
        "bucket": bucket,
        "served": {"tier": reviewer_arm.tier, "provider": reviewer_arm.provider,
                   "model": reviewer_arm.model, "effort": reviewer_arm.effort},
        "attempts": attempts,
        "uplift": uplift_info,
        "cascade": cascade_info,
        "audit": audit_info,
        "refutes": refute_infos,
        "hallucination_rejected": rejected,
        "tokens": {"in": tokens_in, "out": tokens_out},
    }
```

3d. In `consume()`: change the `global` statement to `global _reviews_used, _refutes_used, _audits_used`. Then replace the block from `arms = review.build_arms(cfg)` through the `for arm in order:` loop with (note `tgt` moves UP and the old `tgt = review.target_arm(arms, item.score)` line after `prompt = ...` is DELETED):

```python
    arms = review.build_arms(cfg)
    avail = {m.NAME for m in providers_base.chain(cfg)}

    # --- auto-learn uplift consult (autolearn spec section 8.2). Shadow
    # records the pick without changing eff_score; armed application is
    # Task 7. Fail-open: any policy failure -> deterministic ladder,
    # mode="error" on record, never a crashed drain (spec section 11).
    al_cfg = cfg.llm.get("autolearn", {})
    if not isinstance(al_cfg, dict):
        al_cfg = {}
    al_enabled = bool(al_cfg.get("enabled", True))
    al_armed = bool(al_cfg.get("armed", False))
    tgt = review.target_arm(arms, item.score)
    bucket = autolearn.bucket_for(item.reasons)
    uplift_info = {"mode": "off", "pick": None, "applied": False,
                   "sampled_q": None}
    eff_score = item.score
    if al_enabled and tgt is not None:
        try:
            st = autolearn.load_state()
            picked = autolearn.uplift_pick(
                arms, item.score, bucket, st,
                float(al_cfg.get("uplift_threshold", 0.15)),
                autolearn.decision_rng(item.id, st))
            if picked is not None:
                arm_pick, floor_q = picked
                uplift_info = {"mode": "armed" if al_armed else "shadow",
                               "pick": arm_pick.tier, "applied": False,
                               "sampled_q": round(floor_q, 4)}
        except Exception:
            uplift_info = {"mode": "error", "pick": None, "applied": False,
                           "sampled_q": None}

    order = review.reviewer_order(arms, eff_score, avail)
    if not order:
        if not _any_installed(cfg):
            return ConsumerResult(consumer=NAME, state="ok",
                                  note="llm skipped: no providers installed")
        return ConsumerResult(consumer=NAME, state="degraded",
                              note="all providers unavailable")

    timeout_s = float(cfg.llm.get("call_timeout_s", 240))
    prompt = review.render_review_prompt(packet)
    resp, reviewer_arm = None, None
    attempts = []
    for arm in order:                       # target tier first, then degrade/fallthrough
        r, lat = _call(providers_base.PROVIDERS[arm.provider], prompt, arm.model,
                       cfg, timeout_s, effort=arm.effort)
        attempts.append({"tier": arm.tier, "provider": arm.provider,
                         "model": arm.model, "error": r.error,
                         "latency_s": lat})
        if r.error in ("", providers_base.ERR_MALFORMED):
            resp, reviewer_arm = r, arm
            break
        # unavailable/quota/timeout/error: fall through to the next provider
```

3e. Placeholders for later tasks — right after `verified, rejected = ...`, insert:

```python
    cascade_info = {"triggered": False, "trigger": None, "applied": False}
    audit_info = None
```

(Tasks 8 and 9 replace these two lines with the real cascade/audit blocks.)

3f. Malformed-response exit gains the payload (replace the existing `if candidates is None:` return):

```python
    if candidates is None:
        sel = _selection(tgt, reviewer_arm, bucket, attempts, uplift_info,
                         {"triggered": False, "trigger": None, "applied": False},
                         None, [], 0, tokens_in, tokens_out)
        sel["malformed"] = True
        return ConsumerResult(consumer=NAME, state="degraded", cost=cost,
                              note=f"malformed response from {provider.NAME}",
                              extra={"selection": sel})
```

3g. Refute loop telemetry. Initialize `refute_infos = []` next to `refutes = 0`. In the clipped branch, add ONE append (before the `cand = review.apply_refute(...)` line, which stays byte-identical):

```python
                refute_infos.append({"refuter_provider": None,
                                     "refuter_tier": None,
                                     "outcome": "unavailable",
                                     "latency_s": 0.0})
```

In the live-refute branch, adapt the `_call` unpack and record the outcome BEFORE the fail-safe default overwrites `parsed` (the `apply_refute` call and the fail-safe line stay byte-identical):

```python
            else:
                refuter_arm = review.select_refuter(arms, reviewer_arm, avail)
                rr, rlat = _call(providers_base.PROVIDERS[refuter_arm.provider],
                                 review.render_refute_prompt(cand, packet),
                                 refuter_arm.model, cfg,
                                 timeout_s, effort=refuter_arm.effort)
                _refutes_used += 1
                refutes += 1
                cost += rr.cost_usd
                tokens_in += rr.tokens_in
                tokens_out += rr.tokens_out
                parsed = review.parse_refute_response(rr.text) if not rr.error else None
                refute_infos.append({
                    "refuter_provider": refuter_arm.provider,
                    "refuter_tier": refuter_arm.tier,
                    "outcome": ("unavailable" if parsed is None
                                else ("refuted" if parsed[0] else "survived")),
                    "latency_s": rlat})
                if parsed is None:      # transport failure OR malformed refute:
                    parsed = (True, f"refute unavailable ({rr.error or 'malformed'})")
                cand = review.apply_refute(cand, *parsed)
```

3h. Final return gains the payload (note string construction stays byte-identical):

```python
    sel = _selection(tgt, reviewer_arm, bucket, attempts, uplift_info,
                     cascade_info, audit_info, refute_infos, rejected,
                     tokens_in, tokens_out)
    return ConsumerResult(consumer=NAME, state="ok", findings=raws,
                          cost=cost, note=note, extra={"selection": sel})
```

- [ ] **Step 4: Run the FULL consumer + selection surface to prove no behavior change**

Run: `python -m pytest tests/unit/test_llm_consumer.py tests/unit/test_arm_selection.py tests/integration/test_llm_review.py -q`
Expected: ALL pass — every pre-existing test unchanged. If any pre-existing test fails, the implementation broke the shadow-invariant; fix the implementation, never the test.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/consumers/llm_review.py tests/unit/test_llm_consumer.py
git commit -m "feat(autolearn): structured selection telemetry + shadow uplift consult in llm-review consumer"
```

---

### Task 7: armed uplift

**Files:**
- Modify: `src/aramid/consumers/llm_review.py` (three lines inside the Task 6 uplift consult)
- Test: `tests/unit/test_llm_consumer.py` (append)

- [ ] **Step 1: Write the failing tests.** Append:

```python
# --- auto-learn Task 7: armed uplift ----------------------------------------

def _seed_high_miss_state(key="fake-a/ma|cheap|plain"):
    from aramid import autolearn
    st = autolearn.empty_state()
    st["posteriors"][key] = {"misses": 500, "clean": 0}
    autolearn.save_state(st, NOW.isoformat())


def test_armed_uplift_serves_higher_tier(tmp_path, monkeypatch):
    """Armed + overwhelming miss evidence on the cheap arm -> frontier
    serves a score-45 item; escalate-only (spec section 8.2)."""
    _seed_high_miss_state()
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [])
    b = _Fake("fake-b", [ProviderResponse(text=_finding_json("high"))])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r, cfg=_cfg(ladder=_LADDER_AB,
                                        autolearn={"enabled": True,
                                                   "armed": True}),
                       ledger=led, clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45), ctx)
    finally:
        led.close()
    assert "tier=frontier" in got.note and "provider=fake-b" in got.note
    assert "degraded_from" not in got.note      # uplift is not degradation
    sel = got.extra["selection"]
    assert sel["uplift"] == {"mode": "armed", "pick": "frontier",
                             "applied": True,
                             "sampled_q": sel["uplift"]["sampled_q"]}
    assert sel["uplift"]["sampled_q"] > 0.15
    assert sel["target_tier"] == "cheap"        # the floor stays on record


def test_shadow_records_pick_but_serves_floor(tmp_path, monkeypatch):
    """Same evidence, armed=False -> cheap still serves; pick recorded."""
    _seed_high_miss_state()
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"))])
    b = _Fake("fake-b", [])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45),
                                 _ctx_ladder(r, led, _LADDER_AB))
    finally:
        led.close()
    assert "tier=cheap" in got.note
    sel = got.extra["selection"]
    assert sel["uplift"]["mode"] == "shadow"
    assert sel["uplift"]["pick"] == "frontier"
    assert sel["uplift"]["applied"] is False


def test_armed_cold_start_serves_floor(tmp_path, monkeypatch):
    """Armed but NO evidence -> cold start == ladder (spec section 3.2)."""
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"))])
    b = _Fake("fake-b", [])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r, cfg=_cfg(ladder=_LADDER_AB,
                                        autolearn={"enabled": True,
                                                   "armed": True}),
                       ledger=led, clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45), ctx)
    finally:
        led.close()
    assert "tier=cheap" in got.note and "provider=fake-a" in got.note
    assert got.extra["selection"]["uplift"]["applied"] is False
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/unit/test_llm_consumer.py -q -k "armed_uplift or shadow_records or armed_cold"`
Expected: `test_armed_uplift_serves_higher_tier` FAILS (cheap still serves); the other two already pass (they pin the invariant).

- [ ] **Step 3: Implement.** In the Task 6 uplift consult, after the `uplift_info = {...}` assignment inside `if picked is not None:`, add:

```python
                if al_armed and arm_pick.min_score > tgt.min_score:
                    eff_score = arm_pick.min_score   # escalate-only: floor raised, never lowered
                    uplift_info["applied"] = True
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/unit/test_llm_consumer.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/consumers/llm_review.py tests/unit/test_llm_consumer.py
git commit -m "feat(autolearn): armed uplift raises the reviewer_order floor (escalate-only)"
```

---

### Task 8: cascade re-review

**Files:**
- Modify: `src/aramid/consumers/llm_review.py` (replace the Task 6 `cascade_info` placeholder line)
- Test: `tests/unit/test_llm_consumer.py` (append)

Test helper note: a second, distinct finding at line 1 of the fixture file is needed (distinct fingerprint from `_finding_json`'s line-2 finding). Add next to `_finding_json`:

```python
def _finding_json_line1(severity="high", extra_key=None):
    f = {"title": "hardcoded logic", "owasp": "a03", "severity": severity,
         "file": "src/auth.py", "line": 1,
         "evidence": "def get_order(order_id):",
         "explanation": "e2", "fix_hint": "h2"}
    if extra_key:
        f.update(extra_key)
    return json.dumps({"findings": [f]})
```

- [ ] **Step 1: Write the failing tests.** Append:

```python
# --- auto-learn Task 8: cascade ---------------------------------------------

def test_cascade_critical_triggers_rereview_when_armed(tmp_path, monkeypatch):
    """Cheap review reports a CRITICAL -> one re-review by the next tier;
    candidate sets union; the critical still gets its cross-provider refute."""
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("critical"))])
    b = _Fake("fake-b", [ProviderResponse(text=_finding_json_line1("high")),
                         ProviderResponse(text=json.dumps(
                             {"refuted": False, "reason": "real"}))])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r, cfg=_cfg(ladder=_LADDER_AB,
                                        autolearn={"enabled": True,
                                                   "armed": True}),
                       ledger=led, clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45), ctx)
    finally:
        led.close()
    sel = got.extra["selection"]
    assert sel["cascade"] == {"triggered": True, "trigger": "critical",
                              "applied": True}
    assert len(b.calls) == 2                       # cascade review + refute
    assert len(got.findings) == 2                  # union of both reviews
    assert sel["served"]["provider"] == "fake-a"   # served arm unchanged


def test_cascade_shadow_records_but_does_not_call(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("critical"))])
    b = _Fake("fake-b", [ProviderResponse(text=json.dumps(
        {"refuted": True, "reason": "nope"}))])     # refute only
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45),
                                 _ctx_ladder(r, led, _LADDER_AB))
    finally:
        led.close()
    sel = got.extra["selection"]
    assert sel["cascade"]["triggered"] is True
    assert sel["cascade"]["applied"] is False
    assert len(b.calls) == 1                       # only the refute call


def test_cascade_skipped_when_review_budget_exhausted(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("critical"))])
    b = _Fake("fake-b", [ProviderResponse(text=json.dumps(
        {"refuted": True, "reason": "nope"}))])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r, cfg=_cfg(ladder=_LADDER_AB,
                                        max_items_per_drain=1,
                                        autolearn={"enabled": True,
                                                   "armed": True}),
                       ledger=led, clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45), ctx)
    finally:
        led.close()
    sel = got.extra["selection"]
    assert sel["cascade"]["triggered"] is True
    assert sel["cascade"]["applied"] is False      # no slot left, fail-safe


def test_cascade_candidates_pass_confirmed_strip(tmp_path, monkeypatch):
    """BLOCK-PATH PROOF: a prompt-injected `confirmed: true` on a cascade
    candidate is stripped exactly like a served candidate's."""
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("critical"))])
    b = _Fake("fake-b", [
        ProviderResponse(text=_finding_json_line1(
            "high", extra_key={"confirmed": True})),
        ProviderResponse(text=json.dumps({"refuted": True, "reason": "n"}))])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r, cfg=_cfg(ladder=_LADDER_AB,
                                        autolearn={"enabled": True,
                                                   "armed": True}),
                       ledger=led, clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45), ctx)
    finally:
        led.close()
    injected = [f for f in got.findings if f.rule == "llm/a03"]
    assert injected and injected[0].confirmed is False
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/unit/test_llm_consumer.py -q -k cascade`
Expected: `triggers_rereview` and `confirmed_strip` FAIL; the shadow/budget ones fail on `applied`/`triggered` assertions against the placeholder.

- [ ] **Step 3: Implement.** Replace the Task 6 placeholder line `cascade_info = {"triggered": False, "trigger": None, "applied": False}` with:

```python
    # --- cascade (autolearn spec section 9): armed-only re-review by the
    # next-higher arm on danger signs; candidate union feeds the SAME
    # downstream confirmed-strip/dedupe/refute pass. Consumes a normal
    # review slot; budget exhausted -> skip (fail-safe).
    cascade_info = {"triggered": False, "trigger": None, "applied": False}
    if al_enabled and tgt is not None:
        try:
            trig = autolearn.cascade_trigger(
                reviewer_arm, arms, verified, rejected, packet.truncated,
                int(al_cfg.get("cascade_hallucination_min", 3)))
        except Exception:
            trig = None
        if trig is not None:
            cascade_info["triggered"] = True
            cascade_info["trigger"] = trig
            if al_armed and _reviews_used < max_items:
                up_arm = autolearn.next_arm_above(arms, reviewer_arm)
                if up_arm is not None and up_arm.provider in avail:
                    r2, lat2 = _call(providers_base.PROVIDERS[up_arm.provider],
                                     prompt, up_arm.model, cfg, timeout_s,
                                     effort=up_arm.effort)
                    attempts.append({"tier": up_arm.tier,
                                     "provider": up_arm.provider,
                                     "model": up_arm.model, "error": r2.error,
                                     "latency_s": lat2})
                    c2 = None if r2.error else review.parse_review_response(r2.text)
                    if c2 is not None:
                        _reviews_used += 1
                        cost += r2.cost_usd
                        tokens_in += r2.tokens_in
                        tokens_out += r2.tokens_out
                        v2, _rej2 = review.verify_findings(c2, packet,
                                                           ctx.root, item.head)
                        verified = verified + v2
                        cascade_info["applied"] = True
```

Note `max_items` is already in scope (defined near the top of `consume`). The confirmed-strip loop below now iterates the union — its code is untouched.

- [ ] **Step 4: Run to verify pass + full consumer regression**

Run: `python -m pytest tests/unit/test_llm_consumer.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/consumers/llm_review.py tests/unit/test_llm_consumer.py
git commit -m "feat(autolearn): cascade re-review on danger signs (armed only, budget-capped)"
```

---

### Task 9: audit sampling

**Files:**
- Modify: `src/aramid/consumers/llm_review.py` (replace the Task 6 `audit_info = None` placeholder)
- Test: `tests/unit/test_llm_consumer.py` (append)

- [ ] **Step 1: Write the failing tests.** Append:

```python
# --- auto-learn Task 9: audit sampling --------------------------------------

def _audit_cfg(ladder, **al_over):
    al = {"enabled": True, "armed": False, "audit_every": 1,
          "max_audits_per_drain": 1, **al_over}
    return _cfg(ladder=ladder, autolearn=al)


def test_audit_double_reviews_and_counts_miss(tmp_path, monkeypatch):
    """audit_every=1: the below-frontier review is double-reviewed by the
    frontier arm; a critical only the audit found counts as a miss AND is
    filed for real (through the normal refute path)."""
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"))])
    b = _Fake("fake-b", [
        ProviderResponse(text=_finding_json_line1("critical")),  # audit review
        ProviderResponse(text=json.dumps(
            {"refuted": False, "reason": "real"}))])             # refute
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r, cfg=_audit_cfg(_LADDER_AB), ledger=led,
                       clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45), ctx)
    finally:
        led.close()
    sel = got.extra["selection"]
    assert sel["audit"] == {"performed": True, "tier": "frontier",
                            "new_findings": 1, "missed_criticals": 1}
    assert len(got.findings) == 2          # served high + audit critical
    crit = [f for f in got.findings if f.rule == "llm/a03"]
    assert crit and crit[0].confirmed is True     # survived its refute
    assert sel["served"]["provider"] == "fake-a"  # audit never replaces served


def test_audit_not_counted_against_review_budget(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"))])
    b = _Fake("fake-b", [ProviderResponse(text=_finding_json_line1("high"))])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r,
                       cfg=_audit_cfg(_LADDER_AB, max_items_per_drain=1),
                       ledger=led, clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45), ctx)
    finally:
        led.close()
    assert got.extra["selection"]["audit"]["performed"] is True


def test_audit_cap_respected_per_drain(tmp_path, monkeypatch):
    """max_audits_per_drain=0 -> never audits even at audit_every=1."""
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"))])
    b = _Fake("fake-b", [])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r,
                       cfg=_audit_cfg(_LADDER_AB, max_audits_per_drain=0),
                       ledger=led, clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45), ctx)
    finally:
        led.close()
    assert got.extra["selection"]["audit"] is None


def test_no_audit_when_served_at_frontier(tmp_path, monkeypatch):
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [])
    b = _Fake("fake-b", [ProviderResponse(text=_finding_json("high"))])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r, cfg=_audit_cfg(_LADDER_AB), ledger=led,
                       clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 90), ctx)
    finally:
        led.close()
    assert got.extra["selection"]["audit"] is None


def test_audit_provider_failure_degrades_silently(tmp_path, monkeypatch):
    """Audit call errors -> served review stands, performed=False."""
    r, base_sha, head_sha = _repo(tmp_path)
    a = _Fake("fake-a", [ProviderResponse(text=_finding_json("high"))])
    b = _Fake("fake-b", [ProviderResponse(text="",
                                          error=providers_base.ERR_TIMEOUT)])
    _wire(monkeypatch, a, b)
    led = Ledger(tmp_path / "l.db")
    ctx = DrainContext(root=r, cfg=_audit_cfg(_LADDER_AB), ledger=led,
                       clock=lambda: NOW.isoformat())
    try:
        got = llm_review.consume(_item_score(base_sha, head_sha, 45), ctx)
    finally:
        led.close()
    assert got.state == "ok" and len(got.findings) == 1
    assert got.extra["selection"]["audit"]["performed"] is False
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/unit/test_llm_consumer.py -q -k audit`
Expected: all five FAIL against the `None` placeholder (except `frontier`/`cap`, which pass trivially and pin the invariant).

- [ ] **Step 3: Implement.** Replace the Task 6 placeholder line `audit_info = None` with:

```python
    # --- audit sampling (autolearn spec section 10): the data engine --
    # active in shadow AND armed. One frontier double-review for a hash-
    # sampled below-frontier item; the diff measures what the served arm
    # missed; audit findings are REAL and join the same downstream pass.
    # Own cap (_audits_used), never counted against the review budget.
    audit_info = None
    if al_enabled and tgt is not None:
        try:
            do_audit = (_audits_used < int(al_cfg.get("max_audits_per_drain", 1))
                        and autolearn.should_audit(
                            item.id, reviewer_arm, arms,
                            int(al_cfg.get("audit_every", 8))))
            aud_arm = autolearn.audit_arm(arms, avail) if do_audit else None
            if aud_arm is not None and aud_arm != reviewer_arm:
                ra, lata = _call(providers_base.PROVIDERS[aud_arm.provider],
                                 prompt, aud_arm.model, cfg, timeout_s,
                                 effort=aud_arm.effort)
                attempts.append({"tier": aud_arm.tier,
                                 "provider": aud_arm.provider,
                                 "model": aud_arm.model, "error": ra.error,
                                 "latency_s": lata})
                _audits_used += 1
                ca = None if ra.error else review.parse_review_response(ra.text)
                if ca is not None:
                    cost += ra.cost_usd
                    tokens_in += ra.tokens_in
                    tokens_out += ra.tokens_out
                    va, _reja = review.verify_findings(ca, packet,
                                                       ctx.root, item.head)
                    new_n, missed_n = autolearn.audit_diff(verified, va)
                    audit_info = {"performed": True, "tier": aud_arm.tier,
                                  "new_findings": new_n,
                                  "missed_criticals": missed_n}
                    verified = verified + va
                else:
                    audit_info = {"performed": False, "tier": aud_arm.tier,
                                  "new_findings": 0, "missed_criticals": 0}
        except Exception:
            audit_info = None
```

- [ ] **Step 4: Pin the integration fixture against hash-random audits.** The full-loop tests in `tests/integration/test_llm_review.py` enqueue items with runtime-random uuid ids; at the default `audit_every=8`, ~1 in 8 ids would sample a shadow audit, consume an extra scripted provider response, and desync the refute script — a real flake. This is the ONE sanctioned edit to an existing test file: in `_setup_repo` (right after `assert cmd_init(r) in (0, 2)`), append:

```python
    # Auto-learn hermeticity: item ids are random uuids, and the default
    # audit_every=8 would hash-sample a shadow audit for ~1 in 8 of them,
    # desyncing the scripted provider responses below. Audits have dedicated
    # unit coverage (test_llm_consumer.py Task-9 tests); this file pins the
    # full loop deterministic.
    with (r / "aramid.toml").open("a", encoding="utf-8") as fh:
        fh.write("\n[llm.autolearn]\naudit_every = 0\n")
```

No assertion in the file changes.

- [ ] **Step 5: Run the whole consumer surface**

Run: `python -m pytest tests/unit/test_llm_consumer.py tests/integration/test_llm_review.py -q`
Expected: all PASS. (Unit fixtures use item id `"q1"`, and `sha256("q1") % 8 == 3` — a fixed constant — so no unit test samples an audit unless it sets `audit_every=1` explicitly.)

- [ ] **Step 6: Commit**

```bash
git add src/aramid/consumers/llm_review.py tests/unit/test_llm_consumer.py tests/integration/test_llm_review.py
git commit -m "feat(autolearn): audit sampling -- frontier double-reviews measure misses, active in shadow"
```

---

### Task 10: drain-end rollup wiring

**Files:**
- Modify: `src/aramid/commands/drain.py`
- Test: `tests/integration/test_drain.py` (append)

**Interfaces:**
- Consumes: `autolearn.rollup/load_state/save_state`, `fingerprint.normalize_path`.
- Produces: after the consume loop, each drained repo's new ledger events fold into the machine-global state (fail-open).

- [ ] **Step 1: Write the failing test.** Append to `tests/integration/test_drain.py`:

```python
def test_drain_rolls_up_autolearn_state(tmp_path, monkeypatch):
    """cmd_drain folds drained repos' selection events into the (test-
    isolated) machine-global state; a rollup failure never fails the drain."""
    import json as json_mod

    from aramid import autolearn, config as config_mod, gitutil, queue
    from aramid.commands import drain as drain_mod
    from aramid.ledger import Ledger

    repo = tmp_path / "repo"
    repo.mkdir()
    _git = lambda *a: subprocess.run(["git", *a], cwd=repo, check=True,
                                     capture_output=True, text=True)
    _git("init", "-q", "-b", "main")
    _git("config", "user.email", "t@t")
    _git("config", "user.name", "t")
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git("add", "."); _git("commit", "-m", "c1")
    (repo / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")

    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user.toml")
    monkeypatch.setattr(drain_mod, "_lock_path",
                        lambda: tmp_path / "drain.lock")
    monkeypatch.setattr(drain_mod, "_sweep", lambda *a, **k: None)

    led = Ledger(repo / ".aramid" / "ledger.db")
    try:
        queue.enqueue(led, "2026-07-18T00:00:00+00:00", None,
                      gitutil.rev_sha(repo, "HEAD"), 50, ["risky"])
    finally:
        led.close()

    fake = SimpleNamespace(consume=lambda item, ctx: ConsumerResult(
        consumer="fake", state="ok",
        extra={"selection": {
            "target_tier": "cheap", "bucket": "plain",
            "served": {"tier": "cheap", "provider": "p", "model": "m",
                       "effort": ""},
            "attempts": [], "uplift": {"mode": "shadow", "pick": "cheap",
                                       "applied": False, "sampled_q": 0.1},
            "cascade": {"triggered": False, "trigger": None,
                        "applied": False},
            "audit": {"performed": True, "tier": "frontier",
                      "new_findings": 0, "missed_criticals": 0},
            "refutes": [], "hallucination_rejected": 0,
            "tokens": {"in": 1, "out": 1}}}))
    monkeypatch.setattr(drain_mod, "CONSUMERS", {"fake": fake})

    assert drain_mod.cmd_drain([str(repo)]) == 0

    state = json_mod.loads(autolearn.state_path().read_text(encoding="utf-8"))
    assert state["audits"]["performed"] == 1
    assert state["posteriors"]["p/m|cheap|plain"]["clean"] == 1
    assert list(state["cursors"].values())[0] > 0
```

(If `subprocess`/`SimpleNamespace`/`ConsumerResult` are not yet imported at the top of `test_drain.py`, add them.)

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/integration/test_drain.py::test_drain_rolls_up_autolearn_state -q`
Expected: FAIL — state file never written.

- [ ] **Step 3: Implement.** In `src/aramid/commands/drain.py`:

Add imports: `from aramid import autolearn` (with the other `from aramid import ...` line) and `from aramid.fingerprint import normalize_path`.

In `cmd_drain`, track drained repos — before the consume loop add `rolled: dict[str, tuple] = {}`, and inside the loop body (next to `drained += 1`) add:

```python
            rolled[str(root)] = (root, cfg)
```

After the consume loop (before the final `print(f"aramid drain: {drained} item(s) drained, ...")`), add:

```python
        # Auto-learn rollup (autolearn spec section 8.3): fold each drained
        # repo's new ledger events into the machine-global state. Fail-open:
        # a rollup failure never fails the drain.
        for root, cfg in rolled.values():
            al_cfg = cfg.llm.get("autolearn", {})
            if not isinstance(al_cfg, dict) or not al_cfg.get("enabled", True):
                continue
            try:
                led = Ledger(root / ".aramid" / "ledger.db")
                try:
                    events = led.events()
                finally:
                    led.close()
                state = autolearn.rollup(autolearn.load_state(), events,
                                         normalize_path(str(root)))
                autolearn.save_state(state, clock())
            except Exception as exc:
                print(f"aramid drain: autolearn rollup skipped for {root}: {exc}",
                      file=sys.stderr)
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/integration/test_drain.py tests/integration/test_llm_review.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/drain.py tests/integration/test_drain.py
git commit -m "feat(autolearn): drain-end rollup of drained repos into machine-global state"
```

---

### Task 11: `aramid arm --autolearn`

**Files:**
- Modify: `src/aramid/commands/arm.py`
- Modify: `src/aramid/cli.py`
- Test: `tests/unit/test_arm_autolearn.py` (create), `tests/integration/test_cli_dispatch.py` (append)

- [ ] **Step 1: Write the failing tests.** Create `tests/unit/test_arm_autolearn.py`:

```python
"""arm --autolearn: comment-preserving [llm.autolearn] armed=true rewrite
(mirrors test_arm_llm.py's coverage of _arm_llm_text)."""
from aramid.commands.arm import _arm_autolearn_text, cmd_arm


def test_appends_fresh_section_when_absent():
    got = _arm_autolearn_text("schema_version = 1\n")
    assert got.endswith("[llm.autolearn]\narmed = true\n")
    assert "schema_version = 1" in got


def test_substitutes_existing_key_in_section():
    text = "[llm.autolearn]\nenabled = true\narmed = false\n\n[pack]\nenabled = true\n"
    got = _arm_autolearn_text(text)
    assert "armed = true" in got
    assert "armed = false" not in got
    assert "[pack]\nenabled = true" in got          # rest untouched


def test_inserts_key_under_existing_section_without_key():
    text = "[llm.autolearn]\nenabled = true\n"
    got = _arm_autolearn_text(text)
    assert "[llm.autolearn]\narmed = true\nenabled = true\n" == got


def test_armed_key_in_other_section_untouched():
    text = "[other]\narmed = false\n"
    got = _arm_autolearn_text(text)
    assert "[other]\narmed = false" in got
    assert got.endswith("[llm.autolearn]\narmed = true\n")


def test_cmd_arm_autolearn_writes_and_reports(tmp_path, capsys):
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n",
                                          encoding="utf-8")
    assert cmd_arm(tmp_path, autolearn=True) == 0
    text = (tmp_path / "aramid.toml").read_text(encoding="utf-8")
    assert "[llm.autolearn]\narmed = true" in text
    out = capsys.readouterr().out
    assert "auto-learn armed" in out and "shadow record" in out


def test_cmd_arm_autolearn_missing_toml_errors(tmp_path, capsys):
    assert cmd_arm(tmp_path, autolearn=True) == 3
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/unit/test_arm_autolearn.py -q`
Expected: FAIL with ImportError (`_arm_autolearn_text` missing).

- [ ] **Step 3: Implement.** In `src/aramid/commands/arm.py`, add after `_LLM_SECTION_RE`:

```python
_AL_SECTION_RE = re.compile(r"(?m)^\[llm\.autolearn\]\s*$")
_AL_KEY_RE = re.compile(r"(?m)^armed\s*=\s*\S+\s*$")
_NEXT_SECTION_RE = re.compile(r"(?m)^\[")


def _arm_autolearn_text(text: str) -> str:
    """Comment-preserving single-key rewrite, mirroring _arm_llm_text -- but
    `armed` is a generic key name, so the substitution is SCOPED to the
    [llm.autolearn] section's span (an `armed =` in any other table is
    never touched)."""
    m = _AL_SECTION_RE.search(text)
    if m:
        nxt = _NEXT_SECTION_RE.search(text, m.end())
        span_end = nxt.start() if nxt else len(text)
        section = text[m.end():span_end]
        if _AL_KEY_RE.search(section):
            return (text[:m.end()] + _AL_KEY_RE.sub("armed = true", section,
                                                    count=1) + text[span_end:])
        return text[:m.end()] + "\narmed = true" + text[m.end():]
    prefix = "" if not text or text.endswith("\n") else "\n"
    return text + prefix + "[llm.autolearn]\narmed = true\n"
```

Change `cmd_arm`'s signature to `def cmd_arm(root, llm: bool = False, autolearn: bool = False) -> int:` and insert before the `if llm:` branch:

```python
    if autolearn:
        toml_path.write_text(_arm_autolearn_text(text), encoding="utf-8")
        print(f"aramid: arm: [llm.autolearn] armed=true written to {toml_path}")
        # Arming is an informed act: show the shadow record it stands on.
        try:
            from aramid import autolearn as al_mod
            st = al_mod.load_state()
            sh, au = st.get("shadow", {}), st.get("audits", {})
            print(f"aramid: arm: shadow record at arming: would-uplift "
                  f"{sh.get('would_uplift', 0)}/{sh.get('decisions', 0)}, "
                  f"audits {au.get('performed', 0)}, "
                  f"misses {au.get('missed_criticals', 0)}")
        except Exception:
            print("aramid: arm: shadow record at arming: unavailable")
        print("aramid: arm: auto-learn armed -- uplift and cascade now change "
              "reviewer selection (escalate-only; the ladder tier stays the floor).")
        return 0
```

In `src/aramid/cli.py`: make the two arm flags mutually exclusive —

```python
    p_arm = sub.add_parser("arm", help="end a WARN-only bake (semgrep default, --llm for the LLM reviewer, --autolearn for learned uplift)")
    arm_which = p_arm.add_mutually_exclusive_group()
    arm_which.add_argument("--llm", action="store_true")
    arm_which.add_argument("--autolearn", action="store_true")
```

and the dispatch:

```python
    if args.command == "arm":
        return cmd_arm(root, llm=args.llm, autolearn=args.autolearn)
```

Append a dispatch test to `tests/integration/test_cli_dispatch.py`, following that file's existing monkeypatch pattern for `cmd_arm` (find the existing `arm` dispatch test and copy its structure, asserting `autolearn=True` is passed through for `["arm", "--autolearn"]`, and that `["arm", "--llm", "--autolearn"]` returns exit 3).

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/unit/test_arm_autolearn.py tests/unit/test_arm_llm.py tests/integration/test_arm.py tests/integration/test_cli_dispatch.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/arm.py src/aramid/cli.py tests/unit/test_arm_autolearn.py tests/integration/test_cli_dispatch.py
git commit -m "feat(autolearn): aramid arm --autolearn (scoped comment-preserving toml rewrite)"
```

---

### Task 12: `aramid autolearn` report + `--rebuild`

**Files:**
- Create: `src/aramid/commands/autolearn_cmd.py`
- Modify: `src/aramid/cli.py`
- Test: `tests/integration/test_autolearn_cmd.py` (create)

- [ ] **Step 1: Write the failing tests.** Create `tests/integration/test_autolearn_cmd.py`:

```python
"""aramid autolearn: read-only report + --rebuild from registry ledgers."""
import json

from aramid import autolearn, registry
from aramid.commands.autolearn_cmd import cmd_autolearn
from aramid.ledger import Ledger
from aramid.models import Event, EventType

AT = "2026-07-18T00:00:00+00:00"


def _sel():
    return {"target_tier": "cheap", "bucket": "plain",
            "served": {"tier": "cheap", "provider": "p", "model": "m",
                       "effort": ""},
            "attempts": [], "uplift": {"mode": "shadow", "pick": "frontier",
                                       "applied": False, "sampled_q": 0.3},
            "cascade": {"triggered": False, "trigger": None, "applied": False},
            "audit": {"performed": True, "tier": "frontier",
                      "new_findings": 1, "missed_criticals": 1},
            "refutes": [], "hallucination_rejected": 2,
            "tokens": {"in": 1, "out": 1}}


def test_report_cold_start(tmp_path, capsys):
    assert cmd_autolearn(tmp_path) == 0
    out = capsys.readouterr().out
    assert "aramid autolearn:" in out
    assert "posteriors: none yet" in out
    assert "shadow: would-uplift 0/0" in out


def test_rebuild_replays_registry_ledgers(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "repo"
    (repo / ".aramid").mkdir(parents=True)
    led = Ledger(repo / ".aramid" / "ledger.db")
    try:
        led.append(Event(EventType.CONSUMER_RUN_FINISHED, "r1", AT,
                         payload={"consumer": "llm-review", "item_id": "q1",
                                  "state": "ok", "duration_s": 1.0,
                                  "cost": 0.0, "finding_count": 0,
                                  "note": "x", "selection": _sel()}))
    finally:
        led.close()
    monkeypatch.setattr(registry, "registry_path",
                        lambda: tmp_path / "repos.toml")
    registry.register(repo, AT)

    assert cmd_autolearn(tmp_path, rebuild=True) == 0
    out = capsys.readouterr().out
    assert "1 event(s) replayed" in out
    assert "p/m|cheap|plain: 1/0" in out
    assert "audits: 1 performed, 1 missed critical(s)" in out
    state = json.loads(autolearn.state_path().read_text(encoding="utf-8"))
    assert state["posteriors"]["p/m|cheap|plain"]["misses"] == 1


def test_rebuild_skips_repo_without_ledger(tmp_path, monkeypatch, capsys):
    ghost = tmp_path / "ghost"
    ghost.mkdir()
    monkeypatch.setattr(registry, "registry_path",
                        lambda: tmp_path / "repos.toml")
    registry.register(ghost, AT)
    assert cmd_autolearn(tmp_path, rebuild=True) == 0
    assert "no ledger; skipped" in capsys.readouterr().out
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/integration/test_autolearn_cmd.py -q`
Expected: FAIL with ModuleNotFoundError.

- [ ] **Step 3: Implement.** Create `src/aramid/commands/autolearn_cmd.py`:

```python
"""autolearn command -- read-only report over the machine-global learned
state, plus --rebuild (replay every registered repo's ledger from scratch;
the state file is derived, so rebuild is always safe -- autolearn spec
section 12)."""
import sys
from datetime import datetime, timezone
from pathlib import Path

from aramid import autolearn, registry
from aramid.fingerprint import normalize_path
from aramid.ledger import Ledger


def _mode_line(root: Path) -> str:
    from aramid import config as config_mod
    try:
        cfg = config_mod.load_config(root)
        al = cfg.llm.get("autolearn", {})
        if not isinstance(al, dict) or not al.get("enabled", True):
            return "mode: off (this repo)"
        return ("mode: armed (this repo)" if al.get("armed", False)
                else "mode: shadow (this repo)")
    except Exception:
        return "mode: unknown (config unreadable)"


def cmd_autolearn(root, rebuild: bool = False) -> int:
    now = datetime.now(timezone.utc).isoformat()

    if rebuild:
        state = autolearn.empty_state()
        for entry in registry.load_registry():
            repo = Path(entry["path"])
            db = repo / ".aramid" / "ledger.db"
            if not db.exists():
                print(f"aramid autolearn: {repo}: no ledger; skipped")
                continue
            try:
                led = Ledger(db)
                try:
                    events = led.events()
                finally:
                    led.close()
                state = autolearn.rollup(state, events,
                                         normalize_path(str(repo)))
                print(f"aramid autolearn: {repo}: {len(events)} event(s) replayed")
            except Exception as exc:
                print(f"aramid autolearn: {repo}: skipped ({exc})",
                      file=sys.stderr)
        autolearn.save_state(state, now)
        print(f"aramid autolearn: state rebuilt -> {autolearn.state_path()}")

    state = autolearn.load_state()
    lines = ["aramid autolearn:", f"  {_mode_line(Path(root))}",
             f"  state: {autolearn.state_path()} "
             f"(updated {state.get('updated_at') or 'never'})"]
    sh, au = state.get("shadow", {}), state.get("audits", {})
    lines.append(f"  shadow: would-uplift {sh.get('would_uplift', 0)}"
                 f"/{sh.get('decisions', 0)} decision(s)")
    lines.append(f"  audits: {au.get('performed', 0)} performed, "
                 f"{au.get('missed_criticals', 0)} missed critical(s)")
    posts = state.get("posteriors", {})
    if posts:
        lines.append("  posteriors (arm|band|bucket: misses/clean "
                     "[halluc malformed refuted survived overridden]):")
        for key in sorted(posts):
            c = posts[key]
            lines.append(
                f"    {key}: {c.get('misses', 0)}/{c.get('clean', 0)} "
                f"[{c.get('halluc', 0)} {c.get('malformed', 0)} "
                f"{c.get('refuted', 0)} {c.get('survived', 0)} "
                f"{c.get('overridden', 0)}]")
    else:
        lines.append("  posteriors: none yet (cold start -- ladder behavior)")
    print("\n".join(lines))
    return 0
```

In `src/aramid/cli.py`: import `from aramid.commands.autolearn_cmd import cmd_autolearn`; in `build_parser` add:

```python
    p_autolearn = sub.add_parser("autolearn",
                                 help="learned model-selection report (--rebuild: replay registry ledgers)")
    p_autolearn.add_argument("--rebuild", action="store_true")
```

and in `main`'s dispatch chain:

```python
    if args.command == "autolearn":
        return cmd_autolearn(root, rebuild=args.rebuild)
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/integration/test_autolearn_cmd.py tests/integration/test_cli_dispatch.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/autolearn_cmd.py src/aramid/cli.py tests/integration/test_autolearn_cmd.py
git commit -m "feat(autolearn): aramid autolearn report + --rebuild"
```

---

### Task 13: status line + doctor probe

**Files:**
- Modify: `src/aramid/commands/status.py`
- Modify: `src/aramid/commands/doctor.py`
- Test: `tests/integration/test_status.py` (append), `tests/integration/test_doctor.py` (append)

- [ ] **Step 1: Write the failing tests.** Append to `tests/integration/test_status.py` (follow the file's existing fixture pattern for invoking `cmd_status` — it already isolates `_user_config_path`; the root conftest isolates the state file):

```python
def test_status_shows_autolearn_shadow_line(tmp_path, monkeypatch, capsys):
    from aramid import autolearn, config as config_mod
    from aramid.commands.status import cmd_status
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user.toml")
    st = autolearn.empty_state()
    st["shadow"] = {"decisions": 17, "would_uplift": 3}
    st["audits"] = {"performed": 5, "missed_criticals": 1}
    autolearn.save_state(st, "2026-07-18T00:00:00+00:00")
    repo = tmp_path / "r"
    repo.mkdir()
    assert cmd_status(repo) == 0
    out = capsys.readouterr().out
    assert "autolearn: shadow (would-uplift 3/17, audits 5, misses 1)" in out


def test_status_shows_autolearn_armed(tmp_path, monkeypatch, capsys):
    from aramid import config as config_mod
    from aramid.commands.status import cmd_status
    monkeypatch.setattr(config_mod, "_user_config_path",
                        lambda: tmp_path / "no-user.toml")
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "aramid.toml").write_text("[llm.autolearn]\narmed = true\n",
                                      encoding="utf-8")
    assert cmd_status(repo) == 0
    assert "autolearn: armed" in capsys.readouterr().out
```

Append to `tests/integration/test_doctor.py` (follow its existing probe-test pattern):

```python
def test_doctor_reports_autolearn_state(tmp_path, monkeypatch, capsys):
    from aramid.commands.doctor import _autolearn_probe_line
    line = _autolearn_probe_line()
    assert "autolearn" in line and "cold start" in line   # no state yet

    from aramid import autolearn
    autolearn.save_state(autolearn.empty_state(),
                         "2026-07-18T00:00:00+00:00")
    assert "state readable" in _autolearn_probe_line()

    autolearn.state_path().write_text("{corrupt", encoding="utf-8")
    assert "unreadable" in _autolearn_probe_line()
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/integration/test_status.py -q -k autolearn; python -m pytest tests/integration/test_doctor.py -q -k autolearn`
Expected: FAIL (missing line / missing function).

- [ ] **Step 3: Implement.** In `src/aramid/commands/status.py`, add after `_llm_lines`:

```python
def _autolearn_line(cfg: config_mod.Config) -> str:
    """One line (autolearn spec section 12): off | armed | shadow with the
    shadow/audit record. Never raises -- status stays read-only-safe."""
    al = cfg.llm.get("autolearn", {})
    if not isinstance(al, dict) or not al.get("enabled", True):
        return "autolearn: off"
    if al.get("armed", False):
        return "autolearn: armed"
    try:
        from aramid import autolearn as al_mod
        st = al_mod.load_state()
        sh, au = st.get("shadow", {}), st.get("audits", {})
        return (f"autolearn: shadow (would-uplift {sh.get('would_uplift', 0)}"
                f"/{sh.get('decisions', 0)}, audits {au.get('performed', 0)}, "
                f"misses {au.get('missed_criticals', 0)})")
    except Exception:
        return "autolearn: shadow (state unreadable)"
```

and in `_llm_lines`, before `return lines`, add:

```python
    lines.append(_autolearn_line(cfg))
```

In `src/aramid/commands/doctor.py`, add near `probe_providers`:

```python
def _autolearn_probe_line() -> str:
    """State-file health (autolearn spec section 12). Informational only --
    an unreadable state is treated as empty by the engine (cold start)."""
    import json as _json

    from aramid import autolearn
    try:
        p = autolearn.state_path()
        if not p.exists():
            return "  OK       autolearn    no state yet (cold start = deterministic ladder)"
        try:
            data = _json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return ("  DEGRADED autolearn    state unreadable -- treated as empty; "
                    "`aramid autolearn --rebuild` repairs it")
        if not isinstance(data, dict) or data.get("version") != autolearn.STATE_VERSION:
            return ("  DEGRADED autolearn    foreign state version -- treated as empty; "
                    "`aramid autolearn --rebuild` repairs it")
        return (f"  OK       autolearn    state readable; "
                f"{len(data.get('posteriors', {}))} posterior cell(s)")
    except Exception:
        return "  OK       autolearn    probe unavailable"
```

and in `cmd_doctor`, after the `for line in probe_providers(): print(line)` loop:

```python
    print("autolearn:")
    print(_autolearn_probe_line())
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/integration/test_status.py tests/integration/test_doctor.py -q`
Expected: all PASS (including every pre-existing status/doctor test).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/status.py src/aramid/commands/doctor.py tests/integration/test_status.py tests/integration/test_doctor.py
git commit -m "feat(autolearn): status line + doctor state probe"
```

---

### Task 14: README + full-suite verification

**Files:**
- Modify: `README.md`
- Test: full suite

- [ ] **Step 1: Update `README.md`.** In the Phase 2b section (after the ladder paragraph around lines 112–118), add:

```markdown
**Auto-learn (learned uplift).** The deterministic ladder is a *floor*, not
the final answer: the auto-learn engine measures each arm's real-world miss
rate with **audit sampling** (1 in N below-frontier reviews is double-reviewed
by the frontier arm and the finding sets diffed — audit findings are filed for
real) and applies an escalate-only Thompson **uplift**: an item may be served
by a *higher* tier than its triage score suggests, never a lower one. It ships
shadow-first (bake-then-arm): with the default `[llm.autolearn] enabled = true,
armed = false` it records telemetry, shadow decisions, and audits but never
changes selection; `aramid arm --autolearn` arms it per-repo once
`aramid autolearn` shows a shadow record you trust. A **cascade** re-review
escalates one tier mid-drain (armed only) when a served review shows danger
signs (a verified CRITICAL, heavy hallucination rejections, a truncated
packet). Learning state is machine-global (`~/.aramid/autolearn_state.json`),
derived entirely from per-repo ledgers, and rebuildable at any time with
`aramid autolearn --rebuild`. Cold start, missing state, and any policy error
all degrade to exactly the deterministic ladder.
```

Also update the roadmap line mentioning the auto-learn engine as "next" (if present) to note it shipped, leaving Phase 2c as the next phase.

- [ ] **Step 2: Run the FULL suite**

Run: `python -m pytest -q` (from `F:\Projects\aramid`; ~6 min)
Expected: ALL tests pass (588 pre-existing + all new). Zero failures, zero errors.

- [ ] **Step 3: Ruff check**

Run: `python -m ruff check src tests`
Expected: clean (fix any new-code findings; do not touch pre-existing code for unrelated findings).

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: README -- auto-learn learned uplift (shadow-first, audit sampling, escalate-only)"
```

---

## Plan self-review notes (already applied)

- **Spec coverage:** §5.1 → Tasks 1–2; §5.2 table → Tasks 3–13; §6 → Tasks 4, 6; §7 → Task 5; §8 → Tasks 1, 2, 7, 10; §9 → Task 8; §10 → Task 9; §11 → woven through Tasks 1, 6, 9, 10, 13; §12 → Tasks 11–13; §14 → each task's tests. §13 (forward hooks) deliberately unbuilt.
- **Spec §6 payload delta:** the plan adds `"bucket"` and `"hallucination_rejected"` keys to the `selection` payload (the spec's example omits them; the rollup's posterior key requires them). `target_tier` doubles as the band.
- **Deviation guard:** any implementer deviation from the exact code shown here must be reported in the task report, not silently improvised — especially inside `consume()`.
