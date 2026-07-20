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
ladder: with no data a zero-evidence cell uses the deterministic prior mean
1/(1+PRIOR_CLEAN) = 0.10, under the 0.15 default threshold, so the floor
qualifies and no uplift happens -- exactly, not just in expectation (spec
section 3.2).
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
    q ~ Beta(1+misses, PRIOR_CLEAN+clean) -- except a cell with ZERO
    evidence (misses + clean == 0), which uses the deterministic prior mean
    1/(1+PRIOR_CLEAN) instead of sampling, so empty posteriors reproduce
    today's ladder exactly rather than in expectation (spec section 3.2).
    Serve the lowest arm with q <= threshold. The top arm always qualifies
    (it is the measuring ceiling). Returns (arm, floor_q) where floor_q is
    the q for the floor arm -- the number that explains the decision -- or
    None when there are no arms."""
    tgt = review_mod.target_arm(arms, score)
    if tgt is None:
        return None
    band = tgt.tier
    ladder_up = [a for a in arms if a.min_score >= tgt.min_score]
    floor_q = None
    for a in ladder_up[:-1]:
        c = _counts(state, posterior_key(a, band, bucket))
        n_evidence = int(c.get("misses", 0)) + int(c.get("clean", 0))
        if n_evidence == 0:
            # Zero-evidence cell: deterministic prior mean (spec section 3.2
            # -- cold start must reproduce the ladder EXACTLY, not just in
            # expectation; Thompson sampling begins once audit evidence
            # exists).
            q = 1.0 / (1.0 + PRIOR_CLEAN)
        else:
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


# --- reward rollup ----------------------------------------------------------

def rollup(state: dict, events: list, repo_key: str) -> dict:
    """Fold ledger events past this repo's cursor into posterior counts
    (spec section 8.3). Pure: returns a NEW state dict; the caller saves.
    The cursor is an event COUNT (the ledger is append-only and
    seq-ordered), so replaying the same list twice is a no-op; a shorter
    list than the cursor (rebuilt/compacted ledger) SKIPS the fold (a
    correct rebuild is cross-repo -- run `aramid autolearn --rebuild`).

    Primary reward: audit outcomes -> misses/clean on the SERVED arm's
    (band, bucket) cell. Secondary counters (halluc/malformed/refuted/
    survived/overridden) are recorded for reporting but NOT read by
    uplift_pick (spec section 8.3)."""
    out = json.loads(json.dumps(state))     # deep copy; state is JSON-shaped
    cursor = int(out.get("cursors", {}).get(repo_key, 0))
    if cursor > len(events):
        # Shrunk/compacted ledger: a correct rebuild is CROSS-REPO (posteriors
        # aggregate across every registered repo, keyed by arm-cell), so a
        # single per-repo rollup cannot re-fold without double-counting the
        # surviving events onto posteriors that already include them. Skip the
        # fold (leave the cursor as-is); correct counts after a compaction
        # require a global `aramid autolearn --rebuild`. (Was: cursor=0 then
        # re-fold -> posterior double-count.)
        return out

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
