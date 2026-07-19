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
    """No data: the floor cell has zero evidence, so it uses the
    deterministic prior mean 1/(1+PRIOR_CLEAN) = 0.10 <= 0.15 -- the floor
    arm qualifies. THE load-bearing invariant: cold start == deterministic
    ladder, exactly (no sampling on empty state)."""
    st = autolearn.empty_state()
    rng = autolearn.decision_rng("item-1", st)
    picked = autolearn.uplift_pick(ARMS, 45, "plain", st, 0.15, rng)
    assert picked is not None
    arm, floor_q = picked
    assert arm == CHEAP
    assert floor_q == 1.0 / (1.0 + autolearn.PRIOR_CLEAN)


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


def test_uplift_zero_evidence_is_deterministic_not_sampled():
    """Spec section 3.2: empty posteriors reproduce the ladder EXACTLY.
    Any rng: the floor always qualifies with the prior mean 0.10."""
    st = autolearn.empty_state()
    for item_id in ("a", "b", "c", "q1", "id-7"):
        picked = autolearn.uplift_pick(ARMS, 45, "plain", st, 0.15,
                                       autolearn.decision_rng(item_id, st))
        arm, floor_q = picked
        assert arm == CHEAP
        assert floor_q == 1.0 / (1.0 + autolearn.PRIOR_CLEAN)


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
