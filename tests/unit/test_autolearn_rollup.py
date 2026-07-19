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


def test_rollup_tolerates_null_served():
    sel = _sel(served=None)
    st = autolearn.rollup(autolearn.empty_state(), [_run_ev("r1", sel)], "repo1")
    assert st["posteriors"] == {}
    assert st["shadow"]["decisions"] == 1
