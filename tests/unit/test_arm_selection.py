from types import SimpleNamespace

from aramid import review
from aramid.review import Arm

LADDER = [
    {"tier": "cheap", "provider": "ollama-cloud", "model": "df", "effort": "", "min_score": 40},
    {"tier": "mid", "provider": "codex-cli", "model": "g", "effort": "", "min_score": 60},
    {"tier": "frontier", "provider": "claude-cli", "model": "opus", "effort": "", "min_score": 80},
]
ALL = {"ollama-cloud", "codex-cli", "claude-cli"}


def _cfg(ladder=LADDER):
    return SimpleNamespace(llm={"ladder": ladder})


def test_build_arms_sorts_and_drops_malformed():
    arms = review.build_arms(_cfg(ladder=[
        {"tier": "b", "provider": "p2", "min_score": 80},
        {"tier": "a", "provider": "p1", "min_score": 40},
        {"bad": "entry"},                         # missing keys -> dropped
        "not-a-dict",                             # -> dropped
    ]))
    assert [a.min_score for a in arms] == [40, 80]
    assert [a.tier for a in arms] == ["a", "b"]


def test_target_arm_by_band():
    arms = review.build_arms(_cfg())
    assert review.target_arm(arms, 50).tier == "cheap"
    assert review.target_arm(arms, 65).tier == "mid"
    assert review.target_arm(arms, 95).tier == "frontier"
    assert review.target_arm(arms, 10).tier == "cheap"     # below lowest band
    assert review.target_arm([], 50) is None


def test_reviewer_order_target_first_then_degrade_down_then_up():
    arms = review.build_arms(_cfg())
    # high-risk, all available -> frontier first, then mid, then cheap
    assert [a.tier for a in review.reviewer_order(arms, 95, ALL)] == ["frontier", "mid", "cheap"]
    # low-risk -> cheap first, then mid, then frontier (fallthrough climbs)
    assert [a.tier for a in review.reviewer_order(arms, 45, ALL)] == ["cheap", "mid", "frontier"]


def test_reviewer_order_degrades_when_target_provider_down():
    arms = review.build_arms(_cfg())
    avail = {"codex-cli", "ollama-cloud"}          # claude (frontier) is down
    # high-risk item degrades to the nearest available at/below -> mid then cheap
    assert [a.tier for a in review.reviewer_order(arms, 95, avail)] == ["mid", "cheap"]


def test_reviewer_order_empty_when_nothing_available():
    arms = review.build_arms(_cfg())
    assert review.reviewer_order(arms, 95, set()) == []


def test_reviewer_order_dedupes_provider():
    ladder = LADDER + [{"tier": "frontier2", "provider": "claude-cli",
                        "model": "opus", "effort": "", "min_score": 90}]
    arms = review.build_arms(_cfg(ladder=ladder))
    order = review.reviewer_order(arms, 95, ALL)
    provs = [a.provider for a in order]
    assert len(provs) == len(set(provs))           # each provider once


def test_select_refuter_prefers_different_provider_highest_tier():
    arms = review.build_arms(_cfg())
    reviewer = review.target_arm(arms, 65)          # mid / codex-cli
    ref = review.select_refuter(arms, reviewer, ALL)
    assert ref.provider == "claude-cli"             # frontier, different provider


def test_select_refuter_falls_back_to_self_when_only_one_provider():
    arms = review.build_arms(_cfg())
    reviewer = review.target_arm(arms, 95)          # frontier / claude-cli
    ref = review.select_refuter(arms, reviewer, {"claude-cli"})
    assert ref is reviewer                           # self-refute fallback
