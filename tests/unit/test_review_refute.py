import json

from aramid import review
from aramid.review import Packet


def _finding():
    return {"title": "IDOR", "owasp": "a01", "severity": "critical",
            "file": "src/auth.py", "line": 2, "evidence": "return db.get(order_id)",
            "explanation": "no ownership check", "fix_hint": "verify owner",
            "line_content": "    return db.get(order_id)"}


def test_refute_prompt_contains_finding_and_skeptic_contract():
    prompt = review.render_refute_prompt(_finding(), Packet("PKT", ["src/auth.py"], False))
    for token in ("disprove", "IDOR", "return db.get(order_id)", "refuted",
                  "uncertain", "STRICT JSON", "PKT"):
        assert token in prompt


def test_parse_refute_true_false():
    assert review.parse_refute_response(json.dumps({"refuted": True, "reason": "guarded"})) \
        == (True, "guarded")
    assert review.parse_refute_response(json.dumps({"refuted": False, "reason": "real"})) \
        == (False, "real")


def test_parse_refute_malformed_is_none():
    assert review.parse_refute_response("cannot decide") is None
    assert review.parse_refute_response(json.dumps({"verdict": "eh"})) is None


def test_apply_refute_demotes():
    got = review.apply_refute(_finding(), True, "auth handled upstream")
    assert got["severity"] == "high"
    assert got.get("confirmed", False) is False
    assert "auth handled upstream" in got["explanation"]


def test_apply_refute_survivor_confirmed():
    got = review.apply_refute(_finding(), False, "no guard found")
    assert got["severity"] == "critical"
    assert got["confirmed"] is True
