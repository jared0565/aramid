import json

from aramid import review
from aramid.review import Packet


def _pkt(text, files=("src/auth.py",)):
    return Packet(text=text, files=list(files), truncated=False)


def _cand(**over):
    d = {"title": "IDOR on order endpoint", "owasp": "a01", "severity": "critical",
         "file": "src/auth.py", "line": 2, "evidence": "return db.get(order_id)",
         "explanation": "no ownership check", "fix_hint": "verify owner"}
    d.update(over)
    return d


def test_parse_strict_json():
    got = review.parse_review_response(json.dumps({"findings": [_cand()]}))
    assert got[0]["title"] == "IDOR on order endpoint"


def test_parse_tolerates_markdown_fences():
    body = "```json\n" + json.dumps({"findings": []}) + "\n```"
    assert review.parse_review_response(body) == []


def test_parse_garbage_is_none():
    assert review.parse_review_response("I found three issues: ...") is None


def test_parse_non_str_input_is_none():
    # FIX 3: non-str input must return None, not raise. json.loads(None) and
    # json.loads(123) raise TypeError; json.loads(bytes) silently succeeds
    # but bytes is not a valid contract input either -- all map to None.
    assert review.parse_review_response(None) is None
    assert review.parse_review_response(123) is None
    assert review.parse_review_response(b'{"findings":[]}') is None


def test_parse_drops_schema_invalid_entries():
    good, bad_sev, missing_ev = _cand(), _cand(severity="urgent"), _cand()
    del missing_ev["evidence"]
    got = review.parse_review_response(json.dumps({"findings": [good, bad_sev, missing_ev]}))
    assert len(got) == 1


def test_verify_accepts_verbatim_quote_and_anchors_line(tmp_path, monkeypatch):
    file_content = "def get_order(order_id):\n    return db.get(order_id)\n"
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint",
                        lambda root, ref, f: file_content)
    pkt = _pkt("stuff\n" + file_content + "\nmore")
    verified, rejected = review.verify_findings([_cand(line=99)], pkt, tmp_path, "headsha")
    assert rejected == 0
    assert verified[0]["line"] == 2                      # derived, not the LLM's 99
    assert verified[0]["line_content"] == "    return db.get(order_id)"


def test_verify_whitespace_normalized_quote(tmp_path, monkeypatch):
    file_content = "x = 1\nreturn   db.get( order_id )\n"
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint",
                        lambda root, ref, f: file_content)
    pkt = _pkt(file_content)
    cand = _cand(evidence="return db.get( order_id )")
    verified, rejected = review.verify_findings([cand], pkt, tmp_path, "h")
    assert len(verified) == 1 and rejected == 0


def test_verify_rejects_quote_not_in_packet(tmp_path, monkeypatch):
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint",
                        lambda root, ref, f: "return db.get(order_id)\n")
    pkt = _pkt("completely different content")
    verified, rejected = review.verify_findings([_cand()], pkt, tmp_path, "h")
    assert verified == [] and rejected == 1


def test_verify_rejects_quote_only_in_removed_lines(tmp_path, monkeypatch):
    # quote appears in the packet (old diff side) but NOT in the head file
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint",
                        lambda root, ref, f: "return safe_get(order_id, user)\n")
    pkt = _pkt("-    return db.get(order_id)\n+    return safe_get(order_id, user)")
    verified, rejected = review.verify_findings([_cand()], pkt, tmp_path, "h")
    assert verified == [] and rejected == 1


def test_verify_rejects_file_outside_packet(tmp_path, monkeypatch):
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint",
                        lambda root, ref, f: "return db.get(order_id)\n")
    pkt = _pkt("return db.get(order_id)", files=("src/other.py",))
    verified, rejected = review.verify_findings([_cand()], pkt, tmp_path, "h")
    assert verified == [] and rejected == 1


def test_verify_drops_malformed_candidates_without_raising(tmp_path, monkeypatch):
    # FIX 1: verify_findings must never raise on a crafted candidate dict --
    # missing "file", missing "evidence", or evidence=None must all be
    # dropped (counted as rejected) rather than raising KeyError/TypeError.
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint",
                        lambda root, ref, f: "return db.get(order_id)\n")
    pkt = _pkt("return db.get(order_id)")
    missing_file = _cand()
    del missing_file["file"]
    missing_evidence = _cand()
    del missing_evidence["evidence"]
    none_evidence = _cand(evidence=None)
    candidates = [missing_file, missing_evidence, none_evidence]
    verified, rejected = review.verify_findings(candidates, pkt, tmp_path, "h")
    assert verified == []
    assert rejected == len(candidates)


def test_verify_rejects_multiline_quote_bound_to_wrong_file(tmp_path, monkeypatch):
    # FIX 2: multi-line evidence bypass. The packet contains file A's body
    # (with "except Exception:\n    pass") and also names file B in
    # packet.files. A candidate for B quotes that same multi-line snippet,
    # which does appear somewhere in the packet (file A's section) and whose
    # FIRST line ("except Exception:") also appears in B's head content --
    # but B's head content does NOT contain the quote's full body verbatim.
    # This must be rejected: the quote has to bind to the NAMED file's own
    # live content, not merely appear somewhere in the packet.
    file_a_body = "def f():\n    try:\n        g()\n    except Exception:\n        pass\n"
    file_b_head = "def h():\n    try:\n        g()\n    except Exception:\n        grant_admin(user)\n"

    def _read(root, ref, f):
        assert f == "src/b.py"    # verify_findings only reads the candidate's own file
        return file_b_head

    monkeypatch.setattr(review.gitutil, "read_for_fingerprint", _read)
    pkt_text = (
        "--- FILE: src/a.py ---\n" + file_a_body +
        "--- FILE: src/b.py ---\n" + file_b_head
    )
    pkt = _pkt(pkt_text, files=("src/a.py", "src/b.py"))
    cand = _cand(file="src/b.py", evidence="except Exception:\n        pass")
    verified, rejected = review.verify_findings([cand], pkt, tmp_path, "h")
    assert verified == []
    assert rejected == 1


def test_llm_fingerprint_stable():
    a = review.llm_fingerprint("llm/a01", "src/auth.py", "  return db.get(order_id)")
    b = review.llm_fingerprint("llm/a01", "src/auth.py", "return   db.get(order_id)")
    assert a == b                                        # whitespace-normalized


def test_prompt_contains_contract_and_packet():
    pkt = _pkt("PACKETBODY")
    prompt = review.render_review_prompt(pkt)
    for token in ("STRICT JSON", "evidence", "a01", "UNTRUSTED", "PACKETBODY",
                  "empty", "critical"):
        assert token in prompt


# --- the rejections and caps the integration reviewer reached first --------
#
# The drain confirms a mutant against the unit suite alone; a head file that
# cannot be read, a quote that spans two lines (verbatim in the squashed
# content, anchored to no single line), the dependents cap of 50 and the
# evidence cap of 400 were exercised only by tests/integration/test_review*.py.

def test_verify_rejects_a_candidate_whose_head_file_cannot_be_read(tmp_path, monkeypatch):
    def read(root, ref, f):
        raise RuntimeError(f"no blob for {f}")
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint", read)
    pkt = _pkt("return db.get(order_id)\n")
    assert review.verify_findings([_cand()], pkt, tmp_path, "h") == ([], 1)


def test_verify_rejects_a_quote_that_no_single_head_line_anchors(tmp_path, monkeypatch):
    file_content = "x = 1\nreturn db.get(\n    order_id)\n"
    monkeypatch.setattr(review.gitutil, "read_for_fingerprint",
                        lambda root, ref, f: file_content)
    pkt = _pkt(file_content)
    # Verbatim once whitespace is squashed, so it passes both content checks
    # -- but its first line, "return db.get( order_id)", is on no line.
    cand = _cand(evidence="return db.get( order_id)")
    assert review.verify_findings([cand], pkt, tmp_path, "h") == ([], 1)


def test_parse_caps_evidence_at_400_characters():
    long = "x" * 401
    got = review.parse_review_response(json.dumps({"findings": [_cand(evidence=long)]}))
    assert got[0]["evidence"] == "x" * 400
    exact = "y" * 400
    got = review.parse_review_response(json.dumps({"findings": [_cand(evidence=exact)]}))
    assert got[0]["evidence"] == exact


def test_parse_drops_an_entry_whose_required_field_is_not_a_non_empty_string():
    """`isinstance(v, str) and v` -- both halves: an int title and an empty
    evidence each drop the entry (the derive drew `and` -> `or`, which keeps
    both)."""
    body = json.dumps({"findings": [_cand(title=7), _cand(evidence=""), _cand()]})
    got = review.parse_review_response(body)
    assert [g["title"] for g in got] == ["IDOR on order endpoint"]
