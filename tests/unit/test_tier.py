"""unit: `tier.verdict_now` -- what tier is this finding RIGHT NOW.

The stored `verdict` on a ledger row is a snapshot `policy.classify` computed
at detection time, and the ledger is append-only so it never moves again.
Arming is retroactive, rules get demoted, so the stored value and the truth
drift apart with nothing on the row saying so (interop rounds 80, 82, 87 §6).

This function is TRUTH, deliberately not a ratchet. `override._is_block_tier_now`
answers a neighbouring question -- "may a gitignored local suppression hide
this" -- and ORs with the stored verdict so it can only ever refuse MORE.
Collapsing the two would let a demoted rule make an already-stored BLOCK
locally overridable, which is the one direction that command must never move.
The test below that asserts verdict_now can be LOWER than stored is what keeps
them from being merged by a well-meaning future edit.
"""
from pathlib import Path

from aramid import config as config_mod
from aramid.models import Verdict
from aramid.tier import verdict_now

SQLI_RULE = "owasp-top-ten.a03-injection.python-sqli-string-concat"


def _cfg(tmp_path: Path, toml: str):
    (tmp_path / "aramid.toml").write_text(toml, encoding="utf-8")
    return config_mod.load_config(tmp_path)


def _rec(**kw):
    base = {"tool": "semgrep", "rule": SQLI_RULE, "severity": "high", "verdict": "warn"}
    base.update(kw)
    return base


def test_arming_raises_verdict_now_while_the_stored_verdict_stays_warn(tmp_path):
    """The case the whole change exists for: a mutation finding drained during
    the bake stores "warn" forever, and arming makes it BLOCK-tier everywhere
    that recomputes -- with the row still reading "warn"."""
    cfg = _cfg(tmp_path, "[mutation]\nmutation_block_armed = true\n")
    rec = _rec(tool="mutation", rule="survived", severity="medium", verdict="warn")

    assert verdict_now(cfg, rec) is Verdict.BLOCK
    assert rec["verdict"] == "warn", "the stored value must not be rewritten"


def test_verdict_now_can_be_LOWER_than_the_stored_verdict(tmp_path):
    """TRUTH, not a ratchet -- and this is the assertion that stops this
    function being merged with `override._is_block_tier_now`.

    That one ORs with the stored verdict on purpose, so it can never report
    less than the row says. This one must, or it is not answering "what is the
    tier now" but "what is the most severe tier this has ever been".
    """
    cfg = _cfg(tmp_path, "semgrep_block_armed = false\n")
    rec = _rec(verdict="block")  # stored BLOCK from a config that no longer holds

    assert verdict_now(cfg, rec) is Verdict.WARN


def test_a_confirmed_critical_llm_finding_reports_block_though_classify_says_warn(tmp_path):
    """`policy.classify("llm-review", ...)` ALWAYS returns WARN -- the real
    blocking verdict is computed at gate time in `review.llm_gate_findings`
    and never persisted. A plain classify recompute would therefore report
    `warn` for a finding that genuinely blocks, which is the same limb this
    repo has now got wrong twice."""
    cfg = _cfg(tmp_path, "[llm]\nllm_block_armed = true\n")
    rec = _rec(tool="llm-review", rule="llm/a01", severity="critical",
               verdict="warn", source="llm", confirmed=True)

    assert verdict_now(cfg, rec) is Verdict.BLOCK


def test_an_unconfirmed_llm_finding_is_not_promoted(tmp_path):
    """The negative half of the limb above. Without it, a function that simply
    returned BLOCK for every llm-review row would pass the test before this
    one -- and 10 of this repo's own 19 overrides are exactly this shape."""
    cfg = _cfg(tmp_path, "[llm]\nllm_block_armed = true\n")
    rec = _rec(tool="llm-review", rule="llm/a01", severity="medium",
               verdict="warn", source="llm", confirmed=False)

    assert verdict_now(cfg, rec) is Verdict.WARN


def test_gitleaks_stays_block_regardless_of_config(tmp_path):
    """A firing control for the plain-classify path: gitleaks is unconditional
    BLOCK in classify, so this pins that verdict_now really is delegating
    rather than reimplementing the tier rules."""
    cfg = _cfg(tmp_path, "semgrep_block_armed = false\n")
    rec = _rec(tool="gitleaks", rule="aws-key", severity="high", verdict="block")

    assert verdict_now(cfg, rec) is Verdict.BLOCK
