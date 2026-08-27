"""arm -- end the per-repo WARN-only semgrep bake (design doc section 8):
sets `semgrep_block_armed = true` in the repo's `aramid.toml`. Always a
manual, deliberate act -- no timer, no auto-promotion.

THAT LAST CLAUSE IS A PRECONDITION OF A DESIGN ELSEWHERE, NOT JUST A
DESCRIPTION OF TODAY. Read this before adding any automatic arming --
a bake that promotes on expiry, a scheduled sweep, a config default that
flips on upgrade.

The agreed design for stale overrides (interop rounds 84 §2, 87 §5, 89) is
that arming INVALIDATES an override made while the tool was disarmed and
re-opens the finding, because an operator who suppressed a WARN was never
asked whether they would suppress a BLOCK. That is safe only while arming is
operator-initiated: the person just typed `aramid arm`, asked to be blocked
by this class, and is present to deal with the fallout. Make arming
automatic and the same mechanism re-opens N findings unattended -- a gate
that was green goes red at 3am with nobody able to say what changed.

So: if arming ever becomes automatic, that invalidation must move behind an
explicit operator acknowledgement rather than firing on the arming event.

Confirmed by graph rather than by this docstring when the design was
settled: `cmd_arm`'s only non-test caller is `cli.main`, no other module
writes a `*_block_armed` key, and `bake_started` is read only by
`commands/status.py` for display -- there is no expiry path to promote from.
The note lives HERE, in the file such a feature would be added to, because a
precondition recorded somewhere else is one the breaking change never sees.
Same shape as the `-P` trampoline fix, where the fix was sound and what
undid it was a later change one hop away.

Targeted regex substitution rather than a tomllib-parse/tomli_w-dump
round-trip: TOML comments (e.g. the `# aramid repo config -- detected
stack: ...` header `aramid.config.render_repo_stub` writes) are not
preserved by `tomllib.loads` -- re-serializing the whole file would
silently strip them on every `arm`. Rewriting just the one key preserves
everything else in the file byte-for-byte, mirroring
`aramid.commands.init._update_gitignore`'s own append-only-what's-missing
style.
"""
import re
import sys
from pathlib import Path

# Key-line rewrite family. Horizontal-whitespace-only classes ([^\S\n]) so a
# match can never swallow the newline/section boundary after the line (the
# Task-11 _AL_KEY_RE lesson, now applied to all three), and an optional
# trailing inline comment is captured in group `c` and preserved verbatim by
# _armed_sub (a missed match here inserts a DUPLICATE key -> tomllib
# "Cannot overwrite a value" corruption). The value class excludes `#` so a
# comment abutting the value (`false#x`) lands in `c` instead of being
# swallowed -- safe because these keys only ever hold true/false.
_KEY_RE = re.compile(
    r"(?m)^semgrep_block_armed[^\S\n]*=[^\S\n]*[^\s#]+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
_TDD_KEY_RE = re.compile(
    r"(?m)^tdd_block_armed[^\S\n]*=[^\S\n]*[^\s#]+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
_LLM_KEY_RE = re.compile(
    r"(?m)^llm_block_armed[^\S\n]*=[^\S\n]*[^\s#]+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
_LLM_SECTION_RE = re.compile(r"(?m)^\[llm\]\s*$")
_MUT_KEY_RE = re.compile(
    r"(?m)^mutation_block_armed[^\S\n]*=[^\S\n]*[^\s#]+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
_MUT_SECTION_RE = re.compile(r"(?m)^\[mutation\]\s*$")
_SCORE_KEY_RE = re.compile(
    r"(?m)^score_block_armed[^\S\n]*=[^\S\n]*[^\s#]+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
_RP_KEY_RE = re.compile(
    r"(?m)^red_proof_block_armed[^\S\n]*=[^\S\n]*[^\s#]+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
_RP_SECTION_RE = re.compile(r"(?m)^\[red_proof\]\s*$")
_SHADOW_KEY_RE = re.compile(
    r"(?m)^shadow_block_armed[^\S\n]*=[^\S\n]*[^\s#]+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
_SHADOW_SECTION_RE = re.compile(r"(?m)^\[shadow\]\s*$")
_AL_SECTION_RE = re.compile(r"(?m)^\[llm\.autolearn\]\s*$")
_AL_KEY_RE = re.compile(
    r"(?m)^armed[^\S\n]*=[^\S\n]*[^\s#]+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
_NEXT_SECTION_RE = re.compile(r"(?m)^\[")


def _armed_sub(key_re: re.Pattern, new_line: str, text: str, count: int = 0) -> str:
    """Comment-preserving key rewrite: whatever trailing `# ...` the old line
    carried is re-emitted verbatim after the new value."""
    return key_re.sub(lambda m: new_line + (m.group("c") or ""), text, count=count)


# WHERE A KEY IS READ DECIDES WHERE IT MAY BE WRITTEN. Every rewrite below is
# scoped to the span the loader actually reads the key from -- a [section]'s
# body, or the root span before the first header -- and a same-named key
# anywhere else is never the target. That scoping used to exist only for
# `armed` under [llm.autolearn], justified by its generic name; the others
# searched the whole file, and their docstrings said a globally unique key
# name made scoping unnecessary. Measured 2026-08-27, on the commit that added
# --shadow: a stray top-level `shadow_block_armed = false` was rewritten to
# true, `arm --shadow` printed its BLOCKS line and returned 0, and
# `[shadow].shadow_block_armed` -- the only key policy.classify reads --
# stayed unset. Uniqueness across sections was never the risk; placement was.


def _section_span(text: str, section_re: re.Pattern) -> tuple[int, int] | None:
    """(start, end) of the BODY of the section `section_re` heads: from the
    end of its header line to the next `[` header or EOF. None if absent."""
    m = section_re.search(text)
    if not m:
        return None
    nxt = _NEXT_SECTION_RE.search(text, m.end())
    return m.end(), (nxt.start() if nxt else len(text))


def _root_span(text: str) -> tuple[int, int]:
    """(0, end) of the root table: everything before the first `[` header."""
    m = _NEXT_SECTION_RE.search(text)
    return 0, (m.start() if m else len(text))


def _misplaced_lines(text: str, key_re: re.Pattern,
                     span: tuple[int, int] | None) -> list[int]:
    """1-based line numbers of `key_re` matches OUTSIDE `span` -- copies the
    loader never reads. With no span at all, every match is misplaced."""
    lo, hi = span if span else (0, 0)
    return [text.count("\n", 0, m.start()) + 1
            for m in key_re.finditer(text) if not (lo <= m.start() < hi)]


def _arm_sectioned_key(text: str, section_re: re.Pattern, key_re: re.Pattern,
                       new_line: str, header: str) -> str:
    """Comment-preserving single-key rewrite scoped to `header`'s section:
    key inside the section -> substitute in place; section without the key ->
    insert under the header; no section -> append a fresh one (a bare key at
    EOF would land inside whatever table happens to be last)."""
    span = _section_span(text, section_re)
    if span:
        start, end = span
        body = text[start:end]
        if key_re.search(body):
            return text[:start] + _armed_sub(key_re, new_line, body, count=1) + text[end:]
        return text[:start] + "\n" + new_line + text[start:]
    prefix = "" if not text or text.endswith("\n") else "\n"
    return text + prefix + header + "\n" + new_line + "\n"


def _arm_root_key(text: str, key_re: re.Pattern, new_line: str) -> str:
    """The same for a ROOT key, scoped to the span before the first header:
    key at the root -> substitute in place; a section follows -> insert before
    its header (appending at EOF would land the key inside the last table);
    no sections -> append."""
    start, end = _root_span(text)
    body = text[start:end]
    if key_re.search(body):
        return text[:start] + _armed_sub(key_re, new_line, body, count=1) + text[end:]
    if end < len(text):
        return text[:end] + new_line + "\n" + text[end:]
    prefix = "" if not text or text.endswith("\n") else "\n"
    return text + prefix + new_line + "\n"


def _report_misplaced(text: str, key_re: re.Pattern, span: tuple[int, int] | None,
                      key: str, where: str) -> None:
    """Name every same-named key the rewrite deliberately left alone. It is
    the operator's text, so it is not deleted -- but ignoring it silently is
    how a stray `= true` keeps looking armed. Only for the six uniquely-named
    keys: `armed` under [llm.autolearn] is generic, and an `armed` in some
    other table is legitimately somebody else's."""
    for ln in _misplaced_lines(text, key_re, span):
        print(f"aramid: arm: NOTE: `{key}` at line {ln} is outside {where}, where "
              f"aramid never reads it -- left untouched; delete it to avoid confusion.",
              file=sys.stderr)


def _arm_llm_text(text: str) -> str:
    return _arm_sectioned_key(text, _LLM_SECTION_RE, _LLM_KEY_RE,
                              "llm_block_armed = true", "[llm]")


def _arm_mutation_text(text: str) -> str:
    """Never matches [js_mutation]: the section regex anchors on [mutation]."""
    return _arm_sectioned_key(text, _MUT_SECTION_RE, _MUT_KEY_RE,
                              "mutation_block_armed = true", "[mutation]")


def _arm_mutation_score_text(text: str) -> str:
    return _arm_sectioned_key(text, _MUT_SECTION_RE, _SCORE_KEY_RE,
                              "score_block_armed = true", "[mutation]")


def _arm_red_proof_text(text: str) -> str:
    return _arm_sectioned_key(text, _RP_SECTION_RE, _RP_KEY_RE,
                              "red_proof_block_armed = true", "[red_proof]")


def _arm_autolearn_text(text: str) -> str:
    """`armed` is a generic key name, so this one was scoped from the start;
    it is now the same code path as the rest."""
    return _arm_sectioned_key(text, _AL_SECTION_RE, _AL_KEY_RE,
                              "armed = true", "[llm.autolearn]")


def _arm_shadow_text(text: str) -> str:
    return _arm_sectioned_key(text, _SHADOW_SECTION_RE, _SHADOW_KEY_RE,
                              "shadow_block_armed = true", "[shadow]")


def cmd_arm(root, llm: bool = False, autolearn: bool = False, tdd: bool = False,
            mutation: bool = False, mutation_score: bool = False,
            red_proof: bool = False, shadow: bool = False) -> int:
    root = Path(root)
    toml_path = root / "aramid.toml"
    if not toml_path.exists():
        print(f"aramid: arm: {toml_path} not found -- run `aramid init` first", file=sys.stderr)
        return 3

    text = toml_path.read_text(encoding="utf-8")
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

    if llm:
        toml_path.write_text(_arm_llm_text(text), encoding="utf-8")
        _report_misplaced(text, _LLM_KEY_RE, _section_span(text, _LLM_SECTION_RE),
                          "llm_block_armed", "[llm]")
        print(f"aramid: arm: llm_block_armed=true written to {toml_path}")
        print("aramid: arm: LLM bake ended -- confirmed-CRITICAL llm-review "
              "findings now BLOCK at pre-push.")
        return 0

    if mutation:
        toml_path.write_text(_arm_mutation_text(text), encoding="utf-8")
        _report_misplaced(text, _MUT_KEY_RE, _section_span(text, _MUT_SECTION_RE),
                          "mutation_block_armed", "[mutation]")
        print(f"aramid: arm: mutation_block_armed=true written to {toml_path}")
        print("aramid: arm: mutation bake ended -- surviving-mutant findings "
              "now BLOCK at pre-push.")
        return 0

    if mutation_score:
        toml_path.write_text(_arm_mutation_score_text(text), encoding="utf-8")
        _report_misplaced(text, _SCORE_KEY_RE, _section_span(text, _MUT_SECTION_RE),
                          "score_block_armed", "[mutation]")
        print(f"aramid: arm: score_block_armed=true written to {toml_path}")
        print("aramid: arm: mutation-score bake ended -- transition "
              "regressions now BLOCK at pre-push.")
        return 0

    if red_proof:
        toml_path.write_text(_arm_red_proof_text(text), encoding="utf-8")
        _report_misplaced(text, _RP_KEY_RE, _section_span(text, _RP_SECTION_RE),
                          "red_proof_block_armed", "[red_proof]")
        print(f"aramid: arm: red_proof_block_armed=true written to {toml_path}")
        print("aramid: arm: red-first bake ended -- never-red test findings "
              "now BLOCK at pre-push.")
        return 0

    if shadow:
        toml_path.write_text(_arm_shadow_text(text), encoding="utf-8")
        _report_misplaced(text, _SHADOW_KEY_RE, _section_span(text, _SHADOW_SECTION_RE),
                          "shadow_block_armed", "[shadow]")
        print(f"aramid: arm: shadow_block_armed=true written to {toml_path}")
        # NOT "at pre-push" like its siblings: `shadow` is in _GATE_TOOLS for
        # PRE_COMMIT as well, so arming it changes what happens at COMMIT time.
        # An operator told "pre-push" would not expect the next commit refused.
        print("aramid: arm: shadow bake ended -- a repo-root file that hijacks "
              "`python -m aramid` now BLOCKS at every gate, pre-commit included.")
        return 0

    if tdd:
        new_text = _arm_root_key(text, _TDD_KEY_RE, "tdd_block_armed = true")
        _report_misplaced(text, _TDD_KEY_RE, _root_span(text),
                          "tdd_block_armed", "the root table")
        toml_path.write_text(new_text, encoding="utf-8")
        print(f"aramid: arm: tdd_block_armed=true written to {toml_path}")
        print("aramid: arm: TDD bake ended -- code-without-test findings now BLOCK at pre-push.")
        return 0

    new_text = _arm_root_key(text, _KEY_RE, "semgrep_block_armed = true")
    _report_misplaced(text, _KEY_RE, _root_span(text),
                      "semgrep_block_armed", "the root table")

    toml_path.write_text(new_text, encoding="utf-8")
    print(f"aramid: arm: semgrep_block_armed=true written to {toml_path}")
    print("aramid: arm: WARN-only bake ended -- semgrep BLOCK-tier findings now block.")
    return 0
