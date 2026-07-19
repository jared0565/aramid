"""arm -- end the per-repo WARN-only semgrep bake (design doc section 8):
sets `semgrep_block_armed = true` in the repo's `aramid.toml`. Always a
manual, deliberate act -- no timer, no auto-promotion.

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
# "Cannot overwrite a value" corruption).
_KEY_RE = re.compile(
    r"(?m)^semgrep_block_armed[^\S\n]*=[^\S\n]*\S+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
_LLM_KEY_RE = re.compile(
    r"(?m)^llm_block_armed[^\S\n]*=[^\S\n]*\S+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
_LLM_SECTION_RE = re.compile(r"(?m)^\[llm\]\s*$")
_AL_SECTION_RE = re.compile(r"(?m)^\[llm\.autolearn\]\s*$")
_AL_KEY_RE = re.compile(
    r"(?m)^armed[^\S\n]*=[^\S\n]*\S+(?P<c>[^\S\n]*#[^\n]*)?[^\S\n]*$")
_NEXT_SECTION_RE = re.compile(r"(?m)^\[")


def _armed_sub(key_re: re.Pattern, new_line: str, text: str, count: int = 0) -> str:
    """Comment-preserving key rewrite: whatever trailing `# ...` the old line
    carried is re-emitted verbatim after the new value."""
    return key_re.sub(lambda m: new_line + (m.group("c") or ""), text, count=count)


def _arm_llm_text(text: str) -> str:
    """Comment-preserving single-key rewrite, mirroring the semgrep path:
    key exists -> substitute; [llm] section exists -> insert the key right
    under the header; neither -> append a fresh [llm] section (a bare
    key at EOF would land inside whatever table happens to be last)."""
    if _LLM_KEY_RE.search(text):
        return _armed_sub(_LLM_KEY_RE, "llm_block_armed = true", text)
    m = _LLM_SECTION_RE.search(text)
    if m:
        insert_at = m.end()
        return text[:insert_at] + "\nllm_block_armed = true" + text[insert_at:]
    prefix = "" if not text or text.endswith("\n") else "\n"
    return text + prefix + "[llm]\nllm_block_armed = true\n"


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
            return (text[:m.end()] + _armed_sub(_AL_KEY_RE, "armed = true",
                                                section, count=1) + text[span_end:])
        return text[:m.end()] + "\narmed = true" + text[m.end():]
    prefix = "" if not text or text.endswith("\n") else "\n"
    return text + prefix + "[llm.autolearn]\narmed = true\n"


def cmd_arm(root, llm: bool = False, autolearn: bool = False) -> int:
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
        print(f"aramid: arm: llm_block_armed=true written to {toml_path}")
        print("aramid: arm: LLM bake ended -- confirmed-CRITICAL llm-review "
              "findings now BLOCK at pre-push.")
        return 0

    if _KEY_RE.search(text):
        new_text = _armed_sub(_KEY_RE, "semgrep_block_armed = true", text)
    else:
        m = _NEXT_SECTION_RE.search(text)
        if m:
            # A bare key appended at EOF would land inside whatever [table]
            # happens to be last (e.g. the [llm] section arm --llm writes) --
            # a ROOT key must be inserted before the first section header.
            new_text = (text[:m.start()] + "semgrep_block_armed = true\n"
                        + text[m.start():])
        else:
            prefix = "" if not text or text.endswith("\n") else "\n"
            new_text = text + prefix + "semgrep_block_armed = true\n"

    toml_path.write_text(new_text, encoding="utf-8")
    print(f"aramid: arm: semgrep_block_armed=true written to {toml_path}")
    print("aramid: arm: WARN-only bake ended -- semgrep BLOCK-tier findings now block.")
    return 0
