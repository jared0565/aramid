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

_KEY_RE = re.compile(r"(?m)^semgrep_block_armed\s*=\s*\S+\s*$")
_LLM_KEY_RE = re.compile(r"(?m)^llm_block_armed\s*=\s*\S+\s*$")
_LLM_SECTION_RE = re.compile(r"(?m)^\[llm\]\s*$")


def _arm_llm_text(text: str) -> str:
    """Comment-preserving single-key rewrite, mirroring the semgrep path:
    key exists -> substitute; [llm] section exists -> insert the key right
    under the header; neither -> append a fresh [llm] section (a bare
    key at EOF would land inside whatever table happens to be last)."""
    if _LLM_KEY_RE.search(text):
        return _LLM_KEY_RE.sub("llm_block_armed = true", text)
    m = _LLM_SECTION_RE.search(text)
    if m:
        insert_at = m.end()
        return text[:insert_at] + "\nllm_block_armed = true" + text[insert_at:]
    prefix = "" if not text or text.endswith("\n") else "\n"
    return text + prefix + "[llm]\nllm_block_armed = true\n"


def cmd_arm(root, llm: bool = False) -> int:
    root = Path(root)
    toml_path = root / "aramid.toml"
    if not toml_path.exists():
        print(f"aramid: arm: {toml_path} not found -- run `aramid init` first", file=sys.stderr)
        return 3

    text = toml_path.read_text(encoding="utf-8")
    if llm:
        toml_path.write_text(_arm_llm_text(text), encoding="utf-8")
        print(f"aramid: arm: llm_block_armed=true written to {toml_path}")
        print("aramid: arm: LLM bake ended -- confirmed-CRITICAL llm-review "
              "findings now BLOCK at pre-push.")
        return 0

    if _KEY_RE.search(text):
        new_text = _KEY_RE.sub("semgrep_block_armed = true", text)
    else:
        prefix = "" if not text or text.endswith("\n") else "\n"
        new_text = text + prefix + "semgrep_block_armed = true\n"

    toml_path.write_text(new_text, encoding="utf-8")
    print(f"aramid: arm: semgrep_block_armed=true written to {toml_path}")
    print("aramid: arm: WARN-only bake ended -- semgrep BLOCK-tier findings now block.")
    return 0
