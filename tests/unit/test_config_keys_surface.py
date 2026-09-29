"""The `aramid.toml` key set is public surface (API-2), and the knowledge
base documents every key of it (DOC-12).

Three lists must agree: the keys aramid reads (`config_keys.known_keys()`:
defaults.toml plus OPTIONAL), the `Config` dataclass, and KB section 2. The
first is frozen here, so adding, removing or retyping a key is a decision a
CHANGELOG entry records rather than a side effect. The dataclass is held to
it in both directions (`test_config_keys.py` holds one). The KB is held to
it row by row: a key with no row in its own table is a key a user cannot
look up, and without this guard the reference decays within a month.
"""
import re
from dataclasses import fields
from pathlib import Path

from aramid import config_keys
from aramid.config import Config

KB = Path(__file__).resolve().parents[2] / "docs" / "knowledge-base.md"

KNOWN = {
    "agent_block_armed": "boolean",
    "bake_started": "string",
    "block_rules": "table",
    "dast": "table",
    "dast.base_url": "string",
    "dast.enabled": "boolean",
    "dast.paths": "list",
    "dast.timeout_s": "number",
    "deps": "table",
    "deps.cargo_audit_warnings": "boolean",
    "drain": "table",
    "drain.hard_deadline_s": "number",
    "drain.interval_hours": "number",
    "drain.item_expiry_days": "number",
    "drain.max_items_per_drain": "number",
    "drain.wall_clock_budget_s": "number",
    "fuzz": "table",
    "fuzz.batch_timeout_s": "number",
    "fuzz.cases_per_function": "number",
    "fuzz.enabled": "boolean",
    "fuzz.max_functions": "number",
    "fuzz.skip_name_patterns": "list",
    "fuzz.wall_budget_s": "number",
    "hooks": "table",
    "hooks.pre_push_match_ci": "boolean",
    "ignore_paths": "list",
    "js_mutation": "table",
    "js_mutation.baseline_timeout_s": "number",
    "js_mutation.enabled": "boolean",
    "js_mutation.max_mutants": "number",
    "js_mutation.mutant_timeout_s": "number",
    "js_mutation.wall_budget_s": "number",
    "llm": "table",
    "llm.autolearn": "table",
    "llm.autolearn.armed": "boolean",
    "llm.autolearn.audit_every": "number",
    "llm.autolearn.cascade_hallucination_min": "number",
    "llm.autolearn.enabled": "boolean",
    "llm.autolearn.max_audits_per_drain": "number",
    "llm.autolearn.uplift_threshold": "number",
    "llm.call_timeout_s": "number",
    "llm.enabled": "boolean",
    "llm.ladder": "list",
    "llm.llm_block_armed": "boolean",
    "llm.max_items_per_drain": "number",
    "llm.max_refutes_per_drain": "number",
    "llm.openrouter_monthly_cap_usd": "number",
    "llm.packet_max_bytes": "number",
    "llm.provider_order": "list",
    "mutation": "table",
    "mutation.baseline_timeout_s": "number",
    "mutation.confirm_cap": "number",
    "mutation.enabled": "boolean",
    "mutation.max_mutants": "number",
    "mutation.mutant_timeout_s": "number",
    "mutation.mutation_block_armed": "boolean",
    "mutation.retest_cap": "number",
    "mutation.retest_open_survivors": "boolean",
    "mutation.score_block_armed": "boolean",
    "mutation.test_command": "command",
    "mutation.wall_budget_s": "number",
    "pack": "table",
    "pack.enabled": "boolean",
    "pack.pack_block_armed": "boolean",
    "red_proof": "table",
    "red_proof.enabled": "boolean",
    "red_proof.red_proof_block_armed": "boolean",
    "red_proof.test_timeout_s": "number",
    "red_proof.wall_budget_s": "number",
    "schema_version": "number",
    "semgrep_block_armed": "boolean",
    "shadow": "table",
    "shadow.shadow_block_armed": "boolean",
    "tdd": "table",
    "tdd.enabled": "boolean",
    "tdd_block_armed": "boolean",
    "test_command": "command",
    "tests": "table",
    "tests.command": "command",
    "tests.enabled": "boolean",
    "tests.timeout_s": "number",
    "timeouts": "table",
    "timeouts.pre_commit": "number",
    "timeouts.pre_push": "number",
    "triage": "table",
    "triage.extra_security_paths": "list",
    "triage.min_score": "number",
}
LADDER = {"tier": "string", "provider": "string", "model": "string",
          "effort": "string", "min_score": "number"}


def test_the_keys_aramid_reads_are_exactly_these():
    got = {".".join(path): kind for path, kind in config_keys.known_keys().items()}
    assert got == KNOWN


def test_a_ladder_entry_has_exactly_these_keys():
    assert config_keys.LADDER_KEYS == LADDER


def test_every_top_level_key_is_a_config_field_and_back():
    top = {path[0] for path in config_keys.known_keys()}
    assert top == {f.name for f in fields(Config)}


def _blocks() -> dict[str, str]:
    """KB section 2 split into one block per table: `### Top level` is "",
    `### `[t]`` is "t", and a bold `**`[t.sub]`**` or `**`[[t.sub]]`**` inside a
    section starts that sub-table's block."""
    text = KB.read_text(encoding="utf-8")
    s2 = text[text.index("## 2. Configuration Reference"):text.index("## 3. Consumer Reference")]
    blocks: dict[str, str] = {}
    name = None
    for line in s2.splitlines():
        m = (re.match(r"### `\[([a-z_.]+)\]`", line)
             or re.match(r"\*\*`\[\[?([a-z_.]+)\]?\]`\*\*", line))
        if line.startswith("### Top level"):
            name = ""
        elif m:
            name = m.group(1)
        elif line.startswith("### "):
            name = None       # a prose section (collisions, arming inventory)
        if name is not None:
            blocks[name] = blocks.get(name, "") + line + "\n"
    return blocks


def _has_row(block: str, key: str) -> bool:
    return re.search(rf"(?m)^\| `{re.escape(key)}` \|", block) is not None


def test_the_kb_documents_every_key_in_its_own_table():
    blocks = _blocks()
    assert {"", "llm", "llm.autolearn", "llm.ladder", "drain"} <= set(blocks), \
        f"the section-2 split has gone blind: {sorted(blocks)}"
    missing = []
    for path, kind in config_keys.known_keys().items():
        if path in config_keys.OPEN_TABLES:
            continue          # its keys are rule tables, documented in prose
        if kind == "table":
            if ".".join(path) not in blocks:
                missing.append(f"[{'.'.join(path)}] has no table of its own")
            continue
        table = ".".join(path[:-1])
        if path == ("llm", "ladder"):
            continue          # an array of tables: its keys are the columns below
        if not _has_row(blocks.get(table, ""), path[-1]):
            missing.append(f"{'.'.join(path)} has no row in [{table}]" if table
                           else f"{path[-1]} has no row in the top-level table")
    assert missing == []


def test_the_kb_ladder_table_has_a_column_per_ladder_key():
    header = next(line for line in _blocks()["llm.ladder"].splitlines()
                  if line.startswith("|"))
    assert {c.strip() for c in header.strip("|").split("|")} == set(config_keys.LADDER_KEYS)
