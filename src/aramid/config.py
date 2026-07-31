"""config -- three-layer TOML config (defaults <- ~/.aramid/config.toml <-
<root>/aramid.toml), the always-on ignore-path filter, the suppressions-file
loader, and the near-empty per-repo config stub `init` writes.
"""
import fnmatch
import sys
from copy import deepcopy
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import tomllib
import tomli_w

from aramid.fingerprint import compute_fingerprint, normalize_path
from aramid.models import Finding, Gate, Severity, Source, Verdict
from aramid.policy import OverrideRecord, load_block_rules

CURRENT_SCHEMA_VERSION = 1

# Hard requirement (spec section 8b): these are NEVER removable by user/repo
# config, unioned in after every merge, regardless of what a repo's
# aramid.toml sets for `ignore_paths` (including an explicit `[]`).
_BUILTIN_IGNORE_PATHS = (
    ".aramid/", "graph-out/", ".graphite*", ".cache/",
    "node_modules/", ".venv/", "__pycache__/", ".git/",
)


@dataclass
class Config:
    schema_version: int
    semgrep_block_armed: bool
    bake_started: str | None
    ignore_paths: list[str]
    test_command: str | None
    scope_subpath: str | None
    timeouts: dict
    block_rules: dict
    triage: dict
    drain: dict
    pack: dict
    llm: dict
    mutation: dict = field(default_factory=dict)
    fuzz: dict = field(default_factory=dict)
    js_mutation: dict = field(default_factory=dict)
    dast: dict = field(default_factory=dict)
    tdd_block_armed: bool = False
    tdd: dict = field(default_factory=dict)
    red_proof: dict = field(default_factory=dict)
    tests: dict = field(default_factory=dict)


def _user_config_path() -> Path:
    """Seam for tests -- monkeypatch this rather than touching a real
    ~/.aramid/config.toml on the machine running the test suite."""
    return Path.home() / ".aramid" / "config.toml"


def _read_data_toml(name: str) -> dict:
    text = resources.files("aramid").joinpath("data", name).read_text(encoding="utf-8")
    return tomllib.loads(text)


def _read_toml_file(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _deep_merge(base: dict, override: dict) -> dict:
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _enforce_block_rules_floor(floor: dict, merged: dict) -> dict:
    """A repo's `aramid.toml` legitimately demoting a noisy BLOCK-tier rule is
    an intended, documented capability (`block_rules.toml`'s own header:
    "Repos demote noisy entries via aramid.toml"). But `_deep_merge` replaces
    a list-valued leaf wholesale rather than unioning it, so the SAME
    mechanism let a repo silently clear an entire tool's block list in one
    edit. First fixed (87d302f) as a stderr-only notice; reported again,
    independently, by Operation Firewall's own coding agent once aramid was
    actually running as a real gate on their repo -- a notice is not a
    floor, and their threat model names "a malicious repository" as an
    actor: an adversarial contributor to the SAME repo, who can also edit
    or silence stderr, is exactly what a notice does not stop.

    `floor` is the block_rules state AFTER defaults+user-config merge but
    BEFORE the repo layer touches it -- whatever the operator's own machine
    already established, including any of THEIR OWN demotions. `merged` is
    the state after the repo layer's aramid.toml was merged in. Returns
    `merged` with every entry from `floor` unioned back in: the repo layer
    may only ADD block-tier rule ids relative to `floor`, never remove one.
    User-level (`~/.aramid/config.toml`) demotion is deliberately NOT
    floored here -- it already lives inside `floor` itself, so it is
    preserved automatically; only the repo layer, the one an outside
    contributor can commit to, is constrained. Prints a stderr notice
    naming exactly what a repo's aramid.toml attempted to remove and was
    restored -- an attempt is still visible even though it can no longer
    succeed."""
    enforced = deepcopy(merged)
    for tool, floor_tool in floor.items():
        if not isinstance(floor_tool, dict):
            continue
        merged_tool = enforced.get(tool)
        if not isinstance(merged_tool, dict):
            merged_tool = {}
            enforced[tool] = merged_tool
        for key, floor_value in floor_tool.items():
            if not isinstance(floor_value, list):
                continue
            merged_value = merged_tool.get(key, [])
            if not isinstance(merged_value, list):
                merged_value = []
            missing = [item for item in floor_value if item not in merged_value]
            if missing:
                merged_tool[key] = merged_value + missing
                print(f"aramid: config: aramid.toml narrowed block_rules.{tool}.{key} -- "
                      f"restored {missing!r} (a repo's own aramid.toml cannot remove a "
                      f"rule the operator's config already established; demote it in "
                      f"~/.aramid/config.toml instead if that's genuinely wanted).",
                      file=sys.stderr)
    return enforced


def load_config(root: Path) -> Config:
    merged = _read_data_toml("defaults.toml")
    merged["block_rules"] = load_block_rules()

    user_path = _user_config_path()
    if user_path.exists():
        merged = _deep_merge(merged, _read_toml_file(user_path))

    repo_path = root / "aramid.toml"
    repo_schema_version = None
    if repo_path.exists():
        repo_toml = _read_toml_file(repo_path)
        repo_schema_version = repo_toml.get("schema_version")
        pre_repo_block_rules = merged.get("block_rules", {})
        merged = _deep_merge(merged, repo_toml)
        merged["block_rules"] = _enforce_block_rules_floor(
            pre_repo_block_rules, merged.get("block_rules", {}))

    if repo_schema_version is not None and repo_schema_version != CURRENT_SCHEMA_VERSION:
        print(f"aramid: config schema v{repo_schema_version}→v{CURRENT_SCHEMA_VERSION}; "
              f"review aramid.toml", file=sys.stderr)

    ignore_paths = list(dict.fromkeys((*merged.get("ignore_paths", []), *_BUILTIN_IGNORE_PATHS)))

    return Config(
        schema_version=merged.get("schema_version", CURRENT_SCHEMA_VERSION),
        semgrep_block_armed=merged.get("semgrep_block_armed", False),
        bake_started=merged.get("bake_started"),
        ignore_paths=ignore_paths,
        test_command=merged.get("test_command"),
        scope_subpath=merged.get("scope_subpath"),
        timeouts=merged.get("timeouts", {}),
        block_rules=merged.get("block_rules", {}),
        triage=merged.get("triage", {}),
        drain=merged.get("drain", {}),
        pack=merged.get("pack", {}),
        llm=merged.get("llm", {}),
        mutation=merged.get("mutation", {}),
        fuzz=merged.get("fuzz", {}),
        js_mutation=merged.get("js_mutation", {}),
        dast=merged.get("dast", {}),
        tdd_block_armed=merged.get("tdd_block_armed", False),
        tdd=merged.get("tdd", {}),
        red_proof=merged.get("red_proof", {}),
        tests=merged.get("tests", {}),
    )


def is_ignored(rel_path: str, ignore_paths: list[str]) -> bool:
    norm = normalize_path(rel_path)
    for entry in ignore_paths:
        e = normalize_path(entry)
        if norm.startswith(e) or fnmatch.fnmatch(norm, e):
            return True
    return False


def filter_paths(files: list[str], cfg: Config) -> list[str]:
    return [f for f in files if not is_ignored(f, cfg.ignore_paths)]


def load_suppressions(root: Path) -> tuple[list[OverrideRecord], list[Finding]]:
    path = root / ".aramid-suppressions.toml"
    if not path.exists():
        return [], []

    data = _read_toml_file(path)
    records: list[OverrideRecord] = []
    warnings: list[Finding] = []

    for entry in data.get("suppress", []):
        tool = entry.get("tool", "")
        rule = entry.get("rule", "")
        raw_path = entry.get("path", "")
        entry_id = entry.get("id", "")
        reason = (entry.get("reason") or "").strip()

        if not reason:
            finding_id = compute_fingerprint(
                "aramid", "suppression-without-reason", raw_path or entry_id,
                entry_id or raw_path, 0)
            warnings.append(Finding(
                id=finding_id, tool="aramid", rule="suppression-without-reason",
                severity_raw="low", severity=Severity.LOW, verdict=Verdict.WARN,
                file=raw_path or ".aramid-suppressions.toml", line=0,
                message=f"suppression entry for {tool}/{rule} (id={entry_id}) is missing a reason",
                evidence=f"tool={tool} rule={rule} id={entry_id}",
                gate=Gate.ALL, source=Source.DETERMINISTIC, historical=False))
            continue

        records.append(OverrideRecord(
            id=entry_id, tool=tool, rule=rule,
            path=normalize_path(raw_path) if raw_path else raw_path, reason=reason))

    return records, warnings


def render_repo_stub(stack, pkg_mgr, *, today: str | None = None,
                      scope_subpath: str | None = None,
                      extra_ignore_paths: list[str] | tuple[str, ...] = ()) -> str:
    """Near-empty per-repo `aramid.toml` stub written by `init`. `stack`/
    `pkg_mgr` are surfaced only as an informational header comment -- the
    Config schema itself carries no stack/pkg-manager fields (those are
    re-detected each run by aramid.detectors, not persisted config).

    `scope_subpath` (init step 2, target != true repo root) and
    `extra_ignore_paths` (nested `.git` dirs excluded from scan scope) are
    both omitted entirely when not given -- a repo initted at its own root
    with no nested repos gets a stub with neither key, matching the
    pre-existing stub shape exactly (backward compatible)."""
    from datetime import date

    day = today or date.today().isoformat()
    stack_note = ", ".join(sorted(stack)) if stack else "unknown"
    pkg_note = pkg_mgr or "none"

    header = (f"# aramid repo config -- detected stack: {stack_note}; "
              f"package manager: {pkg_note}\n")
    body_dict = {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "semgrep_block_armed": False,
        "bake_started": day,
    }
    if scope_subpath:
        body_dict["scope_subpath"] = scope_subpath
    if extra_ignore_paths:
        body_dict["ignore_paths"] = list(extra_ignore_paths)
    body = tomli_w.dumps(body_dict)
    return header + body
