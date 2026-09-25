"""config -- three-layer TOML config (defaults <- ~/.aramid/config.toml <-
<root>/aramid.toml), the always-on ignore-path filter, the suppressions-file
loader, and the near-empty per-repo config stub `init` writes.
"""
import fnmatch
import sys
from copy import deepcopy
from dataclasses import dataclass, field, fields
from importlib import resources
from pathlib import Path

import tomllib
import tomli_w

from aramid import config_keys
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
    agent_block_armed: bool = False
    tdd: dict = field(default_factory=dict)
    red_proof: dict = field(default_factory=dict)
    tests: dict = field(default_factory=dict)
    deps: dict = field(default_factory=dict)
    hooks: dict = field(default_factory=dict)
    shadow: dict = field(default_factory=dict)


def arming_state(cfg: "Config") -> dict:
    """Every tier-affecting `*_armed` flag in force, as a plain dict.

    WALKED, never listed. A literal tuple of today's six flags would be
    correct on the day it was written and silently wrong the day someone adds
    the seventh: their flag goes unrecorded, and every override made under it
    joins the unrecorded-legacy population without anyone choosing that. The
    walk means a new armable tool is captured by existing code.

    Scoped to keys ending `_armed` because those are the flags that can move a
    finding between WARN and BLOCK tier -- which is the only thing an override
    is a decision about. `[llm.autolearn].armed` is deliberately NOT captured:
    its key does not match, and it changes reviewer SELECTION (escalate-only,
    the ladder tier stays the floor) rather than any finding's tier, so it
    cannot invalidate a suppression.
    agent_block_armed IS captured although it arms the agent pre-tool-use rejector rather than moving any finding's tier: recording it costs nothing as an override premise, and it cannot invalidate overrides -- invalidate_stale_overrides asks policy.classify, which never reads it.

    Recurses, because four of the six live in sub-tables (`llm`, `mutation`,
    `red_proof`) rather than on the dataclass itself.
    """
    state: dict = {}

    def _walk(d: dict) -> None:
        for key, value in d.items():
            if isinstance(value, dict):
                _walk(value)
            elif isinstance(value, bool) and key.endswith("_armed"):
                state[key] = value

    for f in fields(cfg):
        value = getattr(cfg, f.name)
        if isinstance(value, dict):
            _walk(value)
        elif isinstance(value, bool) and f.name.endswith("_armed"):
            state[f.name] = value
    return state


def _user_config_path() -> Path:
    """Seam for tests -- monkeypatch this rather than touching a real
    ~/.aramid/config.toml on the machine running the test suite."""
    return Path.home() / ".aramid" / "config.toml"


def _read_data_toml(name: str) -> dict:
    text = resources.files("aramid").joinpath("data", name).read_text(encoding="utf-8")
    return tomllib.loads(text)


def _read_toml_file(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


# (file, problem) pairs this process has already printed. load_config runs
# more than once in one command, and a warning repeated per call is noise
# that trains people to skip it.
_WARNED: set[tuple[str, str]] = set()


def _warn_layer(path: Path, raw: dict, known: dict) -> None:
    """Print each config_keys problem in one layer a person writes, once per
    process. WARN only (1.0 DEC-4): what load_config loads is unchanged --
    an unknown key is still ignored, a mistyped value still passes through
    -- and no exit code moves."""
    for problem in config_keys.problems(raw, known=known):
        if (str(path), problem) not in _WARNED:
            _WARNED.add((str(path), problem))
            print(f"aramid: config: {path}: {problem}", file=sys.stderr)


def layer_problems(root: Path) -> list[tuple[Path, str]]:
    """Every config_keys problem in the two layers a person writes -- the
    user's ~/.aramid/config.toml, then <root>/aramid.toml -- for `aramid
    doctor`'s `config:` rows. An unparseable layer raises what tomllib
    raises, as it does in load_config."""
    known = config_keys.known_keys()
    out: list[tuple[Path, str]] = []
    for path in (_user_config_path(), root / "aramid.toml"):
        if path.exists():
            out.extend((path, p) for p in config_keys.problems(_read_toml_file(path), known=known))
    return out


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
    known = config_keys.known_keys(merged)
    merged["block_rules"] = load_block_rules()

    user_path = _user_config_path()
    if user_path.exists():
        user_toml = _read_toml_file(user_path)
        _warn_layer(user_path, user_toml, known)
        merged = _deep_merge(merged, user_toml)

    repo_path = root / "aramid.toml"
    repo_schema_version = None
    if repo_path.exists():
        repo_toml = _read_toml_file(repo_path)
        _warn_layer(repo_path, repo_toml, known)
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
        timeouts=merged.get("timeouts", {}),
        block_rules=merged.get("block_rules", {}),
        triage=merged.get("triage", {}),
        drain=merged.get("drain", {}),
        pack=merged.get("pack", {}),
        llm=merged.get("llm", {}),
        mutation=merged.get("mutation", {}),
        shadow=merged.get("shadow", {}),
        fuzz=merged.get("fuzz", {}),
        js_mutation=merged.get("js_mutation", {}),
        dast=merged.get("dast", {}),
        tdd_block_armed=merged.get("tdd_block_armed", False),
        agent_block_armed=merged.get("agent_block_armed", False),
        tdd=merged.get("tdd", {}),
        red_proof=merged.get("red_proof", {}),
        tests=merged.get("tests", {}),
        deps=merged.get("deps", {}),
        hooks=merged.get("hooks", {}),
    )


def effective_test_command(cfg):
    """The repo's test command as the gate runs it: `[tests].command` if
    the section sets the key, else schema v1's top-level `test_command`.

    PRESENCE, not truthiness: `[tests]\ncommand = ""` is a repo saying "no
    command", and the legacy key is not consulted behind it. A falsy result
    (None/""/[]) means "not configured" to every caller, which then detects.
    A `tests` that is not a table reads as no section, so a hand-edited
    aramid.toml degrades rather than raises.

    The ONE place this is decided. The gate (pipeline.run_gate), its
    applicability mirror (toolset), doctor and the mutation consumer each
    carried their own copy, and the consumer's drifted: it never read the
    legacy key, so a repo configured that way got a bare `pytest -q` at the
    drain (1.0 FN-11). `getattr` so a caller may pass any object shaped like
    a Config."""
    tests = getattr(cfg, "tests", None)
    tests = tests if isinstance(tests, dict) else {}
    return tests.get("command", getattr(cfg, "test_command", None))


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
                      extra_ignore_paths: list[str] | tuple[str, ...] = ()) -> str:
    """Near-empty per-repo `aramid.toml` stub written by `init`. `stack`/
    `pkg_mgr` are surfaced only as an informational header comment -- the
    Config schema itself carries no stack/pkg-manager fields (those are
    re-detected each run by aramid.detectors, not persisted config).

    `extra_ignore_paths` (nested `.git` dirs excluded from scan scope) is
    omitted entirely when not given -- a repo with no nested repos gets a
    stub without the key, matching the pre-existing stub shape exactly
    (backward compatible). There is no `scope_subpath`: until 0.19.0 a
    subdirectory init wrote one, and no runner ever read it."""
    from datetime import date

    day = today or date.today().isoformat()

    # Deliberately carries NO detected stack / package manager. `init` writes
    # this file only when absent and never rewrites it (its idempotency
    # contract), so any DERIVED state written here is frozen for the life of
    # the repo. Stack and package manager are re-detected on every run by
    # aramid.detectors and are not Config fields at all -- a snapshot of them
    # here goes stale the moment a repo adds a language, and it goes stale
    # silently, understating what aramid actually covers. Reported live by
    # `aramid doctor` instead. (graphite, round 14, 2026-07-31: Operation
    # Firewall's stub still read "python; package manager: none" for a Cargo
    # workspace.) `stack`/`pkg_mgr` stay in the signature: callers pass them
    # positionally, and they remain available should a future stub need a
    # genuinely non-derived, stack-dependent default.
    header = "# aramid repo config -- see ARAMID.md; `aramid doctor` reports the live stack\n"
    body_dict = {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "semgrep_block_armed": False,
        "agent_block_armed": False,
        "bake_started": day,
    }
    if extra_ignore_paths:
        body_dict["ignore_paths"] = list(extra_ignore_paths)
    body = tomli_w.dumps(body_dict)
    return header + body
