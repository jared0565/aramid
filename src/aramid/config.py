"""config -- three-layer TOML config (defaults <- ~/.aramid/config.toml <-
<root>/aramid.toml), the always-on ignore-path filter, the suppressions-file
loader, and the near-empty per-repo config stub `init` writes.
"""
import fnmatch
import sys
from copy import deepcopy
from dataclasses import dataclass
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
        merged = _deep_merge(merged, repo_toml)

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


def render_repo_stub(stack, pkg_mgr, *, today: str | None = None) -> str:
    """Near-empty per-repo `aramid.toml` stub written by `init`. `stack`/
    `pkg_mgr` are surfaced only as an informational header comment -- the
    Config schema itself carries no stack/pkg-manager fields (those are
    re-detected each run by aramid.detectors, not persisted config)."""
    from datetime import date

    day = today or date.today().isoformat()
    stack_note = ", ".join(sorted(stack)) if stack else "unknown"
    pkg_note = pkg_mgr or "none"

    header = (f"# aramid repo config -- detected stack: {stack_note}; "
              f"package manager: {pkg_note}\n")
    body = tomli_w.dumps({
        "schema_version": CURRENT_SCHEMA_VERSION,
        "semgrep_block_armed": False,
        "bake_started": day,
    })
    return header + body
