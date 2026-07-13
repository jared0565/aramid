"""pack -- the regression attack pack compiler (spec section 5).

Rules are semgrep rules in <repo>/.aramid-rules/regression.yml (committed,
like .aramid-suppressions.toml). YAML is HAND-RENDERED with json.dumps for
every scalar -- JSON strings are valid YAML flow scalars -- so the runtime
gains no YAML dependency (PyYAML stays dev-only).

Hygiene invariant (spec section 5): a rotated-secret rule is compiled from
the finding's stored REDACTED evidence ("ab…yz (sha256:...)"), never from
the literal secret -- the rules file is committed and embedding the old
value would re-leak it. The resulting pattern is an anchored-prefix/suffix
structural regex scoped to the original file.
"""
import json
import re
from pathlib import Path

RULES_REL_PATH = Path(".aramid-rules") / "regression.yml"
_HEADER = ("# aramid regression attack pack -- compiled from resolved ledger\n"
           "# findings (aramid pack compile / aramid pack add). Committed on\n"
           "# purpose: the pre-push gate replays these rules forever.\n"
           "rules:\n")

_EVIDENCE_RX = re.compile(r"^(?P<pre>.{2,4})…(?P<suf>.{2,4}) \(sha256:")
_DEP_RX = re.compile(r"(?P<pkg>[A-Za-z0-9][A-Za-z0-9_.@/-]{2,})\s+"
                     r"(?P<ver>[0-9][^\s,;]*)")


def _fid8(finding_id: str) -> str:
    return finding_id[:8]


def _tier(rec: dict) -> str:
    return "block" if rec.get("verdict") == "block" else "warn"


def compile_secret_rule(finding_id: str, rec: dict) -> dict | None:
    m = _EVIDENCE_RX.match(rec.get("evidence") or "")
    if not m:
        return None
    pattern = re.escape(m.group("pre")) + r"\S{4,64}" + re.escape(m.group("suf"))
    return {
        "id": f"aramid-regression.{_tier(rec)}.{_fid8(finding_id)}",
        "languages": ["generic"],
        "severity": "ERROR" if _tier(rec) == "block" else "WARNING",
        "message": (f"Reintroduction of rotated secret {_fid8(finding_id)} "
                    f"({rec.get('tool')}:{rec.get('rule')}) resolved in the ledger -- "
                    f"rotate again and remove this value."),
        "paths": {"include": [rec.get("file", "**")]},
        "pattern-regex": pattern,
    }


def compile_dep_rule(finding_id: str, rec: dict) -> dict | None:
    m = _DEP_RX.search(rec.get("message") or "")
    if not m:
        return None
    return {
        "id": f"aramid-regression.{_tier(rec)}.{_fid8(finding_id)}",
        "languages": ["generic"],
        "severity": "ERROR" if _tier(rec) == "block" else "WARNING",
        "message": (f"Reintroduction of banned dependency {m.group('pkg')} "
                    f"({rec.get('rule')}, resolved finding {_fid8(finding_id)})."),
        "paths": {"include": [rec.get("file", "**")]},
        "pattern-regex": m.group("pkg"),
    }


def draft_rule(finding_id: str, rec: dict) -> dict:
    return {
        "id": f"aramid-regression.{_tier(rec)}.{_fid8(finding_id)}",
        "languages": ["generic"],
        "severity": "ERROR" if _tier(rec) == "block" else "WARNING",
        "message": (f"DRAFT from finding {_fid8(finding_id)} "
                    f"({rec.get('tool')}:{rec.get('rule')} in {rec.get('file')}): "
                    f"{rec.get('message', '')} -- edit pattern-regex before committing."),
        "paths": {"include": [rec.get("file", "**")]},
        "pattern-regex": f"AR-EDIT-ME-{_fid8(finding_id)}",
    }


def _render_rule(rule: dict) -> str:
    lines = [f"  - id: {json.dumps(rule['id'])}",
             f"    languages: [{', '.join(json.dumps(x) for x in rule['languages'])}]",
             f"    severity: {json.dumps(rule['severity'])}",
             f"    message: {json.dumps(rule['message'])}",
             "    paths:",
             f"      include: [{', '.join(json.dumps(x) for x in rule['paths']['include'])}]",
             f"    pattern-regex: {json.dumps(rule['pattern-regex'])}"]
    return "\n".join(lines) + "\n"


def render_pack(rules: list[dict]) -> str:
    return _HEADER + "".join(_render_rule(r) for r in rules)


_ID_RX = re.compile(r'^\s*-\s*id:\s*"?([A-Za-z0-9_.\-]+)"?\s*$', re.M)


def existing_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return set(_ID_RX.findall(path.read_text(encoding="utf-8")))


def append_rules(path: Path, rules: list[dict]) -> int:
    seen = existing_ids(path)
    fresh = [r for r in rules if r["id"] not in seen]
    if not fresh:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(render_pack(fresh), encoding="utf-8")
    else:
        path.write_text(path.read_text(encoding="utf-8") +
                        "".join(_render_rule(r) for r in fresh), encoding="utf-8")
    return len(fresh)
