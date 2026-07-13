"""aramid pack list|add|compile (spec section 5). compile auto-promotes:
rotated gitleaks secrets -> redacted reintroduction rules; fixed
dependency findings (CVE/GHSA/PYSEC/OSV rule ids) -> manifest bans.
add promotes ANY ledger finding (draft sentinel when no compiler fits)."""
import re
import sys
from pathlib import Path

from aramid import pack
from aramid.ledger import Ledger

_VULN_ID = re.compile(r"^(CVE-|GHSA-|PYSEC-|OSV-)")


def _compiler_for(rec: dict):
    if rec.get("tool") == "gitleaks" and rec.get("status") == "rotated":
        return pack.compile_secret_rule
    if _VULN_ID.match(rec.get("rule") or "") and rec.get("status") == "fixed":
        return pack.compile_dep_rule
    return None


def _pack_path(root: Path) -> Path:
    return Path(root) / pack.RULES_REL_PATH


def cmd_pack_list(root) -> int:
    ids = sorted(pack.existing_ids(_pack_path(Path(root))))
    if not ids:
        print("aramid pack: no pack rules")
        return 0
    for rid in ids:
        print(f"  {rid}")
    print(f"aramid pack: {len(ids)} rule(s) in {pack.RULES_REL_PATH.as_posix()}")
    return 0


def cmd_pack_add(root, finding_id: str) -> int:
    root = Path(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        rec = ledger.open_findings().get(finding_id)
    finally:
        ledger.close()
    if rec is None:
        print(f"aramid pack: no such finding {finding_id!r}", file=sys.stderr)
        return 3
    compiler = _compiler_for(rec)
    rule = compiler(finding_id, rec) if compiler else None
    if rule is None:
        rule = pack.draft_rule(finding_id, rec)
        print("aramid pack: emitted DRAFT rule -- edit pattern-regex before committing")
    added = pack.append_rules(_pack_path(root), [rule])
    print(f"aramid pack: {added} rule(s) added ({rule['id']})")
    return 0


def cmd_pack_compile(root) -> int:
    root = Path(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
    finally:
        ledger.close()
    rules = []
    for fid, rec in state.items():
        compiler = _compiler_for(rec)
        if compiler is None:
            continue
        rule = compiler(fid, rec)
        if rule is not None:
            rules.append(rule)
    added = pack.append_rules(_pack_path(root), rules)
    print(f"aramid pack: compiled {added} new rule(s) "
          f"({len(rules) - added} already present)")
    return 0
