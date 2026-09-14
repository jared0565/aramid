"""`aramid pack list|add|compile` at unit scope on a real tmp ledger: the
compiler choice per (tool, rule, status), every printed line whole, every
exit code.

The drain confirms a mutant against the unit suite alone, and all 12 of
this module's generator mutants sat on lines the unit suite never
executed -- among them `and` -> `or` on both compiler predicates (an OPEN
gitleaks finding compiled into a reintroduction rule; an open CVE into a
manifest ban) and the `or ""` that keeps a finding without a rule id from
crashing the match: tests/integration/test_pack_cmd.py covers them and
the drain never runs that directory."""
import uuid

import pytest

from aramid import pack
from aramid.commands.pack_cmd import (_compiler_for, cmd_pack_add, cmd_pack_compile,
                                      cmd_pack_list)
from aramid.ledger import Ledger
from aramid.models import Event, EventType

SECRET = {"tool": "gitleaks", "rule": "aws-access-key", "file": "cfg/prod.env",
          "verdict": "block", "severity": "critical", "line": 3,
          "message": "aws key", "evidence": "AK…LE (sha256:abc)", "historical": False}
DEP = {"tool": "pip-audit", "rule": "PYSEC-2024-1234", "file": "requirements.txt",
       "verdict": "block", "severity": "critical", "line": 0,
       "message": "insecure-package 1.0.0 has PYSEC-2024-1234", "evidence": "",
       "historical": False}
CODE = {"tool": "semgrep", "rule": "owasp-top-ten.a01", "file": "api.py",
        "verdict": "warn", "severity": "high", "line": 9, "message": "idor",
        "evidence": "", "historical": False}


# ------------------------------------------------------------ _compiler_for --

@pytest.mark.parametrize("rec, compiler", [
    ({"tool": "gitleaks", "rule": "aws-access-key", "status": "rotated"},
     pack.compile_secret_rule),
    ({"tool": "gitleaks", "rule": "aws-access-key", "status": "open"}, None),
    ({"tool": "gitleaks", "rule": "aws-access-key", "status": "fixed"}, None),
    ({"tool": "semgrep", "rule": "aws-access-key", "status": "rotated"}, None),
    ({"tool": "pip-audit", "rule": "PYSEC-2024-1234", "status": "fixed"}, pack.compile_dep_rule),
    ({"tool": "cargo-audit", "rule": "GHSA-xxxx-yyyy", "status": "fixed"}, pack.compile_dep_rule),
    ({"tool": "pip-audit", "rule": "CVE-2024-1", "status": "fixed"}, pack.compile_dep_rule),
    ({"tool": "pip-audit", "rule": "OSV-2024-1", "status": "fixed"}, pack.compile_dep_rule),
    ({"tool": "pip-audit", "rule": "PYSEC-2024-1234", "status": "open"}, None),
    ({"tool": "pip-audit", "rule": "PYSEC-2024-1234", "status": "rotated"}, None),
    ({"tool": "pip-audit", "rule": "not-a-vuln-id", "status": "fixed"}, None),
    ({"tool": "pip-audit", "rule": None, "status": "fixed"}, None),   # no rule id: no match, no crash
    ({"tool": "semgrep", "status": "fixed"}, None),
    ({}, None),
])
def test_compiler_for(rec, compiler):
    assert _compiler_for(rec) is compiler


# ------------------------------------------------------------------ helpers --

def _seed(root, fid, payload, status_event=None):
    led = Ledger(root / ".aramid" / "ledger.db")
    try:
        led.append(Event(EventType.FINDING_DETECTED, uuid.uuid4().hex,
                         "2026-07-13T00:00:00+00:00", finding_id=fid, payload=payload))
        if status_event is not None:
            led.append(Event(status_event, uuid.uuid4().hex,
                             "2026-07-13T01:00:00+00:00", finding_id=fid))
    finally:
        led.close()


@pytest.fixture
def root(tmp_path):
    (tmp_path / ".aramid").mkdir()
    Ledger(tmp_path / ".aramid" / "ledger.db").close()
    return tmp_path


def _ids(root):
    return sorted(pack.existing_ids(root / pack.RULES_REL_PATH))


# ------------------------------------------------------------ cmd_pack_list --

def test_pack_list_prints_the_rules_or_says_there_are_none(root, capsys):
    assert cmd_pack_list(root) == 0
    assert capsys.readouterr() == ("aramid pack: no pack rules\n", "")

    _seed(root, "a" * 64, SECRET, EventType.FINDING_ROTATED)
    _seed(root, "b" * 64, DEP, EventType.FINDING_RESOLVED)
    assert cmd_pack_compile(root) == 0
    capsys.readouterr()
    assert cmd_pack_list(root) == 0
    assert capsys.readouterr() == (
        f"  aramid-regression.block.{'a' * 8}\n"
        f"  aramid-regression.block.{'b' * 8}\n"
        f"aramid pack: 2 rule(s) in {pack.RULES_REL_PATH.as_posix()}\n", "")


# ------------------------------------------------------------- cmd_pack_add --

def test_pack_add_compiles_a_rotated_secret_and_drafts_anything_else(root, capsys):
    _seed(root, "a" * 64, SECRET, EventType.FINDING_ROTATED)
    _seed(root, "d" * 64, CODE)

    assert cmd_pack_add(root, "a" * 64) == 0
    assert capsys.readouterr() == (
        f"aramid pack: 1 rule(s) added (aramid-regression.block.{'a' * 8})\n", "")

    assert cmd_pack_add(root, "d" * 64) == 0
    assert capsys.readouterr() == (
        "aramid pack: emitted DRAFT rule -- edit pattern-regex before committing\n"
        f"aramid pack: 1 rule(s) added (aramid-regression.warn.{'d' * 8})\n", "")

    assert cmd_pack_add(root, "a" * 64) == 0, "a rule already present is not appended twice"
    assert capsys.readouterr() == (
        f"aramid pack: 0 rule(s) added (aramid-regression.block.{'a' * 8})\n", "")
    assert _ids(root) == [f"aramid-regression.block.{'a' * 8}",
                          f"aramid-regression.warn.{'d' * 8}"]


def test_pack_add_refuses_an_unknown_finding(root, capsys):
    assert cmd_pack_add(root, "nope") == 3
    assert capsys.readouterr() == ("", "aramid pack: no such finding 'nope'\n")
    assert not (root / pack.RULES_REL_PATH).exists()


# --------------------------------------------------------- cmd_pack_compile --

def test_pack_compile_promotes_only_what_a_compiler_fits_and_counts_the_new(root, capsys):
    _seed(root, "a" * 64, SECRET, EventType.FINDING_ROTATED)
    _seed(root, "b" * 64, DEP, EventType.FINDING_RESOLVED)
    _seed(root, "c" * 64, SECRET)                        # still open: not compiled
    _seed(root, "d" * 64, CODE, EventType.FINDING_RESOLVED)   # fixed, but no compiler

    assert cmd_pack_compile(root) == 0
    assert capsys.readouterr() == (
        "aramid pack: compiled 2 new rule(s) (0 already present)\n", "")
    assert _ids(root) == [f"aramid-regression.block.{'a' * 8}",
                          f"aramid-regression.block.{'b' * 8}"]

    assert cmd_pack_compile(root) == 0
    assert capsys.readouterr() == (
        "aramid pack: compiled 0 new rule(s) (2 already present)\n", "")
