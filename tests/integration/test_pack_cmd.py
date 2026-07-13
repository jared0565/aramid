import uuid
from pathlib import Path

from aramid import pack
from aramid.commands.pack_cmd import cmd_pack_add, cmd_pack_compile, cmd_pack_list
from aramid.ledger import Ledger
from aramid.models import Event, EventType


def _seed(led: Ledger, fid: str, payload: dict, status_event: EventType | None):
    led.append(Event(EventType.FINDING_DETECTED, uuid.uuid4().hex,
                     "2026-07-13T00:00:00+00:00", finding_id=fid, payload=payload))
    if status_event is not None:
        led.append(Event(status_event, uuid.uuid4().hex,
                         "2026-07-13T01:00:00+00:00", finding_id=fid))


SECRET_PAYLOAD = {"tool": "gitleaks", "rule": "aws-access-key", "file": "cfg/prod.env",
                  "verdict": "block", "severity": "critical", "line": 3,
                  "message": "aws key", "evidence": "AK…LE (sha256:abc)",
                  "historical": False}
DEP_PAYLOAD = {"tool": "pip-audit", "rule": "PYSEC-2024-1234", "file": "requirements.txt",
               "verdict": "block", "severity": "critical", "line": 0,
               "message": "insecure-package 1.0.0 has PYSEC-2024-1234",
               "evidence": "", "historical": False}


def _repo_with_ledger(tmp_path) -> Path:
    (tmp_path / ".aramid").mkdir()
    return tmp_path


def test_compile_picks_rotated_secrets_and_fixed_deps(tmp_path):
    root = _repo_with_ledger(tmp_path)
    led = Ledger(root / ".aramid" / "ledger.db")
    _seed(led, "a" * 64, SECRET_PAYLOAD, EventType.FINDING_ROTATED)
    _seed(led, "b" * 64, DEP_PAYLOAD, EventType.FINDING_RESOLVED)
    _seed(led, "c" * 64, SECRET_PAYLOAD, None)  # still open -> NOT compiled
    led.close()
    assert cmd_pack_compile(root) == 0
    ids = pack.existing_ids(root / pack.RULES_REL_PATH)
    assert f"aramid-regression.block.{'a' * 8}" in ids
    assert f"aramid-regression.block.{'b' * 8}" in ids
    assert len(ids) == 2


def test_pack_add_promotes_any_finding_as_draft(tmp_path):
    root = _repo_with_ledger(tmp_path)
    led = Ledger(root / ".aramid" / "ledger.db")
    payload = {"tool": "semgrep", "rule": "owasp-top-ten.a01", "file": "api.py",
               "verdict": "warn", "severity": "high", "line": 9,
               "message": "idor", "evidence": "", "historical": False}
    _seed(led, "d" * 64, payload, None)
    led.close()
    assert cmd_pack_add(root, "d" * 64) == 0
    ids = pack.existing_ids(root / pack.RULES_REL_PATH)
    assert f"aramid-regression.warn.{'d' * 8}" in ids


def test_pack_add_unknown_finding_errors(tmp_path):
    root = _repo_with_ledger(tmp_path)
    Ledger(root / ".aramid" / "ledger.db").close()
    assert cmd_pack_add(root, "nope") == 3


def test_pack_list_runs_on_empty_and_populated(tmp_path, capsys):
    root = _repo_with_ledger(tmp_path)
    Ledger(root / ".aramid" / "ledger.db").close()
    assert cmd_pack_list(root) == 0
    assert "no pack rules" in capsys.readouterr().out.lower()
