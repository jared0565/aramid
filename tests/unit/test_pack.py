import yaml  # dev-dependency, tests only

from aramid import pack

SECRET = "AKIAIOSFODNN7EXAMPLE"
FID = "deadbeefcafe0123"

SECRET_REC = {"tool": "gitleaks", "rule": "aws-access-key", "file": "cfg/prod.env",
              "verdict": "block", "severity": "critical", "line": 3,
              "message": "aws key", "status": "rotated",
              "evidence": f"{SECRET[:2]}…{SECRET[-2:]} (sha256:abc123)"}

DEP_REC = {"tool": "pip-audit", "rule": "PYSEC-2024-1234", "file": "requirements.txt",
           "verdict": "block", "severity": "critical", "line": 0,
           "message": "insecure-package 1.0.0 has PYSEC-2024-1234", "status": "fixed",
           "evidence": ""}


def test_secret_rule_never_contains_literal_and_is_scoped():
    rule = pack.compile_secret_rule(FID, SECRET_REC)
    text = pack.render_pack([rule])
    assert SECRET not in text  # THE hygiene invariant (spec section 5)
    assert rule["id"] == f"aramid-regression.block.{FID[:8]}"
    assert rule["paths"]["include"] == ["cfg/prod.env"]
    assert rule["pattern-regex"].startswith("AK")
    assert rule["pattern-regex"].endswith("LE")
    assert r"\S{4,64}" in rule["pattern-regex"]


def test_secret_rule_unparseable_evidence_returns_none():
    rec = dict(SECRET_REC, evidence="…")  # short-secret preview: no anchors
    assert pack.compile_secret_rule(FID, rec) is None


def test_dep_rule_targets_manifest_and_package():
    rule = pack.compile_dep_rule(FID, DEP_REC)
    assert rule["id"] == f"aramid-regression.block.{FID[:8]}"
    assert rule["paths"]["include"] == ["requirements.txt"]
    assert "insecure-package" in rule["pattern-regex"]
    assert "PYSEC-2024-1234" in rule["message"]


def test_dep_rule_unparseable_message_returns_none():
    assert pack.compile_dep_rule(FID, dict(DEP_REC, message="???")) is None


def test_draft_rule_always_compiles_with_sentinel():
    rec = {"tool": "semgrep", "rule": "owasp-top-ten.a01", "file": "api.py",
           "verdict": "warn", "severity": "high", "line": 9,
           "message": "idor risk", "status": "fixed", "evidence": ""}
    rule = pack.draft_rule(FID, rec)
    assert rule["id"] == f"aramid-regression.warn.{FID[:8]}"
    assert f"AR-EDIT-ME-{FID[:8]}" in rule["pattern-regex"]
    assert "edit" in rule["message"].lower()


def test_render_pack_is_valid_yaml_semgrep_shape():
    rule = pack.compile_secret_rule(FID, SECRET_REC)
    data = yaml.safe_load(pack.render_pack([rule]))
    assert data["rules"][0]["id"] == rule["id"]
    assert data["rules"][0]["languages"] == ["generic"]
    assert data["rules"][0]["severity"] == "ERROR"


def test_append_rules_dedups_and_creates(tmp_path):
    target = tmp_path / "regression.yml"
    rule = pack.compile_secret_rule(FID, SECRET_REC)
    assert pack.append_rules(target, [rule]) == 1
    assert pack.append_rules(target, [rule]) == 0  # same id -> skipped
    assert pack.existing_ids(target) == {rule["id"]}
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert len(data["rules"]) == 1
