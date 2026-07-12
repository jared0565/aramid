"""integration: historical-secret fingerprints must be read from the commit
the secret actually lived in, not from HEAD.

Regression covered: `init._scan_history` (the full-history gitleaks scan)
used to normalize every historical finding against `ref_for=lambda f:
"HEAD"`. For a secret committed in an OLD commit, reading the flagged line
from HEAD is wrong once the file has changed or the secret's been removed
there -- unstable/incorrect fingerprint, and non-idempotent (a second
`init` would fingerprint the "same" secret differently as HEAD moves).

gitleaks itself is NOT installed in this environment and there is no
network here -- only `gitleaks_runner.run` is monkeypatched (to hand back a
canned report), so the REAL `gitleaks_runner.parse` (which reads the JSON
report's `Commit` field) and the REAL `_historical_ref_for`/`normalize`
path both run for real, against a real temp git repo.
"""
import json
import subprocess
from pathlib import Path

from aramid import config as config_mod
from aramid.commands import init
from aramid.fingerprint import compute_fingerprint
from aramid.ledger import Ledger
from aramid.runners import gitleaks as gitleaks_runner
from aramid.runners.base import RunnerResult, ToolState

_RULE = "aws-access-token"
_SECRET = "AKIAIOSFODNN7EXAMPLE"
_SECRET_LINE = f'AWS_KEY = "{_SECRET}"'
_REL_FILE = "src/config.py"


def _git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _rev_parse_head(root) -> str:
    cp = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                         text=True, check=True)
    return cp.stdout.strip()


def _repo_with_rotated_secret(tmp_path) -> tuple[Path, str]:
    """commit A adds `_REL_FILE` containing `_SECRET_LINE` on line 2; commit
    B changes that line to a rotated value -- HEAD no longer has the secret
    at all. Returns (root, commit_a_sha)."""
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")

    (root / "src").mkdir()
    (root / _REL_FILE).write_text(f"# config\n{_SECRET_LINE}\n", encoding="utf-8")
    _git(root, "add", _REL_FILE)
    _git(root, "commit", "-q", "-m", "add secret")
    commit_a = _rev_parse_head(root)

    (root / _REL_FILE).write_text('# config\nAWS_KEY = "ROTATED-VALUE"\n', encoding="utf-8")
    _git(root, "add", _REL_FILE)
    _git(root, "commit", "-q", "-m", "rotate secret")

    return root, commit_a


def _fake_history_report(commit_sha: str) -> str:
    return json.dumps([{
        "Description": "AWS Access Key",
        "StartLine": 2,
        "EndLine": 2,
        "Match": _SECRET,
        "Secret": _SECRET,
        "File": _REL_FILE,
        "Commit": commit_sha,
        "RuleID": _RULE,
    }])


def _minimal_config() -> config_mod.Config:
    # Built directly (not config_mod.load_config) so the test doesn't
    # depend on -- or get perturbed by -- a real ~/.aramid/config.toml on
    # the machine running the suite. gitleaks findings always classify to
    # BLOCK regardless of block_rules, so an empty dict is sufficient.
    return config_mod.Config(
        schema_version=1, semgrep_block_armed=False, bake_started=None,
        ignore_paths=[], test_command=None, scope_subpath=None,
        timeouts={}, block_rules={})


def _detected_events(ledger: Ledger):
    return [e for e in ledger.events() if e.type.value == "finding_detected"]


def test_historical_fingerprint_reads_commit_blob_not_head(tmp_path, monkeypatch):
    root, commit_a = _repo_with_rotated_secret(tmp_path)

    def fake_run(ctx):
        return RunnerResult(tool="gitleaks", state=ToolState.OK,
                             raw=_fake_history_report(commit_a), returncode=1)

    monkeypatch.setattr(gitleaks_runner, "run", fake_run)

    cfg = _minimal_config()
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        historical_count = init._scan_history(root, ledger, cfg)
        assert historical_count == 1

        detected = _detected_events(ledger)
        assert len(detected) == 1

        expected_id_from_commit_a = compute_fingerprint(
            "gitleaks", _RULE, _REL_FILE, _SECRET_LINE, 0)
        expected_id_from_head = compute_fingerprint(
            "gitleaks", _RULE, _REL_FILE, 'AWS_KEY = "ROTATED-VALUE"', 0)

        actual_id = detected[0].finding_id
        assert actual_id  # non-empty
        assert actual_id == expected_id_from_commit_a
        assert actual_id != expected_id_from_head

        # Second scan (idempotency contract, brief global constraints /
        # _scan_history's own docstring): same commit sha in, same
        # fingerprint out, no duplicate FINDING_DETECTED for the same
        # secret -- ledger.record_run's "already known, status=historical"
        # check must skip re-appending it.
        historical_count_again = init._scan_history(root, ledger, cfg)
        assert historical_count_again == 1

        detected_again = _detected_events(ledger)
        assert len(detected_again) == 1
        assert detected_again[0].finding_id == actual_id
    finally:
        ledger.close()
