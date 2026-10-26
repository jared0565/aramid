"""`Ledger.record_run(still_found=)`: an id a scan of the whole file still
finds is present, so its row stays open, and is not detected, so the run writes
nothing about it (Re-scan before closing, OPERATOR 2026-10-25)."""
import pytest

from aramid.ledger import Ledger
from aramid.models import Gate, Severity, Verdict
from aramid.normalizer import RawFinding, normalize


def _finding(tmp_path):
    raw = RawFinding(tool="gitleaks", rule="github-pat", severity_raw="high", file="cfg.py",
                     line=2, message="m", line_content='TOKEN = "placeholder"')
    return normalize([raw], tmp_path, lambda f: "HEAD", b"salt", Gate.PRE_COMMIT,
                     lambda *a: (Severity.HIGH, Verdict.BLOCK))[0]


@pytest.mark.parametrize("vouched, status", [(True, "open"), (False, "fixed")])
def test_a_row_a_whole_file_scan_still_finds_stays_open(tmp_path, vouched, status):
    ledger = Ledger(tmp_path / "l.db")
    found = _finding(tmp_path)
    ledger.record_run("leak", "2026-10-25T00:00:00Z", "pre-commit", {"gitleaks"},
                      {"cfg.py"}, [found])
    # The next run's patch scan reports nothing, over the same file.
    ledger.record_run("change", "2026-10-25T00:01:00Z", "pre-commit", {"gitleaks"},
                      {"cfg.py"}, [],
                      still_found=frozenset({found.id}) if vouched else frozenset())
    assert ledger.open_findings()[found.id]["status"] == status
    if vouched:
        assert [e.type for e in ledger.events()
                if e.run_id == "change" and e.finding_id == found.id] == []
