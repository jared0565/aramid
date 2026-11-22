"""A file the gate left out because its name is not valid UTF-8 is a
coverage gap the gate reports, not only a stderr line (operator decision
2026-11-22, drain llm-review row ad601eb4 and the commit security review).

0.20.16 dropped such a name from the tools' file lists and said so once on
stderr, so the run's verdict, its ledger row and `--strict` all read the
run as fully scanned. It now joins `degraded` under `non-utf8-names`, with
the files named: exit 2 (which the default hooks pass, with the gap shown,
and `--strict` refuses), the run row records it, and `--accept-degraded`
is the documented way through. A name the ignore-path filter would drop
anyway is no gap.
"""
import subprocess
from pathlib import Path

import pytest

from aramid import config, gitutil, pipeline, reporter
from aramid.ledger import Ledger
from aramid.models import EventType, Gate

ODD = "caf\udce9.py"   # b"caf\xe9.py" as the listings decode it (surrogateescape)


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("x = 1\n")
    _git(r, "add", "a.py")
    _git(r, "commit", "-m", "initial")
    return r


def _listing(left):
    """A git listing that names a.py and leaves out `left`."""
    def listing(*args, left_out=None):
        if left_out is not None:
            left_out.extend(left)
        return ["a.py"]
    return listing


def _setup(tmp_path, monkeypatch, left, *, listing="all_tracked_files"):
    root = _repo(tmp_path)
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "no-user-config.toml")
    cfg = config.load_config(root)
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_COMMIT, [])
    monkeypatch.setattr(gitutil, listing, _listing(left))
    return root, cfg, Ledger(tmp_path / "ledger.db")


def _row_degraded(ledger):
    finished = [e for e in ledger.events() if e.type is EventType.RUN_FINISHED][-1]
    return finished.payload["degraded"]


@pytest.mark.parametrize("mode, listing", [
    ("all", "all_tracked_files"), ("staged", "staged_files"), ("range", "changed_files")])
def test_a_left_out_name_degrades_the_gate_on_its_verdict_and_its_row(
        tmp_path, monkeypatch, mode, listing):
    root, cfg, ledger = _setup(tmp_path, monkeypatch, [ODD], listing=listing)
    monkeypatch.setattr(gitutil, "resolve_range", lambda root: "HEAD~0..HEAD")
    try:
        result = pipeline.run_gate(root, Gate.PRE_COMMIT, mode, cfg, ledger, run_id="run-u")
        assert result.exit_code == 2
        assert result.degraded == ["non-utf8-names"]
        assert result.degraded_block_tier is False
        assert result.degraded_reasons == {
            "non-utf8-names": "1 file not handed to any tool: name not valid UTF-8: caf\\xe9.py"}
        assert _row_degraded(ledger) == result.degraded_reasons
    finally:
        ledger.close()


def test_a_range_with_no_upstream_counts_the_full_listing_it_falls_back_to(tmp_path, monkeypatch):
    root, cfg, ledger = _setup(tmp_path, monkeypatch, [ODD])
    monkeypatch.setattr(gitutil, "resolve_range", lambda root: None)
    try:
        result = pipeline.run_gate(root, Gate.PRE_COMMIT, "range", cfg, ledger, run_id="run-f")
        assert result.degraded == ["non-utf8-names"]
    finally:
        ledger.close()


def test_a_clean_listing_degrades_nothing(tmp_path, monkeypatch):
    root, cfg, ledger = _setup(tmp_path, monkeypatch, [])
    try:
        result = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger, run_id="run-c")
        assert result.exit_code == 0
        assert result.degraded == []
        assert _row_degraded(ledger) == {}
    finally:
        ledger.close()


def test_a_left_out_name_under_an_ignored_path_is_no_gap(tmp_path, monkeypatch):
    root, cfg, ledger = _setup(tmp_path, monkeypatch, ["vendor/" + ODD])
    cfg.ignore_paths = [*cfg.ignore_paths, "vendor/**"]
    try:
        result = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger, run_id="run-i")
        assert result.degraded == []
    finally:
        ledger.close()


@pytest.mark.parametrize("count, tail", [
    (5, "a\\xe9.py, b\\xe9.py, c\\xe9.py, d\\xe9.py, e\\xe9.py"),
    (6, "a\\xe9.py, b\\xe9.py, c\\xe9.py, d\\xe9.py, e\\xe9.py and 1 more"),
    (7, "a\\xe9.py, b\\xe9.py, c\\xe9.py, d\\xe9.py, e\\xe9.py and 2 more")])
def test_the_reason_names_five_files_and_counts_the_rest(tmp_path, monkeypatch, count, tail):
    names = [f"{c}\udce9.py" for c in "abcdefg"[:count]]
    root, cfg, ledger = _setup(tmp_path, monkeypatch, names)
    try:
        result = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger, run_id="run-n")
        assert result.degraded_reasons == {
            "non-utf8-names": f"{count} files not handed to any tool: name not valid UTF-8: {tail}"}
    finally:
        ledger.close()


def test_the_console_names_the_gap_beside_the_degraded_tools(tmp_path, monkeypatch):
    root, cfg, ledger = _setup(tmp_path, monkeypatch, [ODD])
    try:
        result = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger, run_id="run-r")
        lines = reporter.render_console(result, ledger).splitlines()
        at = lines.index("skipped (degraded tools):")
        assert lines[at + 1] == (
            "  - non-utf8-names (1 file not handed to any tool: name not valid UTF-8: caf\\xe9.py)")
    finally:
        ledger.close()


def test_an_accepted_gap_passes_on_record(tmp_path, monkeypatch):
    root, cfg, ledger = _setup(tmp_path, monkeypatch, [ODD])
    try:
        result = pipeline.run_gate(root, Gate.PRE_COMMIT, "all", cfg, ledger, run_id="run-a",
                                   accept_degraded="legacy Latin-1 fixture, reviewed by hand")
        assert result.exit_code == 0
        (bypass,) = [e for e in ledger.events() if e.type is EventType.INFRASTRUCTURE_BYPASS]
        assert bypass.payload["degraded"] == ["non-utf8-names"]
    finally:
        ledger.close()
