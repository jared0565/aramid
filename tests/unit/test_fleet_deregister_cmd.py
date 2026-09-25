"""`aramid fleet deregister <path|name>` -- 1.0 blocker FN-1.

Before this command the registry had no removal path short of `aramid
uninstall`, which needs the repo on disk (exit 3 on a vanished path) and
strips its hooks as well. A repo that left the disk therefore pinned the
readiness verdict at `insufficient-data` for good, and `~/.aramid/repos.toml`
was edited by a hand-run Python call at least five times (09-03, 09-18/19).
The command removes exactly ONE entry, keeps the file it rewrote, and
re-judges so `aramid fleet` shows the new membership at once rather than at
the next scheduled drain."""
from datetime import datetime, timezone
from pathlib import Path

from aramid import cli, fleet, health, registry
from aramid.commands.fleet_cmd import cmd_fleet_deregister


def _names() -> list[str]:
    return sorted(Path(e["path"]).name for e in registry.load_registry())


def _backups() -> list[Path]:
    return sorted(registry.registry_path().parent.glob("repos.toml.bak-*"))


def _stored(path: Path) -> str:
    return str(path.resolve())


def _green_row(repo_dir: Path) -> dict:
    crit = {k: True for k in health.CRITERIA}
    crit["dep_audit_ran"] = None
    return {"schema_version": 1, "at": datetime.now(timezone.utc).isoformat(),
            "repo": fleet.repo_key(repo_dir.resolve()), "name": repo_dir.name,
            "aramid_version": "0.18.0", "gate": "pre-commit", "run_id": "r1",
            "exit_code": 0, "engine_error": False, "criteria": crit,
            "evidence": {"skip_streaks": {}, "degraded_consumers": [], "stood_down": [],
                         "no_work": [], "resolver_defects": [], "bad_tools": [],
                         "degraded_block_tier": False, "armed": {"semgrep_block_armed": True},
                         "open": 0, "blocking": 0}}


def test_a_path_removes_that_entry_alone_and_keeps_the_file_it_rewrote(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    registry.register(a, "t")
    registry.register(b, "t")
    before = registry.registry_path().read_text(encoding="utf-8")

    assert cmd_fleet_deregister(str(a)) == 0

    assert _names() == ["b"]
    baks = _backups()
    assert len(baks) == 1
    assert baks[0].read_text(encoding="utf-8") == before
    out = capsys.readouterr().out.splitlines()
    assert out[0] == f"aramid fleet: deregistered a ({_stored(a)})"
    assert out[1] == f"aramid fleet: previous registry kept at {baks[0]}"
    assert out[2] == ("aramid fleet: its hooks, aramid.toml and ledger are untouched "
                      "-- `aramid uninstall <path>` reverses onboarding")


def test_a_name_matches_a_repo_whose_path_is_gone_ignoring_case(tmp_path, monkeypatch):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)     # a relative name must not resolve onto the entry
    gone = tmp_path / "File Convert"  # never created: the repo has left the disk
    keep = tmp_path / "keep"
    keep.mkdir()
    registry.register(gone, "t")
    registry.register(keep, "t")

    assert cmd_fleet_deregister("file convert") == 0

    assert _names() == ["keep"]


def test_a_name_two_entries_share_is_refused_and_nothing_is_written(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    x, y = tmp_path / "x" / "app", tmp_path / "y" / "app"
    registry.register(x, "t")
    registry.register(y, "t")
    before = registry.registry_path().read_text(encoding="utf-8")

    assert cmd_fleet_deregister("app") == 3

    assert registry.registry_path().read_text(encoding="utf-8") == before
    assert _backups() == []
    assert capsys.readouterr().err == (
        f"aramid: fleet deregister: 'app' names 2 registered repos "
        f"({_stored(x)}; {_stored(y)}) -- pass the full path\n")


def test_an_unknown_target_is_refused_naming_what_is_registered(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    registry.register(tmp_path / "b", "t")
    registry.register(tmp_path / "a", "t")
    before = registry.registry_path().read_text(encoding="utf-8")

    assert cmd_fleet_deregister("nope") == 3

    assert registry.registry_path().read_text(encoding="utf-8") == before
    assert _backups() == []
    assert capsys.readouterr().err == \
        "aramid: fleet deregister: 'nope' is not registered; registered: a, b\n"


def test_a_registry_that_cannot_be_rewritten_is_exit_3_with_the_reason(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    registry.register(tmp_path / "a", "t")

    def _refuse(_stored):
        raise OSError("disk full")
    monkeypatch.setattr(registry, "remove", _refuse)

    assert cmd_fleet_deregister("a") == 3

    assert _names() == ["a"]
    assert capsys.readouterr().err == "aramid: fleet deregister: failed (disk full)\n"


def test_the_verdict_is_rejudged_at_once_without_the_removed_repo(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    keep = tmp_path / "keep"
    keep.mkdir()
    registry.register(keep, "t")
    registry.register(tmp_path / "gone", "t")
    fleet.append_row(_green_row(keep))

    assert cmd_fleet_deregister("gone") == 0

    verdict = fleet.read_verdict()
    assert verdict is not None
    assert list(verdict["repos"]) == [fleet.repo_key(keep.resolve())]
    assert capsys.readouterr().out.splitlines()[-1] == fleet.readiness_line(verdict)


def test_the_cli_dispatches_deregister_and_bare_fleet_still_reports(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    registry.register(tmp_path / "a", "t")

    assert cli.main(["fleet", "deregister", "a"]) == 0
    assert _names() == []
    assert cli.main(["fleet"]) == 0
    assert cli.main(["fleet", "--json"]) == 0
    capsys.readouterr()


# --- the judge names a vanished entry instead of waiting on it --------------

def test_a_registered_path_that_is_gone_reads_missing_path_not_no_rows(tmp_path):
    here = tmp_path / "here"
    here.mkdir()
    entries = [{"path": str(here.resolve()), "registered_at": "t"},
               {"path": str((tmp_path / "gone").resolve()), "registered_at": "t"}]

    verdict = fleet.run_judgement(datetime.now(timezone.utc).isoformat(),
                                  aramid_version="0.18.0", entries=entries)

    assert verdict is not None
    assert verdict["verdict"] == fleet.INSUFFICIENT
    assert "no rows: here" in verdict["reasons"]
    assert "missing path: gone (`aramid fleet deregister gone`)" in verdict["reasons"]
