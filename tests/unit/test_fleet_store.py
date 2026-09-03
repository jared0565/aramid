"""The fleet store lives in ONE directory and every test is kept off the
real one. `ARAMID_FLEET_DIR` is an env var rather than a patched function
for the reason `toolpath.TOOLS_DIR_ENV` is: a gate driven through a real git
hook runs in a child process, and a monkeypatch cannot reach it."""
import os
from pathlib import Path

from aramid import fleet


def test_suite_isolates_the_store_from_the_real_home(tmp_path):
    # The autouse fixture in tests/conftest.py must already be in force.
    assert os.environ[fleet.FLEET_DIR_ENV].startswith(str(tmp_path))
    assert fleet.store_dir() == tmp_path / "aramid-fleet"
    assert fleet.health_path() == tmp_path / "aramid-fleet" / "fleet_health.jsonl"
    assert fleet.verdict_path() == tmp_path / "aramid-fleet" / "fleet_verdict.json"
    assert fleet.policy_path() == tmp_path / "aramid-fleet" / "fleet.toml"


def test_store_dir_defaults_to_home_dot_aramid(monkeypatch):
    monkeypatch.delenv(fleet.FLEET_DIR_ENV, raising=False)
    assert fleet.store_dir() == Path.home() / ".aramid"


def test_policy_defaults_when_fleet_toml_is_absent():
    assert fleet.load_policy() == fleet.Policy(min_days=14, min_versions=2,
                                               repeat_hours=24, defect_rows=3,
                                               gate_trailer=True)


def test_policy_reads_every_key(tmp_path):
    p = fleet.policy_path()
    p.parent.mkdir(parents=True)
    p.write_text('schema_version = 1\n[readiness]\nmin_days = 3\nmin_versions = 1\n'
                 '[notices]\nrepeat_hours = 6\ndefect_rows = 2\ngate_trailer = false\n',
                 encoding="utf-8")
    assert fleet.load_policy() == fleet.Policy(3, 1, 6, 2, False)


def test_policy_unreadable_falls_back_to_defaults_with_one_note(capsys):
    p = fleet.policy_path()
    p.parent.mkdir(parents=True)
    p.write_text("this is = not [toml\n", encoding="utf-8")
    assert fleet.load_policy() == fleet.Policy()
    err = capsys.readouterr().err
    assert err.startswith("aramid: fleet: ") and "unreadable" in err
    assert "using default policy" in err


def test_policy_key_of_the_wrong_type_falls_back_individually():
    p = fleet.policy_path()
    p.parent.mkdir(parents=True)
    p.write_text('[readiness]\nmin_days = "soon"\nmin_versions = 5\n', encoding="utf-8")
    pol = fleet.load_policy()
    assert pol.min_days == 14
    assert pol.min_versions == 5
