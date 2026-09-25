"""`aramid drain` with nothing registered and no targets given.

The scheduled drain runs on every machine `aramid init` touched, including
one whose last repo was deregistered: the run must say so once, on
stderr, and exit 0 -- a non-zero here would page the scheduler's owner
four times a day for a machine that has nothing to do -- and it must do
so BEFORE the drain lock, the consumers' begin_drain hooks or any repo
loop is touched (the registry is the autouse tmp_path seam: empty)."""
import pytest

from aramid import registry
from aramid.commands import drain as drain_mod
from aramid.commands.drain import cmd_drain


def test_nothing_registered_and_no_targets_is_one_stderr_line_and_exit_0(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: tmp_path / "central" / "drain.lock")

    rc = cmd_drain([], dry_run=False)

    out, err = capsys.readouterr()
    assert rc == 0
    assert err == "aramid drain: no repos registered and none given\n"
    assert out == ""
    assert not (tmp_path / "central").exists(), "returned before the lock was ever acquired"

@pytest.mark.parametrize("body, why", [
    ("repos = [\n", "is unreadable"),
    ("schema_version = 2\n", "was written by a newer aramid (registry schema 2; this one "
                             "reads up to 1) -- upgrade aramid to use it"),
])
def test_a_registry_it_cannot_read_is_an_engine_error_not_an_empty_fleet(
        tmp_path, monkeypatch, capsys, body, why):
    """Empty is a machine with nothing to do (exit 0, above). Unreadable is
    a machine whose drain would do nothing forever while exiting 0 -- the
    exit-3 "registry unusable" case the drain docstring, `drain --help`, the
    user guide and the knowledge base all promised and the code never had."""
    reg = tmp_path / "repos.toml"
    reg.write_text(body, encoding="utf-8")
    monkeypatch.setattr(registry, "registry_path", lambda: reg)
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: tmp_path / "central" / "drain.lock")

    rc = cmd_drain([], dry_run=False)

    out, err = capsys.readouterr()
    assert rc == 3
    assert out == ""
    assert err.startswith(f"aramid: drain: registry unusable -- {reg} {why}")
    assert err.count("\n") == 1
    assert not (tmp_path / "central").exists(), "returned before the lock was ever acquired"
    assert reg.read_text(encoding="utf-8") == body
