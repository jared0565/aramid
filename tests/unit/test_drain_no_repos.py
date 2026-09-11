"""`aramid drain` with nothing registered and no targets given.

The scheduled drain runs on every machine `aramid init` touched, including
one whose last repo was deregistered: the run must say so once, on
stderr, and exit 0 -- a non-zero here would page the scheduler's owner
four times a day for a machine that has nothing to do -- and it must do
so BEFORE the drain lock, the consumers' begin_drain hooks or any repo
loop is touched (the registry is the autouse tmp_path seam: empty)."""
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
