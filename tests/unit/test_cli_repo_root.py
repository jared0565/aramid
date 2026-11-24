"""A command started below the top of an armed repository works on that top
level (interop round 333; operator decision 2026-11-24, "run on the repo
root"). Run from bytes-web's `crm-api-worker/`, `aramid doctor` read no
`aramid.toml` -- so the BLOCK-tier tests gate the root's `[tests].command`
feeds had nothing to run -- and the run kept a second, disagreeing
`.aramid/` there with its own ledger and salt. The MCP tools and `aramid
handover` already resolve the repo at its git root (`gitutil.armed_root`);
the CLI took the cwd. Real git, real ledger."""
import subprocess

import pytest

from aramid import cli, gitutil


def _git(r, *a):
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a], cwd=r,
                   check=True, capture_output=True)


def _repo(tmp_path, *, toml=True, dot_aramid=False):
    r = tmp_path / "r"
    (r / "web" / "worker").mkdir(parents=True)
    _git(r, "init", "-q", "-b", "main")
    if toml:
        (r / "aramid.toml").write_text('[tests]\ncommand = ["node", "test/run.mjs"]\n')
    if dot_aramid:
        (r / ".aramid").mkdir()
    return r.resolve()


def test_below_an_armed_top_the_top_is_the_root(tmp_path):
    r = _repo(tmp_path)

    assert gitutil.gated_top(r / "web" / "worker") == r


def test_a_top_with_only_a_ledger_counts_as_armed(tmp_path):
    """A gate ran there without `init`: its ledger is the repo's."""
    r = _repo(tmp_path, toml=False, dot_aramid=True)

    assert gitutil.gated_top(r / "web") == r


def test_at_the_top_there_is_nothing_to_move_to(tmp_path):
    r = _repo(tmp_path)

    assert gitutil.gated_top(r) is None


def test_below_a_top_aramid_never_ran_in_the_cwd_stays(tmp_path):
    r = _repo(tmp_path, toml=False)

    assert gitutil.gated_top(r / "web") is None


def test_outside_git_the_cwd_stays(tmp_path):
    (tmp_path / "plain").mkdir()

    assert gitutil.gated_top(tmp_path / "plain") is None


def test_a_top_whose_aramid_toml_is_a_directory_is_not_armed(tmp_path):
    r = _repo(tmp_path, toml=False)
    (r / "aramid.toml").mkdir()

    assert gitutil.gated_top(r / "web") is None


@pytest.fixture
def seen(monkeypatch):
    calls = []

    def recorder(name):
        def fake(*a, **k):
            calls.append((name, a, k))
            return 0
        return fake

    for name in ("cmd_doctor", "cmd_check", "cmd_drain", "cmd_ledger_filter"):
        monkeypatch.setattr(cli, name, recorder(name))
    return calls


@pytest.mark.parametrize("argv, name", [
    (["doctor"], "cmd_doctor"),
    (["check", "--gate", "pre-push", "--all"], "cmd_check"),
    (["ledger", "filter", "--status", "open"], "cmd_ledger_filter"),
])
def test_a_command_started_in_a_subdirectory_works_on_the_top(
        tmp_path, monkeypatch, capsys, seen, argv, name):
    r = _repo(tmp_path)
    sub = r / "web" / "worker"
    monkeypatch.chdir(sub)

    assert cli.main(argv) == 0

    assert [(n, a[0]) for n, a, _k in seen] == [(name, r)]
    assert capsys.readouterr().err == (
        f"aramid: working on the repository root {r}, not {sub}: a repository has"
        " one aramid config and one ledger, at its root\n")


def test_a_drain_with_no_repo_named_drains_the_top(tmp_path, monkeypatch, seen):
    r = _repo(tmp_path)
    monkeypatch.chdir(r / "web")

    cli.main(["drain", "--dry-run"])

    assert seen[0][1][0] == [str(r)]


def test_the_subdirectory_own_aramid_state_is_named_unused(tmp_path, monkeypatch, capsys, seen):
    r = _repo(tmp_path)
    sub = r / "web" / "worker"
    (sub / ".aramid").mkdir()
    (sub / "aramid.toml").write_text("")
    monkeypatch.chdir(sub)

    cli.main(["doctor"])

    assert capsys.readouterr().err.endswith(
        " at its root; this directory's own aramid.toml and .aramid/ are not used\n")


def test_a_lone_stray_ledger_is_named_in_the_singular(tmp_path, monkeypatch, capsys, seen):
    """bytes-web's case: `crm-api-worker/.aramid/` with no aramid.toml."""
    r = _repo(tmp_path)
    sub = r / "web" / "worker"
    (sub / ".aramid").mkdir()
    monkeypatch.chdir(sub)

    cli.main(["doctor"])

    assert capsys.readouterr().err.endswith(
        " at its root; this directory's own .aramid/ is not used\n")


def test_at_the_top_nothing_is_said(tmp_path, monkeypatch, capsys, seen):
    r = _repo(tmp_path)
    monkeypatch.chdir(r)

    cli.main(["doctor"])

    assert seen[0][1][0] == r and capsys.readouterr().err == ""


def test_below_an_unarmed_top_the_cwd_is_kept_as_today(tmp_path, monkeypatch, capsys, seen):
    r = _repo(tmp_path, toml=False)
    monkeypatch.chdir(r / "web")

    cli.main(["doctor"])

    assert seen[0][1][0] == r / "web" and capsys.readouterr().err == ""


def test_status_from_a_subdirectory_reads_the_top_ledger_and_writes_none_below(
        tmp_path, monkeypatch, capsys):
    """The second ledger: before, `aramid status` here created
    `web/worker/.aramid/ledger.db` and reported its empty state."""
    r = _repo(tmp_path)
    sub = r / "web" / "worker"
    monkeypatch.chdir(r)
    assert cli.main(["status"]) == 0
    at_top = capsys.readouterr().out
    monkeypatch.chdir(sub)

    assert cli.main(["status"]) == 0

    assert capsys.readouterr().out == at_top
    assert not (sub / ".aramid").exists()


def test_control_characters_in_the_paths_are_escaped_and_backslashes_kept(
        tmp_path, monkeypatch, capsys):
    from pathlib import Path
    monkeypatch.setattr(gitutil, "gated_top", lambda cwd: Path("C:\\top\x1b[2J"))

    assert cli._repo_root_of(Path("C:\\top\\a\nb")) == Path("C:\\top\x1b[2J")

    assert capsys.readouterr().err == (
        "aramid: working on the repository root C:\\top\\x1b[2J, not C:\\top\\a\\x0ab:"
        " a repository has one aramid config and one ledger, at its root\n")


def test_the_agent_hook_keeps_its_own_rule_and_says_nothing(tmp_path, monkeypatch, capsys):
    """It resolves the repo itself (`armed_root`), and its stderr is a hook's."""
    r = _repo(tmp_path)
    monkeypatch.chdir(r / "web")
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("{}"))

    cli.main(["agent-hook", "session-start"])

    assert "working on the repository root" not in capsys.readouterr().err
