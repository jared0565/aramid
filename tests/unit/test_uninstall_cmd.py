"""`aramid uninstall` at unit scope on a real tmp repo with the agent-surface
removals answered: the refusal, each surface's "left untouched" line, the
gitignore edit and the summary line -- whole, with both exits.

The drain confirms a mutant against the unit suite alone, and all eight of
this module's generator mutants sat on lines the unit suite never executed:
tests/integration/test_uninstall.py covers them and the drain never runs
that directory."""
import subprocess
import sys
from pathlib import Path

from aramid import agent_files, agent_mcp, agent_settings, hooks, registry
from aramid.commands import uninstall
from aramid.commands.init import GITIGNORE_ENTRIES


def _repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=r, check=True, capture_output=True)
    return r


def _quiet(monkeypatch, *, blocks=(), settings="removed", mcp="removed"):
    monkeypatch.setattr(agent_files, "remove_agent_blocks", lambda root: list(blocks))
    monkeypatch.setattr(agent_settings, "remove_claude_settings", lambda root: settings)
    monkeypatch.setattr(agent_mcp, "remove_mcp_json", lambda root: mcp)


def _summary(root):
    return (f"aramid: uninstall: {root} -- hooks removed, ARAMID.md removed, agent blocks "
            f"removed, agent hooks removed, mcp server removed, gitignore entries removed. "
            f"The ledger (.aramid/) is KEPT -- delete it by hand if you also want to "
            f"discard finding/security history.\n")


def test_uninstall_refuses_outside_a_git_repository(tmp_path, capsys, monkeypatch):
    _quiet(monkeypatch)
    plain = tmp_path / "plain"
    plain.mkdir()
    assert uninstall.cmd_uninstall(plain) == 3
    assert capsys.readouterr() == ("", (
        f"aramid: uninstall: {plain.resolve()} is not inside a git repository (`git "
        f"rev-parse --show-toplevel` failed)\n"))


def test_uninstall_reverses_init_and_keeps_the_ledger(tmp_path, capsys, monkeypatch):
    _quiet(monkeypatch)
    r = _repo(tmp_path)
    hooks.install(r, Path(sys.executable))
    registry.register(r, "2026-09-14T00:00:00+00:00")
    (r / "ARAMID.md").write_text("# aramid\n", encoding="utf-8")
    (r / ".aramid").mkdir()
    (r / ".aramid" / "ledger.db").write_bytes(b"")
    (r / ".gitignore").write_text("node_modules/\n" + "\n".join(GITIGNORE_ENTRIES) + "\n",
                                  encoding="utf-8")

    assert uninstall.cmd_uninstall(r) == 0
    assert capsys.readouterr() == (_summary(r), "")
    hdir = hooks.hooks_dir(r)
    assert not any((hdir / h).exists() for h in ("pre-commit", "pre-push", "post-commit"))
    assert not (r / "ARAMID.md").exists()
    assert (r / ".aramid" / "ledger.db").exists(), "history survives an uninstall"
    assert (r / ".gitignore").read_text(encoding="utf-8") == "node_modules/\n"
    assert registry.load_registry() == [], "deregistered"


def test_uninstall_names_each_surface_it_had_to_leave_alone(tmp_path, capsys, monkeypatch):
    _quiet(monkeypatch, blocks=[("CLAUDE.md", "damaged"), ("AGENTS.md", "unreadable"),
                                ("GEMINI.md", "removed")],
           settings="unparseable", mcp="unparseable")
    r = _repo(tmp_path)

    assert uninstall.cmd_uninstall(r) == 0
    out, err = capsys.readouterr()
    assert out == _summary(r)
    assert err == (
        "aramid: uninstall: CLAUDE.md has a damaged aramid fence (unterminated or "
        "duplicated begin marker) -- left untouched; remove the fence by hand.\n"
        "aramid: uninstall: AGENTS.md could not be read (not valid UTF-8, or an I/O "
        "error) -- left untouched; remove the fence by hand.\n"
        "aramid: uninstall: .claude/settings.json could not be parsed -- left untouched; "
        "remove aramid's hook entry by hand.\n"
        "aramid: uninstall: .mcp.json could not be parsed -- left untouched; remove "
        "aramid's server entry by hand.\n")


def test_uninstall_leaves_a_registry_from_a_newer_aramid_alone_and_exits_3(
        tmp_path, capsys, monkeypatch):
    """Every other step still runs; the registry -- one file every aramid on
    the machine shares -- is not rewritten by one that cannot read it, and
    the exit says the uninstall was not whole (1.0 blocker API-4)."""
    _quiet(monkeypatch)
    r = _repo(tmp_path)
    reg = tmp_path / "repos.toml"
    monkeypatch.setattr(registry, "registry_path", lambda: reg)
    reg.write_text("schema_version = 2\n", encoding="utf-8")
    newer = (f"{reg} was written by a newer aramid (registry schema 2; this one "
             f"reads up to 1) -- upgrade aramid to use it")

    assert uninstall.cmd_uninstall(r) == 3
    assert capsys.readouterr() == (_summary(r), (
        f"aramid: registry: {newer}; treating as empty\n"
        f"aramid: uninstall: not deregistered -- {newer}\n"))
    assert reg.read_text(encoding="utf-8") == "schema_version = 2\n"


def test_uninstall_leaves_an_unreadable_registry_alone_and_exits_3(
        tmp_path, capsys, monkeypatch):
    """Same contract for a registry nothing can parse: it may be a fleet a
    person can repair, so uninstall does not replace it with an empty one."""
    _quiet(monkeypatch)
    r = _repo(tmp_path)
    reg = tmp_path / "repos.toml"
    monkeypatch.setattr(registry, "registry_path", lambda: reg)
    reg.write_text("not [ valid toml", encoding="utf-8")

    assert uninstall.cmd_uninstall(r) == 3
    out, err = capsys.readouterr()
    assert out == _summary(r)
    lines = err.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("aramid: registry unreadable (")
    assert lines[1].startswith(f"aramid: uninstall: not deregistered -- {reg} is unreadable (")
    assert lines[1].endswith("-- left untouched; fix it by hand, or delete it to start the "
                             "fleet over")
    assert reg.read_text(encoding="utf-8") == "not [ valid toml"


def test_remove_gitignore_entries_rewrites_only_when_something_was_ours(tmp_path):
    uninstall._remove_gitignore_entries(tmp_path)          # no file: nothing to do
    assert not (tmp_path / ".gitignore").exists()

    gi = tmp_path / ".gitignore"
    gi.write_text("node_modules/\ndist/\n", encoding="utf-8")
    before = gi.stat().st_mtime_ns
    uninstall._remove_gitignore_entries(tmp_path)
    assert gi.read_text(encoding="utf-8") == "node_modules/\ndist/\n"
    assert gi.stat().st_mtime_ns == before, "nothing of ours: the file is not rewritten"

    gi.write_text("\n".join(GITIGNORE_ENTRIES) + "\n", encoding="utf-8")
    uninstall._remove_gitignore_entries(tmp_path)
    assert gi.read_text(encoding="utf-8") == "", "only ours: emptied, no trailing newline"

    gi.write_text(f"a/\n  {GITIGNORE_ENTRIES[0]}  \nb/", encoding="utf-8")
    uninstall._remove_gitignore_entries(tmp_path)
    assert gi.read_text(encoding="utf-8") == "a/\nb/\n"
