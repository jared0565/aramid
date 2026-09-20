"""`cli.main` at unit scope: every branch of the dispatch chain, with every
`cmd_*` name replaced by a recorder and the exact call -- positional and
keyword shape included -- asserted per command.

The drain confirms a mutant against the unit suite alone, and until this
file nothing in it executed `main`, `_check_mode`'s gate branches or
`_force_utf8_on_redirect`: tests/integration/test_cli_dispatch.py covers
them, and the drain never runs it. `main` is the most edited function in
the tree (27 commits in 60 days) and every one of its 43 generator mutants
was a survivor by construction: `==` -> `!=` on any command match either
routes that command to `unknown command` (exit 3) or feeds the NEXT arm a
namespace missing its attributes, `or` -> `and` on the two defaults
silently swaps a reason or a notices subcommand, and every exit-code
literal is one `3 -> 4` from a contract the shims and the docs pin.

Seams: `cli.cmd_<x>` rebound to a recorder (the integration file's own
seam), `sys.stdin`/`sys.stdout` replaced only where the code reads their
tty-ness. Nothing here spawns a process."""
import argparse
from pathlib import Path

import pytest

from aramid import __version__, cli
from aramid.models import Gate

RC = 7      # a recorder's exit code: unique, so `main` returning it proves it dispatched


def _bind(monkeypatch, name, rc=RC):
    calls = []

    def recorder(*a, **kw):
        calls.append((a, kw))
        return rc
    monkeypatch.setattr(cli, name, recorder)
    return calls


def _root():
    return Path.cwd()


# --------------------------------------------------------- parse failures --

def test_help_exits_0_without_dispatching(capsys):
    assert cli.main(["--help"]) == 0
    assert capsys.readouterr().out.startswith("usage: aramid")


def test_a_subcommand_help_exits_0(capsys):
    assert cli.main(["check", "--help"]) == 0
    assert capsys.readouterr().out.startswith("usage: aramid check")


def test_a_bad_flag_is_exit_3_not_argparses_own_2(capsys):
    assert cli.main(["check", "--not-a-real-flag"]) == 3
    assert "unrecognized arguments: --not-a-real-flag" in capsys.readouterr().err


def test_an_unregistered_command_is_exit_3(capsys):
    assert cli.main(["definitely-not-a-command"]) == 3
    assert "invalid choice: 'definitely-not-a-command'" in capsys.readouterr().err


def test_a_mutually_exclusive_pair_is_exit_3(capsys):
    assert cli.main(["arm", "--llm", "--tdd"]) == 3
    assert "not allowed with argument" in capsys.readouterr().err


def test_a_non_int_exit_code_from_the_parser_is_exit_3(monkeypatch):
    class Dying(argparse.ArgumentParser):
        def parse_args(self, argv=None, namespace=None):
            raise SystemExit("aramid: parser died")
    monkeypatch.setattr(cli, "build_parser", lambda: Dying(prog="aramid"))

    assert cli.main(["anything"]) == 3


# ------------------------------------------------------ the two non-commands --

def test_version_prints_the_package_version_and_exits_0(capsys):
    assert cli.main(["--version"]) == 0
    assert capsys.readouterr() == (f"aramid {__version__}\n", "")


def test_version_wins_over_a_command_on_the_same_line(monkeypatch, capsys):
    calls = _bind(monkeypatch, "cmd_doctor")

    assert cli.main(["--version", "doctor"]) == 0
    assert capsys.readouterr().out == f"aramid {__version__}\n"
    assert calls == []


def test_no_command_is_exit_3_on_stderr(capsys):
    assert cli.main([]) == 3
    assert capsys.readouterr() == ("", "aramid: no command\n")


# ------------------------------------------------------------ the chain --

def test_init(monkeypatch):
    calls = _bind(monkeypatch, "cmd_init")

    assert cli.main(["init"]) == RC
    assert cli.main(["init", "sub/dir", "--discover"]) == RC
    assert calls == [((Path("."),), {"discover": False}),
                     ((Path("sub/dir"),), {"discover": True})]


@pytest.mark.parametrize("argv, gate, mode", [
    ([], Gate.PRE_COMMIT, "staged"),
    (["--gate", "pre-commit"], Gate.PRE_COMMIT, "staged"),
    (["--gate", "pre-push"], Gate.PRE_PUSH, "range"),
    (["--gate", "all"], Gate.ALL, "all"),
    (["--gate", "all", "--staged"], Gate.ALL, "staged"),
    (["--gate", "pre-push", "--all"], Gate.PRE_PUSH, "all"),
    (["--range"], Gate.PRE_COMMIT, "range"),
    (["--staged"], Gate.PRE_COMMIT, "staged"),
])
def test_check_maps_the_gate_and_the_mode(monkeypatch, argv, gate, mode):
    calls = _bind(monkeypatch, "cmd_check")

    assert cli.main(["check", *argv]) == RC
    assert calls == [((_root(), gate, mode),
                      {"strict": False, "as_json": False, "accept_degraded": None})]
    assert isinstance(calls[0][0][1], Gate)


def test_check_passes_strict_and_json(monkeypatch):
    calls = _bind(monkeypatch, "cmd_check")

    assert cli.main(["check", "--gate", "pre-push", "--strict", "--json"]) == RC
    assert calls == [((_root(), Gate.PRE_PUSH, "range"),
                      {"strict": True, "as_json": True, "accept_degraded": None})]


def test_check_accept_degraded_carries_the_reason_or_the_default(monkeypatch):
    calls = _bind(monkeypatch, "cmd_check")

    assert cli.main(["check", "--accept-degraded", "--reason", "ci sandbox has no gitleaks"]) == RC
    assert cli.main(["check", "--accept-degraded"]) == RC
    assert cli.main(["check", "--reason", "ignored without the flag"]) == RC
    assert [kw["accept_degraded"] for _, kw in calls] == [
        "ci sandbox has no gitleaks", "no reason given", None]


def test_check_passes_record_false_only_when_asked(monkeypatch):
    calls = _bind(monkeypatch, "cmd_check")

    assert cli.main(["check", "--no-record"]) == RC
    assert cli.main(["check"]) == RC
    assert calls == [
        ((_root(), Gate.PRE_COMMIT, "staged"),
         {"strict": False, "as_json": False, "accept_degraded": None, "record": False}),
        ((_root(), Gate.PRE_COMMIT, "staged"),
         {"strict": False, "as_json": False, "accept_degraded": None}),
    ]


def test_check_returns_the_engines_exit_code_unchanged(monkeypatch):
    monkeypatch.setattr(cli, "cmd_check", lambda *a, **kw: 2)
    assert cli.main(["check"]) == 2


def test_doctor(monkeypatch):
    calls = _bind(monkeypatch, "cmd_doctor")

    assert cli.main(["doctor"]) == RC
    assert cli.main(["doctor", "--fix"]) == RC
    assert calls == [((_root(),), {"fix": False}), ((_root(),), {"fix": True})]


def test_status(monkeypatch):
    calls = _bind(monkeypatch, "cmd_status")

    assert cli.main(["status"]) == RC
    assert calls == [((_root(),), {})]


def test_agent_hook_passes_the_event_and_swallows_the_rest(monkeypatch):
    calls = _bind(monkeypatch, "cmd_agent_hook")

    assert cli.main(["agent-hook", "session-start"]) == RC
    assert cli.main(["agent-hook", "future-event", "--future-flag", "x"]) == RC
    assert calls == [(("session-start", _root()), {}), (("future-event", _root()), {})]


def test_resolvers(monkeypatch):
    calls = _bind(monkeypatch, "cmd_resolvers")

    assert cli.main(["resolvers"]) == RC
    assert cli.main(["resolvers", "--json"]) == RC
    assert calls == [((_root(),), {"as_json": False}), ((_root(),), {"as_json": True})]


def test_fleet_takes_no_root(monkeypatch):
    calls = _bind(monkeypatch, "cmd_fleet")

    assert cli.main(["fleet"]) == RC
    assert cli.main(["fleet", "--json"]) == RC
    assert calls == [((), {"as_json": False}), ((), {"as_json": True})]


def test_notices_defaults_to_list_and_passes_the_id(monkeypatch):
    calls = _bind(monkeypatch, "cmd_notices")

    assert cli.main(["notices"]) == RC
    assert cli.main(["notices", "list"]) == RC
    assert cli.main(["notices", "show", "n-1"]) == RC
    assert cli.main(["notices", "ack", "n-2"]) == RC
    assert calls == [(("list", None, _root()), {}), (("list", None, _root()), {}),
                     (("show", "n-1", _root()), {}), (("ack", "n-2", _root()), {})]


def test_mutation_score(monkeypatch):
    calls = _bind(monkeypatch, "cmd_mutation_score")

    assert cli.main(["mutation-score"]) == RC
    assert cli.main(["mutation-score", "--json"]) == RC
    assert calls == [((_root(),), {"as_json": False}), ((_root(),), {"as_json": True})]


def test_triage_defaults_to_head_with_no_budget(monkeypatch):
    calls = _bind(monkeypatch, "cmd_triage")

    assert cli.main(["triage"]) == RC
    assert cli.main(["triage", "abc123", "--budget", "2.5"]) == RC
    assert calls == [((_root(), "HEAD"), {"budget": None}),
                     ((_root(), "abc123"), {"budget": 2.5})]


def test_drain_targets_this_repo_a_named_repo_or_every_repo(monkeypatch):
    calls = _bind(monkeypatch, "cmd_drain")

    assert cli.main(["drain"]) == RC
    assert cli.main(["drain", "--repo", "X:/elsewhere", "--dry-run"]) == RC
    assert cli.main(["drain", "--all", "--max-items", "2"]) == RC
    assert calls == [(([str(_root())],), {"dry_run": False, "max_items": None}),
                     ((["X:/elsewhere"],), {"dry_run": True, "max_items": None}),
                     (([],), {"dry_run": False, "max_items": 2})]


def test_ledger_list_show_filter(monkeypatch):
    lst = _bind(monkeypatch, "cmd_ledger_list")
    show = _bind(monkeypatch, "cmd_ledger_show")
    flt = _bind(monkeypatch, "cmd_ledger_filter")

    assert cli.main(["ledger", "list"]) == RC
    assert cli.main(["ledger", "show", "deadbeef"]) == RC
    assert cli.main(["ledger", "filter"]) == RC
    assert cli.main(["ledger", "filter", "--tool", "semgrep", "--rule", "r1",
                     "--status", "open", "--severity", "block", "--json"]) == RC
    assert lst == [((_root(),), {})]
    assert show == [((_root(), "deadbeef"), {})]
    assert flt == [((_root(),), {"tool": None, "rule": None, "status": None,
                                 "severity": None, "as_json": False}),
                   ((_root(),), {"tool": "semgrep", "rule": "r1", "status": "open",
                                 "severity": "block", "as_json": True})]


def test_ledger_marks_take_the_id_and_the_reason_positionally(monkeypatch):
    rotated = _bind(monkeypatch, "cmd_ledger_mark_rotated")
    nas = _bind(monkeypatch, "cmd_ledger_mark_not_a_secret")
    unreachable = _bind(monkeypatch, "cmd_ledger_mark_unreachable")

    assert cli.main(["ledger", "mark-rotated", "id1", "--reason", "rotated 2x"]) == RC
    assert cli.main(["ledger", "mark-not-a-secret", "id2", "--reason", "fixture"]) == RC
    assert cli.main(["ledger", "mark-unreachable", "id3", "--reason", "dead code"]) == RC
    assert rotated == [((_root(), "id1", "rotated 2x"), {})]
    assert nas == [((_root(), "id2", "fixture"), {})]
    assert unreachable == [((_root(), "id3", "dead code"), {})]


def test_ledger_mark_without_a_reason_is_exit_3(capsys):
    assert cli.main(["ledger", "mark-rotated", "id1"]) == 3
    assert "--reason" in capsys.readouterr().err


def test_ledger_resolve_visits_every_id_and_returns_the_worst_rc(monkeypatch):
    calls = []
    rcs = {"aaa": 0, "bbb": 3, "ccc": 0}
    monkeypatch.setattr(cli, "cmd_ledger_resolve",
                        lambda *a, **kw: calls.append((a, kw)) or rcs[a[1]])

    assert cli.main(["ledger", "resolve", "aaa", "bbb", "ccc",
                     "--out-of-scope", "--reason", "outside [tool.mypy] files"]) == 3
    assert cli.main(["ledger", "resolve", "aaa", "--reason", "fixed upstream"]) == 0
    assert calls == [((_root(), "aaa", True, "outside [tool.mypy] files"), {}),
                     ((_root(), "bbb", True, "outside [tool.mypy] files"), {}),
                     ((_root(), "ccc", True, "outside [tool.mypy] files"), {}),
                     ((_root(), "aaa", False, "fixed upstream"), {})]


def test_ledger_without_a_subcommand_names_them_all_and_exits_3(capsys):
    assert cli.main(["ledger"]) == 3
    assert capsys.readouterr() == (
        "", "aramid: ledger: a subcommand is required "
            "(list|show|filter|consumers|mark-rotated|mark-not-a-secret|mark-unreachable|resolve)\n")


def test_override(monkeypatch):
    calls = _bind(monkeypatch, "cmd_override")

    assert cli.main(["override", "id9", "--reason", "false positive: test fixture"]) == RC
    assert calls == [((_root(), "id9", "false positive: test fixture"), {})]


def test_pack_list_add_compile(monkeypatch):
    lst = _bind(monkeypatch, "cmd_pack_list")
    add = _bind(monkeypatch, "cmd_pack_add")
    compile_ = _bind(monkeypatch, "cmd_pack_compile")

    assert cli.main(["pack", "list"]) == RC
    assert cli.main(["pack", "add", "id4"]) == RC
    assert cli.main(["pack", "compile"]) == RC
    assert lst == [((_root(),), {})]
    assert add == [((_root(), "id4"), {})]
    assert compile_ == [((_root(),), {})]


def test_pack_without_a_subcommand_names_them_all_and_exits_3(capsys):
    assert cli.main(["pack"]) == 3
    assert capsys.readouterr() == (
        "", "aramid: pack: a subcommand is required (list|add|compile)\n")


def test_autolearn(monkeypatch):
    calls = _bind(monkeypatch, "cmd_autolearn")

    assert cli.main(["autolearn"]) == RC
    assert cli.main(["autolearn", "--rebuild"]) == RC
    assert calls == [((_root(),), {"rebuild": False}), ((_root(),), {"rebuild": True})]


ARM_FLAGS = ("llm", "autolearn", "tdd", "mutation", "mutation_score", "red_proof",
             "shadow", "agent")


@pytest.mark.parametrize("flag", (None, *ARM_FLAGS))
def test_arm_passes_exactly_one_surface_or_none(monkeypatch, flag):
    calls = _bind(monkeypatch, "cmd_arm")
    argv = ["arm"] if flag is None else ["arm", "--" + flag.replace("_", "-")]

    assert cli.main(argv) == RC
    assert calls == [((_root(),), {name: name == flag for name in ARM_FLAGS})]


def test_update_rules(monkeypatch):
    calls = _bind(monkeypatch, "cmd_update_rules")

    assert cli.main(["update-rules"]) == RC
    assert calls == [((_root(),), {})]


def test_uninstall_takes_a_path_positionally(monkeypatch):
    calls = _bind(monkeypatch, "cmd_uninstall")

    assert cli.main(["uninstall"]) == RC
    assert cli.main(["uninstall", "other/repo"]) == RC
    assert calls == [((Path("."),), {}), ((Path("other/repo"),), {})]


def test_schedule_passes_the_action(monkeypatch):
    calls = _bind(monkeypatch, "cmd_schedule")

    for action in ("install", "remove", "status"):
        assert cli.main(["schedule", action]) == RC
    assert calls == [((_root(), a), {}) for a in ("install", "remove", "status")]


def test_schedule_rejects_an_unknown_action(capsys):
    assert cli.main(["schedule", "restart"]) == 3
    assert "invalid choice: 'restart'" in capsys.readouterr().err


def test_hooks_is_imported_lazily_and_gets_only_the_action(monkeypatch):
    calls = []
    monkeypatch.setattr("aramid.commands.hooks_template.cmd_hooks",
                        lambda *a, **kw: calls.append((a, kw)) or RC)
    assert not hasattr(cli, "cmd_hooks"), "hooks_template is not imported at module load"

    for action in ("install", "remove", "status"):
        assert cli.main(["hooks", action]) == RC
    assert calls == [((a,), {}) for a in ("install", "remove", "status")]


def test_rebaseline_takes_a_path_and_yes(monkeypatch):
    calls = _bind(monkeypatch, "cmd_rebaseline")

    assert cli.main(["rebaseline"]) == RC
    assert cli.main(["rebaseline", "other/repo", "--yes"]) == RC
    assert calls == [((Path("."),), {"yes": False}), ((Path("other/repo"),), {"yes": True})]


def test_a_parsed_command_the_chain_does_not_know_is_reported_and_exit_3(monkeypatch, capsys):
    """The tail of the chain is reachable only through drift -- a subparser
    registered without a dispatch arm -- so the drift is injected."""
    def parser_with_an_orphan():
        p = argparse.ArgumentParser(prog="aramid")
        p.add_argument("--version", action="store_true")
        p.add_subparsers(dest="command").add_parser("orphan")
        return p
    monkeypatch.setattr(cli, "build_parser", parser_with_an_orphan)

    assert cli.main(["orphan"]) == 3
    assert capsys.readouterr() == ("", "aramid: unknown command: orphan\n")


# ------------------------------------------------------- the utf-8 seam --

class _Stream:
    def __init__(self, tty):
        self.tty = tty
        self.reconfigured = []

    def isatty(self):
        return self.tty

    def reconfigure(self, **kw):
        self.reconfigured.append(kw)


def test_redirected_streams_are_reconfigured_to_utf8_and_a_tty_is_left_alone(monkeypatch):
    out, err = _Stream(tty=False), _Stream(tty=True)
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)

    cli._force_utf8_on_redirect()

    assert out.reconfigured == [{"encoding": "utf-8"}]
    assert err.reconfigured == []


def test_a_stream_without_reconfigure_or_isatty_never_raises(monkeypatch):
    class Bare:
        pass

    class Refusing(_Stream):
        def reconfigure(self, **kw):
            raise ValueError("stream has been detached")
    monkeypatch.setattr("sys.stdout", Bare())
    monkeypatch.setattr("sys.stderr", Refusing(tty=False))

    assert cli._force_utf8_on_redirect() is None


def test_main_reconfigures_before_it_prints(monkeypatch):
    out = _Stream(tty=False)
    out.write = lambda s: None
    monkeypatch.setattr("sys.stdout", out)

    assert cli.main(["--version"]) == 0
    assert out.reconfigured == [{"encoding": "utf-8"}]
