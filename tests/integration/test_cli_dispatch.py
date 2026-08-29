"""integration: aramid.cli -- the full argparse subcommand tree and
dispatch to aramid.commands.*.

Process-level exit-code tests (subprocess, mirroring test_version.py's own
style -- these need real argparse/SystemExit/process semantics) plus
in-process dispatch-mapping tests (monkeypatching the cmd_* names bound
into aramid.cli's own namespace) for argument translation.

EVERY SUBPROCESS HERE IS BOUND TO THIS CHECKOUT, via `run_cli` on top of the
suite-wide `checkout_env` fixture. Until 2026-08-26 the helper spawned a bare
`python -m aramid`, which on a two-aramid machine resolves the INSTALLED
WHEEL: the mutual-exclusion tests below asserted exit 3 and would have passed
against a wheel that had never heard of the flag -- also exit 3. Measured with
`arm --shadow --llm`: the wheel said "unrecognized arguments: --shadow", the
checkout said "--llm: not allowed with argument --shadow", both exited 3.
Only the program differed. CI never saw it (CI installs `-e`, so a bare
child finds the checkout by accident); the local pre-push gate did.
"""
import argparse
import subprocess
import sys
from pathlib import Path

import pytest

from aramid import cli
from aramid.models import Gate


@pytest.fixture
def run_cli(checkout_env):
    """`python -P -m aramid <args>` as a child process of THIS checkout.

    `-P` for the same reason every shim carries it: without it the child's
    sys.path[0] is the CWD, and a repo-root aramid.py would beat the
    PYTHONPATH the fixture just set. `cwd` is for tests that need a
    particular tree under the command; the default is wherever pytest runs.
    """
    def _run(*args, cwd=None):
        return subprocess.run([sys.executable, "-P", "-m", "aramid", *args],
                              capture_output=True, text=True,
                              env=checkout_env, cwd=cwd)
    return _run


# ------------------------------------------------------- process-level ------

def test_version_flag_still_works(run_cli):
    out = run_cli("--version")
    assert out.returncode == 0
    assert out.stdout.strip().startswith("aramid ")


def test_check_help_exits_0(run_cli):
    out = run_cli("check", "--help")
    assert out.returncode == 0


def test_unknown_command_exits_3(run_cli):
    out = run_cli("definitely-not-a-real-command")
    assert out.returncode == 3


def test_no_command_exits_3(run_cli):
    """Deferred from Task 0.1 (progress.md): `python -m aramid` with no
    command must return exit 3, not silently succeed."""
    out = run_cli()
    assert out.returncode == 3


def test_bad_flag_exits_3_not_argparses_own_2(run_cli):
    out = run_cli("check", "--not-a-real-flag")
    assert out.returncode == 3


# --------------------------------------------------------- in-process dispatch

def test_check_dispatch_maps_gate_and_mode(monkeypatch):
    captured = {}

    def fake_cmd_check(root, gate, mode, strict=False, as_json=False, accept_degraded=None):
        captured.update(root=root, gate=gate, mode=mode, strict=strict, as_json=as_json,
                         accept_degraded=accept_degraded)
        return 0

    monkeypatch.setattr(cli, "cmd_check", fake_cmd_check)

    rc = cli.main(["check", "--gate", "pre-push", "--strict", "--json"])

    assert rc == 0
    assert captured["gate"] is Gate.PRE_PUSH
    assert captured["mode"] == "range"  # default mode for pre-push when unspecified
    assert captured["strict"] is True
    assert captured["as_json"] is True
    assert captured["accept_degraded"] is None


def test_check_dispatch_defaults_to_staged_for_pre_commit(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_check",
                         lambda root, gate, mode, **kw: captured.update(gate=gate, mode=mode) or 0)

    cli.main(["check"])

    assert captured["gate"] is Gate.PRE_COMMIT
    assert captured["mode"] == "staged"


def test_check_dispatch_all_flag_overrides_mode(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_check",
                         lambda root, gate, mode, **kw: captured.update(mode=mode) or 0)

    cli.main(["check", "--gate", "pre-push", "--all"])

    assert captured["mode"] == "all"


def test_check_dispatch_accept_degraded_with_reason(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_check",
                         lambda root, gate, mode, **kw: captured.update(**kw) or 0)

    cli.main(["check", "--accept-degraded", "--reason", "ci sandbox has no gitleaks"])

    assert captured["accept_degraded"] == "ci sandbox has no gitleaks"


def test_check_dispatch_returns_engine_exit_code(monkeypatch):
    monkeypatch.setattr(cli, "cmd_check", lambda *a, **kw: 1)
    assert cli.main(["check"]) == 1


def test_doctor_dispatch_maps_fix_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_doctor",
                         lambda root, fix=False: captured.update(fix=fix) or 0)

    cli.main(["doctor", "--fix"])

    assert captured["fix"] is True


def test_init_dispatch_maps_path_and_discover(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_init",
                         lambda path, discover=False: captured.update(path=path, discover=discover) or 0)

    cli.main(["init", "some/path", "--discover"])

    assert captured["path"] == Path("some/path")
    assert captured["discover"] is True


def test_status_dispatch(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "cmd_status", lambda root: calls.append(root) or 0)

    rc = cli.main(["status"])

    assert rc == 0
    assert len(calls) == 1


def test_mutation_score_dispatch(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_mutation_score",
                        lambda root, as_json=False: captured.update(root=root, as_json=as_json) or 0)
    assert cli.main(["mutation-score", "--json"]) == 0
    assert captured["as_json"] is True
    assert captured["root"] == Path.cwd()


def test_ledger_list_dispatch(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "cmd_ledger_list", lambda root: calls.append(root) or 0)

    assert cli.main(["ledger", "list"]) == 0
    assert len(calls) == 1


def test_ledger_show_dispatch(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_ledger_show",
                         lambda root, id: captured.update(id=id) or 0)

    assert cli.main(["ledger", "show", "abc123"]) == 0
    assert captured["id"] == "abc123"


def test_ledger_filter_dispatch(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_ledger_filter",
                         lambda root, **kw: captured.update(**kw) or 0)

    cli.main(["ledger", "filter", "--tool", "ruff", "--status", "open"])

    assert captured["tool"] == "ruff"
    assert captured["status"] == "open"
    assert captured["rule"] is None
    assert captured["severity"] is None


def test_ledger_mark_rotated_dispatch(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_ledger_mark_rotated",
                         lambda root, id, reason: captured.update(id=id, reason=reason) or 0)

    cli.main(["ledger", "mark-rotated", "abc123", "--reason", "rotated in AWS"])

    assert captured["id"] == "abc123"
    assert captured["reason"] == "rotated in AWS"


def test_ledger_mark_not_a_secret_dispatch(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_ledger_mark_not_a_secret",
                         lambda root, id, reason: captured.update(id=id, reason=reason) or 0)

    cli.main(["ledger", "mark-not-a-secret", "abc123", "--reason", "public client id"])

    assert captured["id"] == "abc123"
    assert captured["reason"] == "public client id"


def test_ledger_no_subcommand_returns_3(capsys):
    rc = cli.main(["ledger"])
    err = capsys.readouterr().err

    assert rc == 3
    assert "ledger" in err.lower()


def test_override_dispatch(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_override",
                         lambda root, id, reason: captured.update(id=id, reason=reason) or 0)

    cli.main(["override", "abc123", "--reason", "known false positive"])

    assert captured["id"] == "abc123"
    assert captured["reason"] == "known false positive"


def test_triage_dispatch_maps_budget(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "cmd_triage",
                         lambda root, rev="HEAD", budget=None: calls.append((rev, budget)) or 0)
    assert cli.main(["triage", "--budget", "15"]) == 0
    assert calls == [("HEAD", 15.0)]


def test_triage_dispatch_defaults_no_budget(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "cmd_triage",
                         lambda root, rev="HEAD", budget=None: calls.append((rev, budget)) or 0)
    assert cli.main(["triage", "abc123"]) == 0
    assert calls == [("abc123", None)]


def test_pack_list_dispatch(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "cmd_pack_list", lambda root: calls.append(root) or 0)

    assert cli.main(["pack", "list"]) == 0
    assert calls == [Path.cwd()]


def test_pack_add_dispatch(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_pack_add",
                         lambda root, id: captured.update(root=root, id=id) or 0)

    assert cli.main(["pack", "add", "someid"]) == 0
    assert captured["root"] == Path.cwd()
    assert captured["id"] == "someid"


def test_pack_compile_dispatch(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "cmd_pack_compile", lambda root: calls.append(root) or 0)

    assert cli.main(["pack", "compile"]) == 0
    assert len(calls) == 1


def test_pack_no_subcommand_returns_3(capsys):
    rc = cli.main(["pack"])
    err = capsys.readouterr().err

    assert rc == 3
    assert "pack" in err.lower()


def test_arm_dispatch(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "cmd_arm",
                        lambda root, llm=False, autolearn=False, tdd=False, mutation=False, mutation_score=False, red_proof=False, shadow=False: calls.append((root, llm, autolearn, tdd)) or 0)

    assert cli.main(["arm"]) == 0
    assert len(calls) == 1
    assert calls[0] == (Path.cwd(), False, False, False)


def test_arm_dispatch_with_llm_flag(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "cmd_arm",
                        lambda root, llm=False, autolearn=False, tdd=False, mutation=False, mutation_score=False, red_proof=False, shadow=False: calls.append((root, llm, autolearn, tdd)) or 0)

    assert cli.main(["arm", "--llm"]) == 0
    assert len(calls) == 1
    assert calls[0] == (Path.cwd(), True, False, False)


def test_arm_dispatch_with_autolearn_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_arm",
                        lambda root, llm=False, autolearn=False, tdd=False, mutation=False, mutation_score=False, red_proof=False, shadow=False: captured.update(llm=llm, autolearn=autolearn, tdd=tdd) or 0)

    assert cli.main(["arm", "--autolearn"]) == 0
    assert captured["autolearn"] is True
    assert captured["llm"] is False
    assert captured["tdd"] is False


def test_arm_dispatch_with_tdd_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_arm",
                        lambda root, llm=False, autolearn=False, tdd=False, mutation=False, mutation_score=False, red_proof=False, shadow=False: captured.update(llm=llm, autolearn=autolearn, tdd=tdd) or 0)

    assert cli.main(["arm", "--tdd"]) == 0
    assert captured["tdd"] is True
    assert captured["llm"] is False
    assert captured["autolearn"] is False


def test_arm_dispatch_with_shadow_flag(monkeypatch):
    """Round 126 section 4a: `shadow` was armable by config but had no CLI
    path, so `aramid arm --help` told an operator it could not be armed.

    In-process like its siblings: this pins the DISPATCH MAPPING, which
    keyword the flag becomes. When it was written the subprocess helper still
    resolved the installed wheel, so in-process was also the only way to test
    a flag the wheel lacked; `run_cli` now binds to the checkout, and
    test_arm_dispatch_shadow_and_llm_mutually_exclusive covers that side.
    """
    captured = {}
    monkeypatch.setattr(cli, "cmd_arm",
                        lambda root, llm=False, autolearn=False, tdd=False, mutation=False, mutation_score=False, red_proof=False, shadow=False: captured.update(shadow=shadow, llm=llm, red_proof=red_proof) or 0)

    assert cli.main(["arm", "--shadow"]) == 0
    assert captured["shadow"] is True
    assert captured["llm"] is False
    assert captured["red_proof"] is False


def test_arm_shadow_is_offered_by_the_parser():
    """The literal complaint in round 126 section 4a: an operator runs
    `aramid arm --help`, reads the options, and concludes shadow cannot be
    armed. Asserted against the built parser OBJECT; the rendered `--help`
    of the same checkout is what test_arm_shadow_is_offered_by_the_real_cli
    reads.
    """
    parser = cli.build_parser()
    sub = next(a for a in parser._actions
               if isinstance(a, argparse._SubParsersAction))
    arm = sub.choices["arm"]
    flags = {opt for act in arm._actions for opt in act.option_strings}

    assert "--shadow" in flags, f"arm offers no --shadow; it offers {sorted(flags)}"
    # Non-vacuity: if the navigation above ever returned the wrong parser, an
    # empty or foreign flag set would satisfy the assertion by accident.
    assert {"--llm", "--mutation", "--red-proof"} <= flags, sorted(flags)


def test_arm_shadow_is_offered_by_the_real_cli(run_cli):
    """The same complaint end to end: the text an operator actually reads.
    Against the installed 0.4.1 wheel this line is absent -- which is what
    the old helper would have rendered, and called a pass of THIS checkout."""
    out = run_cli("arm", "--help")
    assert out.returncode == 0, out.stderr
    assert "--shadow" in out.stdout, out.stdout


def test_arm_dispatch_llm_and_autolearn_mutually_exclusive(run_cli):
    rc = run_cli("arm", "--llm", "--autolearn")
    assert rc.returncode == 3


def test_arm_dispatch_tdd_and_llm_mutually_exclusive(run_cli):
    rc = run_cli("arm", "--tdd", "--llm")
    assert rc.returncode == 3


def test_arm_dispatch_with_mutation_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_arm",
                        lambda root, llm=False, autolearn=False, tdd=False, mutation=False, mutation_score=False, red_proof=False, shadow=False:
                        captured.update(llm=llm, autolearn=autolearn, tdd=tdd,
                                        mutation=mutation) or 0)

    assert cli.main(["arm", "--mutation"]) == 0
    assert captured["mutation"] is True
    assert captured["llm"] is False
    assert captured["autolearn"] is False
    assert captured["tdd"] is False


def test_arm_dispatch_mutation_and_llm_mutually_exclusive(run_cli):
    rc = run_cli("arm", "--mutation", "--llm")
    assert rc.returncode == 3


def test_arm_dispatch_with_mutation_score_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_arm",
                        lambda root, llm=False, autolearn=False, tdd=False,
                        mutation=False, mutation_score=False, red_proof=False, shadow=False:
                        captured.update(llm=llm, autolearn=autolearn,
                                        tdd=tdd, mutation=mutation,
                                        mutation_score=mutation_score) or 0)

    assert cli.main(["arm", "--mutation-score"]) == 0
    assert captured["mutation_score"] is True
    assert captured["mutation"] is False
    assert captured["llm"] is False
    assert captured["autolearn"] is False
    assert captured["tdd"] is False


def test_arm_dispatch_mutation_score_and_mutation_mutually_exclusive(run_cli):
    rc = run_cli("arm", "--mutation-score", "--mutation")
    assert rc.returncode == 3


def test_arm_dispatch_with_red_proof_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_arm",
                        lambda root, llm=False, autolearn=False, tdd=False,
                        mutation=False, mutation_score=False, red_proof=False, shadow=False:
                        captured.update(llm=llm, autolearn=autolearn,
                                        tdd=tdd, mutation=mutation,
                                        mutation_score=mutation_score,
                                        red_proof=red_proof) or 0)

    assert cli.main(["arm", "--red-proof"]) == 0
    assert captured["red_proof"] is True
    assert captured["mutation_score"] is False
    assert captured["mutation"] is False
    assert captured["llm"] is False
    assert captured["autolearn"] is False
    assert captured["tdd"] is False


def test_arm_dispatch_red_proof_and_tdd_mutually_exclusive(run_cli):
    rc = run_cli("arm", "--red-proof", "--tdd")
    assert rc.returncode == 3


def test_arm_dispatch_shadow_and_llm_mutually_exclusive(run_cli):
    """The case that exposed the false green. Exit 3 alone cannot tell "these
    two flags exclude each other" from "this program has never heard of
    --shadow" -- the installed wheel said the latter, and exited 3 too. So
    the REASON is asserted alongside the code, in both directions."""
    rc = run_cli("arm", "--shadow", "--llm")
    assert rc.returncode == 3
    assert "not allowed with" in rc.stderr, rc.stderr
    assert "unrecognized" not in rc.stderr, rc.stderr


def test_update_rules_dispatch(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "cmd_update_rules", lambda root: calls.append(root) or 0)

    assert cli.main(["update-rules"]) == 0
    assert len(calls) == 1


def test_uninstall_dispatch_maps_path(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_uninstall", lambda path: captured.update(path=path) or 0)

    cli.main(["uninstall", "some/path"])

    assert captured["path"] == Path("some/path")


def test_schedule_dispatch_maps_action(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_schedule",
                         lambda root, action: captured.update(root=root, action=action) or 0)

    rc = cli.main(["schedule", "install"])

    assert rc == 0
    assert captured["action"] == "install"


def test_ledger_resolve_out_of_scope_dispatch(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_ledger_resolve",
                         lambda root, id, out_of_scope, reason: captured.update(
                             id=id, out_of_scope=out_of_scope, reason=reason) or 0)

    assert cli.main(["ledger", "resolve", "abc123", "--out-of-scope",
                     "--reason", "runner scoped to .py/.pyi"]) == 0

    assert captured == {"id": "abc123", "out_of_scope": True,
                        "reason": "runner scoped to .py/.pyi"}


def test_ledger_resolve_without_out_of_scope_flag_still_reaches_the_command(monkeypatch):
    """The refusal is the command's, with its own message -- not argparse's."""
    captured = {}
    monkeypatch.setattr(cli, "cmd_ledger_resolve",
                         lambda root, id, out_of_scope, reason: captured.update(
                             out_of_scope=out_of_scope) or 3)

    assert cli.main(["ledger", "resolve", "abc123", "--reason", "x"]) == 3
    assert captured["out_of_scope"] is False
