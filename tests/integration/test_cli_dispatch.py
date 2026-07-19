"""integration: aramid.cli -- the full argparse subcommand tree and
dispatch to aramid.commands.*.

Process-level exit-code tests (subprocess, mirroring test_version.py's own
style -- these need real argparse/SystemExit/process semantics) plus
in-process dispatch-mapping tests (monkeypatching the cmd_* names bound
into aramid.cli's own namespace) for argument translation.
"""
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from aramid import cli
from aramid.models import Gate


def _run(*args):
    return subprocess.run([sys.executable, "-m", "aramid", *args],
                           capture_output=True, text=True)


# ------------------------------------------------------- process-level ------

def test_version_flag_still_works():
    out = _run("--version")
    assert out.returncode == 0
    assert out.stdout.strip().startswith("aramid ")


def test_check_help_exits_0():
    out = _run("check", "--help")
    assert out.returncode == 0


def test_unknown_command_exits_3():
    out = _run("definitely-not-a-real-command")
    assert out.returncode == 3


def test_no_command_exits_3():
    """Deferred from Task 0.1 (progress.md): `python -m aramid` with no
    command must return exit 3, not silently succeed."""
    out = _run()
    assert out.returncode == 3


def test_bad_flag_exits_3_not_argparses_own_2():
    out = _run("check", "--not-a-real-flag")
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
    monkeypatch.setattr(cli, "cmd_arm", lambda root, llm=False, autolearn=False: calls.append((root, llm, autolearn)) or 0)

    assert cli.main(["arm"]) == 0
    assert len(calls) == 1
    assert calls[0] == (Path.cwd(), False, False)


def test_arm_dispatch_with_llm_flag(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "cmd_arm", lambda root, llm=False, autolearn=False: calls.append((root, llm, autolearn)) or 0)

    assert cli.main(["arm", "--llm"]) == 0
    assert len(calls) == 1
    assert calls[0] == (Path.cwd(), True, False)


def test_arm_dispatch_with_autolearn_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "cmd_arm",
                        lambda root, llm=False, autolearn=False: captured.update(llm=llm, autolearn=autolearn) or 0)

    assert cli.main(["arm", "--autolearn"]) == 0
    assert captured["autolearn"] is True
    assert captured["llm"] is False


def test_arm_dispatch_llm_and_autolearn_mutually_exclusive():
    rc = subprocess.run([sys.executable, "-m", "aramid", "arm", "--llm", "--autolearn"],
                        capture_output=True, text=True)
    assert rc.returncode == 3


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
