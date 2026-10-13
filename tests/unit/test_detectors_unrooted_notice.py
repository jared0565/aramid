"""FN-52 (channel round 320): the notice for a js project below the root gives
advice that works.

It said "onboard it as its own repo with `aramid init <dir>`", and `init`
resolves a subdirectory to the repository root and re-runs the root's init:
exit 0, "done", nothing changed (bytes-web, aramid 0.20.8). What does work is
the gate run from the subdirectory itself, by hand; the hooks run from the
root and never reach it. Every line is asserted whole."""
import subprocess

import pytest

from aramid import cli, config, detectors, pipeline
from aramid.ledger import Ledger
from aramid.models import Gate
from aramid.runners.base import RunnerResult, ToolState

JS_LINE = (
    "aramid: js: found package.json under app/ but none at the repository root -- "
    "aramid's js gates (eslint, npm/pnpm/yarn) are NOT running for this repo, because "
    "they execute from the root. A clean js result here means 'not checked', not 'no "
    "findings'. The commit and push hooks run from the root too, so they never check "
    "that subdirectory: run `aramid check --gate pre-push --all` from it by hand.")

RUST_LINE = (
    "aramid: rust: found Cargo.toml under crate/ but none at the repository root -- "
    "aramid's rust gates (clippy, cargo-audit) are NOT running for this repo, because "
    "they execute from the root. A clean rust result here means 'not checked', not 'no "
    "findings'. Add a root Cargo.toml declaring a [workspace] over these crates, or run "
    "aramid from that subdirectory.")


def _git(r, *args):
    subprocess.run(["git", *args], cwd=r, check=True, capture_output=True)


def _repo(tmp_path):
    r = tmp_path / "r"
    (r / "app").mkdir(parents=True)
    (r / "app" / "package.json").write_text('{"name": "app", "version": "1.0.0"}\n')
    (r / "app" / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}\n')
    (r / "app" / "index.js").write_text("console.log(1);\n")
    for args in (("init", "-b", "main"), ("config", "user.email", "t@t"),
                 ("config", "user.name", "t"), ("add", "-A"), ("commit", "-m", "initial")):
        _git(r, *args)
    return r


def test_the_js_notice_says_what_works_and_drops_the_init_advice(tmp_path):
    r = _repo(tmp_path)
    assert detectors.unrooted_stack_notices(r) == [JS_LINE]


def test_the_rust_notice_is_unchanged(tmp_path):
    (tmp_path / "crate").mkdir()
    (tmp_path / "crate" / "Cargo.toml").write_text('[package]\nname = "c"\n')
    assert detectors.unrooted_stack_notices(tmp_path) == [RUST_LINE]


class _Recorder:
    """A js runner stand-in that records the root it was run from."""

    def __init__(self, label, seen):
        self.label, self.seen = label, seen

    def run(self, ctx):
        self.seen.append((self.label, ctx.root))
        return RunnerResult(self.label, ToolState.OK, raw="")

    def parse(self, result, ctx):
        return []


def test_the_advice_holds_the_gate_run_from_the_subdirectory_runs_the_js_gates(
        tmp_path, monkeypatch):
    """The CONTROL is the reported bug: from the root, no js runner is chosen."""
    r = _repo(tmp_path)
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "no-user-config.toml")
    seen: list = []
    monkeypatch.setitem(pipeline.RUNNERS, "eslint", _Recorder("eslint", seen))
    monkeypatch.setitem(pipeline.RUNNERS, "deps", _Recorder("deps", seen))
    monkeypatch.setitem(pipeline.GATE_RUNNER_KEYS, Gate.PRE_PUSH, ["eslint", "deps"])

    for where in (r, r / "app"):
        pipeline.run_gate(where, Gate.PRE_PUSH, "all", config.load_config(where),
                          Ledger(tmp_path / f"{where.name}.db"), run_id=f"g-{where.name}")

    app = (r / "app").resolve()
    assert sorted((label, root.resolve()) for label, root in seen) == [
        ("deps", app), ("eslint", app)]


def test_init_help_says_what_discover_does(capsys):
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["init", "--help"])
    out = " ".join(capsys.readouterr().out.split())
    assert ("--discover onboard each git repository found up to 3 levels below path "
            "(a directory that holds .git), each as its own repo") in out
