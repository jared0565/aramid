"""`typecheck.dispatched`: the one place that says which tool the typecheck
runner runs for a repo. The runner runs ONE: tsc when `tsconfig.json` is at
the root, mypy only otherwise. `aramid doctor` reports on that same answer
(`doctor.probe_stack_tools`), so it lives in a function both call."""
from types import SimpleNamespace

from aramid.runners import typecheck


def test_tsconfig_alone_dispatches_tsc(tmp_path):
    (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")
    assert typecheck.dispatched(tmp_path) == typecheck.NAME_TSC


def test_mypy_config_alone_dispatches_mypy(tmp_path):
    (tmp_path / "mypy.ini").write_text("[mypy]\n", encoding="utf-8")
    assert typecheck.dispatched(tmp_path) == typecheck.NAME_MYPY


def test_tsc_takes_the_slot_when_both_are_configured(tmp_path):
    (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")
    (tmp_path / "mypy.ini").write_text("[mypy]\n", encoding="utf-8")
    assert typecheck.dispatched(tmp_path) == typecheck.NAME_TSC


def test_neither_config_dispatches_nothing(tmp_path):
    assert typecheck.dispatched(tmp_path) is None


def test_run_goes_where_dispatched_says(tmp_path, monkeypatch):
    # The runner must not keep a second copy of the precedence: with a
    # tsconfig present, it still follows the owner's answer.
    monkeypatch.setattr(typecheck, "dispatched", lambda root: typecheck.NAME_MYPY)
    monkeypatch.setattr(typecheck, "run_mypy", lambda ctx: "mypy-ran")
    monkeypatch.setattr(typecheck, "run_tsc", lambda ctx: "tsc-ran")
    (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")
    assert typecheck.run(SimpleNamespace(root=tmp_path)) == "mypy-ran"
