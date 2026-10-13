"""FN-53: `run_subprocess(env=...)` is merged over the caller's environment,
and a None value takes that variable OUT of the child's environment. Each
test runs a real child that prints what it sees, so the assertion is about
the process, not about a dict handed to Popen."""
import sys

from aramid.runners.base import ToolState, run_subprocess

_SHOW = ("import os; print(os.environ.get('ARAMID_FN53_PROBE', '<absent>'), "
         "os.environ.get('ARAMID_FN53_KEEP', '<absent>'))")


def _seen(tmp_path, env=None):
    r = run_subprocess([sys.executable, "-c", _SHOW], tmp_path, 30, env=env)
    assert r.state is ToolState.OK and r.returncode == 0, r.stderr
    return r.raw.split()


def test_the_variable_reaches_the_child_when_nothing_removes_it(tmp_path, monkeypatch):
    # The control: what every other test here takes away is really there.
    monkeypatch.setenv("ARAMID_FN53_PROBE", "present")
    monkeypatch.setenv("ARAMID_FN53_KEEP", "kept")
    assert _seen(tmp_path) == ["present", "kept"]


def test_a_none_value_removes_the_variable_and_only_that_one(tmp_path, monkeypatch):
    monkeypatch.setenv("ARAMID_FN53_PROBE", "present")
    monkeypatch.setenv("ARAMID_FN53_KEEP", "kept")
    assert _seen(tmp_path, {"ARAMID_FN53_PROBE": None}) == ["<absent>", "kept"]


def test_a_none_value_removes_the_variable_whatever_its_case(tmp_path, monkeypatch):
    # Windows names are case-insensitive, so the caller's spelling must not
    # decide whether the variable survives.
    monkeypatch.setenv("ARAMID_FN53_PROBE", "present")
    assert _seen(tmp_path, {"aramid_fn53_probe": None})[0] == "<absent>"


def test_a_string_value_still_sets_the_variable(tmp_path, monkeypatch):
    monkeypatch.delenv("ARAMID_FN53_PROBE", raising=False)
    monkeypatch.setenv("ARAMID_FN53_KEEP", "kept")
    assert _seen(tmp_path, {"ARAMID_FN53_PROBE": "given"}) == ["given", "kept"]
