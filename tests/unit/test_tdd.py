from pathlib import Path
from types import SimpleNamespace

from aramid import gitutil, tdd
from aramid.runners.base import RunContext


def _ctx(files, rng="base..head", root=Path("/x")):
    return RunContext(root=root, files=files, rng=rng)


def _cfg(enabled=True):
    return SimpleNamespace(tdd={"enabled": enabled})


def test_is_test_file():
    assert gitutil.is_test_file("tests/test_foo.py") is True
    assert gitutil.is_test_file("pkg/tests/thing.py") is True
    assert gitutil.is_test_file("pkg/test_foo.py") is True
    assert gitutil.is_test_file("pkg/foo_test.py") is True
    assert gitutil.is_test_file("src/aramid/foo.py") is False


def test_prod_change_no_test_flags(monkeypatch):
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda root, b, h: {"src/foo.py": {1, 2}})
    findings = tdd.scan(_ctx(["src/foo.py"]), _cfg())
    assert [f.file for f in findings] == ["src/foo.py"]
    f = findings[0]
    assert (f.tool, f.rule, f.severity_raw, f.line) == ("tdd", "code-without-test", "medium", 0)


def test_prod_change_with_new_test_lines_is_clean(monkeypatch):
    monkeypatch.setattr(gitutil, "diff_new_lines",
                        lambda root, b, h: {"src/foo.py": {1}, "tests/test_foo.py": {5, 6}})
    findings = tdd.scan(_ctx(["src/foo.py", "tests/test_foo.py"]), _cfg())
    assert findings == []


def test_test_only_change_is_clean(monkeypatch):
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda root, b, h: {"tests/test_foo.py": {5}})
    findings = tdd.scan(_ctx(["tests/test_foo.py"]), _cfg())
    assert findings == []


def test_prod_change_with_test_deletion_only_flags(monkeypatch):
    # test file changed but gained NO new lines (pure deletion) -> not "tested"
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda root, b, h: {"src/foo.py": {1}})
    findings = tdd.scan(_ctx(["src/foo.py", "tests/test_foo.py"]), _cfg())
    assert [f.file for f in findings] == ["src/foo.py"]


def test_disabled_returns_nothing(monkeypatch):
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda root, b, h: {"src/foo.py": {1}})
    findings = tdd.scan(_ctx(["src/foo.py"]), _cfg(enabled=False))
    assert findings == []


def test_scan_is_fail_open(monkeypatch):
    def boom(root, b, h):
        raise RuntimeError("git exploded")
    monkeypatch.setattr(gitutil, "diff_new_lines", boom)
    assert tdd.scan(_ctx(["src/foo.py"]), _cfg()) == []


def test_graph_advisory_note_is_inert(tmp_path):
    # No-op stub: no graph -> empty note, never raises.
    assert tdd._graph_advisory_note(tmp_path, "src/foo.py") == ""


def test_first_push_repo_with_test_is_clean(monkeypatch):
    # rng="" (FULL_HISTORY_RNG): tested iff ctx.files has any test file.
    # diff_new_lines returns {} here; if the code wrongly consulted it instead
    # of ctx.files, tests/test_foo.py would be missed and src/foo.py would flag.
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda *a: {})
    findings = tdd.scan(_ctx(["src/foo.py", "tests/test_foo.py"], rng=""), _cfg())
    assert findings == []


def test_first_push_repo_without_test_flags(monkeypatch):
    monkeypatch.setattr(gitutil, "diff_new_lines", lambda *a: {"src/foo.py": {1}})
    findings = tdd.scan(_ctx(["src/foo.py"], rng=""), _cfg())
    assert [f.file for f in findings] == ["src/foo.py"]
