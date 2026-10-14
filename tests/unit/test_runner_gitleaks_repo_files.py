"""FN-40: a hit the repo's `.gitleaksignore` or `.gitleaks.toml` hides is
reported like one a `gitleaks:allow` comment hides: a WARN under the inline
label, naming the file. gitleaks reads both files from the directory it scans,
and no flag turns `.gitleaksignore` off (measured), so the runner adds a third
run that has neither to read: an empty directory as its source and its working
directory, git pointed at the repo through GIT_DIR and GIT_WORK_TREE, and a
config holding only gitleaks' own rules.

These tests answer gitleaks with a fake; the real binary, every file in every
scan mode, is tests/integration/test_gitleaks_repo_files_live.py."""
import json
import subprocess
from pathlib import Path

import pytest

from aramid.runners import gitleaks, inline
from aramid.runners.base import RunContext, RunnerResult, ToolState, _child_env


def _hit(rule="github-pat", file="cfg.py", line=1, commit=""):
    return {"RuleID": rule, "File": file, "StartLine": line, "Commit": commit,
            "Fingerprint": ":".join([*([commit] if commit else []), file, rule, str(line)]),
            "Secret": "placeholder", "Description": "a test rule"}


def _repo(tmp_path):
    # One commit, as under a real hook: HEAD resolves and `.git/index` exists,
    # which the runner checks before it scans (FN-56).
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-q", str(r)], check=True, capture_output=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q",
                    "--allow-empty", "-m", "base"], cwd=r, check=True, capture_output=True)
    return r


class _Fake:
    """Answers the three runs by their flags: the tool's own, the marker pass
    (--ignore-gitleaks-allow) and the file pass (--config). Records what each
    was given, and what its config file and working directory held while it
    ran: both are gone once the runner returns."""

    def __init__(self, own=(), markers=(), files=(), files_rc=None):
        self.reports = {"own": list(own), "markers": list(markers), "files": list(files)}
        self.files_rc = files_rc
        self.calls = []

    def __call__(self, argv, cwd, timeout_s, env=None):
        which = ("files" if "--config" in argv
                 else "markers" if "--ignore-gitleaks-allow" in argv else "own")
        config = Path(argv[argv.index("--config") + 1]).read_text() if "--config" in argv else None
        self.calls.append({"which": which, "argv": argv, "cwd": Path(cwd), "env": env,
                           "config": config, "cwd_holds": sorted(p.name for p in Path(cwd).iterdir())})
        items = self.reports[which]
        Path(argv[argv.index("--report-path") + 1]).write_text(json.dumps(items))
        rc = self.files_rc if which == "files" and self.files_rc is not None else (1 if items else 0)
        return RunnerResult("gitleaks", ToolState.OK, "", "", 0.01, rc)


def _run(monkeypatch, ctx, fake):
    monkeypatch.setattr(gitleaks, "run_subprocess", fake)
    result = gitleaks.run(ctx)
    hidden = [(f.file, f.line, f.message) for f in gitleaks.parse(result, ctx)
              if f.tool == inline.GITLEAKS]
    return result, hidden


def _says(kind, rule="github-pat"):
    return inline.message("gitleaks", rule, kind, "a test rule")


def test_no_repo_file_means_no_third_run(tmp_path, monkeypatch):
    fake = _Fake()
    _run(monkeypatch, RunContext(root=_repo(tmp_path), inline_pass=True), fake)
    assert [c["which"] for c in fake.calls] == ["own", "markers"]


@pytest.mark.parametrize("name", [".gitleaksignore", ".gitleaks.toml"])
def test_a_repo_file_adds_a_run_that_cannot_read_it(tmp_path, monkeypatch, name):
    r = _repo(tmp_path)
    (r / name).write_text("")
    monkeypatch.delenv("GIT_INDEX_FILE", raising=False)
    fake = _Fake()
    _run(monkeypatch, RunContext(root=r, inline_pass=True), fake)
    assert [c["which"] for c in fake.calls] == ["own", "markers", "files"]
    call = fake.calls[2]
    assert call["argv"][:3] == ["gitleaks", "git", "--staged"]
    assert "--ignore-gitleaks-allow" in call["argv"]
    assert call["config"] == "[extend]\nuseDefault = true\n"
    # Its source, the last argument, is the directory it runs in, and that holds nothing.
    assert Path(call["argv"][-1]) == call["cwd"] and call["cwd_holds"] == []
    env = call["env"]
    assert Path(env["GIT_DIR"]).resolve() == (r / ".git").resolve()
    assert Path(env["GIT_WORK_TREE"]) == r
    assert env["GITLEAKS_CONFIG"] is None and env["GITLEAKS_CONFIG_TOML"] is None


def test_a_relative_index_file_is_made_absolute_against_the_work_tree(tmp_path, monkeypatch):
    # What git hands a pre-commit hook for a plain `git add` + `git commit`.
    # Inherited as it is into a run whose working directory is elsewhere, it
    # names no index, and gitleaks reported an empty scan (measured).
    r = _repo(tmp_path)
    (r / ".gitleaks.toml").write_text("")
    monkeypatch.setenv("GIT_INDEX_FILE", ".git/index")
    fake = _Fake()
    _run(monkeypatch, RunContext(root=r, inline_pass=True), fake)
    assert Path(_child_env(fake.calls[2]["env"])["GIT_INDEX_FILE"]) == r / ".git" / "index"


def test_an_absolute_index_file_is_kept(tmp_path, monkeypatch):
    # `git commit -a` and a partial commit hand the hook an absolute path.
    r = _repo(tmp_path)
    (r / ".gitleaks.toml").write_text("")
    given = str(tmp_path / "next-index-1.lock")
    Path(given).write_bytes(b"")   # git hands the hook one it has written
    monkeypatch.setenv("GIT_INDEX_FILE", given)
    fake = _Fake()
    _run(monkeypatch, RunContext(root=r, inline_pass=True), fake)
    assert _child_env(fake.calls[2]["env"])["GIT_INDEX_FILE"] == given


def test_each_hit_names_the_file_that_hid_it(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    (r / ".gitleaksignore").write_text("cfg.py:github-pat:1\nabc123:old.py:github-pat:9\n")
    (r / ".gitleaks.toml").write_text("")
    fake = _Fake(files=[_hit(), _hit(file="old.py", line=9, commit="abc123"),
                        _hit(file="new.py", line=3, commit="abc123"), _hit(file="b.py", line=4)])
    _result, hidden = _run(monkeypatch, RunContext(root=r, inline_pass=True), fake)
    entry, config = "a `.gitleaksignore` entry", "the repo's `.gitleaks.toml`"
    assert hidden == [("cfg.py", 1, _says(entry)), ("old.py", 9, _says(entry)),
                      ("new.py", 3, _says(config)), ("b.py", 4, _says(config))]


def test_a_plain_entry_names_a_hit_in_any_commit(tmp_path, monkeypatch):
    # gitleaks applies a `file:rule:line` entry to a history scan too (measured).
    r = _repo(tmp_path)
    (r / ".gitleaksignore").write_text("cfg.py:github-pat:1\n")
    (r / ".gitleaks.toml").write_text("")
    fake = _Fake(files=[_hit(commit="def456")])
    _result, hidden = _run(monkeypatch, RunContext(root=r, rng="", inline_pass=True), fake)
    assert hidden == [("cfg.py", 1, _says("a `.gitleaksignore` entry"))]


def test_an_entry_for_one_commit_hides_that_commit_alone(tmp_path, monkeypatch):
    # The same line added in two commits: the entry names the first, the
    # tool's own run reports the second. The first is still hidden.
    r = _repo(tmp_path)
    (r / ".gitleaksignore").write_text("aaa111:cfg.py:github-pat:1\n")
    fake = _Fake(own=[_hit(commit="bbb222")], files=[_hit(commit="aaa111"), _hit(commit="bbb222")])
    _result, hidden = _run(monkeypatch, RunContext(root=r, rng="", inline_pass=True), fake)
    assert hidden == [("cfg.py", 1, _says("a `.gitleaksignore` entry"))]


def test_with_only_an_ignore_file_every_hit_is_its_entry(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    (r / ".gitleaksignore").write_text("cfg.py:github-pat:1\n")
    fake = _Fake(files=[_hit(file="other.py", line=2)])
    _result, hidden = _run(monkeypatch, RunContext(root=r, inline_pass=True), fake)
    assert hidden == [("other.py", 2, _says("a `.gitleaksignore` entry"))]


def test_a_place_already_reported_is_not_reported_again(tmp_path, monkeypatch):
    # The repo's own rule found cfg.py:1 under another name, and the marker
    # pass reported m.py:2: neither is hidden by a repo file.
    r = _repo(tmp_path)
    (r / ".gitleaks.toml").write_text("")
    fake = _Fake(own=[_hit(rule="my-own-pat")], markers=[_hit(file="m.py", line=2)],
                 files=[_hit(), _hit(file="m.py", line=2)])
    _result, hidden = _run(monkeypatch, RunContext(root=r, inline_pass=True), fake)
    assert hidden == [("m.py", 2, _says("a `gitleaks:allow` comment"))]


def test_the_all_scan_pins_the_config_on_its_own_copy(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    (r / ".gitleaks.toml").write_text("")
    (r / "a.py").write_text("x = 1\n")
    fake = _Fake()
    ctx = RunContext(root=r, files=["a.py", ".gitleaks.toml"], full_tree=True, inline_pass=True)
    _run(monkeypatch, ctx, fake)
    own, files = fake.calls[0], fake.calls[2]
    assert files["argv"][:3] == own["argv"][:3]           # gitleaks dir <the same copy>
    assert files["argv"][1] == "dir" and Path(files["argv"][2]).name == "tree"
    assert files["config"] == "[extend]\nuseDefault = true\n"
    assert "GIT_DIR" not in files["env"] and files["cwd_holds"] == []


def test_a_failed_file_pass_degrades_the_inline_label_alone(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    (r / ".gitleaks.toml").write_text("")
    fake = _Fake(markers=[_hit(file="m.py", line=2)], files_rc=2)
    result, _hidden = _run(monkeypatch, RunContext(root=r, inline_pass=True), fake)
    own, second = result.sub_results
    assert own.state is ToolState.OK
    assert (second.tool, second.state) == (inline.GITLEAKS, ToolState.CRASHED)


def test_no_budget_left_for_the_file_pass_skips_it_as_degraded(tmp_path, monkeypatch):
    r = _repo(tmp_path)
    (r / ".gitleaks.toml").write_text("")
    left = iter([30.0, None])
    monkeypatch.setattr(inline, "second_pass_timeout", lambda ctx, cap: next(left))
    fake = _Fake()
    result, _hidden = _run(monkeypatch, RunContext(root=r, inline_pass=True), fake)
    assert [c["which"] for c in fake.calls] == ["own", "markers"]
    assert (result.sub_results[1].tool, result.sub_results[1].state) == (inline.GITLEAKS,
                                                                       ToolState.TIMEOUT)
