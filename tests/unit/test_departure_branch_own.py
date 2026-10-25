"""A finding is gone only when what the run certifies lost it AND no branch still carries it
(channel round 325, FN-58).

graphite pushed two sibling topic branches from one checkout. The second never had the first's
new test file, and its pre-push run wrote the first's red-proof row `fixed`, `file_departed`,
while that branch sat unmerged with the file in it. Reproduced, and it was four resolvers, not
one, each asking "is it here?" of the wrong thing:

    file_departed  (red-proof, tdd, mutation)  the working tree
    record_run's departed clause (runner rows) the working tree, at EVERY gate -- a plain commit
                                               on a sibling cleared its semgrep and gitleaks rows
    evidence_gone  (llm-review)                HEAD
    line_departed  (mutation)                  the certified revisions, but not other branches

THE RULE (the operator's decision of 2026-10-24, "Branch's own content"): content is gone only
when no revision the run certifies holds it -- committed content, never the disk -- and no
branch tip (refs/heads, refs/remotes; never a tag) holds it whose merge base with a certified
revision does not. A copy a branch merely INHERITED from shared history is history the
certified line has moved past; a copy its own commits brought is live work on another branch.

Chosen against a 12-case table (graphite's ancestry proposal, a history rule, and two simpler
ref checks were scored too). Every case below is one of those rows. The one this rule gets
wrong without a remote HEAD is pinned as well, `rewritten_pushed_before`: rows on a commit
that was pushed and then rewritten away stay open until the force-push lands, because the
remote-tracking ref still carries the old commit's content. The next push clears them
(`rewritten_after_force_push`).

THE LINE (the operator's decision of 2026-10-25, "INTEG-P", llm-review 8cdf845ab278): with a
remote HEAD, a branch's own commits are told apart against the remote default branch as the
push leaves it, not against the certified revision, and the tracking refs the push replaces
are left out. A branch C cut from an unmerged A that deletes A's file no longer clears A's
rows, and `rewritten_pushed_before` clears with the force-push itself. The tests after the
table pin it, its fallback (no remote HEAD: the rule above) and its residual (a stale remote
HEAD keeps rows open).
"""
import subprocess
from datetime import datetime, timezone

import pytest

from aramid import mutation_gate, review
from aramid.fingerprint import compute_fingerprint
from aramid.ledger import Ledger, resolve_departed
from aramid.models import Finding, Gate, Severity, Source, Verdict
from aramid.pushrefs import PushRef

NOW =datetime(2026, 10, 24, 23, 0, 0, tzinfo=timezone.utc).isoformat()

TEST_A = "from src import f\n\n\ndef test_f():\n    assert f(2) is True\n"
SRC_MAIN = "def f(x):\n    return x > 1\n"
SRC_A = "def f(x):\n    if x < 0:\n        return False\n    return x > 1\n"
SRC_EDITED = "def f(x):\n    if x <= -1:\n        return False\n    return x > 1\n"
LINE = "    if x < 0:"


def _finding(fid, tool, rule, file, line, evidence, source=Source.DETERMINISTIC):
    return Finding(id=fid, tool=tool, rule=rule, severity_raw="warning",
                   severity=Severity.MEDIUM, verdict=Verdict.WARN, file=file, line=line,
                   message=f"{tool} {rule}", evidence=evidence, gate=Gate.PRE_PUSH,
                   source=source)


# Everything branch A's push would leave open: A adds tests/test_a.py and a line in src.py.
ROWS = {
    "red-proof": _finding("1" * 64, "red-proof", "test-not-red", "tests/test_a.py", 4,
                          "def test_f():"),
    "semgrep": _finding("2" * 64, "semgrep", "rule", "tests/test_a.py", 5,
                        "assert f(2) is True"),
    "gitleaks": _finding("5" * 64, "gitleaks", "generic-api-key", "tests/test_a.py", 5,
                         "assert f(2) is True"),
    "llm, A's new file": _finding("3" * 64, "llm-review", "llm", "tests/test_a.py", 5,
                                  "assert f(2) is True", Source.LLM),
    "llm, A's line in a shared file": _finding("4" * 64, "llm-review", "llm", "src.py", 2,
                                               "if x < 0:", Source.LLM),
    "mutation, A's line in a shared file": _finding(
        compute_fingerprint("mutation", "cmp-flip", "src.py", LINE, 0), "mutation", "cmp-flip",
        "src.py", 2, LINE),
}
RUNNER_ROWS = ("semgrep", "gitleaks")


class _Repo:
    def __init__(self, path):
        self.path = path
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@t")
        self.git("config", "user.name", "t")
        self.write("src.py", SRC_MAIN)
        self.main = self.commit("base")
        self.git("checkout", "-q", "-b", "A")
        self.write("tests/test_a.py", TEST_A)
        self.write("src.py", SRC_A)
        self.a1 = self.commit("A1: the rows are raised here")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.path, check=True, capture_output=True,
                              text=True).stdout.strip()

    def write(self, rel, text):
        p = self.path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text.encode())

    def commit(self, msg):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)
        return self.git("rev-parse", "HEAD")

    def sibling(self):
        self.git("checkout", "-q", "-b", "B", self.main)
        self.write("notes.txt", "sibling\n")
        return self.commit("B: a sibling of A, cut from main")

    def delete_and_edit(self):
        self.git("rm", "-q", "tests/test_a.py")
        self.write("src.py", SRC_EDITED)
        return self.commit("delete the test, edit the line")

    def rewrite_away(self):
        self.git("reset", "-q", "--hard", self.main)
        self.write("notes.txt", "rewritten\n")
        return self.commit("A1 rewritten without the test or the line")


# Each case returns (gate, certified revisions) with the repo left as the run would find it.
def _sibling(r):
    b = r.sibling()
    return "pre-push", (b, b)


def _sibling_commit(r):
    """No push at all: a commit on the sibling. At pre-commit run_gate reaches only
    record_run, with no certification, so HEAD."""
    r.sibling()
    return "pre-commit", ("HEAD",)


def _reverse(r):
    """A pushed while B is checked out: certified = A's sha + HEAD (B)."""
    b = r.sibling()
    return "pre-push", (r.a1, b)


def _deleted(r):
    a2 = r.delete_and_edit()
    return "pre-push", (a2, a2)


def _deleted_pushed_before(r):
    r.git("update-ref", "refs/remotes/origin/A", r.a1)
    a2 = r.delete_and_edit()
    return "pre-push", (a2, a2)


def _rewritten(r):
    """The 890d7493 shape: A1 rewritten away before it was ever pushed."""
    a1p = r.rewrite_away()
    return "pre-push", (a1p, a1p)


def _rewritten_pushed_before(r):
    """The rule's known cost: origin/A still holds A1 until the force-push lands."""
    r.git("update-ref", "refs/remotes/origin/A", r.a1)
    a1p = r.rewrite_away()
    return "pre-push", (a1p, a1p)


def _rewritten_after_force_push(r):
    a1p = r.rewrite_away()
    r.git("update-ref", "refs/remotes/origin/A", a1p)
    return "pre-push", (a1p, a1p)


def _disk_only(r):
    """Deleted and edited on disk, never committed: what is not committed is not there."""
    (r.path / "tests" / "test_a.py").unlink()
    r.write("src.py", SRC_EDITED)
    return "pre-push", (r.a1, r.a1)


def _stale_merged(r):
    """A merged into main, then main deletes and edits; branch A still points at A1."""
    r.git("checkout", "-q", "main")
    r.git("merge", "-q", "--ff-only", "A")
    r.git("update-ref", "refs/remotes/origin/A", r.a1)
    m2 = r.delete_and_edit()
    return "pre-push", (m2, m2)


def _snapshot(r):
    """A dependabot-style branch cut from main after A merged: it inherits the file and the
    line, touches only a workflow, and is never merged. Then main deletes and edits."""
    r.git("checkout", "-q", "main")
    r.git("merge", "-q", "--ff-only", "A")
    r.git("branch", "-q", "-D", "A")
    r.git("checkout", "-q", "-b", "D")
    r.write(".github/workflows/x.yml", "bump\n")
    r.git("update-ref", "refs/remotes/origin/D", r.commit("D: bump an action"))
    r.git("checkout", "-q", "main")
    m2 = r.delete_and_edit()
    return "pre-push", (m2, m2)


CASES = {
    "sibling": (_sibling, "open"),
    "sibling_commit": (_sibling_commit, "open"),
    "reverse": (_reverse, "open"),
    "deleted": (_deleted, "fixed"),
    "deleted_pushed_before": (_deleted_pushed_before, "fixed"),
    "rewritten": (_rewritten, "fixed"),
    "rewritten_pushed_before": (_rewritten_pushed_before, "open"),
    "rewritten_after_force_push": (_rewritten_after_force_push, "fixed"),
    "disk_only": (_disk_only, "open"),
    "stale_merged": (_stale_merged, "fixed"),
    "snapshot": (_snapshot, "fixed"),
}


def _run_resolvers(root, gate, revs, pushed=()):
    """The departure resolvers, in run_gate's order, with what run_gate hands them: semgrep
    and gitleaks ran OK; at pre-push the rest follow. `pushed` is the refs git handed the
    hook."""
    led = Ledger(root / "l.db")
    try:
        led.record_run("r0", NOW, gate, set(), set(), list(ROWS.values()))
        led.record_run("r1", NOW, gate, set(RUNNER_ROWS), set(), [], root=root, revs=revs,
                       pushed=pushed)
        if gate == "pre-push":
            review.auto_resolve_llm(root, led, "r1", NOW, revs=revs, pushed=pushed)
            for producer in ("red-proof", "tdd", "mutation"):
                resolve_departed(led, "r1", NOW, root=root, tool=producer, present_ids=set(),
                                 revs=revs, pushed=pushed)
            mutation_gate.auto_resolve_line_departed(led, "r1", NOW, root=root, revs=revs,
                                                     pushed=pushed)
        state = led.open_findings()
        return {name: state[f.id]["status"] for name, f in ROWS.items()}
    finally:
        led.close()


@pytest.mark.parametrize("case", list(CASES))
def test_a_row_is_gone_only_when_no_certified_revision_and_no_own_branch_holds_it(
        tmp_path, case):
    build, want = CASES[case]
    gate, revs = build(_Repo(tmp_path))
    got = _run_resolvers(tmp_path, gate, revs)
    assert got == dict.fromkeys(ROWS, want)


def test_content_in_no_commit_stays_open_while_the_working_tree_has_it(tmp_path):
    """llm-review 81b9d08db396, measured on 62c0c17: a file that was never committed, still
    on disk (a secret file unstaged after gitleaks blocked the commit), was written `fixed`
    at the next commit; 0.20.10 kept it open by reading the disk. The disk is never evidence
    that content is gone, but for a path no certified revision tracks it is the only copy
    there is. A TRACKED file is still judged by committed content alone: the shared file's
    uncommitted line clears its rows, as in 0.20.10."""
    r = _Repo(tmp_path)
    a1p = r.rewrite_away()                         # A1 is in no branch any more
    r.write("tests/test_a.py", TEST_A)             # ...but its file is on disk, untracked
    r.write("src.py", SRC_A)                       # ...and its line, uncommitted
    want = {**dict.fromkeys(ROWS, "open"), "llm, A's line in a shared file": "fixed",
            "mutation, A's line in a shared file": "fixed"}
    assert _run_resolvers(tmp_path, "pre-push", (a1p, a1p)) == want


def test_a_path_inside_a_submodule_is_never_gone(tmp_path):
    """The other half of 81b9d08db396: `ls-tree -r` lists a submodule as one gitlink entry
    and none of its files, so `sub/x.py` read as absent from every revision."""
    from aramid.departure import Departure
    r = _Repo(tmp_path)
    r.git("checkout", "-q", "main")
    r.git("update-index", "--add", "--cacheinfo", f"160000,{r.main},sub")
    r.git("commit", "-q", "-m", "a submodule at sub")
    assert not (tmp_path / "sub" / "x.py").exists()
    assert Departure(tmp_path).gone("sub/x.py") is False
    assert Departure(tmp_path).gone("subx.py") is True      # the control: not under `sub`


def test_a_root_that_is_not_a_repository_resolves_nothing(tmp_path):
    """No revision can be read, so nothing can be shown gone: the safe direction. Before
    FN-58 this asked the disk, where every path of a non-repo is 'absent'."""
    got = _run_resolvers(tmp_path, "pre-push", ("HEAD",))
    assert got == dict.fromkeys(ROWS, "open")


def test_the_certified_revisions_are_each_commit_once_and_none_before_the_first(tmp_path):
    """What `Departure.gone` stands on: with no revision to read, nothing is gone. Before the
    first commit there is none, and three names for one commit are one revision."""
    from aramid.departure import Departure

    def git(root, *args):
        return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True,
                              text=True).stdout.strip()
    empty, full = tmp_path / "empty", tmp_path / "full"
    for root in (empty, full):
        root.mkdir()
        git(root, "init", "-q", "-b", "main")
        git(root, "config", "user.email", "t@t")
        git(root, "config", "user.name", "t")
    git(full, "commit", "-q", "--allow-empty", "-m", "c0")
    head = git(full, "rev-parse", "HEAD")
    assert Departure(empty, ("HEAD", "main")).revs() == []
    assert Departure(full, ("HEAD", "main", head)).revs() == [head]


def test_a_git_mv_still_keeps_the_llm_row_open_at_the_certified_revision(tmp_path):
    """FN-22 stays on top of the rule: a quote moved to another tracked file is not a fix,
    and 'tracked' is asked of the revision the push certifies."""
    r = _Repo(tmp_path)
    r.git("mv", "tests/test_a.py", "tests/test_b.py")
    a2 = r.commit("git mv")
    r.sibling()                                    # HEAD elsewhere: only the certified rev has it
    led = Ledger(tmp_path / "l.db")
    try:
        row = ROWS["llm, A's new file"]
        led.record_run("r0", NOW, "pre-push", set(), set(), [row])
        review.auto_resolve_llm(tmp_path, led, "r1", NOW, revs=(a2,))
        assert led.open_findings()[row.id]["status"] == "open"
    finally:
        led.close()


ZERO = "0" * 40


def _publish(r, at=None):
    """The remote as a clone leaves it: origin/main at `at` (the base by default), and
    origin/HEAD naming origin/main."""
    r.git("update-ref", "refs/remotes/origin/main", at or r.main)
    r.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")


def _push(branch, sha, had=ZERO):
    """One line git hands the pre-push hook: the branch, its new commit, what the remote had."""
    return PushRef(f"refs/heads/{branch}", sha, f"refs/heads/{branch}", had)


def _pushed(case, r, revs):
    """What each table case pushes, once there is a remote: the branch it names, and what
    origin had there before."""
    if revs == ("HEAD",):
        return ()
    branch = {"sibling": "B", "stale_merged": "main", "snapshot": "main"}.get(case, "A")
    had = {"deleted_pushed_before": r.a1, "rewritten_pushed_before": r.a1,
           "rewritten_after_force_push": revs[0], "stale_merged": r.main,
           "snapshot": r.main}.get(case, ZERO)
    return (_push(branch, revs[0], had),)


@pytest.mark.parametrize("case", list(CASES))
def test_against_the_remote_default_branch_the_table_holds_and_a_force_push_clears_at_once(
        tmp_path, case):
    """With a remote default branch every case answers as before but one: rows on a commit
    pushed and then rewritten away clear with the force-push itself, since origin/A is the
    ref that push replaces. `snapshot` pushes main while origin/main lags at the base, and
    the line is the commit the push hands main, not the lagging one."""
    build, want = CASES[case]
    r = _Repo(tmp_path)
    _publish(r)
    gate, revs = build(r)
    want = "fixed" if case == "rewritten_pushed_before" else want
    assert _run_resolvers(tmp_path, gate, revs, _pushed(case, r, revs)) \
        == dict.fromkeys(ROWS, want)


def _stacked(r):
    """C, cut from the unmerged A, deletes A's file and edits A's line; C is pushed, new."""
    r.git("checkout", "-q", "-b", "C")
    c1 = r.delete_and_edit()
    return (c1, c1), (_push("C", c1),)


@pytest.mark.parametrize("a_pushed", [False, True])
def test_a_branch_cut_from_an_unmerged_one_does_not_clear_its_rows(tmp_path, a_pushed):
    """llm-review 8cdf845ab278: C reaches A, so judged against C, A's copy looked inherited,
    and pushing C cleared every row raised on A. Judged against the remote default branch,
    A's commits are its own: live work, and the rows stay open."""
    r = _Repo(tmp_path)
    _publish(r)
    if a_pushed:
        r.git("update-ref", "refs/remotes/origin/A", r.a1)
    revs, pushed = _stacked(r)
    assert _run_resolvers(tmp_path, "pre-push", revs, pushed) == dict.fromkeys(ROWS, "open")


def test_once_the_unmerged_branch_is_merged_and_pushed_the_stacked_delete_clears(tmp_path):
    r = _Repo(tmp_path)
    r.git("update-ref", "refs/remotes/origin/A", r.a1)
    revs, pushed = _stacked(r)
    r.git("checkout", "-q", "main")
    r.git("merge", "-q", "--ff-only", "A")
    _publish(r, at=r.a1)
    r.git("checkout", "-q", "C")
    assert _run_resolvers(tmp_path, "pre-push", revs, pushed) == dict.fromkeys(ROWS, "fixed")


@pytest.mark.parametrize("head", [None, "refs/remotes/origin/master"])
def test_without_a_remote_default_branch_a_stacked_push_still_clears_the_rows(tmp_path, head):
    """The decided fallback, and what it costs: with no remote HEAD, or one naming a branch
    that is gone, there is no line, and each certified revision is judged as before -- so the
    stacked shape clears, as in 0.20.10. `git remote set-head origin --auto` gives a clone
    made by hand its line."""
    r = _Repo(tmp_path)
    r.git("update-ref", "refs/remotes/origin/main", r.main)
    if head:
        r.git("symbolic-ref", "refs/remotes/origin/HEAD", head)
    revs, pushed = _stacked(r)
    assert _run_resolvers(tmp_path, "pre-push", revs, pushed) == dict.fromkeys(ROWS, "fixed")


@pytest.mark.parametrize("stale", [False, True])
def test_a_feature_push_that_deletes_main_s_content_clears_unless_the_remote_head_is_stale(
        tmp_path, stale):
    """main has the content, pushed; F, cut from main, deletes it and is pushed: main's copy
    is history F moved past, and the rows clear. The line's residual, in the safe direction:
    a clone keeps origin/HEAD naming origin/master after a master->main rename until
    `git remote set-head`, and judged against that older commit main's own content looks
    like every branch's own, so nothing clears."""
    r = _Repo(tmp_path)
    r.git("checkout", "-q", "main")
    r.git("merge", "-q", "--ff-only", "A")
    r.git("branch", "-q", "-D", "A")
    _publish(r, at=r.a1)
    if stale:
        r.git("update-ref", "refs/remotes/origin/master", r.main)
        r.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/master")
    r.git("checkout", "-q", "-b", "F")
    f1 = r.delete_and_edit()
    got = _run_resolvers(tmp_path, "pre-push", (f1, f1), (_push("F", f1),))
    assert got == dict.fromkeys(ROWS, "open" if stale else "fixed")


def test_the_ref_a_push_replaces_is_left_out_by_name_a_local_branch_at_its_commit_is_not(
        tmp_path):
    """`rewritten_pushed_before` clears with the force-push because origin/A is the ref the
    push replaces. A local branch left at the old commit is another branch, whose own commits
    still carry the content."""
    r = _Repo(tmp_path)
    _publish(r)
    r.git("update-ref", "refs/remotes/origin/A", r.a1)
    r.git("branch", "A-backup", r.a1)
    a1p = r.rewrite_away()
    got = _run_resolvers(tmp_path, "pre-push", (a1p, a1p), (_push("A", a1p, r.a1),))
    assert got == dict.fromkeys(ROWS, "open")


def test_a_force_push_of_the_default_branch_leaves_its_old_commit_out_under_every_name(
        tmp_path):
    """origin/HEAD is a symbolic ref to origin/main: it names the commit the push replaces
    too, and read as a branch of its own it would keep the rows open."""
    r = _Repo(tmp_path)
    r.git("checkout", "-q", "main")
    r.git("merge", "-q", "--ff-only", "A")
    r.git("branch", "-q", "-D", "A")
    _publish(r, at=r.a1)
    m1p = r.rewrite_away()
    got = _run_resolvers(tmp_path, "pre-push", (m1p, m1p), (_push("main", m1p, r.a1),))
    assert got == dict.fromkeys(ROWS, "fixed")


def test_the_line_moves_with_the_ref_that_pushes_the_default_branch_not_the_first_one(
        tmp_path):
    """A push of two refs: X, new, then main, which deletes and edits while origin/main lags
    at the base and a snapshot branch inherited the content from the local main. The line is
    the commit main's ref hands it, wherever that ref falls in the push."""
    r = _Repo(tmp_path)
    _publish(r)
    _gate, (m2, _) = _snapshot(r)
    r.git("checkout", "-q", "-b", "X", r.main)
    r.write("x.txt", "x\n")
    x = r.commit("X: unrelated")
    pushed = (_push("X", x), _push("main", m2, r.main))
    assert _run_resolvers(tmp_path, "pre-push", (x, m2), pushed) \
        == dict.fromkeys(ROWS, "fixed")


def test_a_symbolic_ref_that_is_not_a_remote_s_head_gives_no_line(tmp_path):
    """Only refs/remotes/<remote>/HEAD names a remote's default branch. Another symbolic ref
    there (an alias someone made) is neither a line nor a branch, so with no remote HEAD the
    stacked push clears as the fallback does."""
    r = _Repo(tmp_path)
    r.git("update-ref", "refs/remotes/origin/main", r.main)
    r.git("symbolic-ref", "refs/remotes/origin/latest", "refs/remotes/origin/main")
    revs, pushed = _stacked(r)
    assert _run_resolvers(tmp_path, "pre-push", revs, pushed) == dict.fromkeys(ROWS, "fixed")


def test_a_lone_remote_not_named_origin_gives_the_line(tmp_path):
    r = _Repo(tmp_path)
    r.git("update-ref", "refs/remotes/fork/main", r.main)
    r.git("symbolic-ref", "refs/remotes/fork/HEAD", "refs/remotes/fork/main")
    revs, pushed = _stacked(r)
    assert _run_resolvers(tmp_path, "pre-push", revs, pushed) == dict.fromkeys(ROWS, "open")


def test_with_several_remotes_origin_gives_the_line(tmp_path):
    """fork has merged A and origin has not. Judged against fork, A's copy is history and
    the stacked push would clear it; against origin it is live work."""
    r = _Repo(tmp_path)
    _publish(r)
    r.git("update-ref", "refs/remotes/fork/main", r.a1)
    r.git("symbolic-ref", "refs/remotes/fork/HEAD", "refs/remotes/fork/main")
    revs, pushed = _stacked(r)
    assert _run_resolvers(tmp_path, "pre-push", revs, pushed) == dict.fromkeys(ROWS, "open")
