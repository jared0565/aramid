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
wrong is pinned as well, `rewritten_pushed_before`: rows on a commit that was pushed and then
rewritten away stay open until the force-push lands, because the remote-tracking ref still
carries the old commit's content. The next push clears them (`rewritten_after_force_push`).
"""
import subprocess
from datetime import datetime, timezone

import pytest

from aramid import mutation_gate, review
from aramid.fingerprint import compute_fingerprint
from aramid.ledger import Ledger, resolve_departed
from aramid.models import Finding, Gate, Severity, Source, Verdict

NOW = datetime(2026, 10, 24, 23, 0, 0, tzinfo=timezone.utc).isoformat()

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


def _run_resolvers(root, gate, revs):
    """The departure resolvers, in run_gate's order, with what run_gate hands them: semgrep
    and gitleaks ran OK; at pre-push the rest follow."""
    led = Ledger(root / "l.db")
    try:
        led.record_run("r0", NOW, gate, set(), set(), list(ROWS.values()))
        led.record_run("r1", NOW, gate, set(RUNNER_ROWS), set(), [], root=root, revs=revs)
        if gate == "pre-push":
            review.auto_resolve_llm(root, led, "r1", NOW, revs=revs)
            for producer in ("red-proof", "tdd", "mutation"):
                resolve_departed(led, "r1", NOW, root=root, tool=producer, present_ids=set(),
                                 revs=revs)
            mutation_gate.auto_resolve_line_departed(led, "r1", NOW, root=root, revs=revs)
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
