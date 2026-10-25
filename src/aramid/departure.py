"""Has a finding's content LEFT what a gate run certifies? (FN-58, channel round 325)

THE RULE, the operator's decision of 2026-10-24 ("Branch's own content"). Content -- a file, or
a quote or line in it -- is gone only when

  1. no revision the run certifies holds it. Committed content, read from git; never the disk,
     so a file deleted or a line edited and not committed is still there (llm-review 88a4fab2
     said this of line_departed; FN-58 makes it true of every departure resolver). And
  2. no branch tip holds it whose OWN commits carry it: a tip under refs/heads or refs/remotes
     (never a tag: a release tag holds every file it ever shipped) that holds the content while
     its merge base with a certified revision does not. A copy a branch merely INHERITED from
     the history it shares with the certified line -- a merged branch never deleted, a
     dependabot branch cut before the fix -- is history that line has moved past. A copy its
     own commits brought is live work on another branch, and the row stays open for it.

WHY. Each departure resolver asked "is it here?" of the wrong thing (round 325, reproduced in
a scratch repo on 0.20.9 and 0.20.10): file_departed and record_run's departed clause asked
the WORKING TREE, evidence_gone asked HEAD, line_departed asked the certified revisions but
nothing else. So pushing -- or for runner rows merely committing on -- a sibling branch wrote
`fixed` on every row raised on the other branch, and pushing a branch from a checkout of
another did the same to the pushed branch's own rows. graphite's red-proof row 7eead5a1 was
written fixed while its branch sat unmerged with the file in it.

CHOSEN AGAINST A TABLE (12 cases, `tests/unit/test_departure_branch_own.py` keeps them).
graphite's proposal -- departed only at a certified revision descending from the one the row
was raised at -- and a history rule (a reachable commit removed it) both leave a commit
REWRITTEN AWAY open forever: the shape file_departed was built for (890d7493, a test file
committed, the push blocked, the commit rewritten without it). Plain "does any branch hold
it" keeps rows open behind every merged-and-kept or snapshot branch. This rule was wrong on
one case: a commit pushed and THEN rewritten away keeps its rows open until the force-push
lands, because the remote-tracking ref still carries it; the next run clears them.

SAFE DIRECTION, everywhere. No resolvable certified revision (no repo, no commits, git could
not answer): nothing is gone. A path that is not repo-relative (absolute, a drive, or climbing
out with `..`) cannot have left the repository: not gone. A branch whose content git cannot
read, or whose history shares nothing with the certified line: it carries the content -- so an
orphan branch (a gh-pages) that holds the same path keeps the row open while it exists, a
residual the table did not have. A `GitTimeout` goes
up (FN-17), and the reader then refuses every later question at once, so the first timeout
is the only one paid.

COST. One `ls-tree` per certified revision per reader, which answers the common question --
the file is still there -- by set lookup. Branches are read only for content absent from
every certified revision: one `for-each-ref --no-merged` per certified revision, which
leaves out every tip that revision already reaches (merged or stale, it holds nothing the
revision lacks), then per remaining tip one `ls-tree` and one merge base, however many paths
are asked about; a text is read only when the question is about text and the path is there.
The first cut read every tip with a `git show` per path: 60 s on Windows for 10 deleted files
and 50 stale branches (`tests/unit/test_departure_cost.py` counts the processes). Paid per
reader: each resolver call builds its own.
"""
from __future__ import annotations

import posixpath
from collections.abc import Callable, Iterable
from pathlib import Path, PurePosixPath, PureWindowsPath

from aramid import gitutil

Holds = Callable[[str], bool]


def repo_path(path: str) -> str | None:
    """The stored path as git names it, normalized (`src/../bad.py` IS `bad.py`), or None when
    it cannot name a file inside the repository: absolute, on a drive, or climbing out with
    `..`. Such a path never departs -- it was never inside."""
    p = path.replace("\\", "/")
    if PurePosixPath(p).is_absolute() or PureWindowsPath(path).drive:
        return None
    norm = posixpath.normpath(p)
    if norm in (".", "..") or norm.startswith("../"):
        return None
    return norm


class Departure:
    """One run's reader for "is this content gone?", caching what git tells it.

    `revs` are the revisions the run certifies, as `pipeline._certified_revs` gives them: the
    pushed refs' local shas, then HEAD; HEAD alone at pre-commit or for a hand-run gate."""

    def __init__(self, root: Path | None, revs: Iterable[str] = ("HEAD",)):
        self.root = root
        self._wanted = tuple(revs) or ("HEAD",)
        self._revs: list[str] | None = None
        self._trees: dict[str, frozenset[str] | None] = {}
        self._blobs: dict[tuple[str, str], str | None] = {}
        self._tips: dict[str, list[str] | None] = {}
        self._bases: dict[tuple[str, str], str | None] = {}
        self._timed_out: gitutil.GitTimeout | None = None

    # -- git, through one door, so a timeout is paid once -------------------------------------
    def _git(self, *args: str):
        if self._timed_out is not None:
            raise self._timed_out
        try:
            return gitutil._run(self.root, *args)
        except gitutil.GitTimeout as exc:
            self._timed_out = exc
            raise

    def revs(self) -> list[str]:
        """The certified revisions git resolves, as commit shas, deduplicated in order. Empty
        without a root, outside a repository, or before its first commit."""
        if self._revs is None:
            shas: list[str] = []
            if self.root is not None:
                for rev in self._wanted:
                    try:
                        cp = self._git("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
                    except OSError:            # git could not start there: a root that is gone
                        break
                    sha = cp.stdout.strip() if cp.returncode == 0 else ""
                    if sha and sha not in shas:
                        shas.append(sha)
            self._revs = shas
        return self._revs

    def _tree(self, rev: str) -> frozenset[str] | None:
        """Every path tracked at `rev`, or None when git could not list it."""
        if rev not in self._trees:
            cp = self._git("ls-tree", "-r", "--name-only", "-z", rev)
            self._trees[rev] = (frozenset(p for p in cp.stdout.split("\0") if p)
                                if cp.returncode == 0 else None)
        return self._trees[rev]

    def _blob(self, rev: str, path: str) -> str | None:
        key = (rev, path)
        if key not in self._blobs:
            cp = self._git("show", f"{rev}:{path}", "--")
            self._blobs[key] = cp.stdout if cp.returncode == 0 else None
        return self._blobs[key]

    def _branch_tips(self, rev: str) -> list[str] | None:
        """The commits at the branch tips, local and remote-tracking, that `rev` does not
        reach, each once. Tags are not branches; a symbolic ref (origin/HEAD) names a commit a
        branch listed here already names. A tip `rev` reaches is its own merge base with it
        and holds nothing `rev` lacks, so it is never read. None when git could not list
        them."""
        if rev not in self._tips:
            cp = self._git("for-each-ref", f"--no-merged={rev}", "--format=%(objectname)",
                           "refs/heads", "refs/remotes")
            self._tips[rev] = list(dict.fromkeys(cp.stdout.split())) if cp.returncode == 0 \
                else None
        return self._tips[rev]

    def _merge_base(self, ref: str, rev: str) -> str | None:
        """The merge base's sha, or None when the two share no history (git exits 1)."""
        key = (ref, rev)
        if key not in self._bases:
            cp = self._git("merge-base", ref, rev)
            self._bases[key] = cp.stdout.strip() if cp.returncode == 0 else None
        return self._bases[key]

    # -- the questions ----------------------------------------------------------------------
    def at_certified(self, path: str, holds: Holds | None = None) -> bool | None:
        """Whether some certified revision holds the content: True, False, or None when git
        could not say for one of them (callers read None as "held")."""
        unsure = False
        for rev in self.revs():
            tree = self._tree(rev)
            if tree is None:
                unsure = True
                continue
            if path not in tree:
                continue
            if holds is None:
                return True
            text = self._blob(rev, path)
            if text is None:
                unsure = True
            elif holds(text):
                return True
        return None if unsure else False

    def tracked_at_certified(self, path: str) -> bool:
        """Whether the PATH is tracked at some certified revision, whatever it holds. A path
        outside the repository is never tracked."""
        norm = repo_path(path) if path else None
        return norm is not None and any(norm in (self._tree(rev) or ()) for rev in self.revs())

    def _holds(self, rev: str, path: str, holds: Holds | None) -> bool | None:
        """Whether `rev` holds the content, from its tree, and its text only when `holds` asks
        about the text; None when git could not say."""
        tree = self._tree(rev)
        if tree is None:
            return None
        if path not in tree:
            return False
        if holds is None:
            return True
        text = self._blob(rev, path)
        return None if text is None else holds(text)

    def carried_by_a_branch(self, path: str, holds: Holds | None = None) -> bool:
        """Whether some branch tip's OWN commits carry the content: the tip holds it and its
        merge base with some certified revision does not. Any doubt answers True."""
        revs = self.revs()
        if not revs:
            return True
        for rev in revs:
            tips = self._branch_tips(rev)
            if tips is None:
                return True
            for tip in tips:
                held = self._holds(tip, path, holds)
                if held is False:
                    continue
                base = None if held is None else self._merge_base(tip, rev)
                if base is None or self._holds(base, path, holds) is not True:
                    return True
        return False

    def gone(self, path: str | None, holds: Holds | None = None) -> bool:
        """The rule: no certified revision holds the content and no branch carries it as its
        own. `holds` tests a revision's text of `path`; None asks only whether the file is
        tracked there. Never True for a path outside the repository or when nothing
        certified can be read."""
        norm = repo_path(path) if path else None
        if norm is None or not self.revs():
            return False
        if self.at_certified(norm, holds) is not False:
            return False
        return not self.carried_by_a_branch(norm, holds)
