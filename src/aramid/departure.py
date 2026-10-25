"""Has a finding's content LEFT what a gate run certifies? (FN-58, channel round 325)

THE RULE, the operator's decision of 2026-10-24 ("Branch's own content"). Content -- a file, or
a quote or line in it -- is gone only when

  1. no revision the run certifies holds it. Committed content, read from git; the disk is
     never evidence that content is gone, so a file deleted or a line edited and not
     committed is still there (llm-review 88a4fab2 said this of line_departed; FN-58 makes it
     true of every departure resolver). For a path no certified revision tracks, the disk is
     the only copy there is: while it has the content the row stays open, as in 0.20.10, and a
     path inside a submodule is never gone (llm-review 81b9d08db396). And
  2. no branch tip holds it whose OWN commits carry it: a tip under refs/heads or refs/remotes
     (never a tag: a release tag holds every file it ever shipped) that holds the content while
     its merge base with THE LINE does not. A copy a branch merely INHERITED from the history
     it shares with the line -- a merged branch never deleted, a dependabot branch cut before
     the fix -- is history that line has moved past. A copy its own commits brought is live
     work on another branch, and the row stays open for it.

THE LINE, the operator's decision of 2026-10-25 ("INTEG-P", llm-review 8cdf845ab278): the
remote default branch as this push leaves it -- the commit refs/remotes/<remote>/HEAD names, or
the commit a pushed ref hands that branch -- and the tracking refs a FAST-FORWARD replaces are
left out by name, since what they hold is what the remote is about to lose. FN-58 first judged
against each certified revision, and a branch that revision REACHES was never read: C, cut
from an unmerged A, deleting A's file, cleared A's rows when C was pushed. With no remote HEAD
there is no line, and each certified revision is judged as it was then. Refined the same day
on three review rows, each the operator's decision:
  - "Fast-forwards only" (6b3e7686eb2d): a force-push's old tip is read like any branch, since
    the server may refuse it (branch protection, a pre-receive hook) and keep the content. Its
    rows clear at the next run, once it has landed. A refused fast-forward still clears, as
    under every rule: the gate certifies what the push meant to do.
  - "Keep open while main has it" (cc6ba8341094): content the line itself holds is content the
    default branch still ships, and its rows stay open however many branches drop it. A push
    that moves the line makes it a certified revision, which already lacks the content.
  - "Forward it, guess when absent" (6ddc2128b981): the remote is the one the push goes to,
    git's `$1`, which the pre-push shim exports (`pushrefs.read_hook_remote`). Its HEAD gives
    the line; with none, the guess below gives a line the push does not move. The tracking
    refs replaced are always the pushed remote's. A shim that names no remote (generated
    before this) gets the guess: origin, else the only remote with a HEAD.

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
it" keeps rows open behind every merged-and-kept or snapshot branch. Judged against each
certified revision, this rule was wrong on one case: a commit pushed and THEN rewritten away
kept its rows open until the force-push landed, because the remote-tracking ref still carried
it. The line was chosen against the same table and seven more cases (stacked branches, a
lagging origin/main, a push of several refs, a stale and a missing remote HEAD). It first let
the force-push clear them itself; since 6b3e7686eb2d that case stays open until it lands, as
the table had it.

SAFE DIRECTION, everywhere. No resolvable certified revision (no repo, no commits, git could
not answer): nothing is gone. A path that is not repo-relative (absolute, a drive, or climbing
out with `..`) cannot have left the repository: not gone. A branch whose content git cannot
read, or whose history shares nothing with the certified line: it carries the content -- so an
orphan branch (a gh-pages) that holds the same path keeps the row open while it exists, a
residual the table did not have. So does a stale line: a clone keeps origin/HEAD naming
origin/master after a master->main rename until `git remote set-head`, and judged against that
older commit, content main's own commits brought looks like every branch's own. So, for a
while, does a lagging one: with no push (pre-commit) the line is origin/HEAD as it stands, so
content a local commit on main drops stays open until main is pushed, and a branch cut from a
local main with unpushed merges carries what they brought until then. Two residuals err the
other way. The old rule's: with no remote HEAD on any remote (a remote added by hand whose
HEAD was never fetched or set), a stacked branch's push still clears its parent's rows. And a
shim generated before the remote was forwarded does not name it, so a push to another remote
is read as going to origin, whose tracking ref is then left out; `aramid init` regenerates
the shim. A `GitTimeout` goes up (FN-17), and the reader then refuses every later question at
once, so the first timeout is the only one paid.

COST. One `ls-tree` per certified revision per reader, which answers the common question --
the file is still there -- by set lookup. Branches are read only for content absent from
every certified revision: one `for-each-ref` of the remote refs, one `merge-base
--is-ancestor` per pushed branch and one `rev-parse` find the line; then the line's tree (one
`ls-tree`, and a text when the question is about text), and one `for-each-ref --no-merged`
against it (against each certified revision without one), which leaves out every tip the
line already reaches (merged or stale, it holds nothing the line lacks), then per remaining
tip one `ls-tree` and one merge base, however many paths are asked about; a text is read only
when the question is about text and the path is there.
The first cut read every tip with a `git show` per path: 60 s on Windows for 10 deleted files
and 50 stale branches (`tests/unit/test_departure_cost.py` counts the processes). Paid per
reader: each resolver call builds its own.
"""
from __future__ import annotations

import posixpath
from collections.abc import Callable, Iterable
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING

from aramid import gitutil

if TYPE_CHECKING:
    from aramid.pushrefs import PushRef

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

    def __init__(self, root: Path | None, revs: Iterable[str] = ("HEAD",),
                 pushed: Iterable[PushRef] = ()):
        self.root = root
        self._wanted = tuple(revs) or ("HEAD",)
        self._pushed = tuple(pushed)
        self._line_read = False
        self._line_sha: str | None = None
        self._replaced: frozenset[str] = frozenset()
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
        reach, each once, leaving out the tracking refs a fast-forward replaces (`_line`).
        Tags are not branches, and a symbolic ref (origin/HEAD, an alias) is not one either:
        it names a ref listed under its own name, read or left out there. A tip `rev`
        reaches is its own merge base with it and holds nothing `rev` lacks, so it is never
        read. None when git could not list them."""
        if rev not in self._tips:
            cp = self._git("for-each-ref", f"--no-merged={rev}",
                           "--format=%(objectname) %(refname) %(symref)",
                           "refs/heads", "refs/remotes")
            rows = [row.split() for row in cp.stdout.splitlines()]
            self._tips[rev] = list(dict.fromkeys(
                row[0] for row in rows if len(row) == 2 and row[1] not in self._replaced)) \
                if cp.returncode == 0 else None
        return self._tips[rev]

    def _line(self) -> str | None:
        """The commit a branch's own commits are told apart against: the remote default
        branch as this push leaves it (llm-review 8cdf845ab278). That is the commit
        `refs/remotes/<remote>/HEAD` names -- the remote the push goes to, when the hook named
        it and it has a HEAD (6ddc2128b981); else origin's, else the only one -- or, when a
        pushed ref goes to that remote's default branch, the commit the push hands it. Also
        notes, by name, the pushed remote's tracking refs that the push FAST-FORWARDS: what
        they hold is what the remote is about to lose. A force-push's old tip is not noted,
        since the server may refuse it (6b3e7686eb2d). None with no remote HEAD, or one that
        names no commit (a branch since pruned); each certified revision is then the line, as
        before."""
        if not self._line_read:
            self._line_read = True
            cp = self._git("for-each-ref", "--format=%(refname) %(symref)", "refs/remotes")
            heads = {}
            for row in cp.stdout.splitlines() if cp.returncode == 0 else ():
                name, _, target = row.partition(" ")
                if target and name.endswith("/HEAD"):
                    heads[name[len("refs/remotes/"):-len("/HEAD")]] = target
            named = next((ref.remote for ref in self._pushed if ref.remote), None)
            if named in heads:
                remote = named
            elif "origin" in heads:
                remote = "origin"
            elif len(heads) == 1:
                remote = next(iter(heads))
            else:
                return None
            target = named or remote
            line, replaced = heads[remote], set()
            for ref in self._pushed:
                if ref.remote_ref.startswith("refs/heads/"):
                    tracking = f"refs/remotes/{target}/{ref.remote_ref[len('refs/heads/'):]}"
                    if self._git("merge-base", "--is-ancestor", tracking,
                                 ref.local_sha).returncode == 0:
                        replaced.add(tracking)
                    if target == remote and tracking == heads[remote]:
                        line = ref.local_sha
            cp = self._git("rev-parse", "--verify", "--quiet", f"{line}^{{commit}}")
            if cp.returncode == 0:
                self._line_sha, self._replaced = cp.stdout.strip(), frozenset(replaced)
        return self._line_sha

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
        """Whether the line (`_line`) holds the content -- the default branch still ships it
        (llm-review cc6ba8341094) -- or some branch tip's OWN commits carry it: the tip holds
        it and its merge base with the line does not; with no line, with some certified
        revision. Any doubt answers True."""
        revs = self.revs()
        if not revs:
            return True
        line = self._line()
        if line and self._holds(line, path, holds) is not False:
            return True
        for rev in (line,) if line else revs:
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

    def _under_a_gitlink(self, path: str) -> bool:
        """Whether a leading part of `path` is an entry of a certified tree. `ls-tree -r` lists
        blobs and gitlinks, never directories, so such an entry is a submodule, whose own
        files git does not list here."""
        parts = path.split("/")
        heads = ["/".join(parts[:n]) for n in range(1, len(parts))]
        return any(head in (self._tree(rev) or ()) for rev in self.revs() for head in heads)

    def _on_disk(self, path: str, holds: Holds | None) -> bool:
        """Whether the working tree has the content. Asked only of a path no certified revision
        tracks, where the disk holds the only copy there is (0.20.10 read it there too). It
        is never evidence that anything is gone."""
        file = self.root / path if self.root is not None else None
        if file is None or not file.is_file():
            return False
        if holds is None:
            return True
        try:
            text = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return True                    # it is there and cannot be read: doubt keeps it
        return holds(text.replace("\r\n", "\n"))

    def gone(self, path: str | None, holds: Holds | None = None) -> bool:
        """The rule: no certified revision holds the content, nor the line, and no branch
        carries it as its own. `holds` tests a revision's text of `path`; None asks only
        whether the file is tracked there. Never True for a path outside the repository or
        when nothing certified can be read; nor for a path no certified revision tracks while
        the working tree has its content or a submodule covers it (llm-review 81b9d08db396)."""
        norm = repo_path(path) if path else None
        if norm is None or not self.revs():
            return False
        if self.at_certified(norm, holds) is not False:
            return False
        if not self.tracked_at_certified(norm) \
                and (self._on_disk(norm, holds) or self._under_a_gitlink(norm)):
            return False
        return not self.carried_by_a_branch(norm, holds)
