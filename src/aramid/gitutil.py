import os
import re
import subprocess
import sys
from pathlib import Path

from aramid import toolpath
from aramid.runners import base as runners_base

class NotARepo(Exception): ...

class GitTimeout(Exception):
    """git did not answer: it outlived GIT_TIMEOUT_S, or the drain's hard
    deadline killed it or came before it started. Never an answer."""

GIT_TIMEOUT_S = 600.0
_GIT: tuple[str, ...] = ("git",)   # test seam: the argv head

def _git_env() -> dict[str, str]:
    """This process's environment for git, without GIT_LITERAL_PATHSPECS
    (FN-42). Every path aramid hands git is marked `:(literal)`
    (`literal_pathspec`), and with that variable set git does not read the
    mark: `:(literal)a.py` is then a name no file has, and finds nothing. A
    caller sets it without meaning to: `git --literal-pathspecs commit`
    exports it to the hooks that commit runs (measured 2026-10-12)."""
    env = dict(os.environ)
    env.pop("GIT_LITERAL_PATHSPECS", None)
    return env

def _decoded(data: bytes, errors: str, translate: bool) -> str:
    """git's bytes as text. `translate` reads `\\r\\n` and a lone `\\r` as
    `\\n`, as the text-mode pipe `_run` used until 0.20.17 did for every
    caller. The patch parser asks for git's own line ends instead: git ends
    a patch line with `\\n` alone, and a `\\r` inside a changed line is part
    of that line (`diff_new_lines`)."""
    text = data.decode("utf-8", errors)
    return text.replace("\r\n", "\n").replace("\r", "\n") if translate else text

def _run(root: Path, *args: str, errors: str = "replace",
         translate_newlines: bool = True) -> subprocess.CompletedProcess:
    """git's answer: its exit code and output, whatever the code. A git that
    did not ANSWER raises `GitTimeout` instead (FN-17) -- one that outlived
    GIT_TIMEOUT_S, one the drain's hard deadline killed, one asked for after
    the deadline -- because the callers read a failed git as an empty answer
    (`staged_files` -> [], `diff_new_lines` -> {}) and a killed one must not
    reach them as one. Registered in `runners.base`'s registry while it runs,
    so the deadline's `kill_live` stops it: before FN-17 a git in flight at
    the deadline outlived the drain, and a hung one hung whatever asked."""
    what = " ".join(["git", *args[:1]])
    if runners_base.closed():
        raise GitTimeout(f"{what} not started: the drain's hard deadline has passed")
    # S603 justification: aramid's single git wrapper -- "git" is a fixed
    # literal (_GIT, never derived from *args; only tests replace it) and
    # every call site passes fixed subcommands (rev-parse, show, rev-list,
    # diff, ls-files, log, merge-base, for-each-ref, worktree). It is started by the
    # absolute path `toolpath.program` finds for it, never by the bare name:
    # Windows looks for a bare name in the current directory before PATH,
    # and that directory is the repo being judged (FN-47).
    # Read as bytes and decoded as UTF-8 here (`_decoded`): git emits UTF-8
    # by default regardless of host locale, and a text-mode pipe would decode
    # with the locale-preferred codec, which mojibakes (or raises
    # UnicodeDecodeError on undefined bytes) on cp1252 Windows hosts -- the
    # target platform, and CI's windows-latest runner.
    # errors="replace": never let a decode hiccup crash triage's per-commit
    # diff scan; a best-effort mangled character is acceptable, a raised
    # exception is not. The name listings pass "surrogateescape" instead, so
    # a name that is not UTF-8 stays recognisable (`_readable`).
    proc = subprocess.Popen(toolpath.launchable([*_GIT, *args]),  # noqa: S603
                            cwd=str(root), env=_git_env(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            **runners_base.own_group())
    try:
        with runners_base.live_process(lambda: runners_base._kill_tree(proc)):
            out, err = proc.communicate(timeout=GIT_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        runners_base._kill_tree(proc)
        try:
            proc.communicate(timeout=runners_base._POST_KILL_DRAIN_S)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise GitTimeout(f"{what} timed out after {GIT_TIMEOUT_S:g} s and was killed") from None
    if runners_base.closed():
        # Killed by the deadline, not finished: its exit code is the kill's.
        raise GitTimeout(f"{what} was killed at the drain's hard deadline")
    return subprocess.CompletedProcess(proc.args, proc.returncode,
                                       _decoded(out, errors, translate_newlines),
                                       _decoded(err, "replace", True))

def repo_root(path: Path) -> Path:
    cp = _run(path, "rev-parse", "--show-toplevel")
    if cp.returncode != 0:
        raise NotARepo(str(path))
    return Path(cp.stdout.strip()).resolve()


def git_dir(root: Path) -> Path:
    """The repository's own git directory, absolute: `root/.git` in a plain
    checkout, the worktree's directory under the main `.git` in a linked one
    (where `.git` is a file)."""
    cp = _run(root, "rev-parse", "--absolute-git-dir")
    if cp.returncode != 0:
        raise NotARepo(str(root))
    return Path(cp.stdout.strip())


def git_not_found() -> bool:
    """True when a git launch has no program to start: the path
    `toolpath.program` hands back for it is no file. That is the place it
    looked first when no directory holds git, so this is the very lookup
    `_run` launches by, and the answer cannot disagree with the launch."""
    try:
        return not Path(toolpath.program(_GIT[0])).is_file()
    except Exception:
        return False


def _root_by_its_dot_git(base: Path) -> Path | None:
    """The nearest directory from `base` up that holds a `.git` entry -- a
    directory in a plain checkout, a file in a linked worktree or a
    submodule -- resolved, as `repo_root` answers. The nearest one, as git
    stops there: a repo nested inside another is its own root. A `base` that
    is not a directory is not walked up from. Never raises."""
    try:
        here = base.resolve()
        if not here.is_dir():
            return None
        for d in (here, *here.parents):
            if (d / ".git").exists():
                return d
    except OSError:
        return None
    return None


def armed_root(start: Path | None = None) -> Path | None:
    """The git root of `start` (the cwd when None), and only when it holds
    an `aramid.toml` FILE -- a repo where `aramid init` ran. None outside
    git, in a repo aramid never armed, or when git cannot answer.

    When git cannot be STARTED (`git_not_found`), the root is the nearest
    `.git` from `start` up instead (interop round 341, operator decision
    2026-11-22). Before, a hook whose PATH held no git read that as "not an
    aramid repo" and printed nothing: no GATED banner, no handover notice,
    no --no-verify warning, and an armed repo let `git commit --no-verify`
    through by absolute path. Only a missing git hands over to the walk: a
    git that runs and says "not a repository" is believed.

    THE ONE COPY (FN-30). The SessionStart hook, the MCP tools and `aramid
    handover` all resolve their repo here. Since 0.20.4 this rule decides
    where a handover file lands, so if two copies drift the CLI writes a
    handover where MCP never reads it. The hook calls it on its fail-open
    path, so every failure is None: a start that does not exist makes the
    git subprocess itself raise, not `NotARepo`."""
    base = Path(start) if start is not None else Path.cwd()
    try:
        repo = repo_root(base)
    except Exception:
        if not git_not_found():
            return None
        repo = _root_by_its_dot_git(base)
        if repo is None:
            return None
    if not (repo / "aramid.toml").is_file():
        return None
    return repo

def read_blob(root: Path, ref: str, rel_path: str) -> str:
    """The file's text at `ref` (`:` for the index), or "" when git has
    none. The `--` after the spec makes git read it as a revision and nothing
    else (FN-42): with no `--`, a spec that names no object and holds a
    wildcard, as an untracked `lib/[ab]/u.ts` does, is read as a pathspec,
    and `git show` answers rc 0 with HEAD's commit or with nothing (measured
    2026-10-13 on git 2.53, and on 2.55 in CI)."""
    spec = f"{ref}:{rel_path}" if ref != ":" else f":{rel_path}"
    cp = _run(root, "show", spec, "--")
    return cp.stdout if cp.returncode == 0 else ""


def blob_at(root: Path, ref: str, rel_path: str) -> str | None:
    """The file's text at `ref`, or None when git has no such blob -- the
    path is not tracked at that revision, escapes the tree, or git itself
    failed. Unlike `read_blob`, an EMPTY file and a missing one differ: a
    resolver that treats "" as "no lines" must not be handed "" for "git
    could not say". The `--` is `read_blob`'s (FN-42)."""
    try:
        cp = _run(root, "show", f"{ref}:{rel_path}", "--")
    except (OSError, ValueError):
        return None
    return cp.stdout if cp.returncode == 0 else None

def resolve_range(root: Path):
    """The push's delta as `base..HEAD`, or None when nothing on this machine
    says what the remote already has (a brand-new repo's first push: the
    caller then scans every commit reachable from HEAD). Two sources, in
    order: the branch's upstream, and the newest commit already on ANY
    remote-tracking ref -- `git merge-base HEAD <every refs/remotes/* sha>`,
    the base of HEAD and a hypothetical merge of them all, which is exactly
    what the push adds to the remote. The second replaced an `origin/HEAD`
    merge-base: a clone made by `git init` + `git remote add` never has
    `refs/remotes/origin/HEAD`, so the first push of a NEW BRANCH fell
    through to the full-history scan and reported secrets that live only in
    old commits as live BLOCKs at the current line numbers (demo-store2,
    channel round 233, 2026-09-19); and wherever `origin/HEAD` does exist,
    its target is one of the remote refs, so this answer is never further
    from HEAD than that one was. A remote ref with no common history (an
    orphan, another project) fails the merge-base: None, full history."""
    if _run(root, "rev-parse", "@{u}").returncode == 0:
        return "@{u}..HEAD"
    refs = _run(root, "for-each-ref", "--format=%(objectname)", "refs/remotes/")
    shas = sorted({s for s in refs.stdout.split() if s}) if refs.returncode == 0 else []
    if shas:
        mb = _run(root, "merge-base", "HEAD", *shas)
        if mb.returncode == 0:
            return f"{mb.stdout.strip()}..HEAD"
    return None

def range_commits(root: Path, rng):
    spec = rng if rng else "HEAD"
    cp = _run(root, "rev-list", spec)
    return [line for line in cp.stdout.splitlines() if line] if cp.returncode == 0 else []

def _names(cp, left_out: list[str] | None = None) -> list[str]:
    """The names of a `-z` listing, as they are on disk. Every listing aramid
    hands its runners is `-z`: without it git C-quotes a name holding a byte
    above 0x7F (core.quotePath, on by default), a quote, a backslash or a
    control character -- `"pronounced-a\\313\\220ramid.js"`, quotes included
    -- and a runner handed that is handed a file that does not exist.
    Measured on the published 0.20.14: `check --all` copied nothing for
    gitleaks to scan, so a secret in such a file was missed with nothing
    said, and semgrep exited 2 for the whole repo. A name that is not UTF-8
    is left out (`_readable`), and put in `left_out` when the caller passes
    one: the gate counts each as a file no tool scanned (`pipeline`)."""
    names = []
    for name in cp.stdout.split("\0"):
        if not name:
            continue
        if _readable(name):
            names.append(name)
        elif left_out is not None:
            left_out.append(name)
    return names

def shown_name(name: str) -> str:
    """A name as a bytes literal reads it: `caf\\xe9.py` for a Latin-1 byte,
    and a control character escaped, never raw to the terminal."""
    return repr(name.encode("utf-8", "surrogateescape"))[2:-1]

def reported_name(name: str) -> str:
    """A left-out name as a tool that reads git itself reports it: each byte
    that is not UTF-8 as one U+FFFD. Measured on gitleaks 8.30.1, staged and
    commit scans alike: `x\\xe9\\x80.py` comes back as two U+FFFD, where
    Python's "replace" would write one for the whole cut-off sequence. The
    ledger keeps rows under it open (`pipeline`, `Ledger.record_run`)."""
    return re.sub("[\udc80-\udcff]", "�", name)

_UNREADABLE_SAID: set[str] = set()

def _readable(name: str) -> bool:
    """Whether a name git listed is valid UTF-8, the only kind aramid hands
    its tools. Linux lets a file be named in Latin-1 (`caf\\xe9.py`), and no
    tool here can be handed one: measured in WSL Ubuntu on 0.20.15, ruff and
    gitleaks report such a file under a name with U+FFFD in it, so their
    findings name a file that does not exist, and semgrep skips it without
    a word. The listings decode it with surrogateescape, which makes it
    fail to encode here. A name left out is said once per process, on
    stderr like `diagnostics`. gitleaks' commit scan reads git itself and
    still caught a token in such a file; its push scan reads git the same
    way, which was not measured separately."""
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        if name not in _UNREADABLE_SAID:
            _UNREADABLE_SAID.add(name)
            print(f"aramid: git: {shown_name(name)} is not handed to the tools: "
                  "its name is not valid UTF-8", file=sys.stderr)
        return False
    return True

# How every name listing and the patch parser read git: a name not UTF-8
# stays recognisable (`_readable`), and a `\r` stays a `\r` -- inside a name
# a `-z` listing ends with NUL, or inside a changed line (`diff_new_lines`).
_AS_GIT_WROTE = {"errors": "surrogateescape", "translate_newlines": False}

def staged_files(root: Path, left_out: list[str] | None = None):
    return _names(_run(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z",
                       **_AS_GIT_WROTE), left_out)

def all_tracked_files(root: Path, left_out: list[str] | None = None):
    return _names(_run(root, "ls-files", "-z", **_AS_GIT_WROTE), left_out)

def changed_files(root: Path, rng, left_out: list[str] | None = None):
    spec = rng if rng else "HEAD"
    return _names(_run(root, "diff", "--name-only", "--diff-filter=ACMR", "-z", spec,
                       **_AS_GIT_WROTE), left_out)

def literal_pathspec(paths) -> list[str]:
    """`--` and each repo path marked `:(literal)`: the ONE spelling of a
    path aramid hands git (FN-42). Unmarked, git reads a path as a pattern,
    so `app/[id]/page.ts` is a character class and names `app/i/page.ts` too
    (measured 2026-10-12: `log` named the sibling's commit, `diff` and `show`
    listed both files, `ls-files --error-unmatch` called an untracked file
    tracked); and before any `--`, a path that starts with `-` is an option.
    `_run` keeps GIT_LITERAL_PATHSPECS out of git's environment, since with
    it set git does not read the mark (`_git_env`)."""
    return ["--", *(f":(literal){p}" for p in paths)]

def newest_commit_touching(root: Path, rng, rel_path):
    spec = rng if rng else "HEAD"
    cp = _run(root, "log", "-1", "--format=%H", spec, *literal_pathspec([rel_path]))
    return cp.stdout.strip() or "HEAD"

def is_tracked(root: Path, rel_path: str) -> bool:
    return _run(root, "ls-files", "--error-unmatch",
                *literal_pathspec([rel_path])).returncode == 0

def read_for_fingerprint(root: Path, ref: str, rel_path: str) -> str:
    blob = read_blob(root, ref, rel_path)
    if blob:
        return blob
    if not is_tracked(root, rel_path):
        p = root / rel_path
        if p.exists():
            # UTF-8, as `git show` above is decoded: otherwise the same line
            # hashes differently once the file is added.
            return p.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
    return ""

def rev_sha(root: Path, rev: str) -> str | None:
    cp = _run(root, "rev-parse", "--verify", f"{rev}^{{commit}}")
    return cp.stdout.strip() if cp.returncode == 0 else None


def remote_default_branch(root: Path) -> tuple[str, str] | None:
    """(`<remote>/<branch>`, commit) of the remote default branch with no push
    in flight: the ref `refs/remotes/<remote>/HEAD` names -- origin's, else
    the only remote that has one -- as `departure` picks its line when no
    push names a remote. None with no such HEAD, two candidates and no
    origin, or a HEAD naming no commit (a branch since pruned). One git
    call: `for-each-ref` prints a symref's resolved commit, and leaves a
    dangling one out."""
    cp = _run(root, "for-each-ref", "--format=%(refname) %(symref) %(objectname)",
              "refs/remotes")
    heads = {}
    for row in cp.stdout.splitlines() if cp.returncode == 0 else ():
        name, target, sha = (row.split(" ") + ["", ""])[:3]
        if target and sha and name.endswith("/HEAD"):
            heads[name[len("refs/remotes/"):-len("/HEAD")]] = (target[len("refs/remotes/"):], sha)
    if "origin" in heads:
        return heads["origin"]
    if len(heads) == 1:
        return next(iter(heads.values()))
    return None


def unreached_by(root: Path, commits, tip: str) -> set[str]:
    """The `commits` that `tip` does not reach, in ONE git call however many
    there are (a spawn costs ~0.1 s on Windows, and the session-start hook
    pays it): `rev-list --ignore-missing <commits> --not <tip>` lists what
    only they reach. A commit git does not know (another clone's, gc'd) is
    left out, never called unreached. Empty when git fails."""
    wanted = set(commits)
    if not wanted:
        return set()
    cp = _run(root, "rev-list", "--ignore-missing", *sorted(wanted), "--not", tip)
    if cp.returncode != 0:
        return set()
    return wanted & set(cp.stdout.split())


def first_parent(root: Path, rev: str) -> str | None:
    cp = _run(root, "rev-parse", "--verify", f"{rev}^")
    return cp.stdout.strip() if cp.returncode == 0 else None


def is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    """True iff `ancestor` is reachable from `descendant` (or equal). An
    unknown rev reads as False, never raises."""
    cp = _run(root, "merge-base", "--is-ancestor", ancestor, descendant)
    return cp.returncode == 0


def on_any_ref(root: Path, sha: str) -> bool | None:
    """Whether a branch, tag or remote-tracking branch still contains the
    commit `sha`. False when none does -- it was amended, rebased or reset
    away -- or when the commit no longer resolves (pruned after that).
    None when git could not say; the caller must not read that as gone."""
    if rev_sha(root, sha) is None:
        return False
    cp = _run(root, "for-each-ref", "--contains", sha, "--count=1",
              "--format=%(refname)", "refs/heads", "refs/tags", "refs/remotes")
    if cp.returncode != 0:
        return None
    return bool(cp.stdout.strip())


def branches_that_held(root: Path, sha: str) -> list[tuple[str, str]] | None:
    """The local branches whose own reflog records the commit `sha`, each as
    (name, tip): where an amend, rebase or reset that rewrote `sha` away left
    the work, because the branch it was rewritten on logged the old value
    before the new one. Only a branch's own reflog is read -- never HEAD's,
    which logs every commit and every checkout, and never a remote-tracking
    branch's, which a force-push of the rewrite logs a second time. A branch
    with no reflog holds nothing. None when git could not say; the caller
    must not read that as "no branch"."""
    cp = _run(root, "for-each-ref", "--format=%(objectname) %(refname)", "refs/heads")
    if cp.returncode != 0:
        return None
    held = []
    for line in cp.stdout.splitlines():
        tip, _, ref = line.partition(" ")
        log = _run(root, "log", "--walk-reflogs", "--format=%H", ref, "--")
        if log.returncode != 0:
            return None
        if sha in log.stdout.split():
            held.append((ref.removeprefix("refs/heads/"), tip))
    return held


def diff_paths(root: Path, base: str | None, head: str) -> list[str]:
    if base is None:
        cp = _run(root, "diff-tree", "--no-commit-id", "--name-only", "-r", "--root", "-z", head,
                  **_AS_GIT_WROTE)
    else:
        cp = _run(root, "diff", "--name-only", "--diff-filter=ACMR", "-z", f"{base}..{head}",
                  **_AS_GIT_WROTE)
    return _names(cp) if cp.returncode == 0 else []


def diff_text(root: Path, base: str | None, head: str, max_bytes: int = 400_000,
             paths: list[str] | None = None) -> str:
    # paths (optional pathspec): scopes the diff to exactly these files. Used
    # by review.build_packet to keep the diff in lockstep with an
    # already-filter_paths()-filtered file list -- spec 8b: graphite
    # artifacts must never leak into an outbound packet via an unscoped
    # base..head diff even when they were excluded from the file list.
    # Literal (`literal_pathspec`): a bracketed path is a pattern otherwise,
    # and lets a sibling the filter dropped into the packet (FN-42).
    pathspec = literal_pathspec(paths) if paths else []
    if base is None:
        cp = _run(root, "show", "--format=", head, *pathspec)
    else:
        cp = _run(root, "diff", f"{base}..{head}", *pathspec)
    text = cp.stdout if cp.returncode == 0 else ""
    # At most max_bytes of UTF-8, never cut inside a character. A text under
    # the cap comes back whole: `_run` decodes with errors="replace", so the
    # text holds no lone surrogate and the round trip changes nothing.
    return text.encode("utf-8", "replace")[:max_bytes].decode("utf-8", "ignore")


def main_checkout(root: Path) -> Path | None:
    """The main checkout a linked `git worktree` belongs to, or None: for a
    main checkout itself, a worktree of a bare repo (it has no main checkout),
    or a git that does not answer. A linked worktree's git directory is
    `<common>/worktrees/<name>`; the main checkout's IS the common one, and
    that is a `.git` inside the checkout. Interop round 343: a gate run in a
    worktree credits its fleet row to the registered repo by this, and
    `aramid init` in a worktree registers the main checkout. A git that
    outlives its timeout still raises `GitTimeout` (`_run`)."""
    cp = _run(Path(root), "rev-parse", "--git-dir", "--git-common-dir")
    lines = (cp.stdout or "").splitlines()
    if cp.returncode != 0 or len(lines) != 2:
        return None
    git_dir, common = ((Path(root) / line.strip()).resolve() for line in lines)
    if git_dir == common or common.name != ".git":
        return None
    return common.parent


def is_test_file(rel: str) -> bool:
    """True for pytest-style test files (canonical helper; the mutation/fuzz/
    js_mutation consumers keep their own local copies, left untouched)."""
    p = rel.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    if p.startswith("tests/") or "/tests/" in p:
        return True
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


_HUNK_RE = re.compile(r"@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

# git's named escapes in a C-quoted path (quote.c), as the byte each stands for.
_C_ESCAPES = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92, '"': 34}


def _unquote_c(text: str) -> str:
    """A path as git C-quotes it in a patch header, read back: `"..."` with
    `\\ooo` octal bytes and the named escapes, decoded as UTF-8 with
    surrogateescape, as the listings are (`_readable`). A patch has no `-z`
    form (`_names`), so this is the one place aramid reads a quoted name.
    Text that is not quoted comes back as is."""
    quoted = re.fullmatch(r'"(.*)"', text, re.DOTALL)
    if quoted is None:
        return text
    body, out, i = quoted.group(1), bytearray(), 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and body[i + 1:i + 2] in _C_ESCAPES:
            out.append(_C_ESCAPES[body[i + 1]])
            i += 2
        elif ch == "\\" and re.fullmatch(r"[0-7]{3}", body[i + 1:i + 4]):
            out.append(int(body[i + 1:i + 4], 8))
            i += 4
        else:
            out += ch.encode("utf-8", "surrogateescape")
            i += 1
    return out.decode("utf-8", "surrogateescape")


def diff_new_lines(root: Path, base: str | None, head: str) -> dict[str, set[int]]:
    """Changed-line map for base..head: repo-relative forward-slash path ->
    1-based line numbers on the NEW (head) side. Parses --unified=0 hunk
    headers (@@ -a,b +c,d @@); a pure deletion has d==0 and contributes
    nothing; git emits forward-slash paths already.

    The b + d lines after a hunk header are its body, skipped by count: an
    added `++ two` is printed `+++ two` and a removed `-- x` `--- x`, the
    spelling of a file header, and before 0.20.16 one was read as a header,
    crediting the file's next hunk to a path named `two`. The
    `\\ No newline at end of file` marker is not among the lines counted.
    A name that is not UTF-8 is left out, as the listings leave it out.

    The count holds only if a line is what git ends with `\\n` and nothing
    else, so the patch is read with its line ends untouched and split on
    `\\n` alone: in 0.20.16 a form feed, a U+2028 or a lone `\\r` inside a
    changed line split it in two, and a second half that read as a hunk
    header swallowed the changes after it."""
    if base is None:
        cp = _run(root, "show", "--format=", "--unified=0", head, **_AS_GIT_WROTE)
    else:
        cp = _run(root, "diff", "--unified=0", f"{base}..{head}", **_AS_GIT_WROTE)
    out: dict[str, set[int]] = {}
    current: str | None = None
    body = 0
    for ln in (cp.stdout if cp.returncode == 0 else "").split("\n"):
        if body:
            if not ln.startswith("\\"):
                body -= 1
            continue
        if ln.startswith("+++ "):
            target = _unquote_c(ln[4:].strip())
            current = None if target == "/dev/null" else \
                (target[2:] if target.startswith("b/") else target)
        elif ln.startswith("@@ "):
            m = _HUNK_RE.match(ln)
            if m is None:
                continue
            start, count = int(m.group(2)), int(m.group(3) or "1")
            body = int(m.group(1) or "1") + count
            if count and current is not None:
                out.setdefault(current, set()).update(range(start, start + count))
    return {name: lines for name, lines in out.items() if _readable(name)}
