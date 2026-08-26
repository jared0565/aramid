"""EVERY launch aramid generates must reach `-m` with `-P`, not just the hook shims.

`tests/unit/test_hook_shim_shadowing.py` guards `hooks.py`. That scope was the
bug: `python -m aramid` puts the CURRENT WORKING DIRECTORY at `sys.path[0]`, so
the hazard belongs to *any* generated launch, and a guard that only reads one
module can only ever certify one module.

Interop round 117 is the reason this file exists. graphite's summary of the
`-P` thread was that template hygiene "has now failed eight times across two
tools, every time because someone enumerated launch points and the list was
incomplete." aramid's own guard had that shape twice over:

  1. It read only `hooks.py`, and `commands/schedule.py` renders TWO launches --
     a Windows Scheduled Task `<Arguments>` and a crontab line -- that reached
     `-m aramid` with no `-P`. Both fire on a TIMER, with no human invocation,
     which is the same self-firing class as `.vscode/tasks.json` on folderOpen.
  2. Its non-vacuity check asserted `len(shims) == 2 * len(GATES) + 1` against a
     HAND-MAINTAINED list, and its docstring claimed that a fourth unlisted
     renderer was what the assertion would catch. Measured 2026-08-26: adding a
     fourth renderer that emits `-m aramid` with no `-P` left all twelve of
     those tests GREEN. Both sides of that comparison came from the same list,
     so it proved determinism, not coverage.

DISCOVERY IS BY SOURCE, NOT BY A LIST. Scanning every string literal in the
package needs no registry to be kept current, cannot be escaped by naming a
renderer something new, and does not care whether a launch is rendered by a
function, a module constant, or a template.

DOCSTRINGS ARE EXCLUDED, and that exclusion is the only judgement here.
`runners/shadow.py`, `cli.py`, `commands/check.py` and `fuzzdriver.py` all
legitimately spell out `python -m aramid` in prose -- shadow.py's docstring
documents the very attack, and flagging the description of a hazard as the
hazard would train people to add exemptions. A docstring cannot be executed; a
string that is assigned, returned or formatted can.
"""
import ast
from pathlib import Path

import pytest

import aramid

SRC = Path(aramid.__file__).parent
# From THIS file, not from the package -- under an installed wheel the package
# lives in site-packages and `.github/` would not be found relative to it.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """id() of every Constant to skip: module/class/function docstrings, plus
    the literal halves INSIDE an f-string.

    The f-string half matters for report quality rather than correctness --
    `ast.walk` yields the JoinedStr and its own Constant children, so without
    this the same crontab line is reported twice, once whole and once as the
    fragment. A guard that double-counts reads as if it found more than it did.
    """
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.Constant):
                    out.add(id(v))
            continue
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", None) or []
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            out.add(id(body[0].value))
    return out


def _render(node: ast.AST) -> str | None:
    """A string literal as SOURCE TEXT, with interpolations collapsed to `{}`.

    An f-string is a JoinedStr whose literal halves are separate Constants, so
    checking those halves individually would split `-P` away from the `-m` it
    guards whenever anything is interpolated between them. Reconstructing the
    whole line keeps the two in the same string, which is what the guard is
    actually about.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            else:
                parts.append("{}")
        return "".join(parts)
    return None


def _executable_segments(chunk: str) -> list[str]:
    """The parts of a line OUTSIDE backticks -- the parts that could be a launch.

    Excluding docstrings was not enough, and the first new code to mention the
    hazard proved it: `arm --shadow`'s help text and confirmation message both
    say "a repo-root file that hijacks `python -m aramid`", which is a
    CITATION of the hazard, not an instance of it. Those are runtime strings,
    not docstrings, so the original scan flagged them and blocked a correct
    commit.

    Backticks are the discriminator, and the reason is mechanical rather than
    stylistic: in `sh` a backtick is COMMAND SUBSTITUTION, so a launch template
    that wrapped its own command in a pair of them would be broken. Measured
    across this package before relying on it -- zero real launch templates in
    `hooks.py` or `schedule.py` contain a backtick, and every prose mention of
    the command is wrapped in a pair.

    Fails CLOSED on an unbalanced count: the pairing is then ambiguous, so the
    whole line is treated as executable and gets checked. A guard that gave up
    quietly on odd input would be the false-clean shape this file exists to
    prevent.
    """
    parts = chunk.split("`")
    if len(parts) % 2 == 0:          # even parts == odd backticks == unbalanced
        return [chunk]
    return parts[0::2]


def _unguarded_launches() -> list[str]:
    """Every executable string literal in the package that reaches `-m aramid`
    without `-P` in front of it. Returns `file:line: text` for each."""
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError) as exc:  # pragma: no cover - see the test
            offenders.append(f"{path}: UNPARSEABLE ({exc})")
            continue
        skip = _docstring_nodes(tree)
        for node in ast.walk(tree):
            if id(node) in skip:
                continue
            text = _render(node)
            if text is None or "-m aramid" not in text:
                continue
            for chunk in text.splitlines():
                # Per OCCURRENCE, not per line: a line may cite the hazard in
                # backticks and launch it for real in the same breath.
                for seg in _executable_segments(chunk):
                    if "-m aramid" not in seg:
                        continue
                    before = seg.split("-m aramid")[0]
                    if not before.rstrip().endswith("-P"):
                        rel = path.relative_to(SRC.parent)
                        offenders.append(
                            f"{rel}:{getattr(node, 'lineno', '?')}: {chunk.strip()}")
    return offenders


def test_no_generated_launch_reaches_dash_m_without_dash_P():
    """The whole point. A failure here names the file and the line, because the
    remedy is always the same one character sequence in the same place."""
    offenders = _unguarded_launches()
    assert not offenders, (
        "these generated launches reach `-m aramid` without `-P`, so a repo-root "
        "aramid.py (or aramid/__init__.py) at their working directory would run "
        "instead of the installed package:\n  " + "\n  ".join(offenders))


def test_the_scan_actually_reads_the_package():
    """Non-vacuity, and NOT the self-referential kind that let a fourth
    renderer through upstream. This asserts against the FILESYSTEM -- if the
    scan silently walked nothing, or every module failed to parse, the test
    above would pass while checking zero launches.
    """
    modules = list(SRC.rglob("*.py"))
    assert len(modules) > 20, f"scan found only {len(modules)} modules under {SRC}"

    parsed = 0
    for path in modules:
        try:
            ast.parse(path.read_text(encoding="utf-8"))
            parsed += 1
        except (OSError, SyntaxError):
            pass
    assert parsed == len(modules), f"only {parsed}/{len(modules)} modules parsed"


def test_no_ci_workflow_reaches_dash_m_without_dash_P():
    """The repo's OWN launches, which the package scan above cannot see.

    `.github/workflows/aramid.yml` ran `python -m aramid check ...` with no
    `-P`, and GitHub Actions runs steps from the checkout root -- so a commit
    or pull request adding an `aramid.py` at the repo root would be imported
    instead of the installed package, in the job whose whole purpose is to
    detect exactly that. The `shadow` runner cannot save this one: the hijack
    happens at import, before the gate it would have run inside.

    Scoped to `.github/workflows/` deliberately. A repo-wide text scan would
    have to exempt CHANGELOG.md and docs/, which legitimately quote the
    UNGUARDED form when recording the hazard -- and a guard that accumulates
    exemptions stops meaning anything.
    """
    workflows = REPO_ROOT / ".github" / "workflows"
    if not workflows.is_dir():  # pragma: no cover - sdist / wheel checkout
        pytest.skip(f"no workflows directory at {workflows}")

    files = sorted(workflows.glob("*.yml")) + sorted(workflows.glob("*.yaml"))
    assert files, f"no workflow files under {workflows} -- scan would be vacuous"

    offenders = []
    for path in files:
        for i, ln in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "-m aramid" not in ln:
                continue
            if not ln.split("-m aramid")[0].rstrip().endswith("-P"):
                offenders.append(f"{path.name}:{i}: {ln.strip()}")
    assert not offenders, (
        "these CI launches reach `-m aramid` without `-P`, and Actions runs "
        "them from the checkout root:\n  " + "\n  ".join(offenders))


def test_a_backticked_citation_is_not_a_launch():
    """The false positive that blocked a correct commit, pinned in both
    directions so the fix cannot quietly become an escape hatch.

    `arm --shadow` describes the hazard in its help text and its confirmation
    message. Those are runtime strings, not docstrings, so docstring exclusion
    alone did not cover them.
    """
    cited = "aramid: arm: a repo-root file that hijacks `python -m aramid` now BLOCKS."
    assert _executable_segments(cited) and "-m aramid" not in "".join(
        _executable_segments(cited)), f"citation still reads as executable: {cited}"

    # ...and the guard must still catch a REAL launch on a line that also
    # cites the hazard. This is the case a whole-line skip would have missed.
    mixed = 'echo "see `python -m aramid`" && "$INTERP" -m aramid check'
    segs = _executable_segments(mixed)
    assert any("-m aramid" in s and not s.split("-m aramid")[0].rstrip().endswith("-P")
               for s in segs), f"a real launch beside a citation was skipped: {segs}"


def test_unbalanced_backticks_fail_closed():
    """An odd count makes the pairing ambiguous. The line must then be checked
    in full rather than silently skipped -- a guard that gives up quietly on
    malformed input is the false-clean this file exists to prevent."""
    odd = 'launch `python -m aramid check'
    assert _executable_segments(odd) == [odd]


def test_the_scan_would_catch_an_unguarded_launch():
    """The discriminator, on a synthetic module rather than by perturbing the
    real tree. A guard nobody has watched reject something is a guard nobody
    has tested -- and this one's predecessor passed for exactly that reason.
    """
    guarded = ast.parse('CMD = f"{interp} -P -m aramid check --gate pre-push"')
    unguarded = ast.parse('CMD = f"{interp} -m aramid drain --all"')
    prose = ast.parse('"""Launch it with python -m aramid drain."""')

    def hits(tree):
        skip = _docstring_nodes(tree)
        found = []
        for node in ast.walk(tree):
            if id(node) in skip:
                continue
            text = _render(node)
            if text is None or "-m aramid" not in text:
                continue
            if not text.split("-m aramid")[0].rstrip().endswith("-P"):
                found.append(text)
        return found

    assert hits(unguarded), "the scan misses an unguarded launch"
    assert not hits(guarded), "the scan flags a correctly guarded launch"
    assert not hits(prose), "the scan flags a docstring describing the hazard"
