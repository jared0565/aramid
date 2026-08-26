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

import aramid

SRC = Path(aramid.__file__).parent


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
                if "-m aramid" not in chunk:
                    continue
                before = chunk.split("-m aramid")[0]
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
