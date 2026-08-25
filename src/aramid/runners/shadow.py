"""module-shadow detector -- a file at the repo root that hijacks `python -m`.

`python -m <name>` puts the CURRENT DIRECTORY on `sys.path[0]`. Running a
script does not -- it puts the script's own directory there -- so `-m` is the
whole mechanism. A repo root that contains `aramid.py`, or an `aramid/`
directory with an `__init__.py`, is therefore imported INSTEAD of the installed
package by every `python -m aramid` launched from that root: git hooks, agent
hooks, MCP servers, editor tasks.

WHY THIS IS A RUNNER AND NOT A SELF-CHECK (interop round 117 §1, measured).
The natural fix is a guard inside aramid that refuses when `aramid.__file__`
is not the installed location. That guard CANNOT FIRE in the case it exists to
catch: when the shadow wins, the real package is never imported, so nothing
inside it runs. Measured from a directory holding a hostile `aramid.py`:

    python -m aramid --version     -> *** SHADOW aramid.py EXECUTED ***  rc=0
    python -P -m aramid --version  -> aramid 0.3.1
    aramid --version (via PATH)    -> aramid 0.3.1

The shadow printed and exited 0. Under a hook's `>/dev/null 2>&1 || true` that
is indistinguishable from success. So the hazard has to be detected as a
property of the FILE, from a process that is not the one being hijacked -- and
that only works if this gate's own launch is itself shadow-proof (`-P`, or a
console script). `-P` is a precondition for this check, not a substitute.

THE PREDICATE, AND THE FALSE POSITIVE IT EXCLUDES. Measured, three shapes:

    <name>.py             at the root  -> HAZARD, shadow executes
    <name>/__init__.py    at the root  -> HAZARD, shadow executes
    <name>/ WITHOUT __init__.py        -> NOT a hazard, do not report

The third is a PEP 420 namespace portion, and a namespace portion loses to a
regular package wherever it sits on `sys.path`. Reporting "a directory named
aramid exists" would fire on repos that are not at risk -- `F:/Projects/graphite`
is exactly that shape and never was a shadow.
"""
import json
from pathlib import Path

from aramid.normalizer import RawFinding
from aramid.runners.base import RunnerResult, ToolState

NAME = "shadow"
RULE = "module-shadow"

# Any distribution this machine's tooling launches with `-m`. One rule protects
# both tools; a repo that launches neither can narrow it in `[shadow] names`.
DEFAULT_NAMES = ("aramid", "graphite")

# The finding is about the file's EXISTENCE, not its contents, so the
# fingerprint must not move when the shadow's body changes -- otherwise the
# attacker controls the finding id and can churn it out of an adjudication.
# A constant here makes the id a stable function of (tool, rule, path).
_STABLE_CONTENT = "\x00aramid:module-shadow"


def _hazards(root: Path, names) -> list[dict]:
    out = []
    for name in names:
        module = root / f"{name}.py"
        if module.is_file():
            out.append({"name": name, "path": f"{name}.py", "shape": "module"})
        init = root / name / "__init__.py"
        if init.is_file():
            out.append({"name": name, "path": f"{name}/__init__.py",
                        "shape": "package"})
    return out


def run(ctx, names=DEFAULT_NAMES) -> RunnerResult:
    """Pure filesystem: a handful of stat calls, no subprocess, no external
    tool. It can therefore never be MISSING/TIMEOUT, which matters because a
    degraded security check is exactly what an attacker would aim for."""
    try:
        found = _hazards(Path(ctx.root), tuple(names))
    except OSError:
        # Unreadable root: report nothing rather than crash the gate. A
        # CRASHED state here would degrade the whole pre-push run.
        return RunnerResult(tool=NAME, state=ToolState.OK, raw="[]")
    return RunnerResult(tool=NAME, state=ToolState.OK, raw=json.dumps(found))


def parse(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    return [
        RawFinding(
            tool=NAME,
            rule=RULE,
            severity_raw="critical",
            file=item["path"],
            line=1,
            message=(
                f"{item['path']} shadows the '{item['name']}' package: "
                f"`python -m {item['name']}` from this directory imports THIS "
                f"file instead of the installed tool, so it runs before the "
                f"real package loads. Hooks discard output, so a hijack here "
                f"is silent. Delete it, rename it, or move it out of the root."
            ),
            line_content=_STABLE_CONTENT,
        )
        for item in result_items(result)
    ]


def result_items(result: RunnerResult) -> list[dict]:
    return json.loads(result.raw or "[]")
