"""Latent mutants: the generator's mutants that sit on lines the unit suite
never executes.

The mutation drain confirms a surviving mutant against tests/unit alone
(stage 1: the module's own test_<stem>*.py files; stage 2: the whole unit
directory). A mutant on a line only tests/integration reaches can never be
killed there: it is LATENT, and it surfaces as a survivor the first time the
drain draws it -- which is how the 2026-09 burn-down found 300 of them. This
script counts those mutants per file from a coverage JSON of the unit suite,
so the count can only go down:

    python -m pytest -q tests/unit --cov=aramid --cov-report=json:cov-unit.json
    python -P scripts/latent_mutants.py measure cov-unit.json [--verbose]
    python -P scripts/latent_mutants.py check cov-unit.json --baseline tests/latent_mutants_baseline.json
    python -P scripts/latent_mutants.py write-baseline cov-unit.json --baseline tests/latent_mutants_baseline.json

`check` exits 1 naming every file whose count is above its baseline (a file
absent from the baseline is at 0). A count below the baseline is reported
too -- lower the baseline with `write-baseline` so the ratchet keeps its
teeth; never raise it by hand. The generator is the TREE's, imported from
src/ ahead of any installed aramid, because the drain that will draw these
mutants runs whatever ships next.

A mutant is attributed to the innermost STATEMENT containing its line: the
coverage JSON lists statement lines only, so a mutant on the continuation
line of a multi-line call or condition is counted against the line
coverage actually recorded.
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from aramid import mutation  # noqa: E402

PREFIX = "src/aramid/"


def statement_lines(tree: ast.AST) -> dict[int, int]:
    """Every line inside a statement -> the first line of the innermost
    statement containing it (ast.walk visits outer statements first, so
    inner ones overwrite)."""
    out: dict[int, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.stmt) and node.end_lineno is not None:
            for line in range(node.lineno, node.end_lineno + 1):
                out[line] = node.lineno
    return out


def latent_mutants(source: str, missing_lines: set[int]) -> list[mutation.Mutant]:
    """The generator's mutants for `source` whose statement the unit suite
    never executed. Unparseable source has no mutants at all."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    stmt = statement_lines(tree)
    every_line = set(range(1, source.count("\n") + 2))
    return [m for m in mutation.generate_mutants(source, every_line)
            if stmt.get(m.line, m.line) in missing_lines]


def measure(cov: dict, root: Path, *, verbose: bool = False, out=None) -> dict[str, int]:
    """Per-file latent counts (files with none are omitted), from a coverage.py
    JSON report; only files under src/aramid/ are measured."""
    out = out or sys.stdout
    counts: dict[str, int] = {}
    for key, data in sorted(cov["files"].items()):
        path = key.replace("\\", "/")
        at = path.find(PREFIX)
        if at == -1:
            continue
        rel = path[at:]
        source = (root / rel).read_text(encoding="utf-8")
        latent = latent_mutants(source, set(data["missing_lines"]))
        if not latent:
            continue
        counts[rel] = len(latent)
        if verbose:
            for m in latent:
                print(f"{rel}:{m.line} {m.op} {m.description}", file=out)
    return counts


def with_total(counts: dict[str, int]) -> dict[str, int]:
    return {"_total": sum(counts.values()), **dict(sorted(counts.items()))}


def check(measured: dict[str, int], baseline: dict[str, int], out=None) -> int:
    out = out or sys.stdout
    over = {f: n for f, n in measured.items() if n > baseline.get(f, 0)}
    below = {f: b for f, b in baseline.items()
             if f != "_total" and measured.get(f, 0) < b}
    for f, n in sorted(over.items()):
        print(f"latent mutants: {f} has {n}, baseline {baseline.get(f, 0)} -- "
              f"a mutant the unit suite never executes was added; pin it "
              f"(tests/unit/test_{Path(f).stem}*.py) or the drain will report it", file=out)
    for f, b in sorted(below.items()):
        print(f"latent mutants: {f} has {measured.get(f, 0)}, baseline {b} -- "
              f"lower the baseline (write-baseline)", file=out)
    total = sum(measured.values())
    print(f"latent mutants: {total} total, baseline {baseline.get('_total', 0)}; "
          f"{len(over)} file(s) over, {len(below)} below", file=out)
    return 1 if over else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="latent_mutants.py",
                                 description="count the generator's mutants on lines "
                                             "the unit suite never executes")
    ap.add_argument("command", choices=["measure", "check", "write-baseline"])
    ap.add_argument("coverage_json", type=Path)
    ap.add_argument("--baseline", type=Path)
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--verbose", action="store_true", help="measure: list every latent mutant")
    args = ap.parse_args(argv)
    if args.command != "measure" and args.baseline is None:
        ap.error(f"{args.command} needs --baseline")
    cov = json.loads(args.coverage_json.read_text(encoding="utf-8"))
    measured = measure(cov, args.root, verbose=args.verbose)
    if args.command == "measure":
        print(json.dumps(with_total(measured), indent=2))
        return 0
    if args.command == "write-baseline":
        args.baseline.write_text(json.dumps(with_total(measured), indent=2) + "\n",
                                 encoding="utf-8")
        print(f"wrote {args.baseline}: {sum(measured.values())} latent in "
              f"{len(measured)} file(s)")
        return 0
    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    return check(measured, baseline)


if __name__ == "__main__":
    sys.exit(main())
