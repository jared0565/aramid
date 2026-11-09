"""mutation -- owned stdlib-ast mutator (Phase 2c-1 spec section 2).

Four operator families, applied one site at a time. A mutant is the
original source with only the mutated expression's text replaced by its
ast.unparse rendering, so every other line, comment and quote is as
written and every line keeps its number. Until 2026-11-09 a mutant was
the WHOLE module re-rendered by ast.unparse, with comments dropped and
quotes normalized, on the reasoning that mutants exist only in the
consumer's throwaway worktree. That holds for running the code, not for
the verdict: a test that reads source text failed on every mutant of the
files it reads, a kill whatever the mutation. On aramid itself that was
test_toolpath's bare-launch scan, for every doctor.py mutant. A splice
that does not parse back to the mutated tree is never used: that mutant
falls back to the whole-module rendering. Deterministic ordering so
budget truncation is reproducible and fingerprints stable across drains.
The copy-by-walk-index trick relies on ast.walk's traversal order being a
pure function of tree shape, which deepcopy preserves."""
import ast
import copy
import re
from dataclasses import dataclass

from aramid import diagnostics

_CMP_FLIP = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.LtE,
             ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt}
_CMP_SYM = {ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<", ast.LtE: "<=",
            ast.Gt: ">", ast.GtE: ">="}


@dataclass
class Mutant:
    file: str          # "" from generate_mutants; the consumer stamps it
    line: int
    op: str
    description: str
    source: str
    func: str = ""     # enclosing eligible function name (enc[2])


def _eligible_spans(tree: ast.Module, target_lines: set[int]) -> list[tuple[int, int, str]]:
    spans = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = node.end_lineno or node.lineno
            if set(range(node.lineno, end + 1)) & target_lines:
                spans.append((node.lineno, end, node.name))
    return spans


def _enclosing(spans, lineno):
    """Innermost eligible function span containing lineno (a node inside a
    nested non-eligible function still counts via its eligible outer -- the
    inner function is part of the outer's body, deliberate overreach)."""
    best = None
    for start, end, name in spans:
        if start <= lineno <= end and (best is None or start > best[0]):
            best = (start, end, name)
    return best


# Every op name `_mutations_at` can yield, in one place. A survivor's id is
# hashed with the op NAME, so the name is part of the finding's identity:
# the gate's `line_departed` resolver trusts an id's recorded op against this
# tuple and never treats a survivor of an op the mutator cannot emit as
# "gone" (nobody can regenerate it; clearing it would be a statement about
# the mutator, not the file). `generate_mutants` refuses a name outside it,
# so the tuple cannot lag the code silently -- a renamed op fails every
# mutation test rather than orphaning every recorded survivor of the old
# name. Pinned both ways in tests/unit/test_mutation.py.
OPS = ("cmp-flip", "bool-swap", "int-bound", "not-drop")


def _mutations_at(node, func_name):
    """Yield (op, description, mutate_fn); mutate_fn edits the COPY node."""
    if isinstance(node, ast.Compare) and len(node.ops) == 1 \
            and type(node.ops[0]) in _CMP_FLIP:
        old = type(node.ops[0])
        yield ("cmp-flip",
               f"{_CMP_SYM[old]} -> {_CMP_SYM[_CMP_FLIP[old]]} in {func_name}",
               lambda n: n.ops.__setitem__(0, _CMP_FLIP[type(n.ops[0])]()))
    elif isinstance(node, ast.BoolOp):
        old = "and" if isinstance(node.op, ast.And) else "or"
        new = "or" if old == "and" else "and"
        yield ("bool-swap", f"{old} -> {new} in {func_name}",
               lambda n: setattr(n, "op",
                                 ast.Or() if isinstance(n.op, ast.And) else ast.And()))
    elif isinstance(node, ast.Constant) and type(node.value) is int:
        yield ("int-bound", f"{node.value} -> {node.value + 1} in {func_name}",
               lambda n: setattr(n, "value", n.value + 1))
    elif isinstance(node, ast.If) and isinstance(node.test, ast.UnaryOp) \
            and isinstance(node.test.op, ast.Not):
        yield ("not-drop", f"'if not ...' -> 'if ...' in {func_name}",
               lambda n: setattr(n, "test", n.test.operand))


# The parser's line breaks (what ast.get_source_segment splits on).
_LINE_BREAK = re.compile(r"\r\n|\r|\n")


def _line_starts(source: str) -> list[int]:
    """The index in `source` at which each line starts; line N is [N - 1]."""
    return [0] + [m.end() for m in _LINE_BREAK.finditer(source)]


def _char_offset(source: str, starts: list[int], lineno: int, col: int) -> int:
    """The index in `source` of AST position (lineno, col). An AST column
    counts UTF-8 BYTES, so a line with non-ASCII text before the position
    would put a character count in the wrong place."""
    begin = starts[lineno - 1]
    end = starts[lineno] if lineno < len(starts) else len(source)
    return begin + len(source[begin:end].encode("utf-8")[:col].decode("utf-8"))


def _splice(source: str, starts: list[int], old: ast.expr, text: str) -> str:
    """`source` with the text of expression `old` replaced by `text`. Anything
    but a literal is parenthesized, so the new operator cannot bind to its
    neighbours, and a replaced span that ran over several lines is padded
    back to that many inside the parentheses, so every line after it keeps
    its number."""
    start = _char_offset(source, starts, old.lineno, old.col_offset)
    end = _char_offset(source, starts, old.end_lineno, old.end_col_offset)
    if not isinstance(old, ast.Constant):
        text = "(" + text + "\n" * (old.end_lineno - old.lineno) + ")"
    return source[:start] + text + source[end:]


def _same_program(text: str, tree: ast.Module) -> bool:
    try:
        return ast.dump(ast.parse(text)) == ast.dump(tree)
    except SyntaxError:
        return False


def generate_mutants(source: str, target_lines: set[int]) -> list[Mutant]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    spans = _eligible_spans(tree, target_lines)
    if not spans:
        return []
    mutants: list[Mutant] = []
    unparseable = 0
    starts = _line_starts(source)
    nodes = list(ast.walk(tree))
    for idx, node in enumerate(nodes):
        lineno = getattr(node, "lineno", None)
        if lineno is None:
            continue
        enc = _enclosing(spans, lineno)
        if enc is None:
            continue
        for op, desc, mutate in _mutations_at(node, enc[2]):
            if op not in OPS:
                raise ValueError(f"unregistered mutation op {op!r}: add it to mutation.OPS")
            tree_copy = copy.deepcopy(tree)
            twin = list(ast.walk(tree_copy))[idx]
            mutate(twin)
            # not-drop rewrites the If's test; every other op, the node itself.
            old, new = (node.test, twin.test) if isinstance(node, ast.If) else (node, twin)
            try:
                text = ast.unparse(new)
            except Exception:
                unparseable += 1
                continue
            try:
                mutated = _splice(source, starts, old, text)
            except (IndexError, UnicodeDecodeError):
                mutated = None
            if mutated is None or not _same_program(mutated, tree_copy):
                # The safety net: a splice that is not the mutated program is
                # never used; this mutant is the whole module rendered, as before.
                try:
                    mutated = ast.unparse(ast.fix_missing_locations(tree_copy))
                except Exception:
                    unparseable += 1
                    continue
            mutants.append(Mutant(file="", line=lineno, op=op,
                                  description=desc, source=mutated, func=enc[2]))
    # Unlike the ledger guards, this one is an EXPECTED outcome of mutating an
    # AST -- some mutations simply do not unparse. It is still worth counting:
    # a file where every mutant is unparseable yields a mutation score computed
    # from nothing, which reads exactly like a well-tested file.
    diagnostics.note_skipped("mutation", unparseable, "unparseable mutant")
    mutants.sort(key=lambda m: (m.line, m.op, m.description))
    return mutants
