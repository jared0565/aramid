"""mutation -- owned stdlib-ast mutator (Phase 2c-1 spec section 2).

Four operator families, applied one site at a time; mutants are rendered
with ast.unparse (comments/formatting lost -- acceptable: mutants exist
only inside the consumer's throwaway worktree). Deterministic ordering so
budget truncation is reproducible and fingerprints stable across drains.
The copy-by-walk-index trick relies on ast.walk's traversal order being a
pure function of tree shape, which deepcopy preserves."""
import ast
import copy
from dataclasses import dataclass

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


def generate_mutants(source: str, target_lines: set[int]) -> list[Mutant]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    spans = _eligible_spans(tree, target_lines)
    if not spans:
        return []
    mutants: list[Mutant] = []
    nodes = list(ast.walk(tree))
    for idx, node in enumerate(nodes):
        lineno = getattr(node, "lineno", None)
        if lineno is None:
            continue
        enc = _enclosing(spans, lineno)
        if enc is None:
            continue
        for op, desc, mutate in _mutations_at(node, enc[2]):
            tree_copy = copy.deepcopy(tree)
            mutate(list(ast.walk(tree_copy))[idx])
            try:
                mutated = ast.unparse(ast.fix_missing_locations(tree_copy))
            except Exception:
                continue
            mutants.append(Mutant(file="", line=lineno, op=op,
                                  description=desc, source=mutated))
    mutants.sort(key=lambda m: (m.line, m.op, m.description))
    return mutants
