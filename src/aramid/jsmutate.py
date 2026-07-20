"""jsmutate -- owned token-level JS/TS mutator (2c-1b spec section 4).

No AST: Python has no stdlib JS parser, so a single forward-pass region-aware
scanner classifies each character as code / string / template / comment / regex
and applies the operator families ONLY in code regions on the target lines.
Operator swaps are like-for-like (syntactically valid); a `/` in a
regex-possible position opens a regex literal whose interior is never mutated
(the failure mode is a missed mutation, never a mis-mutation). Deterministic
ordering so budget truncation is reproducible and fingerprints stable across
drains. Mirrors mutation.Mutant / mutation.generate_mutants."""
from dataclasses import dataclass

_ID_START = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_$")
_ID_CONT = _ID_START | set("0123456789")
_DIGITS = set("0123456789")

# cmp-flip: like-for-like relational/equality swaps.
_CMP_FLIP = {"===": "!==", "!==": "===", "==": "!=", "!=": "==",
             "<": "<=", "<=": "<", ">": ">=", ">=": ">"}

# Multi-char operator tokens recognized for MAXIMAL MUNCH so a longer operator
# is never mis-split into a shorter mutable one (e.g. `=>`/`<<`/`>>`/`===` must
# not be read as `=`/`<`/`>`/`==`). Longest first. Includes non-mutated ops.
_OPERATORS = (">>>=", "===", "!==", ">>>", "<<=", ">>=", "**=", "&&=", "||=",
              "??=", "==", "!=", "<=", ">=", "=>", "<<", ">>", "&&", "||",
              "??", "**", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=",
              "|=", "^=")

# Regex-vs-division: a `/` opens a REGEX literal UNLESS the previous significant
# token is a VALUE (something a `/` could divide) -- see _prev_is_value. These
# keywords are NOT values, so a `/` after them opens a regex (e.g. `return /re/`,
# `typeof /re/`). Enumerating the operators a regex CAN follow is fragile (note
# `++`/`--` ARE values: `x++ / y` divides), so we invert and test for a value.
_REGEX_PREV_KW = {"return", "typeof", "instanceof", "in", "of", "case",
                  "delete", "void", "do", "else", "yield", "await", "new",
                  "throw"}


@dataclass
class Mutant:
    file: str          # "" from generate_mutants; the consumer stamps it
    line: int
    op: str
    description: str
    source: str


def _match_multichar_op(source: str, i: int) -> str | None:
    for op in _OPERATORS:
        if source.startswith(op, i):
            return op
    return None


def _prev_is_value(prev: str) -> bool:
    """True when `prev` is a token a `/` could DIVIDE, so the `/` is division
    (not a regex): a value identifier (variable name, `this`, `true`, ...),
    number, string, template, regex, `)`, `]`, `++`, `--`. False for operators,
    punctuation, a regex-preceding keyword (return/typeof/...), and start-of-
    input -- there a `/` opens a regex."""
    if prev == "":
        return False
    if prev in (")", "]", "'str'", "`t`", "/re/", "++", "--"):
        return True
    first = prev[:1]
    if first in _DIGITS:
        return True
    if first in _ID_START:
        return prev not in _REGEX_PREV_KW   # a keyword like `return` is not a value
    return False   # any operator / punctuation -> not a value -> regex follows


def _consume_string(source: str, i: int) -> int:
    """i at an opening ' or ". Return index just past the closing quote (or at
    the newline / EOF for an unterminated string)."""
    q = source[i]
    i += 1
    n = len(source)
    while i < n:
        c = source[i]
        if c == "\\":
            i += 2
            continue
        if c == q:
            return i + 1
        if c == "\n":
            return i
        i += 1
    return i


def _consume_template(source: str, i: int) -> int:
    """i at a backtick. Return index just past the matching closing backtick.
    `${...}` interpolations are treated conservatively as string (MVP): brace
    depth is counted so the real closing backtick is found; expression contents
    are NOT mutated."""
    i += 1
    n = len(source)
    depth = 0
    while i < n:
        c = source[i]
        if c == "\\":
            i += 2
            continue
        if c == "`" and depth == 0:
            return i + 1
        if c == "$" and i + 1 < n and source[i + 1] == "{":
            depth += 1
            i += 2
            continue
        if c == "}" and depth > 0:
            depth -= 1
        i += 1
    return i


def _consume_regex(source: str, i: int) -> int:
    """i at a `/` known to open a regex. Return index just past the closing
    `/` and any flags. Handles [char classes] (where `/` is literal) and
    backslash escapes."""
    i += 1
    n = len(source)
    in_class = False
    while i < n:
        c = source[i]
        if c == "\\":
            i += 2
            continue
        if c == "\n":
            return i
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            i += 1
            while i < n and source[i] in _ID_CONT:
                i += 1
            return i
        i += 1
    return i


def _candidates(source: str, target_lines: set[int]):
    """Yield (offset, length, op, new_text, description, line) for each mutation
    site in a CODE region on a target line. Single forward pass."""
    out = []
    n = len(source)
    i = 0
    line = 1
    prev = ""   # last significant token seen in code (str); "" at start
    while i < n:
        c = source[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c in " \t\r":
            i += 1
            continue
        # comments
        if c == "/" and source.startswith("//", i):
            i += 2
            while i < n and source[i] != "\n":
                i += 1
            continue
        if c == "/" and source.startswith("/*", i):
            j = i + 2
            while j < n and not source.startswith("*/", j):
                j += 1
            j = min(j + 2, n)
            line += source.count("\n", i, j)
            i = j
            continue
        # regex literal: a `/` that is not dividing a value opens a regex whose
        # interior is never mutated (invariant #3). This catches a `/` after a
        # multi-char operator (`&&`/`=>`/`==`/...), which a punct allow-set misses.
        if c == "/" and not _prev_is_value(prev):
            j = _consume_regex(source, i)
            line += source.count("\n", i, j)
            i = j
            prev = "/re/"
            continue
        # strings + template
        if c in "'\"":
            j = _consume_string(source, i)
            line += source.count("\n", i, j)
            i = j
            prev = "'str'"
            continue
        if c == "`":
            j = _consume_template(source, i)
            line += source.count("\n", i, j)
            i = j
            prev = "`t`"
            continue
        # identifier / keyword
        if c in _ID_START:
            j = i + 1
            while j < n and source[j] in _ID_CONT:
                j += 1
            prev = source[i:j]
            i = j
            continue
        # number (int-bound handled in Task 2; consume whole so it is not
        # mis-split and `prev` tracking stays correct)
        if c in _DIGITS or (c == "." and i + 1 < n and source[i + 1] in _DIGITS):
            j = i + 1
            while j < n and (source[j] in _ID_CONT or source[j] == "."):
                j += 1
            prev = source[i:j]
            i = j
            continue
        # multi-char operator (maximal munch)
        op = _match_multichar_op(source, i)
        if op:
            if line in target_lines and op in _CMP_FLIP:
                out.append((i, len(op), "cmp-flip", _CMP_FLIP[op],
                            f"{op} -> {_CMP_FLIP[op]}", line))
            prev = op
            i += len(op)
            continue
        # single-char relational `<` / `>` (bare; multi-char forms handled above)
        if c in "<>":
            if line in target_lines:
                out.append((i, 1, "cmp-flip", _CMP_FLIP[c],
                            f"{c} -> {_CMP_FLIP[c]}", line))
            prev = c
            i += 1
            continue
        # any other single char
        prev = c
        i += 1
    return out


def generate_mutants(source: str, target_lines: set[int]) -> list[Mutant]:
    if not target_lines:
        return []
    mutants: list[Mutant] = []
    for off, length, op, new_text, desc, line in _candidates(source, target_lines):
        mutated = source[:off] + new_text + source[off + length:]
        mutants.append(Mutant(file="", line=line, op=op, description=desc,
                              source=mutated))
    mutants.sort(key=lambda m: (m.line, m.op, m.description))
    return mutants
