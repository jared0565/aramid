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

# logical-swap: like-for-like short-circuit operator swap.
_LOGIC_FLIP = {"&&": "||", "||": "&&"}

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

    `${...}` interpolations hold arbitrary code -- object/array/block braces,
    nested strings/templates, comments, and regex literals -- so a naive
    brace-count is fooled by a literal `}` or backtick inside any of those. In
    the template's static text (brace depth 0) only a backtick closes it and
    `${` opens an interpolation; inside an interpolation (depth > 0) we route
    every non-code region through the shared _skip_region classifier (identical
    to the top-level scanner) so no comment/regex/string/template content can
    end the template early, and count `{`/`}` for objects and blocks. Minimal
    `prev` tracking feeds _skip_region's regex-vs-division decision.
    Interpolation expression contents are never mutated (MVP). Any residual
    reduces to the top-level scanner's own regex-vs-division ambiguity -- plus,
    under deeply artificial nested-template code, a rare leak-forward where a
    mis-parsed `/` inside an interpolation swallows a `}` and mis-affects code
    after the template close (worst case: one spurious advisory survivor in a
    throwaway worktree)."""
    i += 1
    n = len(source)
    depth = 0
    prev = ""   # last significant token in the current interpolation
    while i < n:
        c = source[i]
        if depth == 0:
            # template static text: `\` escapes (e.g. \` or \${), a backtick
            # closes, `${` opens an interpolation
            if c == "\\":
                i += 2
                continue
            if c == "`":
                return i + 1
            if c == "$" and i + 1 < n and source[i + 1] == "{":
                depth += 1
                prev = ""
                i += 2
                continue
            i += 1
            continue
        # inside an interpolation (depth > 0): classify like real code
        if c in " \t\r\n":
            i += 1
            continue
        region = _skip_region(source, i, prev)
        if region is not None:
            i, prev = region
            continue
        if c == "{":
            depth += 1
            prev = "{"
            i += 1
            continue
        if c == "}":
            depth -= 1
            prev = "}"
            i += 1
            continue
        if c in _ID_START:
            j = i + 1
            while j < n and source[j] in _ID_CONT:
                j += 1
            prev = source[i:j]
            i = j
            continue
        if c in _DIGITS or (c == "." and i + 1 < n and source[i + 1] in _DIGITS):
            j = i + 1
            while j < n and (source[j] in _ID_CONT or source[j] == "."):
                j += 1
            prev = source[i:j]
            i = j
            continue
        op = _match_multichar_op(source, i)
        if op:
            prev = op
            i += len(op)
            continue
        prev = c
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


def _skip_region(source: str, i: int, prev: str):
    """If source[i] opens a non-code region -- a line/block comment, a regex
    literal, a string, or a template literal -- consume it and return
    (end_index, new_prev). Otherwise return None so the caller handles code.

    This is the SINGLE region classifier shared by the top-level scanner and
    the template-interpolation scanner, so both skip the same regions by the
    same rules (no divergent second classifier -- the root cause of earlier
    region-safety bugs). Comments are tested before regex (`//`/`/*` is never a
    regex); the regex-vs-division call uses _prev_is_value, so a `/` after a
    value is left to the caller as division."""
    c = source[i]
    n = len(source)
    if c == "/" and source.startswith("//", i):
        j = i + 2
        while j < n and source[j] != "\n":
            j += 1
        return j, prev
    if c == "/" and source.startswith("/*", i):
        j = i + 2
        while j < n and not source.startswith("*/", j):
            j += 1
        return min(j + 2, n), prev
    if c == "/" and not _prev_is_value(prev):
        return _consume_regex(source, i), "/re/"
    if c in "'\"":
        return _consume_string(source, i), "'str'"
    if c == "`":
        return _consume_template(source, i), "`t`"
    return None


def _consume_number(source: str, i: int) -> tuple[int, bool, int]:
    """Return (end_index, is_plain_int, value). Non-decimal-integer forms
    (hex/bin/oct/float/exponent/bigint) return is_plain_int=False."""
    n = len(source)
    if source[i] == "0" and i + 1 < n and source[i + 1] in "xXbBoO":
        j = i + 2
        while j < n and source[j] in _ID_CONT:
            j += 1
        return j, False, 0
    j = i
    is_float = False
    while j < n and source[j] in _DIGITS:
        j += 1
    if j < n and source[j] == ".":
        is_float = True
        j += 1
        while j < n and source[j] in _DIGITS:
            j += 1
    if j < n and source[j] in "eE":
        is_float = True
        j += 1
        if j < n and source[j] in "+-":
            j += 1
        while j < n and source[j] in _DIGITS:
            j += 1
    if j < n and source[j] in "nN":   # bigint suffix
        return j + 1, False, 0
    if is_float:
        return j, False, 0
    try:
        return j, True, int(source[i:j])
    except ValueError:
        return j, False, 0


def _is_prefix(prev: str) -> bool:
    """True when a `!` at the current position is a UNARY prefix `not` (operand
    start), so dropping it is meaningful. False after a value (identifier /
    number / ) / ] / } / string / template / regex) -- there `!` would be a TS
    non-null assertion. Keywords (prev is identifier-like) are treated as
    non-prefix: we MISS `return !x` (safe) rather than risk mutating `x!`."""
    if prev == "":
        return True
    if prev in (")", "]", "}", "'str'", "`t`", "/re/"):
        return False
    first = prev[:1]
    if first in _ID_START or first in _DIGITS:
        return False
    return True


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
        # non-code regions (comment / regex / string / template) via the shared
        # single classifier -- same rules the interpolation scanner uses.
        region = _skip_region(source, i, prev)
        if region is not None:
            j, prev = region
            line += source.count("\n", i, j)
            i = j
            continue
        # identifier / keyword
        if c in _ID_START:
            j = i + 1
            while j < n and source[j] in _ID_CONT:
                j += 1
            prev = source[i:j]
            i = j
            continue
        # number
        if c in _DIGITS or (c == "." and i + 1 < n and source[i + 1] in _DIGITS):
            j, is_int, value = _consume_number(source, i)
            if line in target_lines and is_int:
                out.append((i, j - i, "int-bound", str(value + 1),
                            f"{value} -> {value + 1}", line))
            prev = source[i:j]
            i = j
            continue
        # multi-char operator (maximal munch)
        op = _match_multichar_op(source, i)
        if op:
            if line in target_lines and op in _CMP_FLIP:
                out.append((i, len(op), "cmp-flip", _CMP_FLIP[op],
                            f"{op} -> {_CMP_FLIP[op]}", line))
            elif line in target_lines and op in _LOGIC_FLIP:
                out.append((i, len(op), "logical-swap", _LOGIC_FLIP[op],
                            f"{op} -> {_LOGIC_FLIP[op]}", line))
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
        # unary `!` in prefix position -> drop it (not-drop). `!=`/`!==` are
        # multi-char ops handled above, so a `!` here is a standalone `!`.
        if c == "!":
            if line in target_lines and _is_prefix(prev):
                out.append((i, 1, "not-drop", "", "drop unary !", line))
            prev = "!"
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
