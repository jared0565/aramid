"""The JS lexer helpers `generate_mutants` skips regions with, called
directly on the escapes and edges the mutant generator's own tests only
reach through tests/integration/test_js_mutation*.py: a backslash escape
advancing exactly two characters in a string, a template's static text and
a regex; a regex's flags read from the character after its closing slash;
a number inside a template interpolation ending at its last digit; an
exponent sign with nothing after it; and the integer fallback on a start
that is not a number at all. Every return is an index, asserted exactly."""
import pytest

from aramid import jsmutate as jm


@pytest.mark.parametrize("source, end", [
    ('"ab"', 4),
    ('"a\\"b"x', 6),                 # the escaped quote does not close
    ('"\\\\"x', 4),                  # the escaped backslash does not escape the quote
    ("'a\nb'", 2),                   # unterminated: stops AT the newline
    ('"abc', 4),                     # unterminated: EOF
])
def test_consume_string(source, end):
    assert jm._consume_string(source, 0) == end


@pytest.mark.parametrize("source, end", [
    ("`ab`x", 4),
    ("`\\``x", 4),                   # an escaped backtick does not close
    ("`\\\\`x", 4),                  # an escaped backslash does not escape the backtick
    ("`${1}`x", 6),                  # a number in the interpolation ends at its digit
    ("`${1.5}`x", 8),
    ("`${a}`x", 6),
    ("`${ab}`x", 7),                 # a two-character identifier ends at its last character
    ("`${ {} }`x", 9),               # braces inside the interpolation are counted
    ("`${ a }`x", 8),                # whitespace inside the interpolation is stepped one at a time
    ("`${'}'}`x", 8),                # a string holding a brace does not close it
    ("`${'`'}`x", 8),                # nor does a string holding a backtick, first in the interpolation
    ("`${a/2}`x", 8),                # a slash after a value is division, not a regex
    ("`${a+b/2}`x", 10),             # ... after a value that follows an operator too
    ("`${a+2/3}`x", 10),             # an operator before a digit is not part of the number
    ("`${1./2}`x", 9),               # a trailing-dot number is a value: division follows
    ("`${a.b5/2}`x", 11),            # a dot before a letter is a member access, not a number
    ("`${x = /}/}`x", 12),           # a slash after an operator is a regex; its brace is literal
    ("`${a.b}`x", 8),                # a dot after an identifier is not a number
    ("`${.5}`x", 7),                 # a dot before a digit is
    ("`${a===b}`x", 10),             # a multi-char operator is one token
    ("`ab$", 4),                     # a dollar at EOF: no interpolation, no read past the end
    ("`${abc", 6),                   # EOF inside an identifier
    ("`${12", 5),                    # EOF inside a number
    ("`${a.", 5),                    # a dot at EOF is an operator, not a read past the end
    ("`ab", 3),                      # unterminated: EOF
])
def test_consume_template(source, end):
    assert jm._consume_template(source, 0) == end


@pytest.mark.parametrize("source, end", [
    ("/a/;", 3),                     # flags start right after the slash: none here
    ("/a/gi;", 5),
    ("/a/g;", 4),                    # one flag
    ("/a/g", 4),                     # flags at EOF: no read past the end
    ("/\\//;", 4),                   # an escaped slash does not close
    ("/\\\\/ ", 4),                  # an escaped backslash does not escape the slash
    ("/[/]/;", 5),                   # a slash inside a class is literal
    ("/a\nb/", 2),                   # unterminated: stops AT the newline
    ("/ab", 3),                      # unterminated: EOF
])
def test_consume_regex(source, end):
    assert jm._consume_regex(source, 0) == end


@pytest.mark.parametrize("source, result", [
    ("42;", (2, True, 42)),
    ("42", (2, True, 42)),           # digits at EOF: no read past the end
    ("0", (1, True, 0)),             # a lone zero is not a prefix
    ("0x1F;", (4, False, 0)),
    ("0x1;", (3, False, 0)),
    ("0x", (2, False, 0)),           # a bare prefix at EOF
    ("1.5;", (3, False, 0)),
    ("1.5", (3, False, 0)),          # a fraction at EOF
    ("1.;", (2, False, 0)),          # a trailing dot is a float
    (".5;", (2, False, 0)),
    ("1e5;", (3, False, 0)),
    ("1e+5;", (4, False, 0)),
    ("1e+", (3, False, 0)),          # a sign with nothing after it: the sign is consumed
    ("1e", (2, False, 0)),
    ("12n;", (3, False, 0)),         # bigint
    ("x", (0, False, 0)),            # not a number at all: the int() fallback
])
def test_consume_number(source, result):
    assert jm._consume_number(source, 0) == result
