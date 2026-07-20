from aramid.jsmutate import Mutant, generate_mutants  # noqa: F401 -- import asserts Mutant is part of the public API


def _sources(muts):
    return sorted(m.source for m in muts)


def test_cmp_flip_strict_equality():
    src = "function f(a, b) {\n  return a === b;\n}\n"
    muts = generate_mutants(src, {2})
    assert any("a !== b" in m.source for m in muts)
    assert any(m.op == "cmp-flip" and m.line == 2 for m in muts)


def test_cmp_flip_relational_single_char():
    src = "const g = (a) => {\n  if (a < 3) return a;\n};\n"
    muts = generate_mutants(src, {2})
    # `<` becomes `<=` (single-char relational), `3` is int-bound (later task)
    assert any("a <= 3" in m.source for m in muts)


def test_no_mutation_inside_string_literals():
    src = "function f() {\n  return 'a === b && c';\n}\n"
    muts = generate_mutants(src, {2})
    assert muts == [], "operators inside a string must never be mutated"


def test_no_mutation_inside_line_comment():
    src = "function f(a, b) {\n  return a; // a === b\n}\n"
    muts = generate_mutants(src, {2})
    assert all("!==" not in m.source for m in muts)


def test_no_mutation_inside_block_comment():
    src = "function f(a, b) {\n  /* a === b */\n  return a;\n}\n"
    muts = generate_mutants(src, {2, 3})
    assert all("!==" not in m.source for m in muts)


def test_no_mutation_inside_regex_literal():
    src = "function f(s) {\n  return /a===b/.test(s);\n}\n"
    muts = generate_mutants(src, {2})
    assert muts == [], "a === inside a regex literal must not be mutated"


def test_no_mutation_inside_regex_after_binary_operator():
    # A `/` after a binary operator (&&, =>, =, ...) opens a regex, NOT division,
    # so operators inside it must never be mutated. A punct-only allow-set for
    # the regex-prev check misses this (prev is the whole op token "&&").
    src = "function f(a, s) {\n  const ok = a && /x===y/.test(s);\n  return ok;\n}\n"
    muts = generate_mutants(src, {2})
    assert all("!==" not in m.source for m in muts), \
        "=== inside a regex after && must not be cmp-flipped"
    assert all(m.op != "cmp-flip" for m in muts)


def test_no_mutation_inside_template_literal():
    src = "function f(a) {\n  return `x === ${a}`;\n}\n"
    muts = generate_mutants(src, {2})
    assert all("!==" not in m.source for m in muts)


def test_division_is_not_a_regex_and_not_mutated():
    src = "function f(a, b) {\n  return a / b === 2;\n}\n"
    muts = generate_mutants(src, {2})
    # the `/` is division (prev token is an identifier), so `=== 2` still parses
    # as code and cmp-flip fires on it
    assert any("a / b !== 2" in m.source for m in muts)
