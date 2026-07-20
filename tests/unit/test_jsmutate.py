from aramid.jsmutate import generate_mutants


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


def test_no_mutation_inside_template_interpolation_object_braces():
    # An interpolation containing object/array braces AND a nested template
    # literal: the nested template's `===` must never be cmp-flipped (the
    # interpolation's own braces must not confuse the closing-backtick scan).
    src = "const msg = `x ${ [ {}, `a===b` ][1] } z`;\n"
    muts = generate_mutants(src, {1})
    assert all("!==" not in m.source for m in muts)
    assert all(m.op != "cmp-flip" for m in muts)


def test_no_mutation_after_string_with_brace_in_interpolation():
    # A string literal containing `}` inside an interpolation must be skipped so
    # the brace count is not thrown off and code after the template stays bounded.
    src = 'const q = `${ "}" } a===b end`;\n'
    muts = generate_mutants(src, {1})
    assert all("!==" not in m.source for m in muts)


def test_no_mutation_in_nested_template_static_text_with_brace():
    # A nested template literal whose STATIC TEXT contains `}` must not end the
    # outer template early -> the trailing `a===b` (still template static text)
    # must not be mutated.
    src = "const w = `outer ${ `a}b` } a===b`;\n"
    muts = generate_mutants(src, {1})
    assert all("!==" not in m.source for m in muts)


def test_no_mutation_after_comment_with_brace_in_interpolation():
    # A /* } */ comment inside an interpolation must be skipped so the brace
    # count is not thrown off; a nested template that follows must not be
    # misread as the outer template's close and mutated.
    src = "const x = `${ /* } */ `a===b` } tail`;\n"
    muts = generate_mutants(src, {1})
    assert all("!==" not in m.source for m in muts)
    assert all(m.op != "cmp-flip" for m in muts)


def test_no_mutation_after_regex_with_brace_in_interpolation():
    # A regex literal containing `}` inside an interpolation must be skipped
    # (regex-vs-division via prev tracking); a nested template that follows must
    # not be misread and mutated.
    src = "const x = `${ a.match(/}/) ; `c===d` } tail`;\n"
    muts = generate_mutants(src, {1})
    assert all("!==" not in m.source for m in muts)
    assert all(m.op != "cmp-flip" for m in muts)


def test_logical_swap():
    src = "function f(a, b) {\n  return a && b;\n}\n"
    muts = generate_mutants(src, {2})
    assert any("a || b" in m.source for m in muts)
    assert any(m.op == "logical-swap" for m in muts)


def test_int_bound_increments_integer_literal():
    src = "function f(a) {\n  return a + 3;\n}\n"
    muts = generate_mutants(src, {2})
    assert any("a + 4" in m.source for m in muts)
    assert any(m.op == "int-bound" and m.description == "3 -> 4" for m in muts)


def test_int_bound_skips_float_hex_and_bigint():
    for lit in ("1.5", "0xff", "10n", "1e3"):
        src = f"function f() {{\n  return {lit};\n}}\n"
        muts = generate_mutants(src, {2})
        assert all(m.op != "int-bound" for m in muts), f"{lit} must not int-bound"


def test_not_drop_in_prefix_position():
    src = "function f(a) {\n  if (!a) return 1;\n}\n"
    muts = generate_mutants(src, {2})
    assert any("if (a)" in m.source for m in muts)
    assert any(m.op == "not-drop" for m in muts)


def test_not_drop_leaves_inequality_and_ts_nonnull_alone():
    # `!=` is cmp-flip's job, not not-drop; TS `x!` (non-null assertion, `!`
    # after a value) must NOT be dropped.
    src = "function f(a, b) {\n  const c = a! + b;\n  return a != b;\n}\n"
    muts = generate_mutants(src, {2, 3})
    assert all(m.op != "not-drop" for m in muts)
    assert any(m.op == "cmp-flip" and "a == b" in m.source for m in muts)
