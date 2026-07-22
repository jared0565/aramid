import ast

from aramid.mutation import generate_mutants

SRC = """\
def clamp(x):
    if x > 10:
        return 10
    return x

def untouched(y):
    return y == 0
"""


def _ops(mutants):
    return sorted(m.op for m in mutants)


def test_cmp_flip_generated_for_targeted_function():
    muts = generate_mutants(SRC, {2})
    assert any(m.op == "cmp-flip" and "clamp" in m.description for m in muts)
    # every mutant parses and differs from the original
    for m in muts:
        assert m.source != SRC
        ast.parse(m.source)
        compile(m.source, "<mutant>", "exec")


def test_function_outside_target_lines_untouched():
    muts = generate_mutants(SRC, {2})
    assert not any("untouched" in m.description for m in muts)


def test_int_bound_skips_bool_constants():
    src = "def f(a):\n    if a is True:\n        return 1\n    return 0\n"
    muts = generate_mutants(src, {1, 2, 3, 4})
    bound = [m for m in muts if m.op == "int-bound"]
    assert bound, "int literals 1 and 0 must be mutated"
    assert all("True" not in m.description for m in bound)


def test_bool_swap_and_not_drop():
    src = ("def g(a, b):\n"
           "    if not a:\n"
           "        return False\n"
           "    return a and b\n")
    muts = generate_mutants(src, {1, 2, 3, 4})
    assert "bool-swap" in _ops(muts)
    assert "not-drop" in _ops(muts)
    nd = next(m for m in muts if m.op == "not-drop")
    assert "if not a" not in nd.source or "if a" in nd.source


def test_deterministic_order():
    a = generate_mutants(SRC, {1, 2, 3, 4})
    b = generate_mutants(SRC, {1, 2, 3, 4})
    assert [(m.line, m.op, m.description) for m in a] == \
           [(m.line, m.op, m.description) for m in b]


def test_syntax_error_source_yields_no_mutants():
    assert generate_mutants("def broken(:\n", {1}) == []


def test_generated_mutants_carry_enclosing_function():
    src = ("def outer(x):\n"
           "    if x == 1:\n"
           "        return True\n"
           "    return False\n")
    muts = generate_mutants(src, {2})
    assert muts
    assert all(m.func == "outer" for m in muts)


def test_mutants_attribute_to_their_own_function():
    src = ("def a(x):\n"
           "    return x == 1\n"
           "def b(y):\n"
           "    return y == 2\n")
    muts = generate_mutants(src, {2, 4})
    assert {m.func for m in muts} == {"a", "b"}
