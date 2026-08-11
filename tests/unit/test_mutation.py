import ast

from aramid.consumers import mutation as mut_consumer
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


def test_mutant_fp_is_stable_and_matches_recipe():
    from aramid.fingerprint import compute_fingerprint
    lines = ["def f(x):", "    return x == 1"]
    fp = mut_consumer._mutant_fp("m.py", "cmp-flip", 2, lines)
    assert fp == compute_fingerprint("mutation", "cmp-flip", "m.py", "    return x == 1", 0)


def test_mutant_fp_out_of_range_line_is_safe():
    # never raises; hashes "" for a line past EOF
    assert isinstance(mut_consumer._mutant_fp("m.py", "cmp-flip", 99, ["a"]), str)


def test_finalize_scores_marks_fully_mutated():
    scores = {"m.py::f": mut_consumer._new_target()}
    scores["m.py::f"].update(generated=3, killed_s1=2, survived_s1=1)
    out = mut_consumer._finalize_scores(scores)
    assert out["schema"] == 1
    assert out["targets"]["m.py::f"]["fully_mutated"] is True


def test_finalize_scores_partial_not_fully_mutated():
    scores = {"m.py::f": mut_consumer._new_target()}
    scores["m.py::f"].update(generated=3, killed_s1=1, survived_s1=1, timeouts=1)
    out = mut_consumer._finalize_scores(scores)
    assert out["targets"]["m.py::f"]["fully_mutated"] is False


# --- a survivor is only ever "survived THE SUITE THAT RAN" ------------------

def test_suite_label_renders_the_scope_a_survivor_was_checked_against():
    """The whole message is asserted, not a substring, because the point is
    that it READS correctly to someone triaging a finding -- a substring check
    would confirm only what I already believed about my own format."""
    import sys

    from aramid.consumers.mutation import _suite_label

    argv = [sys.executable, "-m", "pytest", "-q", "tests/unit"]
    msg = f"mutant survived: flip a+b -> a-b (unkilled by: {_suite_label(argv)})"
    assert msg == "mutant survived: flip a+b -> a-b (unkilled by: pytest -q tests/unit)"


def test_suite_label_omits_the_interpreter_path():
    """The interpreter is an absolute path that differs per machine and per
    mutation worktree. Leaving it in would make the same finding read
    differently on two machines, and inside the worktree it is a temp dir."""
    from aramid.consumers.mutation import _suite_label

    label = _suite_label([r"C:\some\tmp\wt\.venv\Scripts\python.exe",
                          "-m", "pytest", "-q", "tests/unit"])
    assert label == "pytest -q tests/unit"
    assert "python" not in label


def test_suite_label_degrades_to_a_phrase_rather_than_an_empty_paren():
    """`(unkilled by: )` is worse than saying nothing useful -- it reads like
    a bug in aramid rather than a suite it could not name."""
    from aramid.consumers.mutation import _suite_label

    assert _suite_label(["python"]) == "the configured suite"
