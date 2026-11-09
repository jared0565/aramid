import ast

from aramid import mutation
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


def test_every_op_the_mutator_emits_is_registered_and_vice_versa():
    """`mutation.OPS` is what the gate's line_departed resolver trusts an
    id's op against (an unregistered op is never a candidate). Both
    directions: an op yielded under a name the tuple lacks is a survivor
    nobody can ever clear, and a name in the tuple nothing yields is a
    retired op still admitting candidates."""
    src = ("def f(x, y):\n"
           "    if not x:\n"
           "        return 1\n"
           "    return x > y and y\n")
    emitted = {m.op for m in mutation.generate_mutants(src, {1, 2, 3, 4})}
    assert emitted == set(mutation.OPS)
    assert len(mutation.OPS) == len(set(mutation.OPS))


def test_a_mutant_the_unparser_rejects_is_counted_and_skipped(monkeypatch, capsys):
    """The drain confirms a mutant against the unit suite alone, and
    `unparseable += 1` was reached only through tests/integration: one
    mutated tree `ast.unparse` cannot render costs one counted skip, and
    the other mutants of the line are still generated."""
    src = "def f(a, b):\n    return a == b and a > 0\n"
    baseline = generate_mutants(src, {2})
    assert len(baseline) >= 2
    real = mutation.ast.unparse
    calls = []

    def unparse(tree):
        calls.append(tree)
        if len(calls) == 1:
            raise ValueError("cannot render")
        return real(tree)
    monkeypatch.setattr(mutation.ast, "unparse", unparse)

    got = generate_mutants(src, {2})
    assert len(got) == len(baseline) - 1
    assert capsys.readouterr().err == "aramid: mutation: skipped 1 unparseable mutant\n"


# --- a mutant changes its expression and nothing else (2026-11-09) ----------
# A mutant used to be the whole module re-rendered by ast.unparse: comments
# gone, quotes normalized, lines renumbered. A test that reads source TEXT then
# failed on every mutant of the files it reads -- a kill whatever the mutation.
# On aramid itself: test_toolpath's bare-launch scan, for every doctor.py
# mutant. The fixture has a comment, both quote styles, an `or` over two lines,
# and an `é` before a mutated comparison on its line (AST columns count UTF-8
# BYTES, so a splice that counts characters lands in the wrong place there).

SPLICE_SRC = '''\
def probe(kinds, name):
    # a comment the whole-module render dropped
    label = "double-quoted"
    if not kinds:
        return [label, 'single']
    if (name == "x"
            or name == "y"):
        return 10
    return "é" != name and len(kinds) > 2
'''


def _rendered_mutants(src):
    """The generator as it was: the same sites, each module re-rendered whole."""
    tree = ast.parse(src)
    spans = mutation._eligible_spans(tree, set(range(1, len(src.splitlines()) + 1)))
    out = []
    for idx, node in enumerate(ast.walk(tree)):
        lineno = getattr(node, "lineno", None)
        enc = lineno and mutation._enclosing(spans, lineno)
        if not enc:
            continue
        for op, desc, mutate in mutation._mutations_at(node, enc[2]):
            twin = ast.parse(src)
            mutate(list(ast.walk(twin))[idx])
            out.append(((lineno, op, desc), ast.unparse(twin)))
    return sorted(out)


def test_a_mutant_keeps_every_line_outside_its_expression():
    muts = generate_mutants(SPLICE_SRC, set(range(1, 10)))
    assert sorted(m.op for m in muts) == [
        "bool-swap", "bool-swap", "cmp-flip", "cmp-flip", "cmp-flip", "cmp-flip",
        "int-bound", "int-bound", "not-drop"]
    original = SPLICE_SRC.split("\n")
    for m in muts:
        lines = m.source.split("\n")
        assert len(lines) == len(original), (m.op, m.line)
        changed = {n for n, (a, b) in enumerate(zip(original, lines), 1) if a != b}
        assert changed and changed <= {m.line, m.line + 1}, (m.op, m.line, changed)
        assert lines[1] == "    # a comment the whole-module render dropped"
        assert lines[2] == '    label = "double-quoted"'


def test_a_spliced_mutant_is_the_same_program_the_whole_render_was():
    muts = generate_mutants(SPLICE_SRC, set(range(1, 10)))
    rendered = _rendered_mutants(SPLICE_SRC)
    assert [(m.line, m.op, m.description) for m in muts] == [key for key, _ in rendered]
    for m, (_, whole) in zip(muts, rendered):
        assert ast.dump(ast.parse(m.source)) == ast.dump(ast.parse(whole))


def test_a_splice_on_a_byte_column_after_non_ascii_text_lands_on_its_expression():
    [m] = [m for m in generate_mutants(SPLICE_SRC, {9})
           if m.op == "int-bound" and m.line == 9]
    assert m.source.split("\n")[8] == '    return "é" != name and len(kinds) > 3'


def test_a_mutant_of_an_expression_over_two_lines_keeps_both_line_numbers():
    [m] = [m for m in generate_mutants(SPLICE_SRC, {6}) if m.op == "bool-swap" and m.line == 6]
    assert m.source.split("\n")[5:8] == [
        "    if ((name == 'x' and name == 'y'",
        ")):",
        "        return 10"]


def test_a_splice_that_does_not_parse_back_falls_back_to_the_whole_render(monkeypatch):
    """The safety net: a splice whose text is not the mutated program is
    never used. The fallback is the whole-module render, as before."""
    monkeypatch.setattr(mutation, "_splice", lambda source, starts, old, text: source)
    muts = generate_mutants(SPLICE_SRC, {4})
    [nd] = [m for m in muts if m.op == "not-drop"]
    assert nd.source == dict(_rendered_mutants(SPLICE_SRC))[(nd.line, nd.op, nd.description)]
    assert "# a comment" not in nd.source


def test_an_expression_on_the_first_line_is_spliced_in_place():
    src = 'def f(x): return x == "a"  # kept\n'
    [m] = generate_mutants(src, {1})
    assert m.source == 'def f(x): return (x != \'a\')  # kept\n'


def test_the_last_line_of_a_source_with_no_final_newline_is_spliced_in_place():
    src = 'def f(x):\n    return x == "a"  # kept'
    [m] = generate_mutants(src, {2})
    assert m.source == 'def f(x):\n    return (x != \'a\')  # kept'


def test_a_mutant_neither_splice_nor_whole_render_can_give_is_one_counted_skip(
        monkeypatch, capsys):
    real = mutation.ast.unparse

    def unparse(node):
        if isinstance(node, ast.Module):
            raise ValueError("cannot render")
        return real(node)
    monkeypatch.setattr(mutation.ast, "unparse", unparse)
    monkeypatch.setattr(mutation, "_splice", lambda source, starts, old, text: source)

    assert generate_mutants("def f(a, b):\n    return a == b\n", {2}) == []
    assert capsys.readouterr().err == "aramid: mutation: skipped 1 unparseable mutant\n"


def test_a_splice_that_cannot_place_its_text_falls_back_to_the_whole_render(monkeypatch):
    def boom(source, starts, lineno, col):
        raise IndexError(lineno)
    monkeypatch.setattr(mutation, "_char_offset", boom)
    [nd] = [m for m in generate_mutants(SPLICE_SRC, {4}) if m.op == "not-drop"]
    assert nd.source == dict(_rendered_mutants(SPLICE_SRC))[(nd.line, nd.op, nd.description)]
