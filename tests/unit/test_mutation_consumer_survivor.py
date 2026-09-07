"""Unit-scope pins for regenerating a recorded survivor from its fingerprint
(`consumers.mutation._survivor_mutants`). Pure: no repo, no subprocess."""
from aramid import mutation
from aramid.consumers import mutation as mut_consumer

ADULT = ("def is_adult(age):\n"
         "    if age >= 18:\n"
         "        return True\n"
         "    return False\n")


def _recorded():
    lines = ADULT.splitlines()
    m = mutation.generate_mutants(ADULT, {2})[0]
    return m, mut_consumer._mutant_fp("calc.py", m.op, m.line, lines)


def _at(found):
    return [(m.op, m.line) for m in found]


def test_a_survivor_still_inside_its_function_regenerates_where_it_was():
    m, fid = _recorded()
    assert _at(mut_consumer._survivor_mutants("calc.py", fid, ADULT)) == [(m.op, m.line)]


def test_a_survivor_that_moved_out_of_its_function_still_regenerates():
    """Measured on this repo's ledger 2026-09-07: 17 recorded survivors, 15
    regenerate at their recorded line (generation is per FUNCTION, so a
    shift inside the function is tolerated, and the ledger re-anchors a
    re-detected line). Two had moved out of their function -- code inserted
    above them -- and both still existed further down the file, yet the
    re-test regenerated nothing and could neither kill nor re-report them.
    The fingerprint is keyed on content, not on a number: the whole file
    is asked, and the recorded line is not consulted at all."""
    m, fid = _recorded()
    moved = "def other(x):\n    return x\n\n\n" + ADULT     # the recorded line now sits in other()
    assert _at(mut_consumer._survivor_mutants("calc.py", fid, moved)) == [(m.op, m.line + 4)]


def test_a_survivor_whose_line_was_rewritten_regenerates_nowhere():
    """Content that no longer exists anywhere fingerprints to nothing, so a
    rewritten line is not matched to a lookalike elsewhere. That case
    belongs to the gate's resolvers."""
    m, fid = _recorded()
    rewritten = ADULT.replace("age >= 18", "age >= 21")
    assert mut_consumer._survivor_mutants("calc.py", fid, rewritten) == []


def test_every_occurrence_of_the_content_is_returned_across_functions():
    """The id is (tool, op, path, LINE CONTENT) with the occurrence pinned to
    0, so identical mutable lines in different functions ARE one finding.
    Returning the first positional match let a confirmed kill of one
    occurrence be claimed for the id while another survived (llm-review
    77f29313, 2026-09-07 14:02Z). Every occurrence is returned; the caller
    tests them all and claims only when all die."""
    m, fid = _recorded()
    twin = ("def pad():\n    return 0\n\n\n"
            "def other(age):\n    if age >= 18:\n        return 1\n    return 0\n\n\n") + ADULT
    assert _at(mut_consumer._survivor_mutants("calc.py", fid, twin)) == [(m.op, 6), (m.op, 12)]


def test_every_occurrence_inside_one_function_is_returned_too():
    """Same rule inside one function (llm-review a9d2fc25, 18:03Z): the
    per-function path that used to run first also took the first positional
    match, which is why the recorded line is no longer consulted."""
    m, fid = _recorded()
    dup = ("def is_adult(age):\n"
           "    if age >= 18:\n"
           "        return True\n"
           "    if age >= 18:\n"
           "        return True\n"
           "    return False\n")
    assert _at(mut_consumer._survivor_mutants("calc.py", fid, dup)) == [(m.op, 2), (m.op, 4)]


def test_a_survivor_on_the_first_line_of_the_file_is_still_found():
    """A one-line function on line 1 is legal Python and holds a mutant; the
    rescan must start at line 1, not 2 (drain survivor 4031dcd0, 14:27Z)."""
    one_liner = "def is_adult(age): return age >= 18\n"
    lines = one_liner.splitlines()
    m = mutation.generate_mutants(one_liner, {1})[0]
    fid = mut_consumer._mutant_fp("calc.py", m.op, m.line, lines)
    # the scan must include line 1, not start at 2
    assert _at(mut_consumer._survivor_mutants("calc.py", fid, one_liner)) == [(m.op, 1)]


def _spy_generation(monkeypatch):
    """Record the line sets `generate_mutants` is asked for; keep its answer."""
    calls = []
    real = mutation.generate_mutants

    def spy(source, target_lines):
        calls.append(set(target_lines))
        return real(source, target_lines)
    monkeypatch.setattr(mut_consumer.mutation, "generate_mutants", spy)
    return calls


def test_a_departed_line_costs_no_generation(monkeypatch):
    """Generation deep-copies and unparses the whole module PER MUTANT --
    measured 37 ms each, 169 mutants / 6.3 s for consumers/mutation.py
    (2026-09-07). The id is a hash of (op, path, line content), and the
    record carries the op, so which lines could match is known from the
    hashes alone: a line that hashes nowhere is answered without generating
    anything. That is the common answer at the gate (every open survivor,
    every push) and the whole answer for a line that was rewritten."""
    m, fid = _recorded()
    calls = _spy_generation(monkeypatch)
    rewritten = ADULT.replace("age >= 18", "age >= 21")
    assert mut_consumer._survivor_mutants("calc.py", fid, rewritten, op=m.op) == []
    assert calls == []


def test_only_the_lines_that_hash_to_the_id_are_generated(monkeypatch):
    """The prefilter narrows generation to the candidate lines; the result
    is the same every-occurrence answer the whole-file scan gave."""
    m, fid = _recorded()
    calls = _spy_generation(monkeypatch)
    twin = ("def pad():\n    return 0\n\n\n"
            "def other(age):\n    if age >= 18:\n        return 1\n    return 0\n\n\n") + ADULT
    assert _at(mut_consumer._survivor_mutants("calc.py", fid, twin, op=m.op)) == [(m.op, 6), (m.op, 12)]
    assert calls == [{6, 12}]


def test_without_a_recorded_op_the_whole_file_is_generated(monkeypatch):
    """No op to hash with -> nothing to narrow by; the slow answer is still
    the right one, never a miss."""
    m, fid = _recorded()
    calls = _spy_generation(monkeypatch)
    assert _at(mut_consumer._survivor_mutants("calc.py", fid, ADULT)) == [(m.op, m.line)]
    assert calls == [set(range(1, len(ADULT.splitlines()) + 1))]
