"""Unit-scope pins for regenerating a recorded survivor from its fingerprint
(`consumers.mutation._survivor_mutant`). Pure: no repo, no subprocess."""
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


def test_a_survivor_still_inside_its_function_regenerates_at_the_recorded_line():
    m, fid = _recorded()
    found = mut_consumer._survivor_mutant("calc.py", m.line, fid, ADULT)
    assert found is not None and (found.op, found.line) == (m.op, m.line)


def test_a_survivor_that_moved_out_of_its_function_still_regenerates():
    """Measured on this repo's ledger 2026-09-07: 17 recorded survivors, 15
    regenerate at their recorded line (generation is per FUNCTION, so a
    shift inside the function is tolerated, and the ledger re-anchors a
    re-detected line). Two had moved out of their function -- code inserted
    above them -- and both still existed further down the file, yet the
    re-test regenerated nothing and could neither kill nor re-report them.
    The fingerprint is keyed on content, not on a number: when the recorded
    line misses, the whole file is asked."""
    m, fid = _recorded()
    moved = "def other(x):\n    return x\n\n\n" + ADULT     # recorded line now sits in other()
    found = mut_consumer._survivor_mutant("calc.py", m.line, fid, moved)
    assert found is not None, "the survivor still exists four lines down"
    assert (found.op, found.line) == (m.op, m.line + 4)


def test_a_survivor_whose_line_was_rewritten_regenerates_nowhere():
    """The other direction must hold: content that no longer exists anywhere
    fingerprints to nothing, so a rewritten line is not matched to a
    lookalike elsewhere. That case belongs to the gate's resolvers."""
    m, fid = _recorded()
    rewritten = ADULT.replace("age >= 18", "age >= 21")
    assert mut_consumer._survivor_mutant("calc.py", m.line, fid, rewritten) is None
