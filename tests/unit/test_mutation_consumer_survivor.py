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


def test_a_whole_file_match_is_taken_only_when_it_is_unique():
    """The id is (tool, op, path, LINE CONTENT) with the occurrence pinned to
    0, so two identical mutable lines in different functions fingerprint
    identically. A whole-file rescan that returned the first positional
    match could regenerate an unrelated lookalike, and a confirmed kill of
    the lookalike would be claimed as `mutant_killed` for a test gap that
    was never closed (llm-review 77f29313, 2026-09-07 14:02Z). Ambiguous
    means None: the finding stays with the gate's resolvers, as before."""
    m, fid = _recorded()
    twin = ("def pad():\n    return 0\n\n\n"
            "def other(age):\n    if age >= 18:\n        return 1\n    return 0\n\n\n") + ADULT
    assert mut_consumer._survivor_mutant("calc.py", m.line, fid, twin) is None


def test_a_survivor_on_the_first_line_of_the_file_is_still_found():
    """A one-line function on line 1 is legal Python and holds a mutant; the
    rescan must start at line 1, not 2 (drain survivor 4031dcd0, 14:27Z)."""
    one_liner = "def is_adult(age): return age >= 18\n"
    lines = one_liner.splitlines()
    m = mutation.generate_mutants(one_liner, {1})[0]
    fid = mut_consumer._mutant_fp("calc.py", m.op, m.line, lines)
    # recorded line misses (points past the file) -> rescan must include line 1
    found = mut_consumer._survivor_mutant("calc.py", 5, fid, one_liner)
    assert found is not None and (found.op, found.line) == (m.op, 1)
