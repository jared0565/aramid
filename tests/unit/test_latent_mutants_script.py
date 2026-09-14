"""scripts/latent_mutants.py -- the ratchet on mutants the unit suite never
executes. The drain confirms a mutant against tests/unit alone, so a
generator mutant on a line only tests/integration reaches is a survivor
waiting to be drawn; this script counts them from a unit-suite coverage
JSON and `check` refuses a count above the committed baseline.

Driven on a tmp tree with a synthetic coverage report: what counts (a
mutant on a missing line; on the continuation line of a missing
statement), what does not (an executed line, a function with no mutants,
a file outside src/aramid, an unparseable file), and the three commands'
exits and outputs whole."""
import importlib.util
import io
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "latent_mutants.py"


@pytest.fixture(scope="module")
def lm():
    spec = importlib.util.spec_from_file_location("latent_mutants", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Two functions: `f` has one mutant per line (a comparison, an int), `g`
# has a multi-line call whose int literal sits on a continuation line, and
# `h` has nothing the generator mutates.
SRC = (
    "def f(a):\n"
    "    if a > 1:\n"          # L2: cmp-flip and int-bound
    "        return 2\n"       # L3: int-bound
    "    return 0\n"           # L4: int-bound
    "\n"
    "def g(x):\n"
    "    return call(x,\n"     # L7: the statement line
    "                7)\n"     # L8: int-bound, attributed to L7
    "\n"
    "def h(s):\n"
    "    return s.strip()\n"
)


def _tree(tmp_path, **files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return tmp_path


def _cov(**files):
    """{key: missing lines}: the shape coverage.py writes, Windows keys included."""
    return {"meta": {"format": 3}, "files": {
        key: {"executed_lines": [], "missing_lines": sorted(missing),
              "excluded_lines": []} for key, missing in files.items()}}


def test_a_mutant_counts_on_a_missing_statement_and_its_continuation_lines_only(lm, tmp_path):
    root = _tree(tmp_path, **{"src/aramid/m.py": SRC})
    # L2 executed, L3 missing, L4 executed, L7 (the call) missing: the
    # int on L8 belongs to the statement at L7.
    got = lm.measure(_cov(**{"src\\aramid\\m.py": {3, 7}}), root)
    assert got == {"src/aramid/m.py": 2}
    got = lm.measure(_cov(**{"src/aramid/m.py": {2, 3, 4, 7, 11}}), root)
    assert got == {"src/aramid/m.py": 5}, "L11 has no mutant; L2 two, the rest one"
    assert lm.measure(_cov(**{"src/aramid/m.py": set()}), root) == {}, "all executed"


def test_files_outside_src_aramid_and_unparseable_ones_contribute_nothing(lm, tmp_path):
    root = _tree(tmp_path, **{"src/aramid/m.py": SRC, "tests/unit/t.py": SRC,
                              "src/aramid/broken.py": "def (:\n"})
    got = lm.measure(_cov(**{"src/aramid/m.py": {3}, "tests/unit/t.py": {3},
                             "src/aramid/broken.py": {1}}), root)
    assert got == {"src/aramid/m.py": 1}


def test_verbose_lists_every_latent_mutant_by_statement_line(lm, tmp_path):
    root = _tree(tmp_path, **{"src/aramid/m.py": SRC})
    out = io.StringIO()
    lm.measure(_cov(**{"src/aramid/m.py": {2, 7}}), root, verbose=True, out=out)
    assert out.getvalue() == ("src/aramid/m.py:2 cmp-flip > -> >= in f\n"
                              "src/aramid/m.py:2 int-bound 1 -> 2 in f\n"
                              "src/aramid/m.py:8 int-bound 7 -> 8 in g\n")


def test_check_passes_at_or_below_the_baseline_and_names_every_file_over(lm):
    out = io.StringIO()
    assert lm.check({"src/aramid/a.py": 2}, {"_total": 2, "src/aramid/a.py": 2}, out) == 0
    assert out.getvalue() == "latent mutants: 2 total, baseline 2; 0 file(s) over, 0 below\n"

    out = io.StringIO()
    rc = lm.check({"src/aramid/a.py": 3, "src/aramid/b.py": 1, "src/aramid/c.py": 1},
                  {"_total": 4, "src/aramid/a.py": 2, "src/aramid/b.py": 2}, out)
    assert rc == 1
    assert out.getvalue() == (
        "latent mutants: src/aramid/a.py has 3, baseline 2 -- a mutant the unit suite "
        "never executes was added; pin it (tests/unit/test_a*.py) or the drain will "
        "report it\n"
        "latent mutants: src/aramid/c.py has 1, baseline 0 -- a mutant the unit suite "
        "never executes was added; pin it (tests/unit/test_c*.py) or the drain will "
        "report it\n"
        "latent mutants: src/aramid/b.py has 1, baseline 2 -- lower the baseline "
        "(write-baseline)\n"
        "latent mutants: 5 total, baseline 4; 2 file(s) over, 1 below\n")

    out = io.StringIO()
    assert lm.check({}, {"_total": 1, "src/aramid/a.py": 1}, out) == 0, "below is not over"
    assert out.getvalue().splitlines()[0].startswith("latent mutants: src/aramid/a.py has 0")


def test_the_cli_measures_checks_and_writes_a_sorted_baseline(lm, tmp_path, capsys):
    root = _tree(tmp_path, **{"src/aramid/z.py": SRC, "src/aramid/a.py": SRC})
    cov = tmp_path / "cov.json"
    cov.write_text(json.dumps(_cov(**{"src/aramid/z.py": {3}, "src/aramid/a.py": {3, 4}})),
                   encoding="utf-8")
    base = tmp_path / "baseline.json"

    assert lm.main(["measure", str(cov), "--root", str(root)]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "_total": 3, "src/aramid/a.py": 2, "src/aramid/z.py": 1}

    assert lm.main(["write-baseline", str(cov), "--baseline", str(base),
                    "--root", str(root)]) == 0
    assert capsys.readouterr().out == f"wrote {base}: 3 latent in 2 file(s)\n"
    assert base.read_text(encoding="utf-8") == (
        '{\n  "_total": 3,\n  "src/aramid/a.py": 2,\n  "src/aramid/z.py": 1\n}\n')

    assert lm.main(["check", str(cov), "--baseline", str(base), "--root", str(root)]) == 0
    assert capsys.readouterr().out == \
        "latent mutants: 3 total, baseline 3; 0 file(s) over, 0 below\n"

    cov.write_text(json.dumps(_cov(**{"src/aramid/z.py": {3, 4}, "src/aramid/a.py": {3}})),
                   encoding="utf-8")
    assert lm.main(["check", str(cov), "--baseline", str(base), "--root", str(root)]) == 1
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("latent mutants: src/aramid/z.py has 2, baseline 1")
    assert lines[1].startswith("latent mutants: src/aramid/a.py has 1, baseline 2 -- lower")
    assert lines[2] == "latent mutants: 3 total, baseline 3; 1 file(s) over, 1 below"


def test_check_and_write_baseline_refuse_to_run_without_a_baseline_path(lm, tmp_path, capsys):
    cov = tmp_path / "cov.json"
    cov.write_text(json.dumps(_cov()), encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        lm.main(["check", str(cov)])
    assert exc.value.code == 2
    assert "check needs --baseline" in capsys.readouterr().err


def test_the_script_measures_with_the_tree_generator_not_an_installed_one(lm):
    """The drain that draws these mutants ships next from this tree; an
    installed aramid's generator could count a different set."""
    import aramid.mutation
    assert lm.mutation is aramid.mutation
    assert Path(aramid.mutation.__file__).resolve().is_relative_to(REPO / "src")
