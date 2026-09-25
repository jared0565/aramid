"""The known-key schema (1.0 blocker API-5, per DEC-4): what aramid reads,
and one sentence for every key a config layer sets that it does not."""
import tomllib
from dataclasses import fields
from importlib import resources
from pathlib import Path

import pytest

from aramid import config_keys
from aramid.config import Config

REPO = Path(__file__).resolve().parents[2]


def _problems(text: str) -> list[str]:
    return config_keys.problems(tomllib.loads(text))


def test_defaults_toml_is_its_own_known_set():
    """Every key defaults.toml writes is read, with its own type -- no retired
    key survives in the file that seeds every repo's config."""
    text = resources.files("aramid").joinpath("data", "defaults.toml").read_text(encoding="utf-8")
    assert config_keys.problems(tomllib.loads(text)) == []


def test_aramids_own_config_has_no_problems():
    """The dogfood config sets both command forms (argv lists)."""
    assert config_keys.problems(
        tomllib.loads((REPO / "aramid.toml").read_text(encoding="utf-8"))) == []


def test_every_config_field_is_a_known_key():
    """The Config dataclass and the known set must agree: a field the
    dataclass carries but the schema does not know would warn on a key
    aramid reads ([shadow] had a field and no defaults entry)."""
    known = config_keys.known_keys()
    names = {f.name for f in fields(Config)}
    assert "shadow" in names, "the dataclass lost [shadow] -- this pin would pass vacuously"
    assert {n for n in names if (n,) not in known} == set()


def test_no_retired_key_is_also_a_known_one():
    """A key cannot be both read and "does nothing -- delete it"."""
    assert set(config_keys.RETIRED) & set(config_keys.known_keys()) == set()


def test_known_keys_takes_the_parsed_defaults_when_given():
    assert config_keys.known_keys({"a": {"b": 1}}) == {
        ("a",): "table", ("a", "b"): "number", **config_keys.OPTIONAL}


def test_a_clean_layer_has_no_problems():
    assert _problems('test_command = "pytest -q"\n[tests]\ncommand = ["pytest"]\n'
                     'timeout_s = 12.5\n[mutation]\nmutation_block_armed = true\n'
                     '[block_rules.ruff]\nblock = ["S102"]\n[shadow]\n'
                     'shadow_block_armed = false\n') == []


@pytest.mark.parametrize("text, line", [
    ('colour = "red"\n', "unknown key `colour` -- ignored"),
    ("[tests]\ncomand = 1\n", "unknown key [tests].comand -- ignored"),
    ("[mutaton]\nenabled = false\n", "unknown table [mutaton] -- ignored"),
    ("mutation_block_armed = true\n",
     "`mutation_block_armed` is not read there -- it belongs in [mutation]"),
    ("max_mutants = 5\n",
     "`max_mutants` is not read there -- it belongs in [mutation] or [js_mutation]"),
    # the test_arm_misplaced_key.py repro; its home is an OPTIONAL key
    ("shadow_block_armed = false\n",
     "`shadow_block_armed` is not read there -- it belongs in [shadow]"),
    ("[llm]\ntdd_block_armed = true\n",
     "[llm].tdd_block_armed is not read there -- it belongs in the top level"),
    ('[tests]\ntimeout_s = "300"\n', "[tests].timeout_s should be a number, got '300'"),
    ("[tests]\nenabled = 1\n", "[tests].enabled should be true or false, got 1"),
    ("[drain]\nmax_items_per_drain = true\n",
     "[drain].max_items_per_drain should be a number, got True"),
    ("[tests]\ncommand = 3\n",
     "[tests].command should be a string or a list of strings, got 3"),
    ("mutation = 3\n", "`mutation` should be a table, got 3"),
    ("bake_started = 2026-09-25\n",
     "`bake_started` should be a string, got datetime.date(2026, 9, 25)"),
    ('scope_subpath = "sub"\n',
     "`scope_subpath` does nothing -- `aramid init` wrote it for a subdirectory before "
     "0.19.0, and no runner ever read it -- the gate scans the whole repository; delete it"),
    ('[llm]\nmodel_openrouter = "x"\n',
     "[llm].model_openrouter does nothing -- an openrouter arm in [[llm.ladder]] names its "
     "own model; this key was never read; delete it"),
    ("[dast]\nblock_armed = true\n",
     "[dast].block_armed does nothing -- it was reserved and never read -- dast findings "
     "are WARN-only, so setting it arms nothing; delete it"),
    ('[dast]\nstart_command = "npm start"\n',
     "[dast].start_command does nothing -- it was documented as reserved and never read; "
     "delete it"),
    ('[[llm.ladder]]\ntier = "cheap"\nmin_score = "40"\n',
     "[[llm.ladder]] entry 1 min_score should be a number, got '40'"),
    ('[[llm.ladder]]\ntier = "cheap"\ntemperature = 1\n',
     "unknown key 'temperature' in [[llm.ladder]] entry 1 -- ignored"),
    ('[llm]\nladder = "cheap"\n',
     "[llm].ladder should be a list of [[llm.ladder]] tables, got 'cheap'"),
    ("[llm]\nladder = [1]\n", "[[llm.ladder]] entry 1 should be a table, got 1"),
])
def test_each_problem_is_one_sentence(text, line):
    assert _problems(text) == [line]


def test_the_home_list_stops_at_three():
    """Up to three homes are named; a fourth would bury the one sentence, so
    a key read in four or more tables (`enabled` is) reads as unknown."""
    four = {("a", "k"): "number", ("b", "k"): "number", ("c", "k"): "number",
            ("d", "k"): "number"}
    three = dict(list(four.items())[:3])
    assert config_keys.problems({"k": 1}, known=three) == [
        "`k` is not read there -- it belongs in [a] or [b] or [c]"]
    assert config_keys.problems({"k": 1}, known=four) == ["unknown key `k` -- ignored"]
    assert _problems("enabled = true\n") == ["unknown key `enabled` -- ignored"]


def test_problems_come_in_file_order_and_nested_tables_are_walked():
    assert _problems('b = 1\n[llm.autolearn]\narmd = true\n[fuzz]\nzz = 1\n') == [
        "unknown key `b` -- ignored",
        "unknown key [llm.autolearn].armd -- ignored",
        "unknown key [fuzz].zz -- ignored",
    ]


def test_a_later_ladder_entry_is_numbered_and_an_open_table_is_not_walked():
    assert _problems('[[llm.ladder]]\ntier = "a"\n[[llm.ladder]]\ntier = 2\n'
                     '[block_rules.newtool]\nanything = "goes"\n') == [
        "[[llm.ladder]] entry 2 tier should be a string, got 2"]
