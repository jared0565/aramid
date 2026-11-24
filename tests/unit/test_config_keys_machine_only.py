"""A key only the machine's ~/.aramid/config.toml may set (interop round 351:
`[drain].cpu_cores` caps every drain on the machine, so one repo's committed
aramid.toml may not). config_keys names it in a repo layer; config.py asks
for that only of the repo layer."""
import pytest

from aramid import config_keys

SAID = ("[drain].cpu_cores is read only from ~/.aramid/config.toml (it caps every drain on"
        " this machine) -- ignored here")


def test_a_repo_layer_setting_it_is_named():
    assert config_keys.machine_only_problems({"drain": {"cpu_cores": 1}}) == [SAID]


def test_any_value_is_named_even_one_that_is_not_a_count():
    assert config_keys.machine_only_problems({"drain": {"cpu_cores": "x"}}) == [SAID]


@pytest.mark.parametrize("raw", [{}, {"drain": {}}, {"drain": {"interval_hours": 4}},
                                 {"drain": 3}, {"cpu_cores": 1}, {"tests": {"cpu_cores": 1}}])
def test_a_layer_that_does_not_set_it_is_not_named(raw):
    assert config_keys.machine_only_problems(raw) == []


def test_it_is_a_known_key_whose_type_is_a_count():
    known = config_keys.known_keys()

    assert known[("drain", "cpu_cores")] == "count"
    assert config_keys.problems({"drain": {"cpu_cores": 2}}) == []
    assert config_keys.problems({"drain": {"cpu_cores": 0}}) == [
        "[drain].cpu_cores should be a whole number above 0, got 0"]


def test_every_machine_only_key_is_a_known_key():
    assert set(config_keys.MACHINE_ONLY) <= set(config_keys.known_keys())
