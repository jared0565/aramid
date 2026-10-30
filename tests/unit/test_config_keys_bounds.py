"""A number aramid reads with a range says so when a layer sets it outside
that range (operator decision 2026-10-30). `[llm].call_timeout_s = inf`
loads -- TOML has `inf` -- and made every provider call raise OverflowError
after its CLI had started. DEC-4 holds: a WARN line, the loaded value and
every exit code unchanged (config_keys' module docstring); the providers
refuse such a timeout themselves (providers.base.timeout_refused)."""
import math

import pytest
import tomllib

from aramid import config_keys


def _problems(text: str) -> list[str]:
    return config_keys.problems(tomllib.loads(text))


@pytest.mark.parametrize("value", ["inf", "-inf", "nan", "0", "-5.0", "86400.5", "1e300"])
def test_a_call_timeout_out_of_range_is_named(value):
    got = _problems(f"[llm]\ncall_timeout_s = {value}\n")
    assert got == [f"[llm].call_timeout_s should be a number above 0 and at most 86400, "
                   f"got {tomllib.loads(f'v = {value}')['v']!r}"]


@pytest.mark.parametrize("value", ["240", "0.5", "86400"])
def test_a_call_timeout_in_range_is_not(value):
    assert _problems(f"[llm]\ncall_timeout_s = {value}\n") == []


def test_a_wrong_type_is_still_named_as_a_type():
    assert _problems("[llm]\ncall_timeout_s = true\n") == \
        ["[llm].call_timeout_s should be a number, got True"]


def test_in_bounds_reads_the_same_range_for_any_value():
    path = ("llm", "call_timeout_s")
    assert config_keys.in_bounds(path, 240) and config_keys.in_bounds(path, 86400.0)
    for bad in (math.inf, math.nan, 0, -1, 86400.5, True, "240", None):
        assert not config_keys.in_bounds(path, bad), bad
    assert config_keys.in_bounds(("llm", "max_items_per_drain"), 10 ** 9), \
        "a key with no range is always in bounds"
