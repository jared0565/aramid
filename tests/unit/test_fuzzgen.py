import random
from typing import Optional

import pytest

from aramid import fuzzgen
from aramid.fuzzgen import _is_supported, case_seed, gen_value, supported_params


def _rng():
    # noqa S311 here and below: these are SEEDED generators driving reproducible
    # fuzz cases. `secrets` would be actively wrong -- a failing case has to
    # replay identically from its seed, which a CSPRNG cannot do.
    return random.Random(1234)  # noqa: S311  -- seeded, reproducible, not crypto


def test_supported_params_all_hinted():
    def f(a: int, b: str, c: list[int]) -> bool:
        return True
    assert supported_params(f) == ["a", "b", "c"]


def test_supported_params_none_when_unhinted():
    def f(a, b: int):
        return a
    assert supported_params(f) is None


def test_supported_params_none_on_unsupported_hint():
    class Weird:
        pass

    def f(a: Weird):
        return a
    assert supported_params(f) is None


def test_supported_params_none_on_varargs():
    def f(a: int, *args: int):
        return a
    assert supported_params(f) is None


def test_supported_params_optional_ok():
    def f(a: Optional[int]) -> int:
        return a or 0
    assert supported_params(f) == ["a"]


def test_gen_value_types():
    rng = _rng()
    assert isinstance(gen_value(int, rng), int)
    assert isinstance(gen_value(str, rng), str)
    assert isinstance(gen_value(bytes, rng), bytes)
    assert isinstance(gen_value(bool, rng), bool)
    got = gen_value(list[int], rng)
    assert isinstance(got, list) and all(isinstance(x, int) for x in got)
    d = gen_value(dict[str, int], rng)
    assert isinstance(d, dict)


def test_gen_value_optional_can_be_none_and_value():
    seen_none = seen_val = False
    for i in range(50):
        v = gen_value(Optional[int], random.Random(i))  # noqa: S311  -- seeded, not crypto
        seen_none |= v is None
        seen_val |= isinstance(v, int)
    assert seen_none and seen_val


def test_gen_value_special_floats_appear():
    import math
    seen = set()
    for i in range(200):
        v = gen_value(float, random.Random(i))  # noqa: S311  -- seeded, not crypto
        if math.isnan(v):
            seen.add("nan")
        elif math.isinf(v):
            seen.add("inf")
        elif v == 0.0:
            seen.add("zero")
    assert {"nan", "inf", "zero"} <= seen


def test_case_seed_deterministic_and_varies():
    assert case_seed("a.py", "f", 0) == case_seed("a.py", "f", 0)
    assert case_seed("a.py", "f", 0) != case_seed("a.py", "f", 1)
    assert case_seed("a.py", "f", 0) != case_seed("b.py", "f", 0)


def test_gen_value_depth_capped():
    # deeply nested container hint must terminate, not recurse forever
    v = gen_value(list[list[list[list[int]]]], _rng())
    assert isinstance(v, list)


# --- the container hints, both sides of every bound -------------------------
#
# The drain confirms a mutant against the unit suite alone, and the dict and
# tuple arms of `_is_supported` / `gen_value` were reached only through
# tests/integration/test_fuzz_consumer.py: `dict[int]` (one arg) accepted,
# `tuple[int, Weird]` accepted on the strength of its first member, the
# variadic tuple's element read from `args[1]` (Ellipsis) and every element
# generated as None, the nesting depth advancing by two.

class _Fixed:
    """The smallest choice of everything: one element per container, the
    first atom of every table -- so a generated value is a fixed shape the
    assertion can spell out."""

    def randint(self, a, b):
        return 1

    def choice(self, seq):
        return seq[0]

    def random(self):
        return 0.0

    def uniform(self, a, b):
        return a


class _Weird:
    pass


@pytest.mark.parametrize("hint, supported", [
    (dict[str, int], True),
    (dict[str, _Weird], False),
    (dict[int], False),                          # one arg is not a mapping hint
    (dict[str, int, bool], False),
    (tuple[int, ...], True),
    (tuple[_Weird, ...], False),
    (tuple[int, str], True),
    (tuple[int, _Weird], False),                 # the first member does not vouch for the rest
    (tuple[int, str, bytes], True),
    (tuple[()], True),
    (list[tuple[int, ...]], True),
    (list[int, str], False),
    (set[str], True),
    (frozenset[bytes], True),
    (Optional[tuple[int, ...]], True),
    (Optional[_Weird], False),
    (_Weird, False),
])
def test_is_supported_container_hints(hint, supported):
    assert _is_supported(hint) is supported


def test_gen_value_variadic_tuple_generates_its_element_type():
    assert gen_value(tuple[int, ...], _Fixed()) == (0,)
    assert gen_value(tuple[str, ...], _Fixed()) == ("",)
    assert gen_value(tuple[int, str], _Fixed()) == (0, "")
    assert gen_value(tuple[int, str, bytes], _Fixed()) == (0, "", b"")
    assert gen_value(tuple[()], _Fixed()) == ()


def test_gen_value_tuple_nesting_advances_depth_by_one():
    variadic = tuple[tuple[tuple[tuple[int, ...], ...], ...], ...]
    assert gen_value(variadic, _Fixed()) == (((None,),),), \
        "three containers fit above the depth cap; the fourth is None"
    fixed = tuple[tuple[tuple[tuple[int]]]]
    assert gen_value(fixed, _Fixed()) == (((None,),),)
    mixed = tuple[tuple[tuple[int, ...]], ...]
    assert gen_value(mixed, _Fixed()) == (((0,),),)


# The first pass over gen_value reported these red after a stage-2 run had
# broken the worktree (every "kill" from then on took 0 s); a stage-1-only
# sweep on a fresh worktree found fourteen of its mutants unpinned: the
# int table's members and range, the bool threshold, every container's
# length range, the dict key type, and the depth step of the list, set,
# dict and variadic-tuple arms (the tuple arms above pinned only their own).

class _Recording(_Fixed):
    """_Fixed that also keeps every table it was offered and every range it
    was asked for, so a generator's tables and bounds are asserted whole."""

    def __init__(self):
        self.tables, self.ranges = [], []

    def randint(self, a, b):
        self.ranges.append((a, b))
        return 1

    def choice(self, seq):
        self.tables.append(list(seq))
        return seq[0]


def test_gen_value_int_table_and_range_are_asserted_whole():
    rng = _Recording()
    assert gen_value(int, rng) == 0
    assert rng.ranges == [(-9999, 9999)]
    assert rng.tables == [[0, 1, -1, 2, -2, fuzzgen._BIG, -fuzzgen._BIG, 1]]


def test_gen_value_bool_reads_false_exactly_at_the_threshold():
    class _Half(_Fixed):
        def random(self):
            return 0.5
    assert gen_value(bool, _Half()) is False, "`< 0.5`, not `<=`"
    assert gen_value(bool, _Fixed()) is True


@pytest.mark.parametrize("hint", [list[int], set[int], frozenset[int], dict[str, int],
                                  tuple[int, ...]])
def test_gen_value_containers_draw_their_length_from_zero_to_max_len(hint):
    rng = _Recording()
    gen_value(hint, rng)
    assert rng.ranges[0] == (0, fuzzgen._MAX_LEN)


def test_gen_value_dict_keys_come_from_the_key_type_and_values_from_the_value_type():
    assert gen_value(dict[str, int], _Fixed()) == {"": 0}
    assert gen_value(dict[int, str], _Fixed()) == {0: ""}


def test_gen_value_list_set_and_dict_nesting_advances_depth_by_one():
    assert gen_value(list[list[list[int]]], _Fixed()) == [[[0]]]
    assert gen_value(list[list[list[list[int]]]], _Fixed()) == [[[None]]], \
        "three containers fit above the depth cap; the fourth is None"
    assert gen_value(set[frozenset[tuple[int, ...]]], _Fixed()) == {frozenset({(0,)})}
    deep = dict[str, dict[str, dict[str, dict[str, int]]]]
    assert gen_value(deep, _Fixed()) == {"": {"": {"": None}}}
    keyed = dict[tuple[tuple[tuple[int, ...], ...], ...], int]
    assert gen_value(keyed, _Fixed()) == {((None,),): 0}, "the key's depth steps by one too"
