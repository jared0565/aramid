import random
from typing import Optional

from aramid.fuzzgen import case_seed, gen_value, supported_params


def _rng():
    return random.Random(1234)


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
        v = gen_value(Optional[int], random.Random(i))
        seen_none |= v is None
        seen_val |= isinstance(v, int)
    assert seen_none and seen_val


def test_gen_value_special_floats_appear():
    import math
    seen = set()
    for i in range(200):
        v = gen_value(float, random.Random(i))
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
