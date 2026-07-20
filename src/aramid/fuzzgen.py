"""fuzzgen -- owned stdlib input generator for the fuzz consumer (Phase
2c-2 spec section 2). Type-hint-driven, seeded, deterministic: the same
(file, func, case index) always yields the same input, so a crash's seed
IS its repro and fingerprints are stable across drains."""
import hashlib
import random
import typing
from types import NoneType

SUPPORTED_ATOMS = {int, float, str, bytes, bool, NoneType}
_MAX_DEPTH = 3
_MAX_LEN = 5

_BIG = 2 ** 63
_STRS = ["", "a", "0", " ", "\n", "\x00", "é", "🙂", "../../etc", "%s%n",
         "A" * 64]
_BYTES = [b"", b"\x00", b"\xff\xfe", b"ABC", b"\x00" * 16]


def case_seed(file: str, func: str, index: int) -> int:
    digest = hashlib.sha256(f"{file}:{func}:{index}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _origin_args(hint):
    return typing.get_origin(hint), typing.get_args(hint)


def _is_supported(hint) -> bool:
    if hint in SUPPORTED_ATOMS or hint is None:
        return True
    origin, args = _origin_args(hint)
    if origin in (list, set, frozenset):
        return len(args) == 1 and _is_supported(args[0])
    if origin is dict:
        return len(args) == 2 and all(_is_supported(a) for a in args)
    if origin is tuple:
        if len(args) == 2 and args[1] is Ellipsis:
            return _is_supported(args[0])
        return all(_is_supported(a) for a in args)
    if origin is typing.Union:
        return all(a is NoneType or _is_supported(a) for a in args)
    return False


def supported_params(fn):
    """Param names when EVERY parameter has a supported hint and there is no
    *args/**kwargs; None otherwise (including when hint resolution raises)."""
    import inspect
    try:
        sig = inspect.signature(fn)
        hints = typing.get_type_hints(fn)
    except Exception:
        return None
    names = []
    for name, p in sig.parameters.items():
        if p.kind in (inspect.Parameter.VAR_POSITIONAL,
                      inspect.Parameter.VAR_KEYWORD):
            return None
        hint = hints.get(name)
        if hint is None or not _is_supported(hint):
            return None
        names.append(name)
    return names


def gen_value(hint, rng: random.Random, depth: int = 0):
    if hint is None or hint is NoneType:
        return None
    if hint is bool:
        return rng.random() < 0.5
    if hint is int:
        return rng.choice([0, 1, -1, 2, -2, _BIG, -_BIG, rng.randint(-9999, 9999)])
    if hint is float:
        return rng.choice([0.0, -0.0, 1.5, -1.5, float("inf"), float("-inf"),
                           float("nan"), rng.uniform(-1e6, 1e6)])
    if hint is str:
        return rng.choice(_STRS)
    if hint is bytes:
        return rng.choice(_BYTES)

    origin, args = _origin_args(hint)
    if origin is typing.Union:
        return gen_value(rng.choice(args), rng, depth)
    if depth >= _MAX_DEPTH:
        return None
    if origin in (list, set, frozenset):
        vals = [gen_value(args[0], rng, depth + 1)
                for _ in range(rng.randint(0, _MAX_LEN))]
        return vals if origin is list else origin(
            v for v in vals if _hashable(v))
    if origin is dict:
        out = {}
        for _ in range(rng.randint(0, _MAX_LEN)):
            k = gen_value(args[0], rng, depth + 1)
            if _hashable(k):
                out[k] = gen_value(args[1], rng, depth + 1)
        return out
    if origin is tuple:
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(gen_value(args[0], rng, depth + 1)
                         for _ in range(rng.randint(0, _MAX_LEN)))
        return tuple(gen_value(a, rng, depth + 1) for a in args)
    return None


def _hashable(v) -> bool:
    try:
        hash(v)
        return True
    except TypeError:
        return False
