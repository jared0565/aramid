"""config_keys -- which `aramid.toml` / `~/.aramid/config.toml` keys aramid
reads, and what is wrong with a layer that sets others (1.0 blocker API-5,
per DEC-4: a WARN on stderr and a `doctor` row, never an exit-code change).

Until 0.19.0 an unknown, misplaced or mistyped key was accepted in silence
-- `tests/unit/test_arm_misplaced_key.py` records one that left a gate
reading as armed when it was not. The known set is `data/defaults.toml`
itself (every key there is one aramid reads, and its value's type is the
key's type) plus the keys that are read but have no default to write down,
listed in OPTIONAL below. A key aramid wrote or documented and never read
is RETIRED: named, with the reason, so the warning can say "delete it"
rather than "unknown".
"""
from importlib import resources

import tomllib

# Read, but with no value defaults.toml can hold (TOML has no null), so
# they are listed here. Path -> type name.
OPTIONAL: dict[tuple[str, ...], str] = {
    ("test_command",): "command",         # legacy alias, blessed for 1.x (DEC-3)
    ("bake_started",): "string",
    ("tests", "command"): "command",
    ("mutation", "test_command"): "command",
    ("mutation", "baseline_timeout_s"): "number",
    ("js_mutation", "baseline_timeout_s"): "number",
    ("shadow",): "table",
    ("shadow", "shadow_block_armed"): "boolean",
    ("block_rules",): "table",
}

# Tables whose contents are not a fixed key set: block_rules' tool tables
# are merged over data/block_rules.toml by the policy loader.
OPEN_TABLES: tuple[tuple[str, ...], ...] = (("block_rules",),)

# The keys of one [[llm.ladder]] entry (review.py reads them per arm).
LADDER_KEYS: dict[str, str] = {
    "tier": "string", "provider": "string", "model": "string",
    "effort": "string", "min_score": "number",
}

# Written or documented once, read never. Path -> why, for the warning.
RETIRED: dict[tuple[str, ...], str] = {
    ("scope_subpath",): ("`aramid init` wrote it for a subdirectory before 0.19.0, and no "
                         "runner ever read it -- the gate scans the whole repository"),
    ("llm", "model_openrouter"): ("an openrouter arm in [[llm.ladder]] names its own model; "
                                  "this key was never read"),
    ("dast", "block_armed"): ("it was reserved and never read -- dast findings are WARN-only, "
                              "so setting it arms nothing"),
    ("dast", "start_command"): "it was documented as reserved and never read",
}

_TYPE_WORDS = {"boolean": "true or false", "number": "a number", "string": "a string",
               "list": "a list", "table": "a table",
               "command": "a string or a list of strings"}
# A command is argv or one string split POSIX-style (runners/tests._argv).
_ACCEPTS = {"command": ("string", "list")}


def _type_name(value) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "table"
    return type(value).__name__


def _flatten(d: dict, prefix: tuple[str, ...] = ()) -> dict[tuple[str, ...], str]:
    out: dict[tuple[str, ...], str] = {}
    for key, value in d.items():
        path = prefix + (key,)
        out[path] = _type_name(value)
        if isinstance(value, dict):
            out.update(_flatten(value, path))
    return out


def known_keys(defaults: dict | None = None) -> dict[tuple[str, ...], str]:
    """Every key aramid reads, as a path from the top of a config file, with
    its type name: defaults.toml plus OPTIONAL. `defaults` is the parsed
    defaults.toml when the caller already has it (load_config does)."""
    if defaults is None:
        text = (resources.files("aramid").joinpath("data", "defaults.toml")
                .read_text(encoding="utf-8"))
        defaults = tomllib.loads(text)
    known = _flatten(defaults)
    known.update(OPTIONAL)
    return known


def _where(path: tuple[str, ...]) -> str:
    if len(path) == 1:
        return f"`{path[0]}`"
    return f"[{'.'.join(path[:-1])}].{path[-1]}"


def _table_name(path: tuple[str, ...]) -> str:
    return "the top level" if not path else f"[{'.'.join(path)}]"


def problems(raw: dict, *, known: dict | None = None) -> list[str]:
    """What is wrong with one config layer, one sentence each, in file
    order. Empty when every key is one aramid reads, with the right type."""
    known = known_keys() if known is None else known
    by_name: dict[str, list[tuple[str, ...]]] = {}
    for path in known:
        by_name.setdefault(path[-1], []).append(path)
    out: list[str] = []

    def walk(d: dict, prefix: tuple[str, ...]) -> None:
        for key, value in d.items():
            path = prefix + (key,)
            if prefix in OPEN_TABLES:
                continue
            if path in RETIRED:
                out.append(f"{_where(path)} does nothing -- {RETIRED[path]}; delete it")
                continue
            if path == ("llm", "ladder"):
                _ladder(value, out)
                continue
            want = known.get(path)
            if want is None:
                homes = [p for p in by_name.get(key, []) if p != path]
                if 1 <= len(homes) <= 3:
                    out.append(f"{_where(path)} is not read there -- it belongs in "
                               + " or ".join(_table_name(h[:-1]) for h in homes))
                elif isinstance(value, dict):
                    out.append(f"unknown table [{'.'.join(path)}] -- ignored")
                else:
                    out.append(f"unknown key {_where(path)} -- ignored")
                continue
            got = _type_name(value)
            if got not in _ACCEPTS.get(want, (want,)):
                out.append(f"{_where(path)} should be {_TYPE_WORDS[want]}, got {value!r}")
                continue
            if isinstance(value, dict):
                walk(value, path)

    walk(raw, ())
    return out


def _ladder(value, out: list[str]) -> None:
    if not isinstance(value, list):
        out.append(f"[llm].ladder should be a list of [[llm.ladder]] tables, got {value!r}")
        return
    for i, arm in enumerate(value, start=1):
        if not isinstance(arm, dict):
            out.append(f"[[llm.ladder]] entry {i} should be a table, got {arm!r}")
            continue
        for key, v in arm.items():
            want = LADDER_KEYS.get(key)
            if want is None:
                out.append(f"unknown key {key!r} in [[llm.ladder]] entry {i} -- ignored")
            elif _type_name(v) != want:
                out.append(f"[[llm.ladder]] entry {i} {key} should be {_TYPE_WORDS[want]}, "
                           f"got {v!r}")
