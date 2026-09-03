"""fleet -- machine-level fleet health: the append-only health store every
gate run writes one row to, the drain-time 1.0 readiness judgement over it,
and the operator policy that tunes both. Spec:
docs/superpowers/specs/2026-09-02-aramid-fleet-readiness-design.md.

Everything here lives under ONE directory (`store_dir()`, `~/.aramid` by
default) and nothing here opens a ledger other than the current repo's: a
gate run pushes its own repo's row, the drain reads only the rows. No
network, ever. `aramid uninstall` does not touch the store -- it is fleet
state, not repo state.

FAIL-OPEN IS THE CONTRACT, stated as policy (spec section 9): no function in
this module may change a gate's, the drain's, or the hook's exit code, or
raise out of its seam. `record_health`, `run_judgement` and `delivery_lines`
catch everything and say so on stderr, once.
"""
import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = 1

# An env seam rather than a monkeypatchable function, for the reason
# `toolpath.TOOLS_DIR_ENV` is one: the gate runs in a SPAWNED process under a
# git hook, and a monkeypatch in the pytest process cannot reach it. The
# suite-wide autouse fixture in tests/conftest.py sets this, so no test --
# and no gate a test drives through a real hook -- ever writes to the
# developer's real store.
FLEET_DIR_ENV = "ARAMID_FLEET_DIR"

HEALTH_FILE = "fleet_health.jsonl"
VERDICT_FILE = "fleet_verdict.json"
POLICY_FILE = "fleet.toml"


def store_dir() -> Path:
    override = os.environ.get(FLEET_DIR_ENV)
    if override:
        return Path(override)
    return Path.home() / ".aramid"


def health_path() -> Path:
    return store_dir() / HEALTH_FILE


def verdict_path() -> Path:
    return store_dir() / VERDICT_FILE


def policy_path() -> Path:
    return store_dir() / POLICY_FILE


@dataclass(frozen=True)
class Policy:
    """Operator policy from `fleet.toml` (spec section 3.4). The defaults ARE
    the user's chosen strict threshold: 14 days and 2 aramid versions."""
    min_days: int = 14
    min_versions: int = 2
    repeat_hours: int = 24
    defect_rows: int = 3
    gate_trailer: bool = True


def _int_or(value, default: int) -> int:
    # bool is an int subclass; `gate_trailer = true` under the wrong table
    # must not read as 1.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return default
    return value


def load_policy() -> Policy:
    """Absent -> defaults. Unreadable -> defaults plus ONE stderr note (the
    registry precedent). A key of the wrong type falls back to its own
    default rather than discarding the whole file."""
    p = policy_path()
    if not p.exists():
        return Policy()
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError) as exc:
        print(f"aramid: fleet: {p} unreadable ({exc}); using default policy",
              file=sys.stderr)
        return Policy()
    readiness = data.get("readiness")
    notices = data.get("notices")
    readiness = readiness if isinstance(readiness, dict) else {}
    notices = notices if isinstance(notices, dict) else {}
    defaults = Policy()
    trailer = notices.get("gate_trailer", defaults.gate_trailer)
    return Policy(
        min_days=_int_or(readiness.get("min_days"), defaults.min_days),
        min_versions=_int_or(readiness.get("min_versions"), defaults.min_versions),
        repeat_hours=_int_or(notices.get("repeat_hours"), defaults.repeat_hours),
        defect_rows=_int_or(notices.get("defect_rows"), defaults.defect_rows),
        gate_trailer=trailer if isinstance(trailer, bool) else defaults.gate_trailer,
    )
