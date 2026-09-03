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
import json
import os
import sys
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path

from aramid import health as health_mod
from aramid.fingerprint import normalize_path

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


PUSH_BUDGET_S = 2.0
_monotonic = time.monotonic     # seam for the budget tests


def repo_key(root) -> str:
    """The registry's own key for a repo -- resolved, forward slashes,
    casefolded -- so a row and a registry entry compare equal."""
    return normalize_path(str(Path(root).resolve()))


def build_row(root, h: health_mod.Health, *, aramid_version: str, now: str) -> dict:
    """Spec section 3.1, exactly. Every row carries the full `armed` dict:
    arming is an aramid.toml edit, not a ledger event, so the SEQUENCE of
    rows is the only place a disarm is observable (criterion 6)."""
    return {
        "schema_version": SCHEMA_VERSION,
        "at": now,
        "repo": repo_key(root),
        "name": Path(root).resolve().name,
        "aramid_version": aramid_version,
        "gate": h.gate,
        "run_id": h.run_id,
        "exit_code": h.exit_code,
        "engine_error": h.engine_error,
        "criteria": health_mod.criteria(h),
        "evidence": {
            "skip_streaks": {g: dict(t) for g, t in h.skip_streaks.items()},
            "degraded_consumers": [f.name for f in h.degraded_consumers],
            "stood_down": [f.name for f in h.stood_down],
            "no_work": [f.name for f in h.no_work],
            "resolver_defects": [f"{r}/{t} {v}" for r, t, v in h.resolver_defects],
            "bad_tools": list(h.bad_tools),
            "degraded_block_tier": h.degraded_block_tier,
            "armed": dict(h.armed),
            "open": h.open,
            "blocking": h.blocking,
        },
    }


def append_line(path: Path, obj: dict) -> None:
    """One write of one newline-terminated line in O_APPEND mode: concurrent
    gates in different repos interleave WHOLE lines. O_BINARY on Windows,
    or the C runtime turns the newline into CRLF."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(obj, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def append_row(row: dict, path: Path | None = None) -> None:
    append_line(path if path is not None else health_path(), row)


def _read_jsonl(path: Path, required: tuple[str, ...]) -> list[dict]:
    """Tolerant reader shared by the rows and the notices: unreadable lines
    (a torn trailing write, garbage) are skipped, rows newer than this
    schema are ignored, and each class gets ONE stderr note per read."""
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"aramid: fleet: {path} unreadable ({exc}); treating as empty",
              file=sys.stderr)
        return []
    out, skipped, newer = [], 0, 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        version = obj.get("schema_version") if isinstance(obj, dict) else None
        if not isinstance(version, int) or isinstance(version, bool):
            skipped += 1
            continue
        if version > SCHEMA_VERSION:
            newer += 1
            continue
        if any(not isinstance(obj.get(k), (str, dict)) for k in required):
            skipped += 1
            continue
        out.append(obj)
    if skipped:
        print(f"aramid: fleet: skipped {skipped} unreadable row(s) in {path.name}",
              file=sys.stderr)
    if newer:
        print(f"aramid: fleet: ignored {newer} row(s) newer than schema "
              f"{SCHEMA_VERSION} in {path.name}", file=sys.stderr)
    return out


def read_rows(path: Path | None = None) -> list[dict]:
    return _read_jsonl(path if path is not None else health_path(),
                       required=("at", "repo", "criteria"))


def record_health(root, cfg, ledger, result, *, gate, aramid_version: str, now: str,
                  engine_error: bool = False) -> None:
    """The push seam (spec section 5). Called by `cmd_check` after the report
    is printed. NEVER raises and never touches the exit code: any failure --
    a read-only home, a full disk, a store that is a directory, a ledger
    that will not walk -- is one stderr line. Over budget the row is SKIPPED,
    never written partially: a torn row would read as a repo that went
    quiet, which is a different lie."""
    started = _monotonic()
    try:
        h = health_mod.snapshot(cfg, ledger, result, gate=gate, engine_error=engine_error)
        if _monotonic() - started > PUSH_BUDGET_S:
            print(f"aramid: fleet: health row not recorded "
                  f"(over the {PUSH_BUDGET_S:.0f}s budget)", file=sys.stderr)
            return
        append_row(build_row(root, h, aramid_version=aramid_version, now=now))
    except Exception as exc:
        print(f"aramid: fleet: health row not recorded ({exc})", file=sys.stderr)
