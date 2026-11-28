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
import math
import os
import sys
import time
import tomllib
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aramid import health as health_mod
from aramid import leftovers, registry
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
    the user's chosen strict threshold: 14 days and 2 aramid versions, and
    (amendment A1) a latest row no older than 7 days per repo -- 0 disables
    that window. Amendment A2: a repo whose latest row is green and older
    than the window is parked, not counted, and fewer than
    `min_active_repos` counted repos cannot read `ready`."""
    min_days: int = 14
    min_versions: int = 2
    repeat_hours: int = 24
    defect_rows: int = 3
    gate_trailer: bool = True
    max_row_age_days: int = 7
    min_active_repos: int = 3


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
        max_row_age_days=_int_or(readiness.get("max_row_age_days"), defaults.max_row_age_days),
        min_active_repos=_int_or(readiness.get("min_active_repos"), defaults.min_active_repos),
        repeat_hours=_int_or(notices.get("repeat_hours"), defaults.repeat_hours),
        defect_rows=_int_or(notices.get("defect_rows"), defaults.defect_rows),
        gate_trailer=trailer if isinstance(trailer, bool) else defaults.gate_trailer,
    )


PUSH_BUDGET_S = 2.0
MAX_NOTICE_LINES = 3
STALE_AFTER_H = 12              # three drain intervals
_monotonic = time.monotonic     # seam for the budget tests


def repo_key(root) -> str:
    """The registry's own key for a repo -- resolved, forward slashes,
    casefolded -- so a row and a registry entry compare equal."""
    return normalize_path(str(Path(root).resolve()))


def build_row(root, h: health_mod.Health, *, aramid_version: str, now: str) -> dict:
    """Spec section 3.1, exactly. Every row carries the full `armed` dict:
    arming is an aramid.toml edit, not a ledger event, so the SEQUENCE of
    rows is the only place a disarm is observable (criterion 6).

    Interop round 343: a row written in a linked `git worktree` also carries
    `worktree_of`, its main checkout's key, so the judge can count it for
    the registered repo (`judge`). Only there: every other row keeps the
    spec's shape exactly."""
    row = {
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
            "stalled_tools": list(h.stalled_tools),
            "degraded_block_tier": h.degraded_block_tier,
            "armed": dict(h.armed),
            "open": h.open,
            "blocking": h.blocking,
        },
    }
    owner = _worktree_of(root)
    if owner is not None:
        row["worktree_of"] = owner
    return row


def _worktree_of(root) -> str | None:
    """The registry key of the main checkout `root` is a linked worktree of,
    or None. A git that does not answer in time leaves the row uncredited
    rather than unwritten: `record_health` skips a row whose building
    raised, and a missing row reads as a repo gone quiet."""
    from aramid import gitutil
    try:
        main = gitutil.main_checkout(Path(root))
    except Exception:  # noqa: BLE001 -- uncredited, never unwritten (docstring)
        return None
    return repo_key(main) if main is not None else None


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


ROW_WINDOW_DAYS = 180
READY, NOT_READY, INSUFFICIENT = "ready", "not-ready", "insufficient-data"


def _parse(at) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(at))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def registered_repos(entries: list[dict] | None = None) -> dict[str, str]:
    """registry key -> display name for every registered repo that is a
    member; a consumer shell is set aside for `spurious_entries`. The
    registry stores resolved paths, so `repo_key` on them equals the key a
    gate run in that repo writes."""
    entries = registry.load_registry() if entries is None else entries
    return {repo_key(e["path"]): Path(e["path"]).name for e in entries
            if leftovers.shell_of(e["path"]) is None}


def registration_times(entries: list[dict] | None = None) -> dict[str, str]:
    """registry key -> the entry's `registered_at`, for members that carry
    one as a string. Amendment A2: the judge reads it to tell a repo that
    has not gated yet from one that never will (`judge`). An entry without
    one is simply absent, which the judge reads as still waiting."""
    entries = registry.load_registry() if entries is None else entries
    return {repo_key(e["path"]): e["registered_at"] for e in entries
            if leftovers.shell_of(e["path"]) is None and isinstance(e.get("registered_at"), str)}


def spurious_entries(entries: list[dict] | None = None) -> list[str]:
    """Display names of the registry entries that are consumer shells:
    `<temp>/aramid-<kind>-*/wt`, registered by an `aramid init` the consumed
    repo's own tooling ran inside a worktree (2026-09-18, two fuzz
    checkouts; `no rows: wt, wt` held the fleet at insufficient-data with
    no row ever coming). `registry.register` refuses them now; an entry an
    older aramid wrote is named here for the operator to remove, and the
    judge waits on nothing from it."""
    entries = registry.load_registry() if entries is None else entries
    return [Path(e["path"]).name for e in entries if leftovers.shell_of(e["path"]) is not None]


def vanished_repos(entries: list[dict] | None = None) -> set[str]:
    """Registry keys of the member entries whose path no longer exists on
    disk. The judge names such a repo `missing path:` with the command that
    removes it, rather than waiting on a row that can never come (1.0
    blocker FN-1: a vanished repo held the verdict at insufficient-data with
    no CLI able to deregister it)."""
    entries = registry.load_registry() if entries is None else entries
    return {repo_key(e["path"]) for e in entries
            if leftovers.shell_of(e["path"]) is None and not Path(e["path"]).exists()}


def _red_criteria(crit: dict) -> list[str]:
    return [k for k in health_mod.CRITERIA
            if not (crit.get(k) is True or (k == "dep_audit_ran" and crit.get(k) is None))]


def _red_detail(row: dict) -> str:
    """Why a row is red, per criterion, from its own evidence -- so a notice
    can say `(resolvers_ok: file_departed/mutation BLIND)` instead of
    sending the reader to the store."""
    ev = row.get("evidence", {})
    parts = []
    for k in _red_criteria(row.get("criteria", {})):
        if k == "no_skip_streak":
            what = ", ".join(f"{g}/{t} x{n}" for g, tools in sorted((ev.get("skip_streaks") or {}).items())
                             for t, n in sorted(tools.items()))
        elif k == "consumers_healthy":
            what = ", ".join(sorted(set((ev.get("degraded_consumers") or []) + (ev.get("stood_down") or [])
                                        + (ev.get("no_work") or []))))
        elif k == "resolvers_ok":
            what = ", ".join(ev.get("resolver_defects") or [])
        elif k == "no_self_inflicted_block":
            stalled = set(ev.get("stalled_tools") or [])
            what = ("engine error" if row.get("engine_error") else
                    ", ".join(f"{t} (stalled)" if t in stalled else t
                              for t in (ev.get("bad_tools") or [])))
        else:
            what = "pip-audit did not run"
        parts.append(f"{k}: {what}" if what else k)
    return "; ".join(parts)


def judge(rows: list[dict], registered: dict[str, str], policy: Policy, now: str,
          *, aramid_version: str = "", spurious: list[str] | tuple[str, ...] = (),
          vanished: set[str] | frozenset[str] = frozenset(),
          registered_at: dict[str, str] | None = None) -> dict:
    """Spec section 6. Walk the registered repos' rows in time order,
    tracking each repo's latest row; the fleet is green at a row when every
    repo that counts there has a green latest row. The streak starts at the
    row that turned the fleet green and resets on any red row -- or on a
    disarm (criterion 6), which restarts it at the disarming row rather
    than pinning the verdict forever.

    Amendment A2 (parked repos) decides which repos count. With
    `policy.max_row_age_days` as the window, a registered repo is ACTIVE
    while its latest row is inside the window, or is red: a red repo never
    leaves the count by going quiet. It is WAITING while it has no row and
    was registered inside the window (`registered_at`, registry key -> ISO
    time; a missing or unreadable time is waiting too): the verdict is
    insufficient-data until its first row. Otherwise it is PARKED: not
    consulted, so a quiet green repo no longer resets the streak or blocks
    the verdict (A1 did both). The cost is paid when it comes back: a row
    from a repo that was not active just before it -- a first row included
    -- restarts an open streak at that row, and the verdict names the repo.
    Only active repos can supply `armed_anywhere`, and fewer than
    `policy.min_active_repos` of them cannot read ready, so a fleet cannot
    shrink its way there. A window of 0 parks nothing.

    `spurious` names the registry entries that are not members
    (`spurious_entries`): reported for removal, counted for nothing.
    `vanished` holds the keys of members whose path is gone
    (`vanished_repos`): each is reported as `missing path:` with its remedy,
    rows or none, and marked `missing_path`; it is never green, never
    parked and holds no streak, since no row can come from it again, and
    the verdict is insufficient-data until it is deregistered."""
    now_dt = _parse(now) or datetime.now(timezone.utc)
    cutoff = now_dt - timedelta(days=ROW_WINDOW_DAYS)
    # Amendment A1: a row is fresh at time t while t - at <= window; exactly
    # `window` old is still fresh. 0 disables the window (the spec as first
    # written, reachable on purpose).
    window = timedelta(days=policy.max_row_age_days) if policy.max_row_age_days > 0 else None
    reg_at = registered_at if isinstance(registered_at, dict) else {}

    def _fresh(row: dict, at_dt: datetime) -> bool:
        if window is None:
            return True
        row_at = _parse(row.get("at"))
        return row_at is not None and at_dt - row_at <= window

    def _row_green(row: dict) -> bool:
        return health_mod.row_green(row.get("criteria", {}))

    def _active(row: dict, at_dt: datetime) -> bool:
        return _fresh(row, at_dt) or not _row_green(row)

    def _registered_dt(key: str) -> datetime | None:
        # Only a string is a time: `fromisoformat("20260901")` would read an
        # integer written by hand as a date.
        value = reg_at.get(key)
        return _parse(value) if isinstance(value, str) else None

    live = []
    for r in rows:
        at = _parse(r.get("at"))
        if at is None:
            continue
        if r.get("repo") not in registered:
            # Interop round 343: a row from an unregistered linked worktree
            # of a registered repo is that repo's row, named from_worktree.
            owner = r.get("worktree_of")
            if owner not in registered:
                continue
            r = {**r, "repo": owner, "name": registered[owner],
                 "from_worktree": r.get("name") or r.get("repo")}
        live.append((at, r))
    live.sort(key=lambda p: p[0])
    # Rows older than ROW_WINDOW_DAYS are not judged -- except a repo's
    # newest row, however old. Without it a repo silent that long reads as
    # "no rows": a red one would then park (A2 forbids it; drain review
    # 362c0c, 2026-11-28) and a green one would block or change its
    # `parked_since`. `_maybe_compact` keeps the same row in the store.
    newest_at = {r["repo"]: at for at, r in live}
    live = [(at, r) for at, r in live if at >= cutoff or at == newest_at[r["repo"]]]

    latest: dict[str, dict] = {}

    def _waiting(key: str, at_dt: datetime) -> bool:
        if key in latest:
            return False
        if window is None:
            return True
        reg_dt = _registered_dt(key)
        return reg_dt is None or at_dt - reg_dt <= window

    counts: dict[str, int] = defaultdict(int)
    streak_start: str | None = None
    versions: set[str] = set()
    disarm: dict | None = None
    returned: dict | None = None
    for _at, r in live:
        repo = r["repo"]
        prev = latest.get(repo)
        # A2 decision 1: this repo was not counted just before this row (it
        # was parked, or had never gated), so the open streak was held
        # without it and ends here.
        if streak_start is not None and (prev is None or not _active(prev, _at)):
            returned = {"name": r.get("name") or repo, "at": r["at"]}
            streak_start, versions, disarm = None, set(), None
        latest[repo] = r
        counts[repo] += 1
        if prev is not None and streak_start is not None:
            before = prev.get("evidence", {}).get("armed") or {}
            after = r.get("evidence", {}).get("armed") or {}
            for flag, was in before.items():
                if was and not after.get(flag, False):
                    disarm = {"name": r.get("name") or repo, "flag": flag, "at": r["at"]}
                    streak_start, versions, returned = None, set(), None
                    break
        green = (not any(_waiting(k, _at) for k in registered)
                 and all(_row_green(latest[k]) for k in registered
                         if k in latest and _active(latest[k], _at)))
        if green:
            if streak_start is None:
                streak_start, versions = r["at"], set()
            versions.add(str(r.get("aramid_version", "")))
        else:
            streak_start, versions, disarm, returned = None, set(), None, None

    repos_out: dict[str, dict] = {}
    active_keys: list[str] = []
    for key, name in sorted(registered.items(), key=lambda kv: kv[1].casefold()):
        row = latest.get(key)
        gone_here = key in vanished
        if row is None:
            parked = not gone_here and not _waiting(key, now_dt)
            reg_dt = _registered_dt(key)
            repos_out[key] = {"name": name, "rows": 0, "latest_at": None, "green": False,
                              "red_criteria": [], "criteria": {}, "stale": False,
                              "age_days": None, "parked": parked,
                              "parked_since": ((reg_dt + window).isoformat(timespec="seconds")
                                               if parked and reg_dt and window else None)}
            continue
        crit = dict(row.get("criteria", {}))
        row_at = _parse(row["at"])
        age = round(max(0.0, (now_dt - row_at).total_seconds() / 86400.0), 2)
        fresh, row_green = _fresh(row, now_dt), health_mod.row_green(crit)
        parked = not gone_here and not fresh and row_green
        if not gone_here and not parked:
            active_keys.append(key)
        repos_out[key] = {"name": row.get("name") or name, "rows": counts[key],
                          "latest_at": row["at"],
                          "green": row_green and not gone_here,
                          "red_criteria": _red_criteria(crit), "criteria": crit,
                          # A2: only a RED row past the window is stale; a
                          # green one is parked.
                          "stale": not fresh and not row_green, "age_days": age,
                          "parked": parked,
                          "parked_since": ((row_at + window).isoformat(timespec="seconds")
                                           if parked and window else None)}
        if row.get("from_worktree"):
            # Only when the latest row came from a worktree (round 343), so
            # every other verdict reads as before.
            repos_out[key]["from_worktree"] = row["from_worktree"]
    for key, v in repos_out.items():
        # Only on a vanished member, so a verdict without one reads as before.
        if key in vanished:
            v["missing_path"] = True
    waiting = sorted((v["name"] for v in repos_out.values()
                      if v["rows"] == 0 and not v["parked"] and not v.get("missing_path")),
                     key=str.casefold)
    gone = sorted((v["name"] for v in repos_out.values() if v.get("missing_path")),
                  key=str.casefold)
    stale = sorted((v["name"] for v in repos_out.values() if v["stale"]), key=str.casefold)
    active = sorted((repos_out[k]["name"] for k in active_keys), key=str.casefold)
    parked_names = sorted((v["name"] for v in repos_out.values() if v["parked"]),
                          key=str.casefold)
    all_green_now = (bool(registered) and not waiting and not gone and bool(active_keys)
                     and all(repos_out[k]["green"] for k in active_keys))
    if gone or not active_keys:
        # A repo that has left the disk is idle for good, and a fleet with
        # nothing counted holds no streak (A1 step 3, kept for these two).
        streak_start, versions, disarm, returned = None, set(), None, None
    # Spec section 4 criterion 6: ANY `*_armed` flag true on some repo's latest
    # row -- a semgrep or pack arm counts, not only a drain consumer's
    # (channel round 165 read the old wording "armed consumer" as narrower).
    # A2: an ACTIVE repo's; a parked repo's old row arms nothing.
    armed_anywhere = any(any((latest[k].get("evidence", {}).get("armed") or {}).values())
                         for k in active_keys)
    days_held = 0.0
    if streak_start is not None:
        start_dt = _parse(streak_start)
        days_held = max(0.0, (now_dt - start_dt).total_seconds() / 86400.0)
    days_held = round(days_held, 2)

    red_rows = [r for r in latest.values() if not health_mod.row_green(r.get("criteria", {}))]
    breaking = None
    if red_rows:
        b = max(red_rows, key=lambda r: str(r.get("at", "")))
        breaking = {"repo": b["repo"], "name": b.get("name") or b["repo"], "at": b["at"],
                    "run_id": b.get("run_id"), "red_criteria": _red_criteria(b.get("criteria", {})),
                    "detail": _red_detail(b)}

    reasons = [f"{v['name']}: {', '.join(v['red_criteria'])}"
               for v in repos_out.values() if v["red_criteria"]]
    blockers: list[str] = []
    notes: list[str] = []
    if not registered:
        verdict = INSUFFICIENT
        reasons.append("no repos registered")
    elif waiting or gone:
        verdict = INSUFFICIENT
        if waiting:
            reasons.append("no rows: " + ", ".join(waiting))
        reasons.extend(f"missing path: {n} (`aramid fleet deregister {n}`)" for n in gone)
    elif not active_keys:
        verdict = INSUFFICIENT
        reasons.append("no active repos")
    elif not all_green_now:
        verdict = NOT_READY
        if stale:
            # A red row past the window: still red, and old. Named with its
            # age so the reader knows the evidence is not recent.
            reasons.append("stale: " + ", ".join(f"{v['name']} ({v['age_days']:.1f}d)"
                                                 for v in repos_out.values() if v["stale"])
                           + f" -- window {policy.max_row_age_days}d")
    else:
        if days_held < policy.min_days:
            blockers.append(f"streak {_days(days_held)} < {policy.min_days}d")
        if len(versions) < policy.min_versions:
            blockers.append(f"versions {len(versions)}/{policy.min_versions} in streak")
        if not armed_anywhere:
            blockers.append("no repo is armed")
        if len(active_keys) < policy.min_active_repos:
            blockers.append(f"active repos {len(active_keys)} < {policy.min_active_repos}")
        verdict = READY if not blockers else NOT_READY
        if disarm is not None:
            notes.append(f"streak restarted by {disarm['name']} disarming "
                         f"{disarm['flag']} at {disarm['at']}")
        if returned is not None:
            notes.append(f"streak restarted by {returned['name']} returning at {returned['at']}")
    if spurious:
        notes.append(f"spurious: {', '.join(spurious)} "
                     "(consumer worktree; remove from ~/.aramid/repos.toml)")
    reasons.extend(blockers)
    reasons.extend(notes)

    return {"schema_version": SCHEMA_VERSION, "computed_at": now,
            "aramid_version": aramid_version,
            "policy": {"min_days": policy.min_days, "min_versions": policy.min_versions,
                       "max_row_age_days": policy.max_row_age_days,
                       "min_active_repos": policy.min_active_repos},
            "repos": repos_out,
            "fleet": {"all_green_now": all_green_now, "streak_started_at": streak_start,
                      "days_held": days_held, "versions_in_streak": sorted(versions),
                      "armed_anywhere": armed_anywhere, "stale_repos": stale,
                      "active_repos": active, "parked_repos": parked_names,
                      "spurious": list(spurious),
                      "disarm_in_streak": disarm is not None,
                      "returned_in_streak": returned is not None,
                      "blockers": blockers, "notes": notes, "breaking_row": breaking},
            "verdict": verdict, "reasons": reasons}


JUDGE_BUDGET_S = 30.0
COMPACT_EVERY_H = 24


def read_verdict(path: Path | None = None) -> dict | None:
    p = path if path is not None else verdict_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        return None
    return data


def write_verdict(verdict: dict, path: Path | None = None) -> None:
    """tmp + os.replace, the autolearn precedent: a torn write can never
    corrupt the previous verdict."""
    p = path if path is not None else verdict_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(verdict, indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, p)


def _defects_of(row: dict) -> list[tuple[str, str]]:
    """(kind, target) pairs a row carries -- the defects a fleet-defect notice
    is about. `no_work` is deliberately not one: it is cost, not a broken
    mechanism (spec section 6)."""
    ev = row.get("evidence", {})
    out = []
    for gate, tools in sorted((ev.get("skip_streaks") or {}).items()):
        for tool in sorted(tools):
            out.append(("skip", f"{gate}/{tool}"))
    for name in sorted(set((ev.get("degraded_consumers") or []) + (ev.get("stood_down") or []))):
        out.append(("consumer", name))
    for entry in ev.get("resolver_defects") or []:
        out.append(("resolver", str(entry).split(" ")[0]))
    return out


def _post_transitions(previous: dict | None, verdict: dict, now: str) -> None:
    from aramid import notices
    prev_v = previous.get("verdict") if previous else None
    new_v = verdict["verdict"]
    info = verdict["fleet"]
    if new_v == READY and prev_v != READY:
        start = info["streak_started_at"]
        # A2: the repos that were counted. A verdict from before it has no
        # such list, and then every repo was.
        names = info.get("active_repos")
        if names is None:
            names = sorted(v["name"] for v in verdict["repos"].values())
        parked = info.get("parked_repos") or []
        parked_text = f" Parked, not counted: {', '.join(parked)}." if parked else ""
        versions = ", ".join(info["versions_in_streak"])
        notices.post("readiness-reached", f"streak:{start}",
                     title=(f"1.0 readiness reached -- streak since {start} "
                            f"({_days(info['days_held'])}, versions {versions}) across "
                            f"{len(names)} repos"),
                     body=("Every active repo has been green on every criterion since "
                           f"{start}: {', '.join(names)}.{parked_text} "
                           "`aramid fleet` prints the matrix. "
                           "RELEASING.md's \"The 1.0 gate\" names the manual criterion "
                           "(API freeze) still to check before tagging 1.0.0."),
                     evidence={"streak_started_at": start, "days_held": info["days_held"],
                               "versions": info["versions_in_streak"], "repos": names},
                     now=now)
        for n in notices.pending():
            if n.get("notice_kind") == "readiness-broken":
                notices.clear(n["id"], reason="readiness regained", now=now)
    elif prev_v == READY and new_v != READY:
        br = info.get("breaking_row")
        if br:
            key, title = f"run:{br['run_id']}", f"{br['name']} went red at {br['at']} ({br['detail']})"
        else:
            # No single row broke it (e.g. a registered repo lost its rows
            # entirely). Key on the PRIOR verdict's streak start rather than
            # `now`: a write failure leaves the stale READY prior in place,
            # so every retry re-detects the SAME transition with a
            # DIFFERENT `now` -- keying on `now` would mint a fresh notice
            # id every retry. The prior is what re-triggers the transition,
            # so it is what stays stable across retries. `at:<now>` remains
            # only as the last resort when the prior carries no streak
            # start, which a READY verdict never lacks.
            prev_start = (previous or {}).get("fleet", {}).get("streak_started_at")
            key = f"streak:{prev_start}" if prev_start else f"at:{now}"
            title = "fleet readiness lost -- " + "; ".join(verdict["reasons"])
        notices.post("readiness-broken", key, title=title,
                     body=(f"1.0 readiness was READY and is now {new_v.upper()}: "
                           + "; ".join(verdict["reasons"])
                           + ". The streak restarts from the next row on which every "
                             "registered repo is green."),
                     evidence={"breaking_row": br, "reasons": verdict["reasons"]}, now=now)
        for n in notices.pending():
            if n.get("notice_kind") == "readiness-reached":
                notices.clear(n["id"], reason="readiness lost", now=now)


def _post_parks(verdict: dict, now: str) -> None:
    """Amendment A2's log: one `repo-parked` notice per park, cleared by
    itself when the repo counts again or leaves the registry. The key holds
    `parked_since`, so the same park is never posted twice (`notices.post`
    de-duplicates, an ack included) and a later park is a new notice."""
    from aramid import notices
    repos = verdict.get("repos", {})
    window = verdict.get("policy", {}).get("max_row_age_days")
    current: set[str] = set()
    for key, v in repos.items():
        if not v.get("parked"):
            continue
        name, since, latest_at = v["name"], v.get("parked_since"), v.get("latest_at")
        nkey = f"parked:{key}:{since}"
        current.add(notices.notice_id("repo-parked", nkey))
        last = f"since {str(latest_at)[:10]}" if latest_at else "since it was registered"
        out = f"To take it out for good: `aramid fleet deregister {name}`."
        if latest_at:
            body = (f"{name} has recorded no gate run in {window} days and its last row was "
                    "green, so it no longer counts toward 1.0 readiness. The drain still "
                    "walks it. Its next gate run counts it again and restarts the streak. "
                    f"{out} This notice clears itself when the repo returns.")
        else:
            # Never gated: there is no row to call green, and nothing to return to.
            body = (f"{name} has recorded no gate run since it was registered more than "
                    f"{window} days ago, so it does not count toward 1.0 readiness. The "
                    "drain still walks it. Its first gate run counts it and restarts the "
                    f"streak. {out} This notice clears itself when the repo gates.")
        notices.post("repo-parked", nkey, title=f"{name} parked -- no gate run {last}",
                     body=body,
                     evidence={"repo": key, "name": name, "parked_since": since,
                               "latest_at": latest_at}, now=now)
    for n in notices.uncleared():
        if n.get("notice_kind") != "repo-parked" or n["id"] in current:
            continue
        gone = n.get("evidence", {}).get("repo") not in repos
        notices.clear(n["id"], reason="deregistered" if gone else "returned", now=now)


def _post_defects(rows: list[dict], registered: dict[str, str], policy: Policy,
                  now: str) -> None:
    from aramid import notices
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for r in sorted(rows, key=lambda r: str(r.get("at", ""))):
        if r.get("repo") in registered:
            by_repo[r["repo"]].append(r)
    uncleared = {n["id"]: n for n in notices.uncleared() if n.get("notice_kind") == "fleet-defect"}
    for repo, seq in by_repo.items():
        name = seq[-1].get("name") or registered[repo]
        latest = set(_defects_of(seq[-1]))
        window = seq[-policy.defect_rows:]
        persistent = (set.intersection(*(set(_defects_of(r)) for r in window))
                      if len(window) >= policy.defect_rows else set())
        for kind, target in sorted(persistent):
            notices.post("fleet-defect", f"defect:{repo}:{kind}:{target}",
                         title=f"{name}: {kind} {target} on the last {policy.defect_rows} gate runs",
                         body=(f"{name} has carried the same {kind} defect ({target}) on its last "
                               f"{policy.defect_rows} consecutive gate runs. Run `aramid status` "
                               f"in that repo for the line and the remedy; this notice clears "
                               "itself on the first row without it."),
                         evidence={"repo": repo, "name": name, "kind": kind, "target": target,
                                   "rows": policy.defect_rows}, now=now)
        for n in uncleared.values():
            ev = n.get("evidence", {})
            if ev.get("repo") == repo and (ev.get("kind"), ev.get("target")) not in latest:
                notices.clear(n["id"], reason="defect absent from latest row", now=now)


def _row_owners(row: dict) -> list[str]:
    """The registry keys a stored row can count for: its own repo and, for a
    row written in a linked worktree, the main checkout (`judge`)."""
    return [k for k in (row.get("repo"), row.get("worktree_of")) if isinstance(k, str)]


def _maybe_compact(previous: dict | None, now: str) -> str | None:
    """Rewrite the store without rows older than ROW_WINDOW_DAYS, at most
    once per COMPACT_EVERY_H, tmp + replace, under the drain lock the caller
    holds. A gate appending between the read and the replace loses its row;
    accepted for a once-a-day rewrite. On Windows a concurrently open file
    makes os.replace raise; that is reported and skipped, never fatal.

    Works from the store's RAW lines, not `read_rows()`'s parsed list:
    `read_rows()` silently drops a row whose `schema_version` is newer than
    this build's own, and rewriting from that list would delete such a row
    outright rather than merely leave it unjudged. A line this build cannot
    read -- it fails to parse, its schema is newer, or its `at` is missing
    or unparsable -- is always kept verbatim; only a row this build CAN
    read, and whose `at` is older than the window, is dropped.

    One old row per repo is kept as well: its newest, by `repo` and by
    `worktree_of`, since `judge` reads that row whatever its age (a repo's
    last evidence must not expire into "no rows"; drain review 362c0c)."""
    last = (previous or {}).get("compacted_at")
    now_dt, last_dt = _parse(now), _parse(last) if last else None
    if last_dt is not None and now_dt is not None and now_dt - last_dt < timedelta(hours=COMPACT_EVERY_H):
        return last
    p = health_path()
    cutoff = now_dt - timedelta(days=ROW_WINDOW_DAYS)
    try:
        text = p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""
    except OSError as exc:
        print(f"aramid: fleet: compaction skipped ({exc})", file=sys.stderr)
        return last
    keep_lines: list[str] = []
    dropped = 0
    parsed: list[tuple[str, dict | None, datetime | None]] = []
    newest: dict[str, datetime] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            parsed.append((line, None, None))
            continue
        version = obj.get("schema_version") if isinstance(obj, dict) else None
        if not isinstance(version, int) or isinstance(version, bool) or version > SCHEMA_VERSION:
            parsed.append((line, None, None))    # unreadable shape: age cannot be judged
            continue
        at_dt = _parse(obj.get("at"))
        parsed.append((line, obj, at_dt))
        if at_dt is not None:
            for owner in _row_owners(obj):
                if owner not in newest or at_dt > newest[owner]:
                    newest[owner] = at_dt
    for line, obj, at_dt in parsed:
        if obj is None or at_dt is None or at_dt >= cutoff:
            keep_lines.append(line)
        elif any(newest.get(owner) == at_dt for owner in _row_owners(obj)):
            keep_lines.append(line)              # a repo's last row never expires
        else:
            dropped += 1
    if dropped or not p.exists():
        try:
            tmp = p.with_name(p.name + ".tmp")
            tmp.write_text("".join(line + "\n" for line in keep_lines), encoding="utf-8")
            os.replace(tmp, p)
        except OSError as exc:
            print(f"aramid: fleet: compaction skipped ({exc})", file=sys.stderr)
            return last
    return now


def run_judgement(now: str, *, aramid_version: str, entries: list[dict] | None = None,
                  policy: Policy | None = None) -> dict | None:
    """The drain's seam (spec section 6). Reads ONLY the store; never a
    ledger. Never raises; over budget it reports and writes nothing."""
    started = _monotonic()
    try:
        policy = policy or load_policy()
        registered = registered_repos(entries)
        spurious = spurious_entries(entries)
        previous = read_verdict()
        rows = read_rows()
        verdict = judge(rows, registered, policy, now, aramid_version=aramid_version,
                        spurious=spurious, vanished=vanished_repos(entries),
                        registered_at=registration_times(entries))
        if _monotonic() - started > JUDGE_BUDGET_S:
            print(f"aramid: fleet: judgement over the {JUDGE_BUDGET_S:.0f}s budget; "
                  "verdict not written", file=sys.stderr)
            return None
        _post_transitions(previous, verdict, now)
        _post_defects(rows, registered, policy, now)
        _post_parks(verdict, now)
        verdict["compacted_at"] = _maybe_compact(previous, now)
        write_verdict(verdict)
        return verdict
    except Exception as exc:
        print(f"aramid: fleet: judgement skipped ({exc})", file=sys.stderr)
        return None


_LABELS = {READY: "READY", NOT_READY: "NOT READY", INSUFFICIENT: "INSUFFICIENT DATA"}


def _stale_suffix(computed_at, now: str | None) -> str:
    """Empty unless `now` is given and is more than STALE_AFTER_H hours past
    `computed_at`: the marker that the scheduled drain has stopped running."""
    if now is None:
        return ""
    now_dt, computed_dt = _parse(now), _parse(computed_at)
    if now_dt is None or computed_dt is None:
        return ""
    if now_dt - computed_dt > timedelta(hours=STALE_AFTER_H):
        return f" (stale: computed {computed_at})"
    return ""


def _days(value) -> str:
    """A streak length for display: one decimal, TRUNCATED, never rounded up.
    Every surface prints the streak with this (FN-28: the readiness line
    used `:.0f` beside its own blocker's `:.1f`, "streak 1d, ... streak 0.7d
    < 14d"), and rounding would print a 13.96-day streak as "14.0d < 14d",
    at the bar it is failing. No float-error guard is needed: `days_held` is
    rounded to 2 decimals, and floor(x * 10) is exact for every such value
    from 0 to 2000 days (checked 2026-10-09)."""
    return f"{math.floor(float(value or 0.0) * 10) / 10:.1f}d"


def readiness_line(verdict: dict | None, *, now: str | None = None) -> str:
    """Spec section 8's one-line verdict; the same string on every surface."""
    if verdict is None:
        return "fleet: no verdict yet -- the next `aramid drain` computes it"
    repos = verdict.get("repos", {})
    info = verdict.get("fleet", {})
    # Amendment A2: a parked repo is not counted, on either side of the
    # slash. A verdict written before it has no `active_repos` and keeps
    # the wording it was written under.
    parked = sorted((v for v in repos.values() if v.get("parked")),
                    key=lambda v: str(v.get("name", "")).casefold())
    green = sum(1 for v in repos.values() if v.get("green") and not v.get("parked"))
    counted = "active repos" if "active_repos" in info else "repos"
    label = _LABELS.get(verdict.get("verdict"), str(verdict.get("verdict")).upper())
    line = (f"fleet: 1.0 readiness {label} -- {green}/{len(repos) - len(parked)} "
            f"{counted} green, "
            f"streak {_days(info.get('days_held', 0.0))}, "
            f"versions {len(info.get('versions_in_streak', []))}/"
            f"{verdict.get('policy', {}).get('min_versions', 2)}")
    tail = []
    red = [f"{v['name']} ({', '.join(v['red_criteria'])})"
           for v in repos.values() if v.get("red_criteria")]
    if red:
        tail.append("red: " + ", ".join(red))
    missing = sorted((v["name"] for v in repos.values()
                      if not v.get("rows") and not v.get("missing_path")), key=str.casefold)
    if missing:
        tail.append("no rows: " + ", ".join(missing))
    gone = sorted((v["name"] for v in repos.values() if v.get("missing_path")), key=str.casefold)
    tail.extend(f"missing path: {n} (`aramid fleet deregister {n}`)" for n in gone)
    # Amendment A1: verdicts written before it carry no `stale` key and
    # render exactly as before.
    stale = [f"{v['name']} ({float(v.get('age_days') or 0.0):.1f}d)"
             for v in repos.values() if v.get("stale") and not v.get("missing_path")]
    if stale:
        window = verdict.get("policy", {}).get("max_row_age_days")
        tail.append("stale: " + ", ".join(stale) + (f" -- window {window}d" if window else ""))
    if parked:
        tail.append("parked: " + ", ".join(
            f"{v['name']} (since {str(v['parked_since'])[:10]})" if v.get("parked_since")
            else str(v["name"]) for v in parked))
    tail.extend(info.get("blockers", []))
    tail.extend(info.get("notes", []))
    line += "; " + "; ".join(tail) if tail else ""
    return line + _stale_suffix(verdict.get("computed_at"), now)


def delivery_lines(root, *, surface: str, now: str, policy: Policy | None = None) -> list[str]:
    """The readiness line plus every notice due in this repo (spec section
    7): shown at most once per `repeat_hours` per repo, each display recorded
    as a `shown` event. Fail-open: any error yields NO lines -- the hook's
    own contract is a block built fully or not at all."""
    try:
        from aramid import notices as notices_mod
        policy = policy or load_policy()
        lines = [readiness_line(read_verdict(), now=now)]
        repo = repo_key(root)
        due = notices_mod.due(repo, now, policy.repeat_hours)
        shown, remaining = due[:MAX_NOTICE_LINES], due[MAX_NOTICE_LINES:]
        for n in shown:
            lines.append(notices_mod.render_line(n))
            notices_mod.mark_shown(n["id"], repo=repo, surface=surface, now=now)
        if remaining:
            lines.append(f"fleet: ... and {len(remaining)} more notice(s) pending "
                         "-- see `aramid notices`")
        return lines
    except Exception:
        return []


_COLUMNS = (("no_skip_streak", "skip"), ("consumers_healthy", "consumers"),
            ("resolvers_ok", "resolvers"), ("no_self_inflicted_block", "self-block"),
            ("dep_audit_ran", "dep-audit"))


def _snapshot_line(computed_at, now: str | None) -> str:
    """When the verdict was judged, and how long ago (interop round 347,
    operator 2026-11-24). bytesTTS read a 15:00Z snapshot at ~16:10Z that
    left out a repo registered at 16:07Z, and the text printed no time; it
    did only past STALE_AFTER_H, as the verdict line's suffix."""
    if _parse(computed_at) is None:
        return "snapshot computed: unknown"
    now_dt = _parse(now) if now is not None else None
    if now_dt is None:
        return f"snapshot computed {computed_at}"
    from aramid.handover import age
    return f"snapshot computed {computed_at} ({age(str(computed_at), now_dt)} ago)"


def render_report(verdict: dict | None, policy: Policy, *, now: str | None = None) -> str:
    """`aramid fleet`: the repo x criteria matrix, the streak, the verdict
    with its reasons. `ok` / `RED` / `-` (not applicable, or no rows)."""
    window = (f"{policy.max_row_age_days}-day row window" if policy.max_row_age_days > 0
              else "no row window")
    out = [f"fleet health -- 1.0 readiness (policy: {policy.min_days} days, "
           f"{policy.min_versions} versions, {window})", ""]
    if verdict is None:
        out.append("  no verdict yet -- the next `aramid drain` computes it")
        return "\n".join(out)
    out.insert(1, _snapshot_line(verdict.get("computed_at"), now))
    repos = list(verdict.get("repos", {}).values())
    width = max([len(v["name"]) for v in repos] + [4])
    cells_header = "  ".join(f"{label:<10}" for _k, label in _COLUMNS)
    out.append(f"  {'repo':<{width}}  {'rows':>4}  {'latest':<25}  {cells_header}".rstrip())
    for v in repos:
        if v.get("missing_path"):
            # Its rows say what it was, not what it is: no row can come again.
            latest, cells = "(missing path)", ["-"] * len(_COLUMNS)
        elif not v.get("rows"):
            latest, cells = "(no rows)", ["-"] * len(_COLUMNS)
        else:
            latest = str(v.get("latest_at"))
            crit = v.get("criteria", {})
            cells = ["-" if crit.get(k) is None else ("ok" if crit.get(k) is True else "RED")
                     for k, _label in _COLUMNS]
        out.append((f"  {v['name']:<{width}}  {v['rows']:>4}  {latest:<25}  "
                    + "  ".join(f"{c:<10}" for c in cells)).rstrip())
        if v.get("from_worktree"):
            out.append(f"  {'':<{width}}  (latest row from worktree {v['from_worktree']})")
        if v.get("parked"):
            # Amendment A2: its cells are what it last recorded, not counted.
            days = verdict.get("policy", {}).get("max_row_age_days")
            out.append(f"  {'':<{width}}  (parked since {v['parked_since']} -- no gate run in "
                       f"{days} days; its next one restarts the streak)"
                       if v.get("parked_since") and days else
                       f"  {'':<{width}}  (parked -- its next gate run restarts the streak)")
    info = verdict.get("fleet", {})
    out.append("")
    if info.get("streak_started_at"):
        versions = ", ".join(info.get("versions_in_streak", [])) or "none"
        out.append(f"  streak: since {info['streak_started_at']} "
                   f"({_days(info.get('days_held'))}, versions: {versions})")
    else:
        out.append("  streak: none (fleet not green)")
    out.append(f"  armed anywhere: {'yes' if info.get('armed_anywhere') else 'no'}")
    if "active_repos" in info:
        floor = verdict.get("policy", {}).get("min_active_repos")
        out.append(f"  active repos: {len(info['active_repos'])}"
                   + (f" (floor {floor})" if floor is not None else ""))
    out.append("")
    out.append(f"verdict: {verdict.get('verdict')}"
              + _stale_suffix(verdict.get("computed_at"), now))
    out.extend(f"  - {r}" for r in verdict.get("reasons", []))
    return "\n".join(out)
