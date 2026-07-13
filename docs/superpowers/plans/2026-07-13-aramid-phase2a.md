# Aramid Phase 2a Implementation Plan — Watcher Chassis + Regression Attack Pack

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Zero-token commit triage (post-commit hook + catch-up sweep), a risk-scored coalescing queue in the per-repo ledger, a scheduled budgeted drain with pluggable consumers, and the regression attack pack as the first consumer — per the approved spec `docs/superpowers/specs/2026-07-12-aramid-phase2a-chassis-design.md`.

**Architecture:** Everything extends Phase 1's chassis: new event types ride the existing event-sourced SQLite ledger; the post-commit shim reuses the hook machinery; triage is pure computation (git plumbing + regex + ledger + optional graphite graph read); drain iterates a central registry and hands queue items to consumers; pack rules are plain semgrep rules the existing runner picks up in the normal gates.

**Tech Stack:** Python 3.11+ stdlib + existing deps (`tomli-w` for TOML writes). NO new runtime dependencies. Pack YAML is hand-rendered (json-encoded scalars are valid YAML) — PyYAML stays dev-only.

## Global Constraints

- **Zero LLM calls, zero tokens anywhere in 2a** (spec §1 non-goals).
- Triage is pure computation — it must **never spawn a scan tool**; self-budget 2s hard / ~200ms typical (spec §2).
- Post-commit hook is **fail-open absolutely**: any failure exits 0; a commit can never be blocked or noticeably slowed (spec §6).
- Scoring weights verbatim (spec §3): security-surface path **+30**, risky content delta **+25**, novelty **+20**, blast radius **0–25**; clamp to 100; default `min_score = 40`.
- Coalescing (spec §4): **at most one `queued` item per repo**; range extends (base kept, head advances), `score = max(old, new)`, reasons union.
- Sweep bootstrap (spec §2): a repo with no triage history sweeps `HEAD` only — registering a repo must never queue its entire past.
- **Central state is exactly one file:** `~/.aramid/repos.toml` (spec §4).
- Config defaults verbatim (spec §4): `[triage] min_score=40, extra_security_paths=[]`; `[drain] interval_hours=4, max_items_per_drain=10, item_expiry_days=30, wall_clock_budget_s=600`; `[pack] enabled=true`.
- A rotated-secret pack rule must **NEVER contain the literal secret** (spec §5) — golden tests assert the seeded literal is absent.
- Pack rule ids are namespaced `aramid-regression.*`; block-tier sources yield ids `aramid-regression.block.*` enforced via existing `block_rules` (spec §5).
- Drain exit codes reuse the Phase 1 contract: 0 ok / 2 degraded / 3 engine error (spec §2).
- Scheduler task name `aramid-drain`, registered with StartWhenAvailable ("run as soon as possible after a missed start", spec §6) via `schtasks /XML`.
- graphite artifacts are read as *input* (blast radius), never scan targets; absent graph → signal contributes 0 (spec §6, Phase 1 §8b).
- Timestamps ISO-8601 UTC; clocks injected as seams like Phase 1 (`clock: Callable[[], str]`).
- Windows-first: full suite must pass on win32 locally and on `windows-latest` CI. Tools live in `%APPDATA%\Python\Python314\Scripts` (NOT on PATH) — tests needing live semgrep reuse the discovery/skip pattern from `tests/integration/test_semgrep_rules.py`.
- Commit messages end with: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

## Interface facts from Phase 1 (verbatim — do not re-derive)

- `Event(type: EventType, run_id: str, at: str, finding_id: str | None = None, payload: dict = {})` (frozen dataclass, `aramid/models.py`). Ledger stores `finding_id` as a plain indexed TEXT column — queue events reuse it to carry the **queue item id**.
- `Ledger(db_path: Path)`, `.append(event)`, `.events() -> list[Event]`, `.record_run(run_id, at, gate, scope_tools, scope_files, findings)`, `.open_findings() -> dict`, `.compact() -> int`, `.close()` (`aramid/ledger.py`). `compact()` deletes every row not in its keep-set — Task 2 extends it or queue state would be destroyed.
- `EventType` is a `StrEnum` in `aramid/models.py` with members RUN_STARTED…BASELINE_SNAPSHOT.
- Hooks: `GATES = (Gate.PRE_COMMIT, Gate.PRE_PUSH)`, `MARKER_START = "# >>> aramid managed >>>"`, `MARKER_END = "# <<< aramid managed <<<"`, `CHAINED_SUFFIX = ".aramid-chained"`, `render_shim(gate, interpreter) -> bytes`, `install(root, interpreter)`, `uninstall(root)`, `hooks_dir(root)`, `win_sh_path(p)` (`aramid/hooks.py`). Shims are `\n`-only bytes with the baked `INTERP="{win_sh_path(interpreter)}"` line and a chain-check block executing `"$DIR/<hook>.aramid-chained"` first.
- `RunContext(root: Path, files: list[str] = [], rng: str | None = None, pkg_manager: str | None = None, stacks: set[str] = set())` (`aramid/runners/base.py`).
- semgrep runner: `VENDORED_RULES_PATH`, `_build_argv(ctx)` returns `["semgrep", "--config", str(VENDORED_RULES_PATH), "--json", "--metrics=off", "--quiet", "--", *ctx.files]`, `_canonical_rule_id(check_id)` strips everything before `"owasp-top-ten."` (`aramid/runners/semgrep.py`).
- `config.Config` fields: `schema_version, semgrep_block_armed, bake_started, ignore_paths, test_command, scope_subpath, timeouts, block_rules` — Task 4 appends `triage: dict, drain: dict, pack: dict`.
- `gitutil`: `repo_root`, `read_blob`, `resolve_range`, `staged_files`, `all_tracked_files`, `changed_files`, `newest_commit_touching`, `is_tracked`, `read_for_fingerprint`, `_run(root, *args)`, `NotARepo`.
- `normalize(raws, root, ref_for, salt, gate, classify) -> list[Finding]`; `policy.classify(tool, rule, severity_raw, gate, cfg)`; `redact.redact(secret, salt) -> (preview, hash)` where `preview = f"{secret[:2]}…{secret[-2:]}"` and normalize stores `evidence = f"{preview} (sha256:{hash})"`.
- graphite `graph-out/graph.json` shape (verified live): `{"nodes": [{"id", "kind", "name", "source_file", ...}], "edges": [{"source", "target", "relation", ...}], ...}` — node ids map to `source_file`; dependents of a file = distinct `edge["source"]` whose `edge["target"]`'s node has that `source_file`.
- cli dispatch: subcommand → `aramid.commands.<name>.cmd_<name>`; argparse SystemExit remapped to 3; `root = Path.cwd()` except init/uninstall.
- Test conventions: plain pytest functions, `tmp_path`, real git repos via `_git`/`_repo` helpers, no conftest fixtures.

---

## Milestone M1 — Queue events & model

### Task 1: Queue event types + queue module (materialize, enqueue/coalesce, triage records)

**Files:**
- Modify: `src/aramid/models.py` (EventType — append 6 members)
- Create: `src/aramid/queue.py`
- Test: `tests/unit/test_queue.py`

**Interfaces:**
- Consumes: `Event`, `EventType`, `Ledger.append/events` (Phase 1).
- Produces (later tasks rely on these EXACT names):
  - `EventType.TRIAGE_RECORDED/QUEUE_ITEM_ADDED/QUEUE_ITEM_COALESCED/QUEUE_ITEM_DRAINED/QUEUE_ITEM_EXPIRED/CONSUMER_RUN_FINISHED`
  - `queue.QueueItem` (frozen dataclass: `id, base: str | None, head: str, score: int, reasons: tuple[str, ...], state: str, created_at: str, updated_at: str`; property `range_str`)
  - `queue.materialize_queue(events: list[Event]) -> dict[str, QueueItem]`
  - `queue.queued_item(items: dict[str, QueueItem]) -> QueueItem | None`
  - `queue.enqueue(ledger, at: str, base: str | None, head: str, score: int, reasons: list[str]) -> QueueItem`
  - `queue.mark_drained(ledger, item_id: str, run_id: str, at: str) -> None`
  - `queue.expire_stale(ledger, now_iso: str, expiry_days: int) -> list[str]`
  - `queue.record_triage(ledger, at: str, base: str | None, head: str, score: int, queued: bool, paths: list[str]) -> None`
  - `queue.last_triaged_head(ledger) -> str | None`
  - `queue.triaged_paths(ledger) -> set[str]`

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_queue.py
from datetime import datetime, timedelta, timezone

from aramid import queue
from aramid.ledger import Ledger
from aramid.models import EventType


def _iso(dt) -> str:
    return dt.isoformat()


NOW = datetime(2026, 7, 13, 12, 0, 0, tzinfo=timezone.utc)


def test_new_event_types_exist():
    assert EventType.TRIAGE_RECORDED.value == "triage_recorded"
    assert EventType.QUEUE_ITEM_ADDED.value == "queue_item_added"
    assert EventType.QUEUE_ITEM_COALESCED.value == "queue_item_coalesced"
    assert EventType.QUEUE_ITEM_DRAINED.value == "queue_item_drained"
    assert EventType.QUEUE_ITEM_EXPIRED.value == "queue_item_expired"
    assert EventType.CONSUMER_RUN_FINISHED.value == "consumer_run_finished"


def test_enqueue_then_materialize_roundtrip(tmp_path):
    led = Ledger(tmp_path / "l.db")
    item = queue.enqueue(led, _iso(NOW), "aaa1111", "bbb2222", 55, ["security-path: auth.py"])
    items = queue.materialize_queue(led.events())
    got = items[item.id]
    assert got.state == "queued"
    assert got.base == "aaa1111" and got.head == "bbb2222"
    assert got.score == 55
    assert got.reasons == ("security-path: auth.py",)
    assert got.range_str == "aaa1111..bbb2222"
    led.close()


def test_root_commit_item_has_no_base(tmp_path):
    led = Ledger(tmp_path / "l.db")
    item = queue.enqueue(led, _iso(NOW), None, "bbb2222", 41, ["novelty: 3 new paths"])
    got = queue.materialize_queue(led.events())[item.id]
    assert got.base is None
    assert got.range_str == "bbb2222"
    led.close()


def test_enqueue_coalesces_into_existing_queued_item(tmp_path):
    """Spec §4: at most one queued item per repo; base kept, head advances,
    score is max, reasons union."""
    led = Ledger(tmp_path / "l.db")
    first = queue.enqueue(led, _iso(NOW), "aaa", "bbb", 55, ["security-path: auth.py"])
    second = queue.enqueue(led, _iso(NOW + timedelta(minutes=5)), "bbb", "ccc", 41,
                           ["novelty: 1 new path", "security-path: auth.py"])
    assert second.id == first.id  # same item, coalesced
    items = queue.materialize_queue(led.events())
    assert len([i for i in items.values() if i.state == "queued"]) == 1
    got = items[first.id]
    assert got.base == "aaa" and got.head == "ccc"
    assert got.score == 55  # max(55, 41)
    assert got.reasons == ("novelty: 1 new path", "security-path: auth.py")  # sorted union
    assert got.updated_at == _iso(NOW + timedelta(minutes=5))
    types = [e.type for e in led.events()]
    assert types.count(EventType.QUEUE_ITEM_ADDED) == 1
    assert types.count(EventType.QUEUE_ITEM_COALESCED) == 1
    led.close()


def test_mark_drained_transitions_state(tmp_path):
    led = Ledger(tmp_path / "l.db")
    item = queue.enqueue(led, _iso(NOW), "a", "b", 50, ["r"])
    queue.mark_drained(led, item.id, "run42", _iso(NOW + timedelta(hours=1)))
    got = queue.materialize_queue(led.events())[item.id]
    assert got.state == "drained"
    assert queue.queued_item(queue.materialize_queue(led.events())) is None
    led.close()


def test_drained_item_does_not_block_new_enqueue(tmp_path):
    led = Ledger(tmp_path / "l.db")
    old = queue.enqueue(led, _iso(NOW), "a", "b", 50, ["r"])
    queue.mark_drained(led, old.id, "run1", _iso(NOW))
    new = queue.enqueue(led, _iso(NOW + timedelta(hours=2)), "b", "c", 44, ["r2"])
    assert new.id != old.id
    assert queue.materialize_queue(led.events())[new.id].state == "queued"
    led.close()


def test_expire_stale_only_past_expiry(tmp_path):
    led = Ledger(tmp_path / "l.db")
    old = queue.enqueue(led, _iso(NOW - timedelta(days=31)), "a", "b", 50, ["r"])
    expired = queue.expire_stale(led, _iso(NOW), expiry_days=30)
    assert expired == [old.id]
    assert queue.materialize_queue(led.events())[old.id].state == "expired"
    fresh = queue.enqueue(led, _iso(NOW - timedelta(days=29)), "b", "c", 50, ["r"])
    assert queue.expire_stale(led, _iso(NOW), expiry_days=30) == []
    assert queue.materialize_queue(led.events())[fresh.id].state == "queued"
    led.close()


def test_triage_records_head_and_paths(tmp_path):
    led = Ledger(tmp_path / "l.db")
    assert queue.last_triaged_head(led) is None
    queue.record_triage(led, _iso(NOW), None, "abc123", 12, False, ["a.py", "b.md"])
    queue.record_triage(led, _iso(NOW + timedelta(minutes=1)), "abc123", "def456", 66, True,
                        ["src/auth.py"])
    assert queue.last_triaged_head(led) == "def456"
    assert queue.triaged_paths(led) == {"a.py", "b.md", "src/auth.py"}
    led.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run (repo root, PATH note in Global Constraints):
`python -m pytest tests/unit/test_queue.py -v`
Expected: FAIL — `AttributeError: TRIAGE_RECORDED` / `ModuleNotFoundError: aramid.queue`.

- [ ] **Step 3: Implement**

Append to the `EventType` enum in `src/aramid/models.py` (keep existing members untouched):

```python
    # --- Phase 2a: triage/queue/drain events (spec section 4) ---
    TRIAGE_RECORDED = "triage_recorded"
    QUEUE_ITEM_ADDED = "queue_item_added"
    QUEUE_ITEM_COALESCED = "queue_item_coalesced"
    QUEUE_ITEM_DRAINED = "queue_item_drained"
    QUEUE_ITEM_EXPIRED = "queue_item_expired"
    CONSUMER_RUN_FINISHED = "consumer_run_finished"
```

Create `src/aramid/queue.py`:

```python
"""queue -- risk-scored review queue, materialized from ledger events.

Same event-sourcing discipline as Phase 1: events are appended, never
mutated; queue state is replayed by materialize_queue(). Queue events
reuse the ledger's finding_id column to carry the queue item id (it is
a plain indexed TEXT column). Invariant (spec section 4): at most one
"queued" item exists per repo ledger at any time -- enqueue() coalesces
into it (base kept, head advances, score = max, reasons union).
"""
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from aramid.ledger import Ledger
from aramid.models import Event, EventType

QUEUED = "queued"
DRAINED = "drained"
EXPIRED = "expired"


@dataclass(frozen=True)
class QueueItem:
    id: str
    base: str | None
    head: str
    score: int
    reasons: tuple[str, ...]
    state: str
    created_at: str
    updated_at: str

    @property
    def range_str(self) -> str:
        return f"{self.base}..{self.head}" if self.base else self.head


def materialize_queue(events: list[Event]) -> dict[str, QueueItem]:
    items: dict[str, QueueItem] = {}
    for e in events:
        if e.type is EventType.QUEUE_ITEM_ADDED:
            items[e.finding_id] = QueueItem(
                id=e.finding_id, base=e.payload.get("base"), head=e.payload["head"],
                score=e.payload["score"], reasons=tuple(e.payload.get("reasons", [])),
                state=QUEUED, created_at=e.at, updated_at=e.at)
        elif e.type is EventType.QUEUE_ITEM_COALESCED and e.finding_id in items:
            prev = items[e.finding_id]
            items[e.finding_id] = QueueItem(
                id=prev.id, base=e.payload.get("base"), head=e.payload["head"],
                score=e.payload["score"], reasons=tuple(e.payload.get("reasons", [])),
                state=prev.state, created_at=prev.created_at, updated_at=e.at)
        elif e.type is EventType.QUEUE_ITEM_DRAINED and e.finding_id in items:
            prev = items[e.finding_id]
            items[e.finding_id] = QueueItem(
                id=prev.id, base=prev.base, head=prev.head, score=prev.score,
                reasons=prev.reasons, state=DRAINED,
                created_at=prev.created_at, updated_at=e.at)
        elif e.type is EventType.QUEUE_ITEM_EXPIRED and e.finding_id in items:
            prev = items[e.finding_id]
            items[e.finding_id] = QueueItem(
                id=prev.id, base=prev.base, head=prev.head, score=prev.score,
                reasons=prev.reasons, state=EXPIRED,
                created_at=prev.created_at, updated_at=e.at)
    return items


def queued_item(items: dict[str, QueueItem]) -> QueueItem | None:
    for item in items.values():
        if item.state == QUEUED:
            return item
    return None


def enqueue(ledger: Ledger, at: str, base: str | None, head: str,
            score: int, reasons: list[str]) -> QueueItem:
    existing = queued_item(materialize_queue(ledger.events()))
    if existing is not None:
        merged_reasons = sorted(set(existing.reasons) | set(reasons))
        payload = {"absorbed": f"{base}..{head}" if base else head,
                   "base": existing.base, "head": head,
                   "score": max(existing.score, score), "reasons": merged_reasons}
        ledger.append(Event(EventType.QUEUE_ITEM_COALESCED, uuid.uuid4().hex, at,
                            finding_id=existing.id, payload=payload))
        return QueueItem(id=existing.id, base=existing.base, head=head,
                         score=max(existing.score, score),
                         reasons=tuple(merged_reasons), state=QUEUED,
                         created_at=existing.created_at, updated_at=at)
    item_id = uuid.uuid4().hex
    payload = {"base": base, "head": head, "score": score,
               "reasons": sorted(set(reasons))}
    ledger.append(Event(EventType.QUEUE_ITEM_ADDED, uuid.uuid4().hex, at,
                        finding_id=item_id, payload=payload))
    return QueueItem(id=item_id, base=base, head=head, score=score,
                     reasons=tuple(sorted(set(reasons))), state=QUEUED,
                     created_at=at, updated_at=at)


def mark_drained(ledger: Ledger, item_id: str, run_id: str, at: str) -> None:
    ledger.append(Event(EventType.QUEUE_ITEM_DRAINED, run_id, at, finding_id=item_id))


def expire_stale(ledger: Ledger, now_iso: str, expiry_days: int) -> list[str]:
    now = datetime.fromisoformat(now_iso)
    expired: list[str] = []
    for item in materialize_queue(ledger.events()).values():
        if item.state != QUEUED:
            continue
        created = datetime.fromisoformat(item.created_at)
        if now - created > timedelta(days=expiry_days):
            age = (now - created).days
            ledger.append(Event(EventType.QUEUE_ITEM_EXPIRED, uuid.uuid4().hex, now_iso,
                                finding_id=item.id, payload={"age_days": age}))
            expired.append(item.id)
    return expired


def record_triage(ledger: Ledger, at: str, base: str | None, head: str,
                  score: int, queued: bool, paths: list[str]) -> None:
    ledger.append(Event(EventType.TRIAGE_RECORDED, uuid.uuid4().hex, at,
                        payload={"base": base, "head": head, "score": score,
                                 "queued": queued, "paths": sorted(paths)}))


def last_triaged_head(ledger: Ledger) -> str | None:
    head = None
    for e in ledger.events():
        if e.type is EventType.TRIAGE_RECORDED:
            head = e.payload.get("head")
    return head


def triaged_paths(ledger: Ledger) -> set[str]:
    seen: set[str] = set()
    for e in ledger.events():
        if e.type is EventType.TRIAGE_RECORDED:
            seen.update(e.payload.get("paths", []))
    return seen
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_queue.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/models.py src/aramid/queue.py tests/unit/test_queue.py
git commit -m "feat(queue): triage/queue event types and coalescing queue model"
```

---

### Task 2: `Ledger.compact()` preserves queue/triage/drain state

**Files:**
- Modify: `src/aramid/ledger.py` (the `compact` method)
- Test: `tests/unit/test_ledger_compact.py` (append tests)

**Interfaces:**
- Consumes: `queue.materialize_queue`, `queue.QUEUED` (Task 1).
- Produces: `compact()` keep-set additionally retains: ALL `queue_item_*` events belonging to items whose materialized state is `queued`; the LATEST `triage_recorded`; the LATEST `consumer_run_finished`; the LATEST `run_finished` (status's "last run" line survives compaction). Events of drained/expired items and older triage/consumer/run-finished rows are deleted.

**Background for the implementer:** current `compact()` (ledger.py:104-137) keeps only latest-detect-per-finding, post-detect terminal transitions, and baseline snapshots — everything else is deleted, which would destroy Phase 2a state.

- [ ] **Step 1: Write the failing tests** (append to `tests/unit/test_ledger_compact.py`)

```python
from aramid import queue
from aramid.models import Event, EventType


def test_compact_keeps_queued_item_events_and_latest_triage(tmp_path):
    led = Ledger(tmp_path / "l.db")
    queue.record_triage(led, "2026-07-13T10:00:00+00:00", None, "aaa", 10, False, ["x.py"])
    queue.record_triage(led, "2026-07-13T11:00:00+00:00", "aaa", "bbb", 55, True, ["auth.py"])
    item = queue.enqueue(led, "2026-07-13T11:00:00+00:00", "aaa", "bbb", 55, ["r1"])
    queue.enqueue(led, "2026-07-13T11:30:00+00:00", "bbb", "ccc", 40, ["r2"])  # coalesce
    led.compact()
    items = queue.materialize_queue(led.events())
    got = items[item.id]
    assert got.state == "queued" and got.base == "aaa" and got.head == "ccc"
    assert got.score == 55
    assert queue.last_triaged_head(led) == "bbb"
    triage_events = [e for e in led.events() if e.type is EventType.TRIAGE_RECORDED]
    assert len(triage_events) == 1  # only the latest survives
    led.close()


def test_compact_drops_terminal_queue_items_keeps_latest_consumer_and_run(tmp_path):
    led = Ledger(tmp_path / "l.db")
    item = queue.enqueue(led, "2026-07-13T10:00:00+00:00", "a", "b", 50, ["r"])
    queue.mark_drained(led, item.id, "run1", "2026-07-13T12:00:00+00:00")
    for i, at in ((1, "2026-07-13T12:00:01+00:00"), (2, "2026-07-13T13:00:00+00:00")):
        led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"run{i}", at,
                         payload={"consumer": "regression_pack", "finding_count": i}))
        led.append(Event(EventType.RUN_FINISHED, f"run{i}", at, payload={"blocking": 0}))
    led.compact()
    events = led.events()
    assert not any(e.type in (EventType.QUEUE_ITEM_ADDED, EventType.QUEUE_ITEM_DRAINED)
                   for e in events), "terminal item's queue events are redundant"
    consumer = [e for e in events if e.type is EventType.CONSUMER_RUN_FINISHED]
    finished = [e for e in events if e.type is EventType.RUN_FINISHED]
    assert len(consumer) == 1 and consumer[0].payload["finding_count"] == 2
    assert len(finished) == 1 and finished[0].run_id == "run2"
    led.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_ledger_compact.py -v`
Expected: new tests FAIL (queue state destroyed / events missing); pre-existing compact tests still PASS.

- [ ] **Step 3: Implement** — inside `compact()`, after the existing `keep` set is built (after the BASELINE_SNAPSHOT loop, before `to_delete`), insert:

```python
        # --- Phase 2a events (spec section 4). Local import: queue.py already
        # imports Ledger from this module; importing at module scope would be
        # circular.
        from aramid.queue import QUEUED, materialize_queue

        full_events = self.events()
        queued_ids = {item.id for item in materialize_queue(full_events).values()
                      if item.state == QUEUED}
        queue_types = {EventType.QUEUE_ITEM_ADDED.value,
                       EventType.QUEUE_ITEM_COALESCED.value,
                       EventType.QUEUE_ITEM_DRAINED.value,
                       EventType.QUEUE_ITEM_EXPIRED.value}
        latest_singleton: dict[str, int] = {}  # type -> newest seq
        for seq, type_, finding_id in rows:
            if type_ in queue_types and finding_id in queued_ids:
                keep.add(seq)
            if type_ in (EventType.TRIAGE_RECORDED.value,
                         EventType.CONSUMER_RUN_FINISHED.value,
                         EventType.RUN_FINISHED.value):
                latest_singleton[type_] = seq
        keep.update(latest_singleton.values())
```

- [ ] **Step 4: Run the full compact + queue test files**

Run: `python -m pytest tests/unit/test_ledger_compact.py tests/unit/test_queue.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/ledger.py tests/unit/test_ledger_compact.py
git commit -m "fix(ledger): compact preserves queued-item, triage, consumer, and last-run events"
```

---

## Milestone M2 — Triage

### Task 3: gitutil diff helpers

**Files:**
- Modify: `src/aramid/gitutil.py` (append four functions)
- Test: `tests/unit/test_gitutil.py` (append tests)

**Interfaces:**
- Produces:
  - `gitutil.rev_sha(root: Path, rev: str) -> str | None` — full sha or None if unresolvable.
  - `gitutil.first_parent(root: Path, rev: str) -> str | None` — sha of `rev^`, None for a root commit.
  - `gitutil.diff_paths(root: Path, base: str | None, head: str) -> list[str]` — changed paths; `base=None` lists everything the (root) commit introduces.
  - `gitutil.diff_text(root: Path, base: str | None, head: str, max_bytes: int = 400_000) -> str` — unified diff text, truncated at `max_bytes`.

- [ ] **Step 1: Write the failing tests** (append to `tests/unit/test_gitutil.py`; the file already has `_git`-style subprocess helpers — reuse its existing repo-building pattern; if it has none, use this one)

```python
def _commit(root: Path, name: str, content: str, msg: str) -> None:
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", name], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", msg], cwd=root, check=True, capture_output=True)


def _make_repo(tmp_path: Path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    for args in (["init", "-q", "-b", "main"], ["config", "user.email", "t@t"],
                 ["config", "user.name", "t"]):
        subprocess.run(["git", *args], cwd=r, check=True, capture_output=True)
    return r


def test_rev_sha_and_first_parent(tmp_path):
    r = _make_repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "first")
    root_sha = gitutil.rev_sha(r, "HEAD")
    assert root_sha and len(root_sha) == 40
    assert gitutil.first_parent(r, "HEAD") is None  # root commit
    _commit(r, "b.py", "y = 2\n", "second")
    assert gitutil.first_parent(r, "HEAD") == root_sha
    assert gitutil.rev_sha(r, "not-a-rev") is None


def test_diff_paths_single_commit_and_root(tmp_path):
    r = _make_repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "first")
    head1 = gitutil.rev_sha(r, "HEAD")
    assert gitutil.diff_paths(r, None, head1) == ["a.py"]  # root commit: full tree
    _commit(r, "sub/b.py", "y = 2\n", "second")
    head2 = gitutil.rev_sha(r, "HEAD")
    assert gitutil.diff_paths(r, head1, head2) == ["sub/b.py"]


def test_diff_text_contains_added_lines_and_truncates(tmp_path):
    r = _make_repo(tmp_path)
    _commit(r, "a.py", "x = 1\n", "first")
    h1 = gitutil.rev_sha(r, "HEAD")
    _commit(r, "a.py", "x = 1\nexec(x)  # обед\n", "second")
    h2 = gitutil.rev_sha(r, "HEAD")
    text = gitutil.diff_text(r, h1, h2)
    assert "+exec(x)" in text
    full = gitutil.diff_text(r, h1, h2)
    full_bytes = len(full.encode("utf-8"))
    assert len(full) < full_bytes  # precondition: multi-byte content present
    cap = full_bytes - 2  # cut lands inside the trailing multi-byte run
    truncated = gitutil.diff_text(r, h1, h2, max_bytes=cap)
    assert len(truncated.encode("utf-8")) <= cap
    assert truncated != full  # naive char-slice would return the FULL text here
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_gitutil.py -v`
Expected: new tests FAIL with `AttributeError`.

- [ ] **Step 3: Implement** (append to `src/aramid/gitutil.py`, matching its existing `_run` helper style)

```python
def rev_sha(root: Path, rev: str) -> str | None:
    cp = _run(root, "rev-parse", "--verify", f"{rev}^{{commit}}")
    return cp.stdout.strip() if cp.returncode == 0 else None


def first_parent(root: Path, rev: str) -> str | None:
    cp = _run(root, "rev-parse", "--verify", f"{rev}^")
    return cp.stdout.strip() if cp.returncode == 0 else None


def diff_paths(root: Path, base: str | None, head: str) -> list[str]:
    if base is None:
        cp = _run(root, "diff-tree", "--no-commit-id", "--name-only", "-r", "--root", head)
    else:
        cp = _run(root, "diff", "--name-only", "--diff-filter=ACMR", f"{base}..{head}")
    return [ln for ln in cp.stdout.splitlines() if ln] if cp.returncode == 0 else []


def diff_text(root: Path, base: str | None, head: str, max_bytes: int = 400_000) -> str:
    if base is None:
        cp = _run(root, "show", "--format=", head)
    else:
        cp = _run(root, "diff", f"{base}..{head}")
    text = cp.stdout if cp.returncode == 0 else ""
    if len(text.encode("utf-8", "replace")) <= max_bytes:
        return text
    return text.encode("utf-8", "replace")[:max_bytes].decode("utf-8", "ignore")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_gitutil.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/gitutil.py tests/unit/test_gitutil.py
git commit -m "feat(gitutil): rev/parent resolution and diff helpers for triage"
```

---

### Task 4: Config sections `[triage] [drain] [pack]`

**Files:**
- Modify: `src/aramid/config.py` (Config dataclass + load_config), `src/aramid/data/defaults.toml`
- Test: `tests/unit/test_config.py` (append tests)

**Interfaces:**
- Produces: `Config.triage: dict`, `Config.drain: dict`, `Config.pack: dict` — merged through the existing three-layer merge; repo `aramid.toml` overrides win.

- [ ] **Step 1: Write the failing tests** (append to `tests/unit/test_config.py`; the file already monkeypatches `config._user_config_path` — follow its existing pattern for isolating `~/.aramid/config.toml`)

```python
def test_phase2a_defaults_present(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "nouser.toml")
    cfg = config.load_config(tmp_path)
    assert cfg.triage["min_score"] == 40
    assert cfg.triage["extra_security_paths"] == []
    assert cfg.drain["interval_hours"] == 4
    assert cfg.drain["max_items_per_drain"] == 10
    assert cfg.drain["item_expiry_days"] == 30
    assert cfg.drain["wall_clock_budget_s"] == 600
    assert cfg.pack["enabled"] is True


def test_repo_config_overrides_triage(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "nouser.toml")
    (tmp_path / "aramid.toml").write_text(
        'schema_version = 1\n[triage]\nmin_score = 70\n', encoding="utf-8")
    cfg = config.load_config(tmp_path)
    assert cfg.triage["min_score"] == 70
    assert cfg.triage["extra_security_paths"] == []  # deep merge keeps sibling default
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_config.py -v`
Expected: new tests FAIL with `AttributeError: 'Config' object has no attribute 'triage'`.

- [ ] **Step 3: Implement**

Append to `src/aramid/data/defaults.toml`:

```toml

# --- Phase 2a (spec sections 3-4): zero-token triage, drain scheduling, pack ---
[triage]
min_score = 40
extra_security_paths = []

[drain]
interval_hours = 4
max_items_per_drain = 10
item_expiry_days = 30
wall_clock_budget_s = 600

[pack]
enabled = true
```

In `src/aramid/config.py`: add fields to the `Config` dataclass —

```python
    triage: dict
    drain: dict
    pack: dict
```

— and in `load_config`'s return, after `block_rules=...`:

```python
        triage=merged.get("triage", {}),
        drain=merged.get("drain", {}),
        pack=merged.get("pack", {}),
```

- [ ] **Step 4: Run the config test file**

Run: `python -m pytest tests/unit/test_config.py -v`
Expected: all PASS (pre-existing Config constructions in other test files construct via `load_config`, not positionally — if any test constructs `Config(...)` positionally it will now fail; fix by adding `triage={}, drain={}, pack={}` keywords there).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/config.py src/aramid/data/defaults.toml tests/unit/test_config.py
git commit -m "feat(config): [triage]/[drain]/[pack] sections with spec defaults"
```

---

### Task 5: Triage signals and scorer

**Files:**
- Create: `src/aramid/triage.py`
- Test: `tests/unit/test_triage.py`

**Interfaces:**
- Consumes: `gitutil.diff_paths/diff_text/rev_sha/first_parent` (Task 3), `queue.triaged_paths/record_triage/enqueue` (Task 1), `Config.triage` (Task 4).
- Produces:
  - `triage.TriageResult` (frozen dataclass: `score: int, reasons: tuple[str, ...], base: str | None, head: str, paths: tuple[str, ...]`)
  - `triage.path_signal(paths: list[str], extra_patterns: list[str]) -> tuple[int, list[str]]`
  - `triage.content_signal(diff_text: str, paths: list[str]) -> tuple[int, list[str]]`
  - `triage.novelty_signal(seen_paths: set[str], paths: list[str]) -> tuple[int, list[str]]`
  - `triage.blast_radius_signal(root: Path, paths: list[str]) -> tuple[int, list[str]]`
  - `triage.score(root: Path, base: str | None, head: str, cfg, ledger, *, budget_s: float = 2.0, monotonic: Callable[[], float] = time.monotonic) -> TriageResult`
  - `triage.run_triage(root: Path, cfg, ledger, base: str | None, head: str, at: str) -> tuple[TriageResult, bool]` — scores, records the triage event, enqueues when `score >= min_score`; returns (result, queued). **This is the single orchestration entry point both `cmd_triage` (Task 6) and the drain sweep (Task 11) call.**

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_triage.py
import json
from pathlib import Path

from aramid import queue, triage
from aramid.ledger import Ledger


# --- path signal -----------------------------------------------------------

def test_path_signal_fires_on_security_tokens():
    score, reasons = triage.path_signal(["src/auth/login.py", "README.md"], [])
    assert score == 30
    assert any("auth" in r for r in reasons)


def test_path_signal_zero_on_benign_paths():
    assert triage.path_signal(["docs/notes.md", "src/util/math.py"], []) == (0, [])


def test_path_signal_honors_extra_patterns():
    score, reasons = triage.path_signal(["billing/charge.py"], ["billing/*"])
    assert score == 30


# --- content signal --------------------------------------------------------

def test_content_signal_exec_class():
    score, reasons = triage.content_signal("+    exec(payload)\n", ["x.py"])
    assert score == 25 and any("exec" in r for r in reasons)


def test_content_signal_sql_class():
    diff = '+    cur.execute("SELECT * FROM t WHERE id=" + uid)\n'
    score, reasons = triage.content_signal(diff, ["db.py"])
    assert score == 25


def test_content_signal_manifest_path():
    score, reasons = triage.content_signal("+requests==2.99.0\n", ["requirements.txt"])
    assert score == 25 and any("manifest" in r for r in reasons)


def test_content_signal_ignores_removed_lines():
    assert triage.content_signal("-    exec(payload)\n", ["x.py"]) == (0, [])


# --- novelty signal --------------------------------------------------------

def test_novelty_signal_new_vs_seen():
    assert triage.novelty_signal({"a.py"}, ["a.py"]) == (0, [])
    score, reasons = triage.novelty_signal({"a.py"}, ["a.py", "brand_new.py"])
    assert score == 20 and "brand_new.py" in reasons[0]


# --- blast radius ----------------------------------------------------------

def _write_graph(root: Path, edges: list[tuple[str, str]], files: dict[str, str]):
    (root / "graph-out").mkdir()
    nodes = [{"id": nid, "kind": "file", "source_file": sf} for nid, sf in files.items()]
    payload = {"nodes": nodes,
               "edges": [{"source": s, "target": t, "relation": "imports"}
                          for s, t in edges]}
    (root / "graph-out" / "graph.json").write_text(json.dumps(payload), encoding="utf-8")


def test_blast_radius_absent_graph_is_zero(tmp_path):
    assert triage.blast_radius_signal(tmp_path, ["core.py"]) == (0, [])


def test_blast_radius_scales_with_dependents(tmp_path):
    files = {"core": "core.py", **{f"d{i}": f"d{i}.py" for i in range(12)}}
    _write_graph(tmp_path, [(f"d{i}", "core") for i in range(12)], files)
    score, reasons = triage.blast_radius_signal(tmp_path, ["core.py"])
    assert score == 25  # >= 10 dependents
    score2, _ = triage.blast_radius_signal(tmp_path, ["d3.py"])  # nothing depends on d3
    assert score2 == 0


def test_blast_radius_thresholds(tmp_path):
    files = {"core": "core.py", "a": "a.py", "b": "b.py", "c": "c.py", "d": "d.py"}
    _write_graph(tmp_path, [("a", "core"), ("b", "core")], files)
    assert triage.blast_radius_signal(tmp_path, ["core.py"])[0] == 10  # 1-2 dependents


# --- combined scorer + budget ---------------------------------------------

def _fake_git(monkeypatch, paths, diff):
    from aramid import triage as t
    monkeypatch.setattr(t.gitutil, "diff_paths", lambda root, base, head: paths)
    monkeypatch.setattr(t.gitutil, "diff_text", lambda root, base, head, max_bytes=400_000: diff)


def test_score_combines_and_clamps(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "l.db")
    _fake_git(monkeypatch, ["src/auth/handler.py"], "+exec(x)\n")
    cfg_triage = {"min_score": 40, "extra_security_paths": []}
    cfg = type("C", (), {"triage": cfg_triage})()
    result = triage.score(tmp_path, "a", "b", cfg, led)
    # path 30 + content 25 + novelty 20 (+ blast 0, no graph) = 75
    assert result.score == 75
    assert result.paths == ("src/auth/handler.py",)
    led.close()


def test_score_budget_stops_early(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "l.db")
    _fake_git(monkeypatch, ["src/auth/handler.py"], "+exec(x)\n")
    cfg = type("C", (), {"triage": {"min_score": 40, "extra_security_paths": []}})()
    clock = iter([0.0, 0.1, 99.0, 99.0, 99.0, 99.0]).__next__  # budget blown after 1st signal
    result = triage.score(tmp_path, "a", "b", cfg, led, budget_s=2.0, monotonic=clock)
    assert result.score == 30  # only the path signal ran
    assert any("budget" in r for r in result.reasons)
    led.close()


def test_run_triage_records_and_enqueues(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "l.db")
    _fake_git(monkeypatch, ["src/auth/handler.py"], "+exec(x)\n")
    cfg = type("C", (), {"triage": {"min_score": 40, "extra_security_paths": []}})()
    result, queued = triage.run_triage(tmp_path, cfg, led, "a", "b", "2026-07-13T12:00:00+00:00")
    assert queued is True
    assert queue.last_triaged_head(led) == "b"
    item = queue.queued_item(queue.materialize_queue(led.events()))
    assert item is not None and item.score == result.score
    led.close()


def test_run_triage_below_threshold_records_but_does_not_enqueue(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "l.db")
    _fake_git(monkeypatch, ["docs/notes.md"], "+hello\n")
    cfg = type("C", (), {"triage": {"min_score": 40, "extra_security_paths": []}})()
    result, queued = triage.run_triage(tmp_path, cfg, led, "a", "b", "2026-07-13T12:00:00+00:00")
    assert queued is False and result.score == 20  # novelty only
    assert queue.queued_item(queue.materialize_queue(led.events())) is None
    assert queue.last_triaged_head(led) == "b"  # still recorded
    led.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_triage.py -v`
Expected: FAIL — `ModuleNotFoundError: aramid.triage`.

- [ ] **Step 3: Implement**

```python
# src/aramid/triage.py
"""triage -- the zero-token risk scorer (spec sections 2-3).

Pure computation: git plumbing text, regexes over the diff, ledger
lookups, and an optional read of graphite's graph-out/graph.json. It
must NEVER spawn a scan tool. Self-budgeted: score() checks elapsed
time between signals and stops early past budget_s, keeping whatever
partial score it has (the post-commit hook can never be slowed past
its fail-open ceiling).
"""
import fnmatch
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from aramid import gitutil, queue
from aramid.fingerprint import normalize_path

PATH_WEIGHT = 30
CONTENT_WEIGHT = 25
NOVELTY_WEIGHT = 20
BLAST_MAX = 25

_SECURITY_TOKENS = ("auth", "session", "login", "crypto", "token", "secret",
                    "permission", "middleware", "config")

_MANIFEST_NAMES = ("pyproject.toml", "package.json", "requirements",
                   "package-lock.json", "pnpm-lock.yaml", "yarn.lock")

_RISKY_CLASSES: tuple[tuple[str, re.Pattern], ...] = (
    ("exec/eval/subprocess", re.compile(
        r"^\+.*\b(exec\(|eval\(|subprocess\.|os\.system\()", re.M)),
    ("sql-string-build", re.compile(
        r"^\+.*(SELECT|INSERT|UPDATE|DELETE)\b.*(\+|%|\bformat\()", re.M | re.I)),
    ("http-handler", re.compile(
        r"^\+.*(@app\.route|@router\.|createServer\(|addEventListener\("
        r"|app\.(get|post|put|delete)\()", re.M)),
)


@dataclass(frozen=True)
class TriageResult:
    score: int
    reasons: tuple[str, ...]
    base: str | None
    head: str
    paths: tuple[str, ...]


def path_signal(paths: list[str], extra_patterns: list[str]) -> tuple[int, list[str]]:
    hits = []
    for p in paths:
        norm = normalize_path(p)
        if any(tok in norm for tok in _SECURITY_TOKENS) or \
           any(fnmatch.fnmatch(norm, pat) for pat in extra_patterns):
            hits.append(p)
    if hits:
        return PATH_WEIGHT, [f"security-path: {', '.join(sorted(hits)[:5])}"]
    return 0, []


def content_signal(diff_text: str, paths: list[str]) -> tuple[int, list[str]]:
    reasons = []
    for name, rx in _RISKY_CLASSES:
        if rx.search(diff_text):
            reasons.append(f"risky-content: {name}")
    manifest_hits = [p for p in paths
                     if any(m in normalize_path(p) for m in _MANIFEST_NAMES)]
    if manifest_hits:
        reasons.append(f"risky-content: dependency-manifest ({', '.join(sorted(manifest_hits)[:3])})")
    return (CONTENT_WEIGHT, reasons) if reasons else (0, [])


def novelty_signal(seen_paths: set[str], paths: list[str]) -> tuple[int, list[str]]:
    fresh = sorted(p for p in paths if p not in seen_paths)
    if fresh:
        return NOVELTY_WEIGHT, [f"novelty: {len(fresh)} unseen path(s) incl. {fresh[0]}"]
    return 0, []


def blast_radius_signal(root: Path, paths: list[str]) -> tuple[int, list[str]]:
    graph_file = root / "graph-out" / "graph.json"
    if not graph_file.exists():
        return 0, []
    try:
        data = json.loads(graph_file.read_text(encoding="utf-8"))
        changed = {normalize_path(p) for p in paths}
        target_ids = {n["id"] for n in data.get("nodes", [])
                      if normalize_path(n.get("source_file") or "") in changed}
        dependents = {e["source"] for e in data.get("edges", [])
                      if e.get("target") in target_ids and e.get("source") not in target_ids}
    except (json.JSONDecodeError, OSError, KeyError, TypeError):
        return 0, []
    n = len(dependents)
    if n >= 10:
        return BLAST_MAX, [f"blast-radius: {n} dependents"]
    if n >= 3:
        return 18, [f"blast-radius: {n} dependents"]
    if n >= 1:
        return 10, [f"blast-radius: {n} dependents"]
    return 0, []


def score(root: Path, base: str | None, head: str, cfg, ledger, *,
          budget_s: float = 2.0,
          monotonic: Callable[[], float] = time.monotonic) -> TriageResult:
    start = monotonic()
    paths = gitutil.diff_paths(root, base, head)
    diff = gitutil.diff_text(root, base, head)
    extra = list(cfg.triage.get("extra_security_paths", []))

    total, reasons = 0, []
    signals: tuple[Callable[[], tuple[int, list[str]]], ...] = (
        lambda: path_signal(paths, extra),
        lambda: content_signal(diff, paths),
        lambda: novelty_signal(queue.triaged_paths(ledger), paths),
        lambda: blast_radius_signal(root, paths),
    )
    for sig in signals:
        if monotonic() - start > budget_s:
            reasons.append("triage-budget-exceeded: partial score")
            break
        pts, why = sig()
        total += pts
        reasons.extend(why)
    return TriageResult(score=min(total, 100), reasons=tuple(reasons),
                        base=base, head=head, paths=tuple(paths))


def run_triage(root: Path, cfg, ledger, base: str | None, head: str,
               at: str) -> tuple[TriageResult, bool]:
    """Single orchestration entry point shared by `aramid triage` and the
    drain sweep: score, always record the triage event (the sweep resumes
    from its head), enqueue only at/above min_score."""
    result = score(root, base, head, cfg, ledger)
    min_score = int(cfg.triage.get("min_score", 40))
    queued = result.score >= min_score
    if queued:
        queue.enqueue(ledger, at, base, head, result.score, list(result.reasons))
    queue.record_triage(ledger, at, base, head, result.score, queued, list(result.paths))
    return result, queued
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_triage.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/triage.py tests/unit/test_triage.py
git commit -m "feat(triage): zero-token risk scorer with budget and graphite blast radius"
```

---

### Task 6: `aramid triage` command + CLI wiring

**Files:**
- Create: `src/aramid/commands/triage_cmd.py`
- Modify: `src/aramid/cli.py`
- Test: `tests/integration/test_triage_cmd.py`

**Interfaces:**
- Consumes: `triage.run_triage` (Task 5), `gitutil.rev_sha/first_parent` (Task 3), `config.load_config`, `Ledger`.
- Produces: `cmd_triage(root, rev: str = "HEAD") -> int` (0 success, 3 engine error). CLI: `aramid triage [rev]` (rev `nargs="?"`, default `"HEAD"`). NOTE the module is `triage_cmd.py` (the engine module `triage.py` already owns the plain name).

- [ ] **Step 1: Write the failing tests**

```python
# tests/integration/test_triage_cmd.py
import subprocess
import sys
from pathlib import Path

from aramid import queue
from aramid.commands.triage_cmd import cmd_triage
from aramid.ledger import Ledger


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    return r


def _commit(root, name, content, msg):
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(content, encoding="utf-8")
    _git(root, "add", name)
    _git(root, "commit", "-m", msg)


def test_triage_head_scores_risky_commit_and_enqueues(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "src/auth/login.py", "def f(x):\n    exec(x)\n", "risky")
    assert cmd_triage(r, "HEAD") == 0
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        item = queue.queued_item(queue.materialize_queue(led.events()))
        assert item is not None
        assert item.score >= 40
        assert queue.last_triaged_head(led) is not None
    finally:
        led.close()


def test_triage_benign_commit_records_without_enqueue(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "docs/note.md", "hello\n", "docs")
    # novelty alone (+20) stays under min_score 40
    assert cmd_triage(r, "HEAD") == 0
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        assert queue.queued_item(queue.materialize_queue(led.events())) is None
        assert queue.last_triaged_head(led) is not None
    finally:
        led.close()


def test_triage_bad_rev_is_engine_error(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "a.py", "x=1\n", "c")
    assert cmd_triage(r, "no-such-rev") == 3


def test_triage_outside_repo_is_engine_error(tmp_path):
    assert cmd_triage(tmp_path / "empty", "HEAD") == 3


def test_cli_dispatches_triage(tmp_path):
    r = _repo(tmp_path)
    _commit(r, "src/auth/login.py", "def f(x):\n    exec(x)\n", "risky")
    out = subprocess.run([sys.executable, "-m", "aramid", "triage"],
                         cwd=r, capture_output=True, text=True)
    assert out.returncode == 0
    assert "triage" in (out.stdout + out.stderr).lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/integration/test_triage_cmd.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

```python
# src/aramid/commands/triage_cmd.py
"""aramid triage <rev> -- score one commit (or A..B range) and enqueue.

Called by the post-commit shim with HEAD (which additionally maps ANY
exit to 0 -- fail-open lives in the shim, spec section 6); usable
manually. Engine errors return 3 per the Phase 1 exit-code contract.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

from aramid import config as config_mod
from aramid import gitutil, triage
from aramid.ledger import Ledger


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def cmd_triage(root, rev: str = "HEAD") -> int:
    try:
        repo = gitutil.repo_root(Path(root).resolve())
    except gitutil.NotARepo:
        print("aramid: triage: not a git repository", file=sys.stderr)
        return 3
    try:
        if ".." in rev:
            base_rev, head_rev = rev.split("..", 1)
            base = gitutil.rev_sha(repo, base_rev)
            head = gitutil.rev_sha(repo, head_rev)
            if base is None or head is None:
                print(f"aramid: triage: cannot resolve range {rev!r}", file=sys.stderr)
                return 3
        else:
            head = gitutil.rev_sha(repo, rev)
            if head is None:
                print(f"aramid: triage: cannot resolve rev {rev!r}", file=sys.stderr)
                return 3
            base = gitutil.first_parent(repo, head)
        cfg = config_mod.load_config(repo)
        ledger = Ledger(repo / ".aramid" / "ledger.db")
        try:
            result, queued = triage.run_triage(repo, cfg, ledger, base, head, _now())
        finally:
            ledger.close()
        state = "queued" if queued else "below threshold"
        print(f"aramid triage: {head[:7]} score {result.score} ({state}); "
              f"{'; '.join(result.reasons) or 'no signals'}")
        return 0
    except Exception as exc:  # engine error tier -- the hook maps this to 0 anyway
        print(f"aramid: triage: engine error: {exc}", file=sys.stderr)
        return 3
```

In `src/aramid/cli.py`: add the subparser next to the existing ones —

```python
    sp = sub.add_parser("triage")
    sp.add_argument("rev", nargs="?", default="HEAD")
```

— and the dispatch branch (match the file's existing pattern of lazy imports if present, else plain import at top):

```python
    if args.command == "triage":
        from aramid.commands.triage_cmd import cmd_triage
        return cmd_triage(root, args.rev)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/integration/test_triage_cmd.py tests/integration/test_cli_dispatch.py -v`
Expected: all PASS (cli-dispatch suite guards against regressions in parser wiring).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/triage_cmd.py src/aramid/cli.py tests/integration/test_triage_cmd.py
git commit -m "feat(cli): aramid triage command"
```

---

## Milestone M3 — Post-commit hook

### Task 7: Post-commit shim (render, install, uninstall, chaining)

**Files:**
- Modify: `src/aramid/hooks.py`
- Test: `tests/unit/test_hooks.py` (append tests)

**Interfaces:**
- Consumes: existing `MARKER_START/MARKER_END/CHAINED_SUFFIX`, `win_sh_path`, `hooks_dir`, `_make_executable`, `_is_aramid_shim` internals.
- Produces:
  - `hooks.TRIAGE_HOOK = "post-commit"`
  - `hooks.render_triage_shim(interpreter: Path) -> bytes` — marker-wrapped, `\n`-only, chains a foreign `post-commit.aramid-chained` first, runs `"$INTERP" -m aramid triage HEAD` with all output discarded and **unconditionally `exit 0`**.
  - `install()` additionally writes the post-commit shim (same foreign-hook preservation); `uninstall()` additionally reverses it.

- [ ] **Step 1: Write the failing tests** (append to `tests/unit/test_hooks.py`, reusing its `_repo` helper)

```python
def test_install_writes_post_commit_shim_fail_open(tmp_path):
    r = _repo(tmp_path)
    install(r, Path("C:/py/python.exe"))
    shim = r / ".git" / "hooks" / "post-commit"
    assert shim.exists()
    raw = shim.read_bytes()
    assert MARKER_START.encode() in raw
    assert b"\r" not in raw
    text = raw.decode()
    assert "-m aramid triage HEAD" in text
    # fail-open: the LAST executable line is an unconditional exit 0, and the
    # triage invocation itself cannot propagate a failure (|| true)
    assert "|| true" in text
    assert text.rstrip().endswith("exit 0")


def test_install_chains_foreign_post_commit_and_uninstall_restores(tmp_path):
    r = _repo(tmp_path)
    hdir = r / ".git" / "hooks"
    hdir.mkdir(exist_ok=True)
    foreign = b"#!/bin/sh\necho foreign\n"
    (hdir / "post-commit").write_bytes(foreign)
    install(r, Path("C:/py/python.exe"))
    assert (hdir / "post-commit.aramid-chained").read_bytes() == foreign
    assert MARKER_START.encode() in (hdir / "post-commit").read_bytes()
    uninstall(r)
    assert (hdir / "post-commit").read_bytes() == foreign
    assert not (hdir / "post-commit.aramid-chained").exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_hooks.py -v`
Expected: new tests FAIL (no post-commit shim written).

- [ ] **Step 3: Implement** in `src/aramid/hooks.py`:

Add the constant next to `GATES`:

```python
TRIAGE_HOOK = "post-commit"  # Phase 2a: fail-open triage enqueue (spec section 2)
```

Add the renderer (mirror `render_shim`'s existing line-building style — same marker block, same chain-check block with `TRIAGE_HOOK` as the hook name, same `INTERP` resolution WITHOUT the `py -3` fallback error path since failure must be silent):

```python
def render_triage_shim(interpreter: Path) -> bytes:
    """Post-commit shim: run triage, swallow EVERYTHING, exit 0. A commit
    can never be blocked or noisy-failed by triage (spec section 6); the
    drain's catch-up sweep recovers anything this shim misses."""
    interp_sh = win_sh_path(interpreter)
    lines = [
        "#!/bin/sh",
        MARKER_START,
        'DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)',
        f'CHAINED="$DIR/{TRIAGE_HOOK}{CHAINED_SUFFIX}"',
        'if [ -f "$CHAINED" ]; then',
        '    "$CHAINED" "$@" || true',
        "fi",
        f'INTERP="{interp_sh}"',
        'if [ -x "$INTERP" ]; then',
        '    "$INTERP" -m aramid triage HEAD >/dev/null 2>&1 || true',
        "elif command -v py >/dev/null 2>&1; then",
        "    py -3 -m aramid triage HEAD >/dev/null 2>&1 || true",
        "fi",
        MARKER_END,
        "exit 0",
        "",
    ]
    return "\n".join(lines).encode()
```

Extend `install()`: after the existing per-gate loop, apply the same write-with-chaining sequence for `TRIAGE_HOOK` using `render_triage_shim(interpreter)` (reuse the exact existing block: preserve foreign hook to `post-commit.aramid-chained` when present and not ours, then `write_bytes` + `_make_executable`). Extend `uninstall()`: include `TRIAGE_HOOK` in the list of hook names it reverses (the existing loop iterates `gate.value` for GATES; generalize to `[g.value for g in GATES] + [TRIAGE_HOOK]`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_hooks.py -v`
Expected: all PASS (including all pre-existing hook tests — chaining/uninstall behavior for pre-commit/pre-push must be unchanged).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/hooks.py tests/unit/test_hooks.py
git commit -m "feat(hooks): fail-open post-commit triage shim with chaining"
```

---

### Task 8: e2e — real commit triggers triage through git dispatch (Windows)

**Files:**
- Test: `tests/e2e/test_windows_hooks.py` (append tests; module is win32-gated already)

**Interfaces:**
- Consumes: `hooks.install`, `queue.materialize_queue/last_triaged_head`, `Ledger`, the module's existing `_repo`/`_git` helpers.

- [ ] **Step 1: Write the failing tests** (append)

```python
# --- 4. post-commit triage fires through real git dispatch ---------------

def test_real_commit_triggers_triage_enqueue(tmp_path):
    from aramid import queue as queue_mod
    r = _repo(tmp_path)
    hooks.install(r, Path(sys.executable))
    (r / "src").mkdir()
    (r / "src" / "auth_login.py").write_text("def f(x):\n    exec(x)\n", encoding="utf-8")
    _git(r, "add", "src/auth_login.py")
    cp = _git(r, "commit", "-m", "risky", env={**os.environ})
    assert cp.returncode == 0, cp.stdout + cp.stderr  # post-commit can NEVER block
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        assert queue_mod.last_triaged_head(led) is not None, \
            "real git dispatch must have run aramid triage"
        item = queue_mod.queued_item(queue_mod.materialize_queue(led.events()))
        assert item is not None and item.score >= 40
    finally:
        led.close()


def test_post_commit_fail_open_with_broken_interpreter(tmp_path):
    r = _repo(tmp_path)
    hooks.install(r, Path("C:/nonexistent/python.exe"))
    (r / "ok.py").write_text("x = 1\n", encoding="utf-8")
    _git(r, "add", "ok.py")
    cp = _git(r, "commit", "-m", "clean")
    assert cp.returncode == 0, "broken triage interpreter must never block a commit"
```

Note for the implementer: BOTH tests commit through the FULL hook set — the pre-commit gate also fires (in the first test `exec(x)` trips ruff S102 BLOCK; in the second the broken-interpreter pre-commit shim falls back to `py -3` and runs a slow real gate). Both tests must bypass the pre-commit shim while keeping post-commit: after `hooks.install`, delete it (`(r / ".git" / "hooks" / "pre-commit").unlink()`) before committing. Add that line and this comment to both tests verbatim.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/e2e/test_windows_hooks.py -v`
Expected: new tests FAIL (before Task 7's install writes post-commit, or if triage never ran).

- [ ] **Step 3: Fix wiring surfaced by the e2e run** — expected issues: the shim needs `aramid` importable by the baked interpreter (it is — editable install), and triage runs from the hook's CWD (git sets CWD to repo root for post-commit; `cmd_triage` resolves `repo_root` anyway).

- [ ] **Step 4: Run the full e2e module**

Run: `python -m pytest tests/e2e/ -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/e2e/test_windows_hooks.py
git commit -m "test(e2e): post-commit triage fires through real git dispatch, fail-open verified"
```

---

## Milestone M4 — Registry, consumers, drain, scheduler

### Task 9: Central repo registry + init/uninstall integration

**Files:**
- Create: `src/aramid/registry.py`
- Modify: `src/aramid/commands/init.py` (register after hooks.install), `src/aramid/commands/uninstall.py` (deregister)
- Test: `tests/unit/test_registry.py`, `tests/integration/test_init.py` (append one test), `tests/integration/test_uninstall.py` (append one test)

**Interfaces:**
- Produces:
  - `registry.registry_path() -> Path` — `Path.home() / ".aramid" / "repos.toml"`; **monkeypatch seam for every test** (mirrors `config._user_config_path`).
  - `registry.load_registry() -> list[dict]` — `[{"path": str, "registered_at": str}, ...]`; `[]` on missing/corrupt file.
  - `registry.register(path: Path, at: str) -> None` — dedup by `normalize_path(str(resolved))`.
  - `registry.deregister(path: Path) -> None`

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_registry.py
from pathlib import Path

from aramid import registry
from aramid.fingerprint import normalize_path


def _seam(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "repos.toml")


def test_register_load_roundtrip(tmp_path, monkeypatch):
    _seam(tmp_path, monkeypatch)
    registry.register(tmp_path / "repoA", "2026-07-13T00:00:00+00:00")
    got = registry.load_registry()
    assert len(got) == 1
    assert normalize_path(got[0]["path"]) == normalize_path(str((tmp_path / "repoA").resolve()))
    assert got[0]["registered_at"] == "2026-07-13T00:00:00+00:00"


def test_register_is_idempotent(tmp_path, monkeypatch):
    _seam(tmp_path, monkeypatch)
    registry.register(tmp_path / "repoA", "2026-07-13T00:00:00+00:00")
    registry.register(tmp_path / "repoA", "2026-07-14T00:00:00+00:00")
    assert len(registry.load_registry()) == 1


def test_deregister_removes_only_target(tmp_path, monkeypatch):
    _seam(tmp_path, monkeypatch)
    registry.register(tmp_path / "a", "t")
    registry.register(tmp_path / "b", "t")
    registry.deregister(tmp_path / "a")
    got = registry.load_registry()
    assert len(got) == 1 and got[0]["path"].endswith("b")


def test_load_missing_and_corrupt_files(tmp_path, monkeypatch):
    _seam(tmp_path, monkeypatch)
    assert registry.load_registry() == []
    (tmp_path / "repos.toml").write_text("not [ valid toml", encoding="utf-8")
    assert registry.load_registry() == []
```

Append to `tests/integration/test_init.py`. That module already has a happy-path `cmd_init` test with a repo builder and a doctor/gitleaks stub (init refuses to arm when doctor fails) — copy that test verbatim as the starting scaffold, rename it `test_init_registers_repo_in_central_registry`, add the registry seam, and end with the two assertions below. The seam line and assertions are exact; the scaffold comes from the file you are editing:

```python
    # added lines (seam first, assertions replacing the copied test's tail):
    from aramid import registry
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "central" / "repos.toml")
    ...
    assert cmd_init(repo) == 0
    assert any(Path(e["path"]).resolve() == repo.resolve() for e in registry.load_registry())
```

Append to `tests/integration/test_uninstall.py` symmetrically: register via init (or direct `registry.register`), run `cmd_uninstall`, assert the entry is gone.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_registry.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

```python
# src/aramid/registry.py
"""registry -- the ONE piece of central state (spec section 4):
~/.aramid/repos.toml, the list of onboarded repos the drain iterates.
Everything else stays in per-repo ledgers."""
import sys
import tomllib
from pathlib import Path

import tomli_w

from aramid.fingerprint import normalize_path


def registry_path() -> Path:
    """Seam for tests -- monkeypatch this, never touch the real file."""
    return Path.home() / ".aramid" / "repos.toml"


def load_registry() -> list[dict]:
    p = registry_path()
    if not p.exists():
        return []
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        print(f"aramid: registry unreadable ({exc}); treating as empty", file=sys.stderr)
        return []
    return [e for e in data.get("repos", []) if isinstance(e, dict) and e.get("path")]


def _write(entries: list[dict]) -> None:
    p = registry_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(tomli_w.dumps({"repos": entries}), encoding="utf-8")


def register(path: Path, at: str) -> None:
    resolved = normalize_path(str(Path(path).resolve()))
    entries = load_registry()
    if any(normalize_path(e["path"]) == resolved for e in entries):
        return
    entries.append({"path": str(Path(path).resolve()), "registered_at": at})
    _write(entries)


def deregister(path: Path) -> None:
    resolved = normalize_path(str(Path(path).resolve()))
    entries = [e for e in load_registry() if normalize_path(e["path"]) != resolved]
    _write(entries)
```

In `commands/init.py`, immediately after the `hooks.install(root, Path(sys.executable))` step:

```python
    from aramid import registry
    registry.register(root, _now())
```

In `commands/uninstall.py`, after `hooks.uninstall(root)`:

```python
    from aramid import registry
    registry.deregister(root)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_registry.py tests/integration/test_init.py tests/integration/test_uninstall.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/registry.py src/aramid/commands/init.py src/aramid/commands/uninstall.py tests/unit/test_registry.py tests/integration/test_init.py tests/integration/test_uninstall.py
git commit -m "feat(registry): central repos.toml; init registers, uninstall deregisters"
```

---

### Task 10: Consumer protocol

**Files:**
- Create: `src/aramid/consumers/__init__.py`, `src/aramid/consumers/base.py`
- Test: `tests/unit/test_consumers_base.py`

**Interfaces:**
- Produces:
  - `consumers.base.DrainContext` (dataclass: `root: Path, cfg, ledger, clock: Callable[[], str]`)
  - `consumers.base.ConsumerResult` (dataclass: `consumer: str, state: str, findings: list, duration_s: float = 0.0, cost: float = 0.0, note: str = ""`) — `state ∈ {"ok", "degraded", "error"}`; `findings` is a `list[RawFinding]`; `cost` is the Phase 4 metering slot, always 0.0 in 2a.
  - `consumers.base.CONSUMERS: dict[str, object]` — name → module with `NAME: str` and `consume(item: QueueItem, ctx: DrainContext) -> ConsumerResult`. Starts EMPTY; Task 16 registers `regression_pack`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_consumers_base.py
from pathlib import Path

from aramid.consumers.base import CONSUMERS, ConsumerResult, DrainContext


def test_protocol_shapes():
    ctx = DrainContext(root=Path("."), cfg=None, ledger=None, clock=lambda: "t")
    res = ConsumerResult(consumer="fake", state="ok", findings=[])
    assert res.cost == 0.0 and res.duration_s == 0.0 and res.note == ""
    assert isinstance(CONSUMERS, dict)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/unit/test_consumers_base.py -v` — FAIL, module not found.

- [ ] **Step 3: Implement**

```python
# src/aramid/consumers/__init__.py  (empty file)
```

```python
# src/aramid/consumers/base.py
"""Consumer protocol (spec section 2): a consumer is a module exposing
NAME: str and consume(item: QueueItem, ctx: DrainContext) -> ConsumerResult.
Mirrors runners/: the drain iterates CONSUMERS like the pipeline iterates
RUNNERS. ConsumerResult.cost is the Phase 4 metering slot -- every 2a
consumer writes 0.0 (zero tokens by construction)."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

OK = "ok"
DEGRADED = "degraded"
ERROR = "error"


@dataclass
class DrainContext:
    root: Path
    cfg: object
    ledger: object
    clock: Callable[[], str]


@dataclass
class ConsumerResult:
    consumer: str
    state: str
    findings: list = field(default_factory=list)
    duration_s: float = 0.0
    cost: float = 0.0
    note: str = ""


CONSUMERS: dict[str, object] = {}  # populated by consumer modules (Task 16)
```

- [ ] **Step 4: Run to verify it passes** — `python -m pytest tests/unit/test_consumers_base.py -v`

- [ ] **Step 5: Commit**

```bash
git add src/aramid/consumers tests/unit/test_consumers_base.py
git commit -m "feat(consumers): drain consumer protocol"
```

---

### Task 11: `aramid drain` — lock, sweep, pop, consume, record

**Files:**
- Create: `src/aramid/commands/drain.py`
- Modify: `src/aramid/cli.py`
- Test: `tests/integration/test_drain.py`

**Interfaces:**
- Consumes: `registry.load_registry`, `queue.*` (Task 1), `triage.run_triage` (Task 5), `consumers.base.CONSUMERS/DrainContext/ConsumerResult`, `normalize`/`policy.classify`/`redact.load_or_create_salt` (Phase 1), `Config.drain`.
- Produces:
  - `cmd_drain(targets: list[Path], *, dry_run: bool = False, max_items: int | None = None, clock=..., monotonic=...) -> int` — 0 ok / 2 degraded / 3 engine error.
  - CLI: `aramid drain [--all] [--repo PATH] [--dry-run] [--max-items N]` (`--all` and `--repo` mutually exclusive; default `--repo .`).
  - Lock helpers `_acquire_lock(budget_s) -> Path | None` / `_release_lock(path)` at `~/.aramid/drain.lock` — JSON `{pid, started_at}`; stale when the PID is dead OR the lock is older than `2 * budget_s`.
  - Per-item ledger trail: consumer findings recorded via `ledger.record_run(run_id, at, "drain", scope_tools, scope_files, findings)`, one `CONSUMER_RUN_FINISHED` event per consumer, one `queue.mark_drained` per item.

- [ ] **Step 1: Write the failing tests**

```python
# tests/integration/test_drain.py
import subprocess
from pathlib import Path

import pytest

from aramid import queue, registry
from aramid.commands import drain as drain_mod
from aramid.commands.drain import cmd_drain
from aramid.consumers.base import CONSUMERS, ConsumerResult
from aramid.ledger import Ledger
from aramid.models import EventType
from aramid.normalizer import RawFinding


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path, name="r") -> Path:
    r = tmp_path / name
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    return r


def _commit(root, name, content, msg):
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(content, encoding="utf-8")
    _git(root, "add", name)
    _git(root, "commit", "-m", msg)


class _FakeConsumer:
    NAME = "fake"
    calls: list = []

    @classmethod
    def consume(cls, item, ctx):
        cls.calls.append(item)
        raw = RawFinding(tool="semgrep", rule="aramid-regression.warn.deadbeef",
                         severity_raw="WARNING", file="src/auth_login.py", line=1,
                         message="reintroduction")
        return ConsumerResult(consumer=cls.NAME, state="ok", findings=[raw])


@pytest.fixture
def fake_consumer(monkeypatch):
    _FakeConsumer.calls = []
    monkeypatch.setitem(CONSUMERS, "fake", _FakeConsumer)
    yield _FakeConsumer


@pytest.fixture
def seam(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "central" / "repos.toml")
    monkeypatch.setattr(drain_mod, "_lock_path", lambda: tmp_path / "central" / "drain.lock")


def _risky_repo(tmp_path, name="r"):
    r = _repo(tmp_path, name)
    _commit(r, "src/auth_login.py", "def f(x):\n    exec(x)\n", "risky")
    return r


def test_drain_sweeps_pops_consumes_records(tmp_path, seam, fake_consumer):
    r = _risky_repo(tmp_path)
    registry.register(r, "t0")
    rc = cmd_drain([], dry_run=False)  # [] + registry -> --all semantics
    assert rc == 0
    assert len(fake_consumer.calls) == 1  # sweep triaged HEAD, item queued, popped
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        events = led.events()
        assert any(e.type is EventType.CONSUMER_RUN_FINISHED for e in events)
        assert any(e.type is EventType.QUEUE_ITEM_DRAINED for e in events)
        assert queue.queued_item(queue.materialize_queue(events)) is None
        state = led.open_findings()
        assert any(rec.get("rule") == "aramid-regression.warn.deadbeef"
                   for rec in state.values())
    finally:
        led.close()


def test_drain_bootstrap_sweeps_head_only(tmp_path, seam, fake_consumer):
    """Spec section 2 bootstrap rule: no triage history -> triage HEAD only,
    never the whole past."""
    r = _repo(tmp_path)
    _commit(r, "old_secret_config.py", "exec(1)\n", "old risky commit")
    _commit(r, "docs/readme.md", "hi\n", "benign HEAD")
    registry.register(r, "t0")
    cmd_drain([], dry_run=False)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        # benign HEAD scores novelty only (20 < 40): recorded, nothing queued,
        # and the risky OLD commit was never triaged
        assert queue.last_triaged_head(led) is not None
        assert queue.queued_item(queue.materialize_queue(led.events())) is None
        triage_events = [e for e in led.events() if e.type is EventType.TRIAGE_RECORDED]
        assert len(triage_events) == 1
    finally:
        led.close()


def test_drain_dry_run_writes_nothing(tmp_path, seam, fake_consumer):
    r = _risky_repo(tmp_path)
    registry.register(r, "t0")
    rc = cmd_drain([], dry_run=True)
    assert rc == 0
    assert fake_consumer.calls == []
    assert not (r / ".aramid" / "ledger.db").exists()


def test_drain_isolates_broken_repo_exit_2(tmp_path, seam, fake_consumer):
    good = _risky_repo(tmp_path, "good")
    registry.register(tmp_path / "vanished", "t0")  # path does not exist
    registry.register(good, "t0")
    rc = cmd_drain([], dry_run=False)
    assert rc == 2  # degraded: one repo skipped
    assert len(fake_consumer.calls) == 1  # good repo still drained


def test_drain_lock_contention(tmp_path, seam, fake_consumer):
    r = _risky_repo(tmp_path)
    registry.register(r, "t0")
    lock = drain_mod._acquire_lock(600.0)
    assert lock is not None
    try:
        assert cmd_drain([], dry_run=False) == 3  # engine error: locked
        assert fake_consumer.calls == []
    finally:
        drain_mod._release_lock(lock)


def test_drain_respects_max_items(tmp_path, seam, fake_consumer):
    r1, r2 = _risky_repo(tmp_path, "r1"), _risky_repo(tmp_path, "r2")
    registry.register(r1, "t0")
    registry.register(r2, "t0")
    assert cmd_drain([], dry_run=False, max_items=1) == 0
    assert len(fake_consumer.calls) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/integration/test_drain.py -v` — FAIL, module not found.

- [ ] **Step 3: Implement**

```python
# src/aramid/commands/drain.py
"""aramid drain -- iterate the registry, catch-up-sweep, pop queued items
by score, hand them to consumers, record everything (spec section 2).

Exit codes reuse the Phase 1 contract: 0 ok, 2 degraded (some repo or
consumer failed; the rest completed), 3 engine error (lock held, registry
unusable). Singleton lock at ~/.aramid/drain.lock: JSON {pid, started_at};
stale when the PID is dead OR the lock is older than 2x the wall-clock
budget (spec section 6)."""
import functools
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from aramid import config as config_mod
from aramid import gitutil, policy, queue, redact, registry, triage
from aramid.consumers.base import CONSUMERS, DrainContext
from aramid.ledger import Ledger
from aramid.models import Event, EventType, Gate
from aramid.normalizer import normalize


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _lock_path() -> Path:
    """Seam for tests."""
    return Path.home() / ".aramid" / "drain.lock"


def _pid_alive(pid: int) -> bool:
    if sys.platform == "win32":
        # noqa justification (S603/S607): fixed argv querying our own recorded
        # PID via the standard Windows tasklist binary.
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],  # noqa: S603,S607
                             capture_output=True, text=True)
        return str(pid) in out.stdout
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _acquire_lock(budget_s: float) -> Path | None:
    p = _lock_path()
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            age = time.time() - float(data.get("started_at", 0))
            if _pid_alive(int(data.get("pid", -1))) and age < 2 * budget_s:
                return None  # genuinely held
            print("aramid: drain: breaking stale lock", file=sys.stderr)
        except (json.JSONDecodeError, ValueError, OSError):
            pass  # unreadable lock is stale
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"pid": os.getpid(), "started_at": time.time()}),
                 encoding="utf-8")
    return p


def _release_lock(p: Path) -> None:
    try:
        p.unlink()
    except OSError:
        pass


def _sweep(root: Path, cfg, ledger, at: str) -> None:
    head = gitutil.rev_sha(root, "HEAD")
    if head is None:
        return  # empty repo: nothing to triage
    last = queue.last_triaged_head(ledger)
    if last == head:
        return
    if last is None:
        # Bootstrap rule (spec section 2): first contact triages HEAD only.
        triage.run_triage(root, cfg, ledger, gitutil.first_parent(root, head), head, at)
    else:
        triage.run_triage(root, cfg, ledger, last, head, at)


def _consume_item(root: Path, cfg, ledger, item, clock) -> bool:
    """Run every enabled consumer against one queue item. Returns True if
    all consumers finished without error state."""
    ok = True
    run_id = uuid.uuid4().hex
    salt = redact.load_or_create_salt(root / ".aramid")
    for name, module in CONSUMERS.items():
        started = time.monotonic()
        try:
            result = module.consume(item, DrainContext(root=root, cfg=cfg,
                                                        ledger=ledger, clock=clock))
        except Exception as exc:
            from aramid.consumers.base import ConsumerResult
            result = ConsumerResult(consumer=name, state="error", note=str(exc))
        duration = time.monotonic() - started
        findings = []
        if result.findings:
            findings = normalize(result.findings, root, lambda f: item.head, salt,
                                 Gate.ALL, functools.partial(policy.classify, cfg=cfg))
            ledger.record_run(run_id, clock(), "drain",
                              {r.tool for r in result.findings},
                              {r.file for r in result.findings}, findings)
        ledger.append(Event(EventType.CONSUMER_RUN_FINISHED, run_id, clock(),
                            payload={"consumer": name, "item_id": item.id,
                                     "state": result.state,
                                     "duration_s": round(duration, 3),
                                     "cost": result.cost,
                                     "finding_count": len(findings),
                                     "note": result.note}))
        if result.state == "error":
            ok = False
    queue.mark_drained(ledger, item.id, run_id, clock())
    return ok


def cmd_drain(targets: list, *, dry_run: bool = False, max_items: int | None = None,
              clock: Callable[[], str] = _now,
              monotonic: Callable[[], float] = time.monotonic) -> int:
    repos = [Path(t) for t in targets] if targets else \
            [Path(e["path"]) for e in registry.load_registry()]
    if not repos:
        print("aramid drain: no repos registered and none given", file=sys.stderr)
        return 0

    probe_cfg_budget = 600.0
    lock = None
    if not dry_run:
        lock = _acquire_lock(probe_cfg_budget)
        if lock is None:
            print("aramid: drain: another drain is running (lock held)", file=sys.stderr)
            return 3
    degraded = False
    started = monotonic()
    try:
        candidates = []  # (score, repo, item, cfg)
        for repo_path in repos:
            try:
                root = gitutil.repo_root(repo_path.resolve())
                cfg = config_mod.load_config(root)
                if dry_run:
                    # read-only preview: report what WOULD be swept/popped
                    if (root / ".aramid" / "ledger.db").exists():
                        ledger = Ledger(root / ".aramid" / "ledger.db")
                        try:
                            item = queue.queued_item(queue.materialize_queue(ledger.events()))
                        finally:
                            ledger.close()
                    else:
                        item = None
                    print(f"aramid drain (dry-run): {root} queued="
                          f"{item.score if item else 'none'}")
                    continue
                ledger = Ledger(root / ".aramid" / "ledger.db")
                try:
                    _sweep(root, cfg, ledger, clock())
                    queue.expire_stale(ledger, clock(),
                                       int(cfg.drain.get("item_expiry_days", 30)))
                    item = queue.queued_item(queue.materialize_queue(ledger.events()))
                finally:
                    ledger.close()
                if item is not None and item.score >= int(cfg.triage.get("min_score", 40)):
                    candidates.append((item.score, root, item, cfg))
            except (gitutil.NotARepo, OSError) as exc:
                print(f"aramid drain: skipping {repo_path}: {exc}", file=sys.stderr)
                degraded = True
        if dry_run:
            return 0

        candidates.sort(key=lambda c: -c[0])
        budget_s = max((float(c[3].drain.get("wall_clock_budget_s", 600.0))
                        for c in candidates), default=600.0)
        limit = max_items if max_items is not None else \
                max((int(c[3].drain.get("max_items_per_drain", 10))
                     for c in candidates), default=10)
        drained = 0
        for score_val, root, item, cfg in candidates:
            if drained >= limit or monotonic() - started > budget_s:
                print(f"aramid drain: budget reached; {len(candidates) - drained} "
                      f"item(s) left queued")
                break
            ledger = Ledger(root / ".aramid" / "ledger.db")
            try:
                if not _consume_item(root, cfg, ledger, item, clock):
                    degraded = True
            except Exception as exc:
                print(f"aramid drain: {root}: {exc}", file=sys.stderr)
                degraded = True
            finally:
                ledger.close()
            drained += 1
        print(f"aramid drain: {drained} item(s) drained, "
              f"{len(candidates) - drained} left")
        return 2 if degraded else 0
    finally:
        if lock is not None:
            _release_lock(lock)
```

In `src/aramid/cli.py`: subparser —

```python
    sp = sub.add_parser("drain")
    g = sp.add_mutually_exclusive_group()
    g.add_argument("--all", action="store_true")
    g.add_argument("--repo", default=None)
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--max-items", type=int, default=None)
```

— dispatch:

```python
    if args.command == "drain":
        from aramid.commands.drain import cmd_drain
        targets = [] if args.all else ([args.repo] if args.repo else [str(root)])
        return cmd_drain(targets, dry_run=args.dry_run, max_items=args.max_items)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/integration/test_drain.py tests/integration/test_cli_dispatch.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/drain.py src/aramid/cli.py tests/integration/test_drain.py
git commit -m "feat(drain): registry sweep, budgeted pop, consumer dispatch, singleton lock"
```

---

### Task 12: `aramid schedule` — Task Scheduler registration

**Files:**
- Create: `src/aramid/commands/schedule.py`
- Modify: `src/aramid/cli.py`
- Test: `tests/unit/test_schedule.py`, `tests/e2e/test_schedule_e2e.py`

**Interfaces:**
- Produces:
  - `schedule.TASK_NAME = "aramid-drain"`
  - `schedule.render_task_xml(interpreter: Path, interval_hours: int, start_boundary: str) -> str` — Task Scheduler XML with `<StartWhenAvailable>true</StartWhenAvailable>` (spec §6 "run as soon as possible after a missed start") and a repeating time trigger `PT{interval_hours}H`.
  - `cmd_schedule(root, action: str) -> int` — `install` (renders XML to a temp file, `schtasks /Create /TN aramid-drain /XML <file> /F`), `remove` (`/Delete /TN aramid-drain /F`), `status` (`/Query /TN aramid-drain`); 0 on success, 3 on failure/unsupported platform.
  - CLI: `aramid schedule {install,remove,status}`.

- [ ] **Step 1: Write the failing unit tests**

```python
# tests/unit/test_schedule.py
from pathlib import Path

from aramid.commands import schedule


def test_xml_contains_startwhenavailable_interval_and_interpreter():
    xml = schedule.render_task_xml(Path("C:/py/python.exe"), 4,
                                   "2026-07-13T00:00:00")
    assert "<StartWhenAvailable>true</StartWhenAvailable>" in xml
    assert "<Interval>PT4H</Interval>" in xml
    assert "C:\\py\\python.exe" in xml or "C:/py/python.exe" in xml
    assert "-m aramid drain --all" in xml
    assert "<StartBoundary>2026-07-13T00:00:00</StartBoundary>" in xml


def test_schtasks_argvs():
    assert schedule._create_argv(Path("t.xml")) == \
        ["schtasks", "/Create", "/TN", "aramid-drain", "/XML", "t.xml", "/F"]
    assert schedule._delete_argv() == \
        ["schtasks", "/Delete", "/TN", "aramid-drain", "/F"]
    assert schedule._query_argv() == \
        ["schtasks", "/Query", "/TN", "aramid-drain"]


def test_install_invokes_schtasks(monkeypatch, tmp_path):
    calls = {}

    def fake_run(argv, **kw):
        calls["argv"] = argv
        class R: returncode = 0; stdout = ""; stderr = ""
        return R()

    monkeypatch.setattr(schedule.subprocess, "run", fake_run)
    assert schedule.cmd_schedule(tmp_path, "install") == 0
    assert calls["argv"][:4] == ["schtasks", "/Create", "/TN", "aramid-drain"]
```

- [ ] **Step 2: Run to verify failure** — `python -m pytest tests/unit/test_schedule.py -v`

- [ ] **Step 3: Implement**

```python
# src/aramid/commands/schedule.py
"""aramid schedule install|remove|status -- Windows Task Scheduler entry
running `aramid drain --all` every [drain].interval_hours (spec section 2).
XML registration is used (not bare /SC flags) because StartWhenAvailable
-- "run as soon as possible after a missed start", spec section 6 -- is
only expressible in the XML schema. The sweep additionally self-heals any
fully missed window."""
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from aramid import config as config_mod

TASK_NAME = "aramid-drain"

_XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>aramid: scheduled queue drain (zero-token triage consumers)</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>{start}</StartBoundary>
      <Repetition>
        <Interval>PT{hours}H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Settings>
    <StartWhenAvailable>true</StartWhenAvailable>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{interpreter}</Command>
      <Arguments>-m aramid drain --all</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def render_task_xml(interpreter: Path, interval_hours: int, start_boundary: str) -> str:
    return _XML_TEMPLATE.format(start=start_boundary, hours=interval_hours,
                                interpreter=str(interpreter))


def _create_argv(xml_path: Path) -> list[str]:
    return ["schtasks", "/Create", "/TN", TASK_NAME, "/XML", str(xml_path), "/F"]


def _delete_argv() -> list[str]:
    return ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"]


def _query_argv() -> list[str]:
    return ["schtasks", "/Query", "/TN", TASK_NAME]


def cmd_schedule(root, action: str) -> int:
    if sys.platform != "win32":
        print("aramid: schedule: only supported on Windows (Task Scheduler)",
              file=sys.stderr)
        return 3
    try:
        if action == "install":
            cfg = config_mod.load_config(Path(root))
            hours = int(cfg.drain.get("interval_hours", 4))
            start = datetime.now().replace(microsecond=0).isoformat()
            xml = render_task_xml(Path(sys.executable), hours, start)
            with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False,
                                             encoding="utf-16") as f:
                f.write(xml)
                xml_path = Path(f.name)
            try:
                cp = subprocess.run(_create_argv(xml_path), capture_output=True, text=True)
            finally:
                xml_path.unlink(missing_ok=True)
        elif action == "remove":
            cp = subprocess.run(_delete_argv(), capture_output=True, text=True)
        elif action == "status":
            cp = subprocess.run(_query_argv(), capture_output=True, text=True)
            print(cp.stdout.strip() or "aramid-drain: not installed")
            return 0 if cp.returncode == 0 else 3
        else:
            print(f"aramid: schedule: unknown action {action!r}", file=sys.stderr)
            return 3
        if cp.returncode != 0:
            print(f"aramid: schedule {action} failed: {cp.stderr.strip()}", file=sys.stderr)
            return 3
        print(f"aramid schedule: {action} ok ({TASK_NAME})")
        return 0
    except Exception as exc:
        print(f"aramid: schedule: engine error: {exc}", file=sys.stderr)
        return 3
```

CLI subparser + dispatch:

```python
    sp = sub.add_parser("schedule")
    sp.add_argument("action", choices=["install", "remove", "status"])
```

```python
    if args.command == "schedule":
        from aramid.commands.schedule import cmd_schedule
        return cmd_schedule(root, args.action)
```

- [ ] **Step 4: Write + run the e2e test** (real Task Scheduler, disposable unique name)

```python
# tests/e2e/test_schedule_e2e.py
"""Real schtasks round-trip with a DISPOSABLE task name -- never touches the
real aramid-drain task. Skips where schtasks is unavailable (non-Windows)."""
import shutil
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path

import pytest

from aramid.commands import schedule

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or shutil.which("schtasks") is None,
    reason="Windows Task Scheduler required")


def test_real_register_query_delete_roundtrip(monkeypatch, tmp_path):
    disposable = f"aramid-test-{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(schedule, "TASK_NAME", disposable)
    try:
        xml = schedule.render_task_xml(Path(sys.executable), 4,
                                       datetime.now().replace(microsecond=0).isoformat())
        xml_file = tmp_path / "t.xml"
        xml_file.write_text(xml, encoding="utf-16")
        cp = subprocess.run(schedule._create_argv(xml_file), capture_output=True, text=True)
        assert cp.returncode == 0, cp.stderr
        q = subprocess.run(schedule._query_argv(), capture_output=True, text=True)
        assert q.returncode == 0 and disposable in q.stdout
    finally:
        subprocess.run(schedule._delete_argv(), capture_output=True, text=True)
    q2 = subprocess.run(schedule._query_argv(), capture_output=True, text=True)
    assert q2.returncode != 0, "disposable task must be cleaned up"
```

Run: `python -m pytest tests/unit/test_schedule.py tests/e2e/test_schedule_e2e.py -v`
Expected: all PASS (e2e may require the CI runner to allow schtasks — it does on windows-latest; if a local policy blocks it, the failure output will show `ERROR: Access is denied`, in which case add a skip on that stderr, documented in the test).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/schedule.py src/aramid/cli.py tests/unit/test_schedule.py tests/e2e/test_schedule_e2e.py
git commit -m "feat(schedule): Task Scheduler registration with StartWhenAvailable via XML"
```

---

## Milestone M5 — Regression attack pack

### Task 13: Pack rule compilers + hand-rendered YAML

**Files:**
- Create: `src/aramid/pack.py`
- Test: `tests/unit/test_pack.py`

**Interfaces:**
- Consumes: ledger state records (dicts from `open_findings()`: keys `tool, file, rule, verdict, severity, line, message, evidence, historical, status`).
- Produces:
  - `pack.RULES_REL_PATH = Path(".aramid-rules") / "regression.yml"`
  - `pack.compile_secret_rule(finding_id: str, rec: dict) -> dict | None` — from a gitleaks record whose evidence is `"{pre}…{suf} (sha256:…)"`; pattern `re.escape(pre) + r"\S{4,64}" + re.escape(suf)`, scoped `paths.include: [rec["file"]]`, id `aramid-regression.block.<fid8>`. Returns None when evidence is unparseable.
  - `pack.compile_dep_rule(finding_id: str, rec: dict) -> dict | None` — manifest-scoped ban from a dependency finding; id tier from `rec["verdict"]`.
  - `pack.draft_rule(finding_id: str, rec: dict) -> dict` — always compiles; `pattern-regex` is the sentinel `AR-EDIT-ME-<fid8>` and the message instructs the user to edit before committing.
  - `pack.render_pack(rules: list[dict]) -> str` — YAML via json-encoded scalars (valid YAML), **no PyYAML at runtime**.
  - `pack.existing_ids(path: Path) -> set[str]`; `pack.append_rules(path: Path, rules: list[dict]) -> int` — appends only unseen ids, creates file+header when absent, returns count appended.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_pack.py
import yaml  # dev-dependency, tests only

from aramid import pack

SECRET = "AKIAIOSFODNN7EXAMPLE"
FID = "deadbeefcafe0123"

SECRET_REC = {"tool": "gitleaks", "rule": "aws-access-key", "file": "cfg/prod.env",
              "verdict": "block", "severity": "critical", "line": 3,
              "message": "aws key", "status": "rotated",
              "evidence": f"{SECRET[:2]}…{SECRET[-2:]} (sha256:abc123)"}

DEP_REC = {"tool": "pip-audit", "rule": "PYSEC-2024-1234", "file": "requirements.txt",
           "verdict": "block", "severity": "critical", "line": 0,
           "message": "insecure-package 1.0.0 has PYSEC-2024-1234", "status": "fixed",
           "evidence": ""}


def test_secret_rule_never_contains_literal_and_is_scoped():
    rule = pack.compile_secret_rule(FID, SECRET_REC)
    text = pack.render_pack([rule])
    assert SECRET not in text  # THE hygiene invariant (spec section 5)
    assert rule["id"] == f"aramid-regression.block.{FID[:8]}"
    assert rule["paths"]["include"] == ["cfg/prod.env"]
    assert rule["pattern-regex"].startswith("AK")
    assert rule["pattern-regex"].endswith("LE")
    assert r"\S{4,64}" in rule["pattern-regex"]


def test_secret_rule_unparseable_evidence_returns_none():
    rec = dict(SECRET_REC, evidence="…")  # short-secret preview: no anchors
    assert pack.compile_secret_rule(FID, rec) is None


def test_dep_rule_targets_manifest_and_package():
    rule = pack.compile_dep_rule(FID, DEP_REC)
    assert rule["id"] == f"aramid-regression.block.{FID[:8]}"
    assert rule["paths"]["include"] == ["requirements.txt"]
    assert "insecure-package" in rule["pattern-regex"]
    assert "PYSEC-2024-1234" in rule["message"]


def test_dep_rule_unparseable_message_returns_none():
    assert pack.compile_dep_rule(FID, dict(DEP_REC, message="???")) is None


def test_draft_rule_always_compiles_with_sentinel():
    rec = {"tool": "semgrep", "rule": "owasp-top-ten.a01", "file": "api.py",
           "verdict": "warn", "severity": "high", "line": 9,
           "message": "idor risk", "status": "fixed", "evidence": ""}
    rule = pack.draft_rule(FID, rec)
    assert rule["id"] == f"aramid-regression.warn.{FID[:8]}"
    assert f"AR-EDIT-ME-{FID[:8]}" in rule["pattern-regex"]
    assert "edit" in rule["message"].lower()


def test_render_pack_is_valid_yaml_semgrep_shape():
    rule = pack.compile_secret_rule(FID, SECRET_REC)
    data = yaml.safe_load(pack.render_pack([rule]))
    assert data["rules"][0]["id"] == rule["id"]
    assert data["rules"][0]["languages"] == ["generic"]
    assert data["rules"][0]["severity"] == "ERROR"


def test_append_rules_dedups_and_creates(tmp_path):
    target = tmp_path / "regression.yml"
    rule = pack.compile_secret_rule(FID, SECRET_REC)
    assert pack.append_rules(target, [rule]) == 1
    assert pack.append_rules(target, [rule]) == 0  # same id -> skipped
    assert pack.existing_ids(target) == {rule["id"]}
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert len(data["rules"]) == 1
```

- [ ] **Step 2: Run to verify failure** — `python -m pytest tests/unit/test_pack.py -v`

- [ ] **Step 3: Implement**

```python
# src/aramid/pack.py
"""pack -- the regression attack pack compiler (spec section 5).

Rules are semgrep rules in <repo>/.aramid-rules/regression.yml (committed,
like .aramid-suppressions.toml). YAML is HAND-RENDERED with json.dumps for
every scalar -- JSON strings are valid YAML flow scalars -- so the runtime
gains no YAML dependency (PyYAML stays dev-only).

Hygiene invariant (spec section 5): a rotated-secret rule is compiled from
the finding's stored REDACTED evidence ("ab…yz (sha256:...)"), never from
the literal secret -- the rules file is committed and embedding the old
value would re-leak it. The resulting pattern is an anchored-prefix/suffix
structural regex scoped to the original file.
"""
import json
import re
from pathlib import Path

RULES_REL_PATH = Path(".aramid-rules") / "regression.yml"
_HEADER = ("# aramid regression attack pack -- compiled from resolved ledger\n"
           "# findings (aramid pack compile / aramid pack add). Committed on\n"
           "# purpose: the pre-push gate replays these rules forever.\n"
           "rules:\n")

_EVIDENCE_RX = re.compile(r"^(?P<pre>.{2,4})…(?P<suf>.{2,4}) \(sha256:")
_DEP_RX = re.compile(r"(?P<pkg>[A-Za-z0-9][A-Za-z0-9_.@/-]{2,})\s+"
                     r"(?P<ver>[0-9][^\s,;]*)")


def _fid8(finding_id: str) -> str:
    return finding_id[:8]


def _tier(rec: dict) -> str:
    return "block" if rec.get("verdict") == "block" else "warn"


def compile_secret_rule(finding_id: str, rec: dict) -> dict | None:
    m = _EVIDENCE_RX.match(rec.get("evidence") or "")
    if not m:
        return None
    pattern = re.escape(m.group("pre")) + r"\S{4,64}" + re.escape(m.group("suf"))
    return {
        "id": f"aramid-regression.{_tier(rec)}.{_fid8(finding_id)}",
        "languages": ["generic"],
        "severity": "ERROR" if _tier(rec) == "block" else "WARNING",
        "message": (f"Reintroduction of rotated secret {_fid8(finding_id)} "
                    f"({rec.get('tool')}:{rec.get('rule')}) resolved in the ledger -- "
                    f"rotate again and remove this value."),
        "paths": {"include": [rec.get("file", "**")]},
        "pattern-regex": pattern,
    }


def compile_dep_rule(finding_id: str, rec: dict) -> dict | None:
    m = _DEP_RX.search(rec.get("message") or "")
    if not m:
        return None
    return {
        "id": f"aramid-regression.{_tier(rec)}.{_fid8(finding_id)}",
        "languages": ["generic"],
        "severity": "ERROR" if _tier(rec) == "block" else "WARNING",
        "message": (f"Reintroduction of banned dependency {m.group('pkg')} "
                    f"({rec.get('rule')}, resolved finding {_fid8(finding_id)})."),
        "paths": {"include": [rec.get("file", "**")]},
        "pattern-regex": re.escape(m.group("pkg")),
    }


def draft_rule(finding_id: str, rec: dict) -> dict:
    return {
        "id": f"aramid-regression.{_tier(rec)}.{_fid8(finding_id)}",
        "languages": ["generic"],
        "severity": "ERROR" if _tier(rec) == "block" else "WARNING",
        "message": (f"DRAFT from finding {_fid8(finding_id)} "
                    f"({rec.get('tool')}:{rec.get('rule')} in {rec.get('file')}): "
                    f"{rec.get('message', '')} -- edit pattern-regex before committing."),
        "paths": {"include": [rec.get("file", "**")]},
        "pattern-regex": f"AR-EDIT-ME-{_fid8(finding_id)}",
    }


def _render_rule(rule: dict) -> str:
    lines = [f"  - id: {json.dumps(rule['id'])}",
             f"    languages: [{', '.join(json.dumps(x) for x in rule['languages'])}]",
             f"    severity: {json.dumps(rule['severity'])}",
             f"    message: {json.dumps(rule['message'])}",
             "    paths:",
             f"      include: [{', '.join(json.dumps(x) for x in rule['paths']['include'])}]",
             f"    pattern-regex: {json.dumps(rule['pattern-regex'])}"]
    return "\n".join(lines) + "\n"


def render_pack(rules: list[dict]) -> str:
    return _HEADER + "".join(_render_rule(r) for r in rules)


_ID_RX = re.compile(r'^\s*-\s*id:\s*"?([A-Za-z0-9_.\-]+)"?\s*$', re.M)


def existing_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return set(_ID_RX.findall(path.read_text(encoding="utf-8")))


def append_rules(path: Path, rules: list[dict]) -> int:
    seen = existing_ids(path)
    fresh = [r for r in rules if r["id"] not in seen]
    if not fresh:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(render_pack(fresh), encoding="utf-8")
    else:
        path.write_text(path.read_text(encoding="utf-8") +
                        "".join(_render_rule(r) for r in fresh), encoding="utf-8")
    return len(fresh)
```

- [ ] **Step 4: Run to verify pass** — `python -m pytest tests/unit/test_pack.py -v`

- [ ] **Step 5: Commit**

```bash
git add src/aramid/pack.py tests/unit/test_pack.py
git commit -m "feat(pack): regression rule compilers with redacted-secret hygiene"
```

---

### Task 14: `aramid pack list|add|compile` commands

**Files:**
- Create: `src/aramid/commands/pack_cmd.py`
- Modify: `src/aramid/cli.py`
- Test: `tests/integration/test_pack_cmd.py`

**Interfaces:**
- Consumes: `pack.*` (Task 13), `Ledger.open_findings`.
- Produces: `cmd_pack_list(root) -> int`, `cmd_pack_add(root, finding_id) -> int`, `cmd_pack_compile(root) -> int`. Auto-compile policy (spec §5): gitleaks records with `status == "rotated"` → `compile_secret_rule`; records whose rule looks like a vuln id (`CVE-|GHSA-|PYSEC-|OSV-` prefix) with `status == "fixed"` → `compile_dep_rule`. `pack add` picks the compiler by the same shape test, falling back to `draft_rule`. CLI: `aramid pack {list,add,compile}` with `add` taking `id`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/integration/test_pack_cmd.py
import uuid
from pathlib import Path

from aramid import pack
from aramid.commands.pack_cmd import cmd_pack_add, cmd_pack_compile, cmd_pack_list
from aramid.ledger import Ledger
from aramid.models import Event, EventType


def _seed(led: Ledger, fid: str, payload: dict, status_event: EventType | None):
    led.append(Event(EventType.FINDING_DETECTED, uuid.uuid4().hex,
                     "2026-07-13T00:00:00+00:00", finding_id=fid, payload=payload))
    if status_event is not None:
        led.append(Event(status_event, uuid.uuid4().hex,
                         "2026-07-13T01:00:00+00:00", finding_id=fid))


SECRET_PAYLOAD = {"tool": "gitleaks", "rule": "aws-access-key", "file": "cfg/prod.env",
                  "verdict": "block", "severity": "critical", "line": 3,
                  "message": "aws key", "evidence": "AK…LE (sha256:abc)",
                  "historical": False}
DEP_PAYLOAD = {"tool": "pip-audit", "rule": "PYSEC-2024-1234", "file": "requirements.txt",
               "verdict": "block", "severity": "critical", "line": 0,
               "message": "insecure-package 1.0.0 has PYSEC-2024-1234",
               "evidence": "", "historical": False}


def _repo_with_ledger(tmp_path) -> Path:
    (tmp_path / ".aramid").mkdir()
    return tmp_path


def test_compile_picks_rotated_secrets_and_fixed_deps(tmp_path):
    root = _repo_with_ledger(tmp_path)
    led = Ledger(root / ".aramid" / "ledger.db")
    _seed(led, "a" * 64, SECRET_PAYLOAD, EventType.FINDING_ROTATED)
    _seed(led, "b" * 64, DEP_PAYLOAD, EventType.FINDING_RESOLVED)
    _seed(led, "c" * 64, SECRET_PAYLOAD, None)  # still open -> NOT compiled
    led.close()
    assert cmd_pack_compile(root) == 0
    ids = pack.existing_ids(root / pack.RULES_REL_PATH)
    assert f"aramid-regression.block.{'a' * 8}" in ids
    assert f"aramid-regression.block.{'b' * 8}" in ids
    assert len(ids) == 2


def test_pack_add_promotes_any_finding_as_draft(tmp_path):
    root = _repo_with_ledger(tmp_path)
    led = Ledger(root / ".aramid" / "ledger.db")
    payload = {"tool": "semgrep", "rule": "owasp-top-ten.a01", "file": "api.py",
               "verdict": "warn", "severity": "high", "line": 9,
               "message": "idor", "evidence": "", "historical": False}
    _seed(led, "d" * 64, payload, None)
    led.close()
    assert cmd_pack_add(root, "d" * 64) == 0
    ids = pack.existing_ids(root / pack.RULES_REL_PATH)
    assert f"aramid-regression.warn.{'d' * 8}" in ids


def test_pack_add_unknown_finding_errors(tmp_path):
    root = _repo_with_ledger(tmp_path)
    Ledger(root / ".aramid" / "ledger.db").close()
    assert cmd_pack_add(root, "nope") == 3


def test_pack_list_runs_on_empty_and_populated(tmp_path, capsys):
    root = _repo_with_ledger(tmp_path)
    Ledger(root / ".aramid" / "ledger.db").close()
    assert cmd_pack_list(root) == 0
    assert "no pack rules" in capsys.readouterr().out.lower()
```

- [ ] **Step 2: Run to verify failure** — `python -m pytest tests/integration/test_pack_cmd.py -v`

- [ ] **Step 3: Implement**

```python
# src/aramid/commands/pack_cmd.py
"""aramid pack list|add|compile (spec section 5). compile auto-promotes:
rotated gitleaks secrets -> redacted reintroduction rules; fixed
dependency findings (CVE/GHSA/PYSEC/OSV rule ids) -> manifest bans.
add promotes ANY ledger finding (draft sentinel when no compiler fits)."""
import re
import sys
from pathlib import Path

from aramid import pack
from aramid.ledger import Ledger

_VULN_ID = re.compile(r"^(CVE-|GHSA-|PYSEC-|OSV-)")


def _compiler_for(rec: dict):
    if rec.get("tool") == "gitleaks" and rec.get("status") == "rotated":
        return pack.compile_secret_rule
    if _VULN_ID.match(rec.get("rule") or "") and rec.get("status") == "fixed":
        return pack.compile_dep_rule
    return None


def _pack_path(root: Path) -> Path:
    return Path(root) / pack.RULES_REL_PATH


def cmd_pack_list(root) -> int:
    ids = sorted(pack.existing_ids(_pack_path(Path(root))))
    if not ids:
        print("aramid pack: no pack rules")
        return 0
    for rid in ids:
        print(f"  {rid}")
    print(f"aramid pack: {len(ids)} rule(s) in {pack.RULES_REL_PATH.as_posix()}")
    return 0


def cmd_pack_add(root, finding_id: str) -> int:
    root = Path(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        rec = ledger.open_findings().get(finding_id)
    finally:
        ledger.close()
    if rec is None:
        print(f"aramid pack: no such finding {finding_id!r}", file=sys.stderr)
        return 3
    compiler = _compiler_for(rec)
    rule = compiler(finding_id, rec) if compiler else None
    if rule is None:
        rule = pack.draft_rule(finding_id, rec)
        print("aramid pack: emitted DRAFT rule -- edit pattern-regex before committing")
    added = pack.append_rules(_pack_path(root), [rule])
    print(f"aramid pack: {added} rule(s) added ({rule['id']})")
    return 0


def cmd_pack_compile(root) -> int:
    root = Path(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        state = ledger.open_findings()
    finally:
        ledger.close()
    rules = []
    for fid, rec in state.items():
        compiler = _compiler_for(rec)
        if compiler is None:
            continue
        rule = compiler(fid, rec)
        if rule is not None:
            rules.append(rule)
    added = pack.append_rules(_pack_path(root), rules)
    print(f"aramid pack: compiled {added} new rule(s) "
          f"({len(rules) - added} already present)")
    return 0
```

CLI subparser + dispatch:

```python
    sp = sub.add_parser("pack")
    packsub = sp.add_subparsers(dest="pack_command")
    packsub.add_parser("list")
    pa = packsub.add_parser("add")
    pa.add_argument("id")
    packsub.add_parser("compile")
```

```python
    if args.command == "pack":
        from aramid.commands.pack_cmd import cmd_pack_add, cmd_pack_compile, cmd_pack_list
        if args.pack_command == "list":
            return cmd_pack_list(root)
        if args.pack_command == "add":
            return cmd_pack_add(root, args.id)
        if args.pack_command == "compile":
            return cmd_pack_compile(root)
        print("aramid: pack: missing subcommand", file=sys.stderr)
        return 3
```

- [ ] **Step 4: Run to verify pass** — `python -m pytest tests/integration/test_pack_cmd.py tests/integration/test_cli_dispatch.py -v`

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/pack_cmd.py src/aramid/cli.py tests/integration/test_pack_cmd.py
git commit -m "feat(cli): aramid pack list/add/compile"
```

---

### Task 15: Gates pick up the pack (semgrep extra config + block tier)

**Files:**
- Modify: `src/aramid/runners/base.py` (RunContext field), `src/aramid/pipeline.py` (populate it), `src/aramid/runners/semgrep.py` (argv + canonical id), `src/aramid/data/block_rules.toml`
- Test: `tests/unit/test_runner_semgrep.py` (append), `tests/unit/test_policy.py` (append), `tests/unit/test_pipeline.py` (append)

**Interfaces:**
- Produces:
  - `RunContext.extra_semgrep_configs: tuple[str, ...] = ()` (additive field, default keeps every existing construction site valid).
  - `pipeline.run_gate` sets it to `(str(root / ".aramid-rules" / "regression.yml"),)` iff the file exists AND `cfg.pack.get("enabled", True)`.
  - `semgrep._build_argv` emits one extra `--config <path>` pair per entry.
  - `semgrep._canonical_rule_id` also canonicalizes `aramid-regression.` prefixed ids (strips semgrep's config-path prefix, same reason as the owasp fix in Phase 1 commit 56e4022).
  - `block_rules.toml` `[semgrep].block` gains `"aramid-regression.block.*"`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_runner_semgrep.py`:

```python
def test_argv_includes_extra_configs(tmp_path):
    ctx = RunContext(root=tmp_path, files=["a.py"],
                     extra_semgrep_configs=(str(tmp_path / "regression.yml"),))
    argv = semgrep._build_argv(ctx)
    assert argv.count("--config") == 2
    assert str(tmp_path / "regression.yml") in argv


def test_canonical_rule_id_strips_prefix_for_pack_rules():
    live = "repo.aramid-rules.regression.aramid-regression.block.deadbeef"
    assert semgrep._canonical_rule_id(live) == "aramid-regression.block.deadbeef"
    # owasp behavior unchanged
    assert semgrep._canonical_rule_id("x.y.owasp-top-ten.a01") == "owasp-top-ten.a01"
```

Append to `tests/unit/test_policy.py`:

```python
def test_pack_block_rule_classifies_block(tmp_path, monkeypatch):
    from aramid import config
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "nouser.toml")
    cfg = config.load_config(tmp_path)
    severity, verdict = policy.classify(
        "semgrep", "aramid-regression.block.deadbeef", "ERROR", Gate.PRE_PUSH, cfg=cfg)
    assert verdict is Verdict.BLOCK


def test_pack_warn_rule_classifies_warn(tmp_path, monkeypatch):
    from aramid import config
    monkeypatch.setattr(config, "_user_config_path", lambda: tmp_path / "nouser.toml")
    cfg = config.load_config(tmp_path)
    severity, verdict = policy.classify(
        "semgrep", "aramid-regression.warn.deadbeef", "WARNING", Gate.PRE_PUSH, cfg=cfg)
    assert verdict is Verdict.WARN
```

Append to `tests/unit/test_pipeline.py` (follow its existing run_gate stub pattern — the file stubs RUNNERS heavily; assert on the ctx the stub receives):

```python
def test_run_gate_sets_extra_semgrep_configs_when_pack_present(<existing stub pattern>):
    (root / ".aramid-rules").mkdir()
    (root / ".aramid-rules" / "regression.yml").write_text("rules:\n", encoding="utf-8")
    # run run_gate with the module's stubbed runner capturing ctx
    assert captured_ctx.extra_semgrep_configs == (
        str(root / ".aramid-rules" / "regression.yml"),)
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/unit/test_runner_semgrep.py tests/unit/test_policy.py tests/unit/test_pipeline.py -v`

- [ ] **Step 3: Implement**

`runners/base.py` — append to RunContext:

```python
    extra_semgrep_configs: tuple[str, ...] = ()
```

`pipeline.py` — where `ctx = RunContext(...)` is built:

```python
    pack_file = root / ".aramid-rules" / "regression.yml"
    extra_configs = ((str(pack_file),)
                     if cfg.pack.get("enabled", True) and pack_file.exists() else ())
    ctx = RunContext(root=root, files=files, rng=rng,
                      pkg_manager=detect_package_manager(root),
                      stacks=detect_stacks(root, root),
                      extra_semgrep_configs=extra_configs)
```

`runners/semgrep.py`:

```python
_PACK_RULE_PREFIX = "aramid-regression."


def _canonical_rule_id(check_id: str) -> str:
    for prefix in (_CANONICAL_RULE_PREFIX, _PACK_RULE_PREFIX):
        idx = check_id.find(prefix)
        if idx != -1:
            return check_id[idx:]
    return check_id


def _build_argv(ctx) -> list[str]:
    argv = ["semgrep", "--config", str(VENDORED_RULES_PATH)]
    for extra in getattr(ctx, "extra_semgrep_configs", ()):
        argv += ["--config", extra]
    argv += ["--json", "--metrics=off", "--quiet", "--", *ctx.files]
    return argv
```

`data/block_rules.toml` `[semgrep]` list:

```toml
block = ["owasp-top-ten.*", "*sqli*", "*deserialization*", "*command-injection*",
         "aramid-regression.block.*"]
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/unit/test_runner_semgrep.py tests/unit/test_policy.py tests/unit/test_pipeline.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/runners/base.py src/aramid/runners/semgrep.py src/aramid/pipeline.py src/aramid/data/block_rules.toml tests/unit/test_runner_semgrep.py tests/unit/test_policy.py tests/unit/test_pipeline.py
git commit -m "feat(gates): semgrep replays the regression pack; block-tier pack rules enforce"
```

---

### Task 16: Regression-pack consumer + live reintroduction e2e

**Files:**
- Create: `src/aramid/consumers/regression_pack.py`
- Test: `tests/integration/test_regression_pack_consumer.py`

**Interfaces:**
- Consumes: `pack.RULES_REL_PATH`, `queue.QueueItem`, `DrainContext/ConsumerResult`, semgrep runner internals (`run_subprocess`, `json_or_crashed`, `semgrep.parse`), `gitutil.diff_paths`, `config.filter_paths`.
- Produces: `consumers/regression_pack.py` with `NAME = "regression_pack"`, `consume(item, ctx) -> ConsumerResult`, registered into `CONSUMERS` at import; `commands/drain.py` gains `import aramid.consumers.regression_pack  # noqa: F401` so registration happens.

- [ ] **Step 1: Write the failing tests**

```python
# tests/integration/test_regression_pack_consumer.py
"""Fixture-driven consumer tests + THE reintroduction e2e (spec section 7):
resolve a finding -> compile pack rule -> reintroduce the pattern ->
the gate blocks. Live-semgrep parts reuse test_semgrep_rules.py's
discovery/skip pattern."""
import json
import subprocess
from pathlib import Path

import pytest

from aramid import pack, queue
from aramid.consumers import regression_pack
from aramid.consumers.base import CONSUMERS, DrainContext
from aramid.ledger import Ledger
from aramid.runners.base import RunnerResult, ToolState


def test_consumer_registered():
    assert CONSUMERS.get("regression_pack") is regression_pack


def _item(head="deadbee"):
    return queue.QueueItem(id="i1", base=None, head=head, score=50, reasons=("r",),
                           state="queued", created_at="t", updated_at="t")


def test_no_pack_file_is_ok_noop(tmp_path):
    ctx = DrainContext(root=tmp_path, cfg=None, ledger=None, clock=lambda: "t")
    res = regression_pack.consume(_item(), ctx)
    assert res.state == "ok" and res.findings == [] and "no pack" in res.note


def test_consume_parses_semgrep_output(tmp_path, monkeypatch):
    (tmp_path / pack.RULES_REL_PATH).parent.mkdir(parents=True)
    (tmp_path / pack.RULES_REL_PATH).write_text("rules: []\n", encoding="utf-8")
    payload = {"results": [{"check_id": "x.aramid-regression.block.deadbeef",
                            "path": "cfg/prod.env", "start": {"line": 3},
                            "extra": {"severity": "ERROR", "message": "reintroduction"}}]}
    monkeypatch.setattr(regression_pack, "_changed_paths", lambda root, item: ["cfg/prod.env"])
    monkeypatch.setattr(
        regression_pack, "run_subprocess",
        lambda argv, cwd, timeout_s, env=None: RunnerResult(
            tool="semgrep", state=ToolState.OK, raw=json.dumps(payload)))
    ctx = DrainContext(root=tmp_path, cfg=None, ledger=None, clock=lambda: "t")
    res = regression_pack.consume(_item(), ctx)
    assert res.state == "ok"
    assert res.findings[0].rule == "aramid-regression.block.deadbeef"
    assert res.cost == 0.0
```

Plus the live e2e (same file; copy `_find_semgrep`/PATH-fixture pattern from `tests/integration/test_semgrep_rules.py` verbatim, including its skipif):

```python
@pytest.mark.skipif(_SEMGREP_BIN is None, reason=_SKIP_REASON)
def test_reintroduction_blocks_at_gate_live(tmp_path, semgrep_path_env):
    """resolve -> compile -> reintroduce -> BLOCK, through the real pipeline."""
    import uuid
    from aramid import config as config_mod
    from aramid import pipeline
    from aramid.models import Event, EventType, Gate, Verdict

    root = _make_git_repo(tmp_path)  # same _git/_repo helpers as the module's other tests
    # 1. seed a rotated gitleaks finding whose evidence anchors are known
    led = Ledger(root / ".aramid" / "ledger.db")
    fid = "e" * 64
    led.append(Event(EventType.FINDING_DETECTED, uuid.uuid4().hex, "t", finding_id=fid,
                     payload={"tool": "gitleaks", "rule": "generic-api-key",
                              "file": "cfg.env", "verdict": "block",
                              "severity": "critical", "line": 1, "message": "key",
                              "evidence": "AK…LE (sha256:x)", "historical": False}))
    led.append(Event(EventType.FINDING_ROTATED, uuid.uuid4().hex, "t", finding_id=fid))
    led.close()
    # 2. compile the pack
    from aramid.commands.pack_cmd import cmd_pack_compile
    assert cmd_pack_compile(root) == 0
    # 3. reintroduce a matching value and commit it
    (root / "cfg.env").write_text("AKSOMETHINGSECRETLE\n", encoding="utf-8")
    _git(root, "add", "cfg.env")
    _git(root, "commit", "-m", "reintroduce")
    # 4. the ALL gate must now block via the pack rule
    cfg = config_mod.load_config(root)
    led = Ledger(root / ".aramid" / "ledger.db")
    try:
        result = pipeline.run_gate(root, Gate.ALL, "all", cfg, led)
        pack_blocks = [f for f in result.findings
                       if f.rule.startswith("aramid-regression.block.")
                       and f.verdict is Verdict.BLOCK]
        assert pack_blocks, [f"{f.rule}:{f.verdict}" for f in result.findings]
    finally:
        led.close()
```

- [ ] **Step 2: Run to verify failure** — `python -m pytest tests/integration/test_regression_pack_consumer.py -v`

- [ ] **Step 3: Implement**

```python
# src/aramid/consumers/regression_pack.py
"""Drain-time pack replay (spec section 5): run semgrep with ONLY the
regression ruleset against the queue item's changed files. Zero tokens;
cost is always 0.0. The normal gates already replay the pack on diffs
(Task 15) -- this consumer covers drained ranges, including commits that
bypassed hooks."""
import time

from aramid import gitutil
from aramid import config as config_mod
from aramid.consumers import base
from aramid.consumers.base import ConsumerResult, DrainContext
from aramid.pack import RULES_REL_PATH
from aramid.runners import semgrep as semgrep_runner
from aramid.runners._util import json_or_crashed
from aramid.runners.base import RunnerResult, ToolState, run_subprocess

NAME = "regression_pack"
TIMEOUT_S = 120.0
_OK_RETURNCODES = frozenset({0, 1})


def _changed_paths(root, item) -> list[str]:
    return gitutil.diff_paths(root, item.base, item.head)


def consume(item, ctx: DrainContext) -> ConsumerResult:
    pack_file = ctx.root / RULES_REL_PATH
    if not pack_file.exists():
        return ConsumerResult(consumer=NAME, state="ok", note="no pack file")
    files = _changed_paths(ctx.root, item)
    if ctx.cfg is not None:
        files = config_mod.filter_paths(files, ctx.cfg)
    files = [f for f in files if (ctx.root / f).exists()]
    if not files:
        return ConsumerResult(consumer=NAME, state="ok", note="no files in range")
    started = time.monotonic()
    argv = ["semgrep", "--config", str(pack_file), "--json", "--metrics=off",
            "--quiet", "--", *files]
    result = run_subprocess(argv, ctx.root, TIMEOUT_S)
    checked = json_or_crashed("semgrep", result, _OK_RETURNCODES, empty="{}")
    duration = time.monotonic() - started
    if checked.state is not ToolState.OK:
        return ConsumerResult(consumer=NAME, state="degraded",
                              duration_s=duration, note=f"semgrep {checked.state}")
    from aramid.runners.base import RunContext
    findings = semgrep_runner.parse(checked, RunContext(root=ctx.root, files=files))
    return ConsumerResult(consumer=NAME, state="ok", findings=findings,
                          duration_s=duration, cost=0.0)


base.CONSUMERS[NAME] = __import__(__name__, fromlist=["consume"])
```

(Simpler registration alternative the implementer may prefer: at the bottom of the module, `from aramid.consumers.base import CONSUMERS` then `CONSUMERS[NAME] = sys.modules[__name__]`.)

In `commands/drain.py`, add near the other imports:

```python
import aramid.consumers.regression_pack  # noqa: F401  -- registers the consumer
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/integration/test_regression_pack_consumer.py tests/integration/test_drain.py -v`
Expected: all PASS (drain tests confirm the real consumer coexists with the fake; if the fake-consumer tests assumed CONSUMERS empty, monkeypatch-replace the dict content there: `monkeypatch.setattr(base, "CONSUMERS", {"fake": _FakeConsumer})` — adjust Task 11's tests accordingly).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/consumers/regression_pack.py src/aramid/commands/drain.py tests/integration/test_regression_pack_consumer.py tests/integration/test_drain.py
git commit -m "feat(consumers): regression-pack drain replay + live reintroduction e2e"
```

---

## Milestone M6 — Status, docs, dogfood

### Task 17: `aramid status` queue/drain/schedule sections

**Files:**
- Modify: `src/aramid/commands/status.py`
- Test: `tests/integration/test_status.py` (append)

**Interfaces:**
- Consumes: `queue.materialize_queue/queued_item`, `EventType.CONSUMER_RUN_FINISHED`, `registry.load_registry`, `schedule._query_argv`.
- Produces: three new sections after the existing ones —
  - `queue: 1 queued (score 55, 3h old) | 4 drained | 1 expired` + one reason line per queued item; or `queue: empty`.
  - `last drain: <at> (<consumer>, N finding(s))` from the latest `CONSUMER_RUN_FINISHED`, or `last drain: never`.
  - `registry: registered` / `registry: NOT registered (aramid init to register)`; `scheduled drain: installed|not installed|unknown` via a guarded `schtasks /Query` (any exception → `unknown`).

- [ ] **Step 1: Write the failing tests** (append to `tests/integration/test_status.py`, reusing its existing seeded-ledger + capsys pattern)

```python
def test_status_shows_queue_and_drain_sections(tmp_path, capsys, monkeypatch):
    from aramid import queue, registry
    from aramid.models import Event, EventType
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "repos.toml")
    root = tmp_path / "repo"
    (root / ".aramid").mkdir(parents=True)  # cmd_status needs only config+ledger, no git
    led = Ledger(root / ".aramid" / "ledger.db")
    queue.enqueue(led, "2026-07-13T00:00:00+00:00", "a", "b", 55, ["security-path: auth.py"])
    led.append(Event(EventType.CONSUMER_RUN_FINISHED, "r1", "2026-07-13T01:00:00+00:00",
                     payload={"consumer": "regression_pack", "finding_count": 2}))
    led.close()
    assert cmd_status(root) == 0
    out = capsys.readouterr().out
    assert "queue: 1 queued (score 55" in out
    assert "security-path: auth.py" in out
    assert "last drain: 2026-07-13T01:00:00+00:00 (regression_pack, 2 finding(s))" in out
    assert "registry: NOT registered" in out


def test_status_empty_queue_and_never_drained(tmp_path, capsys, monkeypatch):
    from aramid import registry
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "repos.toml")
    root = tmp_path / "repo"
    (root / ".aramid").mkdir(parents=True)
    Ledger(root / ".aramid" / "ledger.db").close()  # empty ledger
    assert cmd_status(root) == 0
    out = capsys.readouterr().out
    assert "queue: empty" in out
    assert "last drain: never" in out
```

- [ ] **Step 2: Run to verify failure** — `python -m pytest tests/integration/test_status.py -v`

- [ ] **Step 3: Implement** — inside `cmd_status`'s existing print flow, after the current sections:

```python
    # --- Phase 2a: queue / drain / registry / schedule (spec section 2) ---
    from datetime import datetime, timezone

    from aramid import queue as queue_mod
    from aramid import registry as registry_mod

    items = queue_mod.materialize_queue(ledger.events())
    queued = [i for i in items.values() if i.state == queue_mod.QUEUED]
    drained_n = sum(1 for i in items.values() if i.state == queue_mod.DRAINED)
    expired_n = sum(1 for i in items.values() if i.state == queue_mod.EXPIRED)
    if queued:
        q = queued[0]
        age_h = int((datetime.now(timezone.utc)
                     - datetime.fromisoformat(q.created_at)).total_seconds() // 3600)
        print(f"queue: {len(queued)} queued (score {q.score}, {age_h}h old) | "
              f"{drained_n} drained | {expired_n} expired")
        for reason in q.reasons:
            print(f"  {reason}")
    else:
        print(f"queue: empty | {drained_n} drained | {expired_n} expired"
              if (drained_n or expired_n) else "queue: empty")

    last_consumer = None
    for e in ledger.events():
        if e.type is EventType.CONSUMER_RUN_FINISHED:
            last_consumer = e
    if last_consumer:
        print(f"last drain: {last_consumer.at} "
              f"({last_consumer.payload.get('consumer')}, "
              f"{last_consumer.payload.get('finding_count', 0)} finding(s))")
    else:
        print("last drain: never")

    from aramid.fingerprint import normalize_path
    registered = any(normalize_path(e["path"]) == normalize_path(str(root.resolve()))
                     for e in registry_mod.load_registry())
    print("registry: registered" if registered
          else "registry: NOT registered (aramid init to register)")
    try:
        import subprocess as _sp
        from aramid.commands.schedule import _query_argv
        cp = _sp.run(_query_argv(), capture_output=True, text=True)
        print("scheduled drain: installed" if cp.returncode == 0
              else "scheduled drain: not installed")
    except Exception:
        print("scheduled drain: unknown")
```

- [ ] **Step 4: Run to verify pass** — `python -m pytest tests/integration/test_status.py -v` (all pre-existing status tests must still pass).

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/status.py tests/integration/test_status.py
git commit -m "feat(status): queue, last-drain, registry, and schedule sections"
```

---

### Task 18: Docs, dogfood, full suite, CI

**Files:**
- Modify: `src/aramid/data/ARAMID.md.tmpl`, `README.md`
- Test: full suite + live dogfood on aramid's own repo

- [ ] **Step 1: Update `ARAMID.md.tmpl`** — append after the existing gate description:

```markdown
## Always-on triage (Phase 2a)

Every commit is scored at zero cost by a post-commit hook (security-surface
paths, risky content, novelty, graphite blast radius). Commits scoring >= 40
join a review queue drained on a schedule (`aramid drain`, Task Scheduler
task `aramid-drain`). The regression attack pack (`.aramid-rules/regression.yml`,
committed) replays rules compiled from resolved findings — reintroducing a
rotated secret or banned dependency blocks at pre-push. `aramid status` shows
queue depth and drain history; `aramid pack list|add|compile` manages rules.
```

- [ ] **Step 2: Update `README.md`** — add a short "Phase 2a: watcher chassis" section mirroring the same content plus the new commands (`triage`, `drain`, `schedule`, `pack`).

- [ ] **Step 3: Run the FULL suite**

Run: `python -m pytest -q`
Expected: every test passes (321 Phase 1 + all new ones). Fix anything that fails before proceeding.

- [ ] **Step 4: Dogfood on aramid's own repo**

```bash
python -m aramid triage HEAD
python -m aramid status
python -m aramid drain --repo . --dry-run
```

Expected: triage prints a score line; status shows the queue section; dry-run prints the repo's queued state. (Do NOT `aramid schedule install` on the dev machine as part of the task — that is the user's call.)

- [ ] **Step 5: Commit and push; verify CI**

```bash
git add src/aramid/data/ARAMID.md.tmpl README.md
git commit -m "docs: Phase 2a triage/drain/pack usage"
git push
gh run watch $(gh run list --repo jared0565/aramid --limit 1 --json databaseId --jq '.[0].databaseId') --repo jared0565/aramid --exit-status
```

Expected: CI green — everything in 2a is zero-token, so the existing workflow covers it (including the schtasks e2e on windows-latest).

---

## Plan self-review notes (already applied)

- **Spec coverage:** §2 components → Tasks 1-17; §3 scoring → Task 5; §4 data model/config → Tasks 1, 4; §5 pack → Tasks 13-16; §6 error handling → embedded per task (fail-open Task 7/8, lock/isolation Task 11, StartWhenAvailable Task 12, registry rot printed in drain Task 11, expiry Tasks 1/11, graphite-absent Task 5); §7 testing → every task + Task 18 full suite; §8 forward hooks → cost fields Tasks 10/11, consumer protocol Task 10.
- **Naming:** engine module `triage.py`, command module `triage_cmd.py` (CLI name is still `aramid triage`); pack engine `pack.py`, command `pack_cmd.py` — mirrors Phase 1's `ledger.py`/`ledger_cmd.py` precedent.
- **Type consistency spot-checks:** `QueueItem` fields used by drain/status/consumer match Task 1; `ConsumerResult.findings: list[RawFinding]` consumed by Task 11's normalize call; `run_triage` signature identical at both call sites (Tasks 6, 11).
