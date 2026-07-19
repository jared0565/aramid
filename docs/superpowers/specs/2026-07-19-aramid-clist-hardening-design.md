# Aramid C-list hardening bundle — design

Date: 2026-07-19
Scope decision (user, on record): the three Phase 1/2a residuals shelved by the
LLM-hardening bundle — subprocess encoding, override-reason materialization,
triage shim self-timeout. All three re-verified OPEN against `main @ f961029`
before scoping (per the stale-ticket lesson: the refute-cap ticket died this way).
Branch: `feat/clist-hardening` off `main @ f961029`.

## 1. Items

### Item 1 (behavior): subprocess encoding sweep — complete the `text=True` class

Current: `gitutil._run` got `encoding="utf-8", errors="replace"` in the Phase 2a
whole-branch fix (cp1252 hosts mojibake UTF-8 output, and bytes undefined in
cp1252 — 0x81 0x8D 0x8F 0x90 0x9D — raise `UnicodeDecodeError`). Eight more
`subprocess` call sites across six files in `src/` still use `text=True` with
no `encoding=` (`providers/base.py`'s two sites already have it;
`runners/base.py`'s taskkill runs in bytes mode — no decode):

| Site | Emitter | Exposure |
|---|---|---|
| `hooks.py:65` (`_git_config`) | git (UTF-8) | decode crash → propagates out of `hooks_dir` into install/uninstall/doctor |
| `runners/base.py:93` (scanner `Popen`) | ruff/semgrep/gitleaks/eslint/etc. JSON (UTF-8) | mojibaked paths break fingerprints; decode crash → CRASHED tool state in the **gate path** |
| `doctor.py:149` (`--version` probes) | tools (UTF-8) | decode crash inside probe loop |
| `drain.py:46` (`tasklist`) | Windows OEM codepage | decode crash in lock-staleness probe |
| `schedule.py:82,86,88` (`schtasks`) | Windows OEM codepage | decode crash in schedule create/remove/status |
| `status.py:242` (`schtasks` query) | Windows OEM codepage | decode crash in status section |

Fix — two groups, by what the child actually emits:

- **UTF-8 emitters** (`hooks.py`, `runners/base.py`, `doctor.py`): add
  `encoding="utf-8", errors="replace"`, mirroring `gitutil._run` and its
  rationale comment.
- **OEM emitters** (`drain.py`, `schedule.py`, `status.py`): add
  `errors="replace"` ONLY, keeping the locale-preferred codec. `tasklist` and
  `schtasks` emit the console/ANSI codepage, not UTF-8 — forcing UTF-8 there
  would trade one mojibake for another. The consuming logic is ASCII-only
  (`str(pid)` containment, returncode checks, verbatim print), which decodes
  identically under any of these codecs; `errors="replace"` removes only the
  crash mode.

No call-site logic changes anywhere; every change converts a possible
`UnicodeDecodeError` into a best-effort replacement character.

Tests: a real-subprocess round-trip through `runners/base.py` with non-UTF-8
bytes on stdout (proves no raise + replacement); a `_git_config` decode test
via `hooks_dir` with a real UTF-8 config value. AMENDMENT (plan-time): the
OEM-group sites get NO dedicated test — a fake `tasklist`/`schtasks` cannot be
injected (fixed argv resolved by `CreateProcess`, which appends `.exe` only, so
no PATH/script seam), and a real one cannot be made to emit non-ASCII
deterministically. The two UTF-8-group tests discriminate the fix through
Python's actual subprocess decode path — the identical mechanism at all eight
sites; the OEM sites are the same one-argument pattern, review-verified.

### Item 2 (behavior): override-reason materialization

Current: `Ledger._materialize` (`ledger.py:33-35`) folds a `finding_overridden`
event into status only; the payload (the `--reason` recorded by
`cmd_override`) is dropped from materialized state, so
`pipeline._overrides_from_ledger` (`pipeline.py:224-231`) always constructs
`OverrideRecord(reason="")`. The reason is durable in the raw event stream —
only the materialized view loses it. Known gap since Task 5.3, documented in
`override.py`'s docstring.

Fix: in the `finding_overridden` branch, additionally fold
`state[e.finding_id]["reason"] = e.payload.get("reason", "")`. Nothing else
changes:

- `_overrides_from_ledger` already reads `rec.get("reason", "")` → the real
  reason now flows into `OverrideRecord` with zero pipeline change.
- `compact()` keeps the latest `FINDING_OVERRIDDEN` row whole (payload intact,
  `last_terminal` selection) → the reason survives compaction. Verified against
  current `compact()`; no compaction change.
- A re-detect after an override rebuilds state from the detect payload (no
  `reason` key) — correct: the finding is open again, the override is history.
- Delete the now-stale KNOWN-GAP paragraph from `override.py`'s docstring and
  the Task 5.3 cross-reference comment it carries.

Tests: materialize carries the reason (detect → override → `open_findings()`
shows `status=="overridden"` + reason); `_overrides_from_ledger` surfaces it in
`OverrideRecord.reason`; compact round-trip preserves it (compact → re-open →
reason still present).

### Item 3 (behavior): triage watchdog — bound `git commit` latency

Current: the post-commit shim (`hooks.py:136-159`) swallows output and exit
codes but has NO wall-clock bound; `cmd_triage` (`triage_cmd.py`) is likewise
unbounded. A wedged git subprocess inside triage hangs `git commit`
indefinitely. Phase 2a spec section 6 specified a "2s self-timeout +
`.aramid/logs/triage-<ts>.log`"; neither shipped (flagged at Task 7, deferred
at final review).

Decisions (user, on record): Python-side watchdog armed via a shim-passed flag;
budget 15s (not the spec's 2s — cold `python -m aramid` start plus a real diff
can exceed 2s legitimately, and every kill drops a live enqueue that drain must
recover); NO log file (ledger + drain catch-up already provide observability —
YAGNI). This supersedes Phase 2a spec section 6's "2s + log file" on those two
points; the self-timeout obligation itself is hereby met.

Fix:

- `render_triage_shim`: both interpreter branches invoke
  `… -m aramid triage HEAD --budget 15 …` (redirects unchanged). Shim remains
  byte-rendered `\n`-only; golden tests updated.
- `cmd_triage(root, rev="HEAD", budget=None)`: when `budget` is set, the FIRST
  statement arms a daemon `threading.Timer(budget, _die)` where `_die` prints
  `aramid: triage: watchdog: exceeded {budget}s -- killing` to stderr, flushes
  both streams, and calls `os._exit(3)`. The timer is cancelled in a `finally`.
  Arming precedes repo resolution, config load, ledger open — every hang class
  (git subprocess, config read, sqlite, filesystem) is covered by construction.
- Safety argument: the shim maps ANY exit to 0 (fail-open), SQLite is in WAL
  mode (crash-safe against `os._exit` mid-write), and the drain catch-up sweep
  re-derives any enqueue the killed run failed to record. `os._exit` skipping
  interpreter cleanup is exactly the point — a hung non-daemon thread must not
  keep the process alive.
- `cli.py`: `p_triage.add_argument("--budget", type=float, default=None)`;
  dispatch passes it through. Manual `aramid triage` without the flag is
  unbounded, unchanged.
- Existing installed shims (no `--budget`) keep old behavior until regenerated;
  `aramid init` is idempotent and rewrites them. README note.

Tests: golden shim bytes contain `--budget 15` in both branches; watchdog fires
on an injected hang (monkeypatch `os._exit` to a recording sentinel +
monkeypatch a hang point) and does NOT fire on a fast run (timer cancelled —
assert via sentinel after completion); no-flag path arms no timer; existing
live post-commit e2e still passes (now exercising the flag through a real git
dispatch); CLI dispatch test for `--budget`.

## 2. Invariants (whole-bundle)

1. **Gate behavior unchanged**: no change to verdict logic, exit-code mapping,
   or pre-commit/pre-push shims. (`runners/base.py` encoding can only change
   decoded *text* where output was previously mojibake/crash.)
2. **Fail-open preserved**: the post-commit path still cannot block or
   noisy-fail a commit — the watchdog exits 3, the shim maps it to 0.
3. **Ledger event stream untouched**: Item 2 changes materialization only; no
   event shape, append, or compaction change.
4. **No new dependencies, no network** — stdlib `threading`/`os` only.

## 3. Execution shape

Same as the LLM-hardening bundle: INLINE execution on `feat/clist-hardening`,
one commit per item, sonnet per-item reviews, ruff parity check (base vs
branch), full suite, whole-branch review, CI, then finishing skill.
