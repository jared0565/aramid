import json
import re
import sqlite3
from pathlib import Path

# Module scope, NOT a lazy import inside the one branch that uses it: an
# ImportError would then surface only on a ledger corrupt enough to make
# `resolve_departed` swallow something, i.e. exactly when the diagnostic is
# needed. Safe because `diagnostics` imports nothing but `sys` -- unlike
# `queue`, which imports Ledger from here and so must stay local (see
# `compact`).
from aramid import diagnostics
from aramid.models import Event, EventType, Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL, run_id TEXT NOT NULL, at TEXT NOT NULL,
  finding_id TEXT, payload TEXT NOT NULL DEFAULT '{}');
"""


_SYNTHETIC_RE = re.compile(r"^<.*>$")


def _is_synthetic_path(file: str | None) -> bool:
    """True for a `<...>` label that stands in for a finding with no file.

    The tests runner reports every whole-suite finding against `<test-suite>`
    (runners/tests.py). It is not a path, so "does it still exist?" has no
    answer, and `_departed` must not invent one -- see the LANDMINE there.

    Matched by SHAPE, not by importing `_SUITE_FILE_MARKER`. Three reasons:
    `record_run` sees only a string and has no way to know which producer
    wrote it; a second synthetic marker inherits the guard rather than needing
    a second fix; and `ledger` importing a runner inverts the layering that
    `tests_gate` exists to respect ("no runner imports the ledger"). A real
    file honestly named `<x>` therefore never resolves via the departed route
    -- the safe direction, since it leaves the finding OPEN.
    `test_the_real_suite_marker_matches_the_synthetic_shape` pins the shape to
    the live constant so a rename cannot silently escape the guard.
    """
    return bool(file) and _SYNTHETIC_RE.match(file) is not None


def _resolved_root(root: Path | None) -> Path | None:
    """`root.resolve()`, or None if there is no root or it cannot be resolved.

    Split out so a caller checking many findings resolves the repo root ONCE.
    It was inside `_departed`, i.e. recomputed per finding, and on Windows
    `Path.resolve()` is a filesystem round trip -- measured at roughly half the
    0.8 ms each `_departed` call was costing. `resolve_departed` walks every
    open finding of a producer, so that was linear waste on every gate run.
    """
    if root is None:
        return None
    try:
        return root.resolve()
    except (OSError, ValueError):
        return None


def _departed(root: Path | None, file: str | None,
              base: Path | None = None) -> bool:
    """True when `file` is no longer present in the repo at all.

    Pass `base` (an already-resolved root) to skip re-resolving per call; it
    takes precedence over `root`, which may then be None.

    OPT-IN BY DESIGN: `root` is None for every caller except the gate, so this
    returns False and behaviour is unchanged for them. That is not tidiness,
    it is a safety requirement -- `commands/init._scan_history` records
    HISTORICAL gitleaks findings from `git log --all`, whose paths are those of
    OLD commits and routinely do not exist at HEAD. Resolving on absence there
    would clear every historical secret the instant it was recorded.

    LANDMINE, and this docstring asserted the OPPOSITE until 2026-08-09. It
    claimed a path that "cannot even be tested (the `<test-suite>` marker is
    not a legal Windows filename) is reported as present, i.e. NOT departed",
    on the theory that the check would raise and hit the `except` below.
    MEASURED FALSE, and on both platforms:

        Path(r'F:\\Projects\\aramid') / '<test-suite>'   .resolve()  -> no raise
                                                          .exists()  -> False

    Non-strict `Path.resolve()` does not validate the name, and `.exists()`
    answers False for an illegal one rather than raising -- so this returned
    True and the marker read as DEPARTED. On Linux `<test-suite>` is simply a
    legal filename that does not exist: True again. The documented safety
    property held on no platform at all, and the consequence was live: whenever
    the tool clause let a suite finding through, `record_run` resolved it here
    -- BLOCK-tier -- without the `suite_completed` evidence that
    `tests_gate.auto_resolve_tests` requires before clearing one, and several
    steps before that resolver was consulted.

    MEASURED, not inferred. The two routes write different payloads, so
    aramid's own ledger can be asked directly: of 4 historical resolutions of
    whole-suite findings, 3 carry an EMPTY payload (this route) and 1 carries
    `auto_resolved: suite_completed_clean`. The single exception is the shape
    worth remembering -- it is a run where the tool clause DID stop
    `record_run`, leaving the finding open for the real resolver, which is
    exactly the protection this guard now provides unconditionally.

    Outcomes agreed with the correct ones only because `scope_tools` holds
    `Path(argv[0]).name` and aramid's own `[tests].command` makes that
    "python", so "the suite ran OK" and "python in scope_tools" are the same
    condition HERE; in a repo where those labels diverge, they are not.

    The property is now enforced rather than assumed, by `_is_synthetic_path`
    ahead of any filesystem question. Do not replace that with a `try/except`
    around the existence check -- there is no exception to catch.

    CONTAINMENT. `root / file` does not keep you inside root. Measured:

        Path(r'F:\\Projects\\aramid') / 'C:/Windows/win.ini' -> C:\\Windows\\win.ini
        Path(r'F:\\Projects\\aramid') / '/etc/passwd'        -> F:\\etc\\passwd

    An absolute `file` discards root outright and `..` is never normalized
    away, so the check lands on some unrelated path that almost never exists --
    reporting "departed" and silently RESOLVING the finding. A path that was
    never inside the repository cannot have departed it, so an escape returns
    False, which is also the safe direction: the finding stays open.
    """
    if not file or _is_synthetic_path(file):
        return False
    if base is None:
        base = _resolved_root(root)
    if base is None:
        return False
    try:
        target = base / file
        # EXISTENCE FIRST, containment only on absence -- and this ordering is
        # an optimisation, not a semantic change. `resolve()` is a filesystem
        # round trip on Windows and dominated the cost when `resolve_departed`
        # walks every open finding of a producer; the overwhelmingly common
        # answer is "the file is still there", which one `exists()` settles.
        # Equivalent case by case, because containment can only ever turn a
        # True into a False, and a path that EXISTS is already False:
        #   inside + exists   -> False both ways
        #   inside + absent   -> True  both ways (containment passes)
        #   escaped + exists  -> False both ways ("C:/Windows/win.ini" is
        #                        there, so `not exists()` was already False)
        #   escaped + absent  -> False both ways (containment rejects it)
        # Symlinks included: `exists()` follows them, so a link out of the repo
        # to a live file answers False exactly as `resolve()` + containment did.
        if target.exists():
            return False
        if not target.resolve().is_relative_to(base):
            return False       # never inside the repo, so it cannot have left
        return True
    except (OSError, ValueError):
        return False


def note_yield(ledger, run_id: str, at: str, *, resolver: str, tool: str,
               considered: int, resolved: int) -> None:
    """Record what a resolver LOOKED AT, alongside what it cleared.

    A resolution writes itself into the ledger; a non-resolution writes
    nothing, so the ledger cannot distinguish a resolver that examined a
    hundred candidates and declined them all from one that was never called.
    Those two want opposite responses, and four times in this repo the second
    masqueraded as the first -- `gap_addressed` at zero lifetime fires with
    eleven open mutation findings, because `[hooks].pre_push_match_ci` runs
    the shim with `--all` and every range-scoped resolver sat behind
    `if mode == "range"`. Nothing detected it. Nothing could.

    `considered` is the candidate set the resolver ACTUALLY WALKED after its
    own filters, not the open set: a resolver is not idle for declining to
    look at another producer's findings. `tool` is the producer whose findings
    it clears, so a reader can join a zero against that producer's volume --
    which is the whole discriminator, because zero-of-zero is honest and
    zero-of-eleven is a defect.

    EVERY INVOCATION EMITS, INCLUDING THE EARLY RETURNS. `resolve_departed`
    with `root=None`, `resolve_repaired` with no claimed ids, and
    `auto_resolve_tests` on an incomplete suite all clear nothing by design
    and all still say so. That is deliberate and load-bearing: it is what
    reserves "no event" for "was never called", and that is the only shape
    that catches a resolver switched off by its caller rather than broken in
    itself. Emitting only when there is something to report would make the
    detector blind to the exact bug it was built for.

    NEVER RAISES. Every resolver instrumented here documents that it does not
    raise into `run_gate`, and bookkeeping must not quietly withdraw that
    guarantee -- a diagnostic that can fail a push is worse than no
    diagnostic. A yield event lost to a broken ledger reads downstream as
    "not called", which is the safe direction: it over-reports rather than
    conceals.
    """
    try:
        ledger.append(Event(EventType.RESOLVER_YIELD, run_id, at,
                            payload={"resolver": resolver, "tool": tool,
                                     "considered": int(considered),
                                     "resolved": int(resolved)}))
    except Exception:
        diagnostics.note_skipped(f"{resolver}-yield", 1, noun="record")


def resolve_departed(ledger, run_id: str, at: str, *, root, tool: str,
                     present_ids) -> list[str]:
    """Resolve one producer's open findings whose file has LEFT the repository.

    WHY PRODUCERS NEED THEIR OWN CALL. `record_run` already does this, but only
    after `rec["tool"] in scope_tools` -- and that set is
    `{r.tool for r in results if OK}`, i.e. runner labels taken from
    `Path(argv[0]).name`. The synchronous producers emit no RunnerResult at
    all, so `red-proof` and `tdd` can never appear there and the departed check
    was unreachable for them. Unlike a runner they have no second route either:
    `auto_resolve_red_proof` clears a finding only via `proven_red`, which
    requires a base-tree pytest run on a file that no longer exists to run it
    against. Their findings on a deleted file were IMMORTAL.

    Live instance in aramid's own ledger: `890d7493a3e3`, red-proof on
    `tests/unit/test_zz_ci_dump_rehearsal.py` -- committed in `2d7dfe51`,
    judged, then the push was blocked and the commit rewritten without that
    file. Open across every later run until it was closed by hand.

    OPT-IN, AND DELIBERATELY NOT A GLOBAL RULE IN `record_run`. Moving the
    check ahead of the tool gate would cover these two for free and was the
    first attempt; it also silently resolves every finding whose stored `file`
    is not a path -- `consumers/dast.py` writes `"GET /login"`, which does not
    exist, joins to `root/GET/login`, passes containment, and reads as gone.
    Opting in per producer keeps that impossible: a producer that does not call
    this keeps findings open, which is the safe direction.

    OPTED IN: `red-proof`, `tdd`, `mutation` -- see the tuple in
    `pipeline.run_gate`. A name qualifies only if its findings are anchored to
    a real repo-relative path, which is the whole admission criterion.

    NOT OPTED IN, and each for a reason worth re-checking rather than
    assuming:
      - `llm-review` needs nothing -- `auto_resolve_llm` fires when the stored
        evidence quote is absent from HEAD, and deleting the file removes it.
      - `js-mutation` and `fuzz` now resolve through `resolve_repaired`
        instead, which was the right shape for them: they had no resolver of
        any kind, so a genuine FIX cleared nothing, and opting them in here
        would have fixed only the deletion half of that. They could still opt
        in -- both are anchored to real repo-relative paths -- but a departed
        file is a rare case next to a fixed one, and each addition here is a
        standing invitation to the `dast` mistake below.
      - `dast` must NEVER opt in: its `file` is a method+endpoint
        ("GET /login"), so departure is not a question that has an answer, and
        the string does not exist as a path -- it would read as departed and
        clear live security findings. It resolves via `resolve_repaired`, whose
        scope is endpoints that actually ANSWERED, which is a question its
        `file` can be asked.
      - `mutation-score` is synthesized at gate time from stored scores rather
        than persisted like the others; whether it holds resolvable open
        findings at all is unchecked, so it is deliberately uncharacterised
        rather than assumed safe.

    `present_ids` skips anything this run's producer re-fired, for the same
    reason `auto_resolve_red_proof` does: resolution runs after `record_run`,
    so a still-live finding is already re-detected and must not be resolved out
    from under itself. `root` None makes this a no-op, so a caller that has no
    repo to check cannot accidentally clear anything. Never raises.

    COST, measured rather than assumed (Windows / CPython 3.14, both producers,
    steady state with every file present). This walks every open finding of the
    named producer on every pre-push, so it is linear and worth watching:

        10 open findings ->   3.0 ms      <- realistic
       200 open findings ->  31.1 ms
      1000 open findings -> 120.5 ms

    The naive form -- `root.resolve()` per finding, then `resolve()` again on
    the target before testing existence -- measured 808 ms at 1000. Hoisting
    the root (`_resolved_root`) and testing existence before containment
    (`_departed`) accounts for the 6.7x; `open_findings()` itself is ~10 ms at
    that size and is not the bottleneck. If a producer with a large backlog
    ever opts in, re-measure before assuming this stays cheap.
    """
    base = _resolved_root(root)
    if base is None:
        note_yield(ledger, run_id, at, resolver="file_departed", tool=tool,
                   considered=0, resolved=0)
        return []                      # no repo to check -> clear nothing
    resolved: list[str] = []
    skipped = 0
    considered = 0
    for fid, rec in ledger.open_findings().items():
        if rec.get("tool") != tool or rec.get("status") != "open" \
           or fid in present_ids:
            continue
        considered += 1
        try:
            if _departed(None, rec.get("file"), base=base):
                ledger.append(Event(EventType.FINDING_RESOLVED, run_id, at,
                                    finding_id=fid,
                                    payload={"auto_resolved": "file_departed"}))
                resolved.append(fid)
        except Exception:
            skipped += 1
            continue
    diagnostics.note_skipped(f"{tool}-departed-resolve", skipped)
    note_yield(ledger, run_id, at, resolver="file_departed", tool=tool,
               considered=considered, resolved=len(resolved))
    return resolved


def resolve_repaired(ledger, run_id: str, at: str, *, tool: str, reason: str,
                     ids, present_ids) -> list[str]:
    """Resolve one producer's open findings that it has PROVED repaired.

    The counterpart to `resolve_departed`: a producer whose finding is
    genuinely fixed -- not deleted, fixed -- proving it directly. `record_run`
    cannot carry this (`scope_tools` holds runner labels from
    `Path(argv[0]).name`, and no consumer emits a RunnerResult), and
    `drain._consume_item` passes empty scopes on purpose.

    WHAT THIS IS *NOT*. `mutation_gate.auto_resolve_mutation` already resolves
    mutation findings at pre-push, and this does not replace it. That one is
    deliberately OPTIMISTIC -- it resolves on INTENT (the push touched the
    source, or added a test whose basename is `test_<module>.py`) so a dev who
    wrote the test is not blocked, and names the re-drain as its authoritative
    backstop. The backstop could only ever RE-REPORT; it had no way to confirm
    a repair. This is that missing half: resolution on PROOF, recorded as
    `mutant_killed` rather than `gap_addressed`.

    The gap between intent and proof is not theoretical. The module mapping
    matches only `test_<module>.py` / `<module>_test.py`, so tests added in any
    other file do not register -- `test_doctor_version_parsing.py`, closing two
    real gaps in `doctor._version_of`, resolved nothing. Proof does not care
    what the file is called.

    USED BY all four drain producers, each proving something different, and the
    differences are the interesting part:

      - `mutation` / `js-mutation` -- POSITIVE proof. The killed mutant's
        fingerprint IS the finding's id, so the claim needs no scope at all.
      - `fuzz` -- deterministic replay. `case_seed(file, func, i)` reruns
        exactly the corpus that found the crash, so for a function the driver
        actually CALLED, "no crash" is a re-examination. Scoped by the driver's
        `fuzzed` list, never by the targets it was asked to run.
      - `dast` -- complete re-scan. Every check family runs against one
        response, so absence means clean -- but only for endpoints that
        ANSWERED, which is why `probe_scoped` reports what it reached.

    The two shapes differ in where the evidence lives. Mutation names ids it
    disproved; fuzz and dast name ids inside a scope they completely
    re-examined and did not re-report. Both are honest, and both exclude
    anything re-fired this run -- in the consumer AND again through
    `present_ids` here, because a producer claiming repair for a finding it is
    reporting in the same breath is the worst failure available to it.

    POSITIVE ASSERTION, NOT INFERRED ABSENCE -- this is the whole reason it is
    safe where scope-based resolution is not. The drain refuses to resolve
    because it runs a narrow ruleset: semgrep's pack findings and its OWASP
    findings share a tool name, so "ran and didn't re-report" proves nothing.
    Here the producer hands over the exact fingerprints it RE-DERIVED and
    disproved. `consumers/mutation.py` re-mutates the same line with the same
    operator and computes the identical `compute_fingerprint(...)` the finding
    would carry (`_mutant_fp`, and `PIN_OCCURRENCE` makes both sides use
    occurrence 0); an id only appears in `killed_fps` when the suite actually
    failed on that mutant. Silence proves nothing here and is used for nothing.

    Consequently a producer that reports NOTHING resolves nothing -- the safe
    direction, and the same opt-in property `resolve_departed` has. The tool
    gate is redundant against the fingerprint, which already binds the tool
    name, but it is not redundant against a caller passing the wrong list.

    `present_ids` skips anything this run re-reported, for the reason
    `resolve_departed` documents: resolution runs after `record_run`, so a
    live finding has already been re-detected. Never raises; a malformed
    record is skipped and counted through `diagnostics`, not swallowed.
    """
    wanted = set(ids or ())
    if not wanted:
        note_yield(ledger, run_id, at, resolver=reason, tool=tool,
                   considered=0, resolved=0)
        return []
    resolved: list[str] = []
    skipped = 0
    # Driven by the CLAIM, not by the ledger: a producer proves a bounded
    # handful of identities per run (mutation is capped at `max_mutants`)
    # while the open set is unbounded. Sorted so a run's resolution events
    # land in a stable order -- the ledger is append-only, and a diff of two
    # runs should show what changed, not how a dict happened to iterate.
    state = ledger.open_findings()
    for fid in sorted(wanted):
        if fid in present_ids:
            continue
        try:
            rec = state.get(fid)
            if rec is None or rec.get("tool") != tool or rec.get("status") != "open":
                continue
            ledger.append(Event(EventType.FINDING_RESOLVED, run_id, at,
                                finding_id=fid,
                                payload={"auto_resolved": reason}))
            resolved.append(fid)
        except Exception:
            skipped += 1
            continue
    diagnostics.note_skipped(f"{tool}-repaired-resolve", skipped)
    # `wanted`, not the open set: this resolver is driven by the producer's
    # CLAIM (see above), so what it walked is what was claimed. A claim that
    # matches nothing open is the interesting row -- a producer proving
    # repairs the ledger has no record of is as broken as one proving none.
    #
    # NOTE THE ASYMMETRY, because it changes who is at fault. Everywhere else
    # `considered` is counted AFTER the tool/status filter, so a low number
    # means the resolver saw little. Here it is counted BEFORE, so a high
    # `considered` with a zero `resolved` indicts the PRODUCER -- it proved
    # repairs for ids the ledger does not hold open -- not this function. The
    # report grades that combination as informational for exactly that reason.
    note_yield(ledger, run_id, at, resolver=reason, tool=tool,
               considered=len(wanted), resolved=len(resolved))
    return resolved


# How far a rewritten line may have moved and still be the same site. The
# reporting case (round 135 s3) was 369 -> 383; a rewrite that grows a call
# into a `with` block moves the flagged line by the lines it added, not by
# hundreds. Same tool/rule/file alone is NOT enough: one site genuinely
# fixed and an unrelated one introduced elsewhere in the same file would
# otherwise read as a rewrite, which is the opposite lie.
_REWRITE_WINDOW = 40


def _successors(state: dict, present: set[str], findings: list, new_ids: list[str]) -> dict[str, str]:
    """Map each open finding that vanished this run to the NEW finding that
    rewrote it: same tool, rule and file, within `_REWRITE_WINDOW` lines of
    its last recorded line, nearest first, each sibling claiming at most
    one. Ids hash content, so a rewrite always arrives as a new id beside
    an absent old one; without this pairing the old one is written `fixed`
    at exactly the moment the call is being rewritten."""
    fresh = [f for f in findings if f.id in set(new_ids)]
    vanished = [(fid, rec) for fid, rec in state.items()
                if rec.get("status") == "open" and fid not in present]
    pairs = []
    for fid, rec in vanished:
        for f in fresh:
            if (f.tool, f.rule, f.file) != (rec.get("tool"), rec.get("rule"), rec.get("file")):
                continue
            old_line = rec.get("line")
            if not isinstance(old_line, int) or f.line is None:
                continue
            distance = abs(f.line - old_line)
            if distance <= _REWRITE_WINDOW:
                pairs.append((distance, fid, f.id))
    out: dict[str, str] = {}
    claimed: set[str] = set()
    for _, fid, new in sorted(pairs):
        if fid in out or new in claimed:
            continue
        out[fid] = new
        claimed.add(new)
    return out


def _detect_payload(f: Finding) -> dict:
    return {"tool": f.tool, "file": f.file, "rule": f.rule, "verdict": str(f.verdict),
            "severity": str(f.severity), "line": f.line, "message": f.message,
            "evidence": f.evidence, "historical": f.historical,
            "source": str(f.source), "confirmed": f.confirmed,
            "refuted": f.refuted}


def _materialize(events):
    state: dict[str, dict] = {}
    seen: set[str] = set()
    for e in events:
        if e.type.value == "finding_detected":
            seen.add(e.finding_id)
            state[e.finding_id] = {**e.payload,
                                   "status": "historical" if e.payload.get("historical") else "open"}
        elif e.type.value == "finding_resolved":
            if e.finding_id in state:
                successor = e.payload.get("superseded_by")
                if successor:
                    state[e.finding_id]["status"] = "superseded"
                    state[e.finding_id]["reason"] = f"rewritten -- superseded by {successor}"
                else:
                    state[e.finding_id]["status"] = "fixed"
        elif e.type.value == "finding_overridden":
            if e.finding_id in state:
                state[e.finding_id]["status"] = "overridden"
                state[e.finding_id]["reason"] = e.payload.get("reason", "")
        elif e.type.value == "finding_rotated":
            if e.finding_id in state:
                state[e.finding_id]["status"] = "rotated"
        elif e.type.value == "finding_not_a_secret":
            if e.finding_id in state:
                state[e.finding_id]["status"] = "not_a_secret"
                state[e.finding_id]["reason"] = e.payload.get("reason", "")
        elif e.type.value == "finding_moved":
            # Line only. Never status, never tool/file/rule -- `file` and the
            # line's CONTENT are fingerprint ingredients, so a change to either
            # produces a different finding id and arrives here as a genuinely
            # new finding rather than as a move.
            if e.finding_id in state:
                state[e.finding_id]["line"] = e.payload.get("line")
        elif e.type.value == "finding_override_invalidated":
            # Back to open, for re-adjudication. `reason` is REMOVED rather
            # than left in place: it justified a suppression that no longer
            # binds, and a row reading status=open beside a live-looking
            # suppression reason invites every reader to conclude the
            # override still applies. Preserved under its own key so the
            # audit trail keeps it -- the ledger is append-only and the
            # original event is still there regardless.
            if e.finding_id in state:
                rec = state[e.finding_id]
                rec["status"] = "open"
                rec["invalidated_cause"] = e.payload.get("cause", "")
                if "reason" in rec:
                    rec["invalidated_override_reason"] = rec.pop("reason")
        elif e.type.value == "finding_unreachable":
            if e.finding_id in state:
                state[e.finding_id]["status"] = "unreachable"
                state[e.finding_id]["reason"] = e.payload.get("reason", "")
        elif e.type.value == "finding_out_of_scope":
            if e.finding_id in state:
                state[e.finding_id]["status"] = "out_of_scope"
                state[e.finding_id]["reason"] = e.payload.get("reason", "")
    return state, seen


class Ledger:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._c = sqlite3.connect(str(db_path))
        self._c.execute("PRAGMA journal_mode=WAL")
        self._c.executescript(_SCHEMA)
        self._c.commit()

    def append(self, event: Event) -> None:
        self._c.execute(
            "INSERT INTO events(type,run_id,at,finding_id,payload) VALUES(?,?,?,?,?)",
            (str(event.type), event.run_id, event.at, event.finding_id,
             json.dumps(event.payload)))
        self._c.commit()

    def events(self) -> list[Event]:
        rows = self._c.execute(
            "SELECT type,run_id,at,finding_id,payload FROM events ORDER BY seq").fetchall()
        return [Event(EventType(t), r, a, fid, json.loads(p)) for t, r, a, fid, p in rows]

    def close(self): self._c.close()

    def open_findings(self) -> dict:
        state, _ = _materialize(self.events())
        return state

    def record_run(self, run_id, at, gate, scope_tools, scope_files, findings, *,
                   selected_tools: set[str] | None = None,
                   expected_tools: set[str] | None = None,
                   root: Path | None = None,
                   examined_by_tool: dict[str, set[str]] | None = None,
                   finished_at: str | None = None):
        state, seen = _materialize(self.events())
        present = {f.id for f in findings}
        payload = {"gate": gate, "tools": sorted(scope_tools)}
        if selected_tools is not None:
            payload["selected"] = sorted(selected_tools)
        if expected_tools is not None:
            # What THIS GATE should have run, as opposed to `selected` (the
            # union across every gate) and `tools` (what actually ran). The
            # three are genuinely different questions and the skip report needs
            # all of them: without `expected` it can only notice a tool that
            # ran once and stopped, never one that never started.
            #
            # Written only when the caller supplies it, so the key stays absent
            # rather than empty on any path that cannot compute it -- `status`
            # reads absent as "too old to record" and falls back, and empty as
            # a positive claim that nothing was expected.
            payload["expected"] = sorted(expected_tools)
        self.append(Event(EventType.RUN_STARTED, run_id, at, payload=payload))
        new_ids = []
        for f in findings:
            if f.id not in state or state[f.id]["status"] in ("fixed", "unreachable", "superseded", "out_of_scope"):
                self.append(Event(EventType.FINDING_DETECTED, run_id, at,
                                  finding_id=f.id, payload=_detect_payload(f)))
            elif state[f.id].get("line") != f.line:
                # RE-ANCHOR. A finding that is merely still present gets no
                # detect event -- correct, since re-detecting would reset its
                # status -- so its recorded line was frozen at first sight and
                # drifted as the file changed around it. A consumer repo
                # auditing 26 findings had to match every one by content
                # because the numbers pointed at the wrong code.
                #
                # Guarded on an actual change, not emitted unconditionally:
                # this runs for every open finding on every gate run, so the
                # unguarded version trades a stale number for a ledger that
                # grows one row per finding per run.
                self.append(Event(EventType.FINDING_MOVED, run_id, at,
                                  finding_id=f.id, payload={"line": f.line}))
            if f.id not in seen:
                new_ids.append(f.id)
        successors = _successors(state, present, findings, new_ids)
        for fid, rec in state.items():
            if rec["status"] != "open" or fid in present:
                continue
            # THE TOOL GATE STAYS AHEAD OF THE DEPARTED CHECK. Considered
            # moving it (2026-08-09) so that producers absent from scope_tools
            # -- red-proof, tdd -- could resolve findings on deleted files, and
            # REVERTED before shipping. Doing so exposes every finding whose
            # stored `file` is not a repo-relative path at all, because
            # `_departed` answers "gone" for anything that does not exist:
            #
            #     consumers/dast.py writes  file=f"{f.method} {f.path}"
            #     _departed(root, "GET /login")  ->  True
            #
            # It passes containment (it joins to root/GET/login) and every open
            # DAST finding would be written `fixed` on the next gate run -- a
            # false repair, of security findings, into an append-only audit
            # trail. That is the exact class this block exists to prevent.
            # `<test-suite>` was merely the instance we already knew about.
            #
            # A global departure rule is wrong in PRINCIPLE for such producers:
            # "has this file left the repo" is not a question you can ask about
            # an HTTP endpoint. So departure is opt-in per producer, via
            # `resolve_departed` below, and a producer that never opts in keeps
            # the safe behaviour by default. Fail-safe, rather than a denylist
            # of shapes that a new consumer must remember to join.
            if rec.get("tool") not in scope_tools:
                continue
            # `file in <what the tool examined>` is the ordinary route. The
            # second clause exists because every discovery path filters
            # `--diff-filter=ACMR` (gitutil) -- Deleted is excluded, since a
            # gone file cannot be linted -- so a deleted file is NEVER in
            # scope_files and its findings could never resolve. `git rm` a
            # file and its findings stayed open forever; repos accumulated one
            # immortal entry per file they ever deleted. It has to stay ahead
            # of the examination check too: nothing can examine a file that no
            # longer exists, so requiring examination would re-create exactly
            # that bug.
            #
            # EXAMINATION, not mere presence in the run's file set. A runner
            # reports `examined` for the files it can vouch for; absent from
            # the map means "could not report" and falls back to scope_files,
            # which is the pre-2026-08-06 behaviour. An EMPTY set is a
            # positive claim that nothing was looked at, and resolves nothing.
            # Without this, a runner whose own config excluded a file still
            # exited 0, landed in scope_tools, and its findings there were
            # recorded as FIXED -- a false repair written into an append-only
            # audit trail. Measured on ruff `--force-exclude`; the same shape
            # applies to .eslintignore and clippy exclusions.
            # INTERSECT, never replace. This read
            #     `rec["file"] in scope_files if tool_scope is None
            #      else rec["file"] in tool_scope`
            # so the moment a runner reported anything, the gate's own scope
            # stopped constraining resolution -- the same false-repair class
            # this block exists to prevent, reintroduced from the too-WIDE
            # side. Both this module's contract and the 0.1.0 changelog say
            # "resolution intersects against that"; the code did not.
            #
            # It bites WHOLE-PROJECT runners, which report far more than the
            # gate scoped: clippy's examined set is every `.rs` file cargo
            # compiled in the crate, tsc's `--listFiles` is the whole program.
            # A `range`-mode push touching one file compiles the crate, and
            # because cargo replays no diagnostic for files it did not
            # recompile, every open finding in an UNTOUCHED file was written
            # `fixed`. ruff never exposed it -- it is handed an explicit file
            # list, so its examined set cannot exceed the scope.
            tool_scope = (examined_by_tool or {}).get(rec.get("tool"))
            in_scope = (rec.get("file") in scope_files
                        and (tool_scope is None or rec.get("file") in tool_scope))
            if in_scope or _departed(root, rec.get("file")):
                payload = {}
                if fid in successors:
                    payload = {"auto_resolved": "rewritten", "superseded_by": successors[fid]}
                self.append(Event(EventType.FINDING_RESOLVED, run_id, at, finding_id=fid,
                                  payload=payload))
        # `at` is the run's IDENTITY stamp and every event in the run carries
        # it, so on its own RUN_FINISHED could not tell a ten-minute gate from
        # a one-second one (interop round 130 s3 -- the consumer had to read
        # a push log's mtimes instead). `finished_at` is a second clock read,
        # taken by the caller when the run's findings were recorded. Written
        # only when supplied, never copied from `at`: absent means 'too old
        # to have recorded it', which a reader must not confuse with zero.
        finished = {"blocking": sum(1 for f in findings if str(f.verdict)=="block")}
        if finished_at is not None:
            finished["finished_at"] = finished_at
        self.append(Event(EventType.RUN_FINISHED, run_id, at, payload=finished))
        return new_ids

    def has_baseline(self) -> bool:
        return any(e.type == EventType.BASELINE_SNAPSHOT for e in self.events())

    def write_baseline(self, run_id, at, fingerprints: set[str]) -> None:
        self.append(Event(EventType.BASELINE_SNAPSHOT, run_id, at,
                          payload={"ids": sorted(fingerprints)}))

    def baseline_ids(self) -> set[str]:
        ids: set[str] = set()
        for e in self.events():
            if e.type == EventType.BASELINE_SNAPSHOT:
                ids = set(e.payload.get("ids", []))
        return ids

    def is_new(self, finding_id: str) -> bool:
        _, seen = _materialize(self.events())
        return finding_id not in self.baseline_ids() and finding_id not in seen

    def compact(self) -> int:
        # LANDMINE -- compact() is currently DEAD CODE (no src/ call sites).
        # Wiring it into a command must still coordinate one integration:
        # (1) autolearn.rollup cursors are event COUNTS: compacting shrinks
        #     the list below a stored cursor. rollup now SKIPS the fold on a
        #     shrunk ledger (no double-count) -- but its posteriors are then
        #     stale, so any wiring must rebuild the autolearn state
        #     (`aramid autolearn --rebuild`, cross-repo) in the same operation.
        # (2) give-up history is now preserved: every per-(consumer,item)
        #     CONSUMER_RUN_FINISHED row is kept (below), so
        #     consumers.base.prior_note_count (llm malformed / mutation
        #     baseline-failing counters) survives a compaction intact.
        rows = self._c.execute(
            "SELECT seq,type,finding_id,payload FROM events ORDER BY seq").fetchall()

        # Latest FINDING_DETECTED seq per finding — carries the tool/file/payload
        # that _materialize needs to resurrect the finding.
        last_detect: dict[str, int] = {}
        for seq, type_, finding_id, _payload in rows:
            if type_ == EventType.FINDING_DETECTED.value and finding_id:
                last_detect[finding_id] = seq

        # Latest terminal transition per finding, but only one that occurred
        # AFTER that finding's latest detect — anything before it would have
        # been overwritten by the re-detect and is redundant.
        terminal_types = {EventType.FINDING_RESOLVED.value,
                           EventType.FINDING_OVERRIDDEN.value,
                           EventType.FINDING_ROTATED.value,
                           EventType.FINDING_NOT_A_SECRET.value,
                           EventType.FINDING_UNREACHABLE.value}
        last_terminal: dict[str, int] = {}
        for seq, type_, finding_id, _payload in rows:
            if type_ in terminal_types and finding_id and finding_id in last_detect \
               and seq > last_detect[finding_id]:
                if finding_id not in last_terminal or seq > last_terminal[finding_id]:
                    last_terminal[finding_id] = seq

        # Latest FINDING_MOVED per finding, and only one after that finding's
        # latest detect -- a detect carries its own line, so any move before it
        # is already superseded. Keeping just the newest is sufficient because
        # the event is absolute (the current line), not a delta.
        last_moved: dict[str, int] = {}
        for seq, type_, finding_id, _payload in rows:
            if type_ == EventType.FINDING_MOVED.value and finding_id \
               and finding_id in last_detect and seq > last_detect[finding_id]:
                last_moved[finding_id] = seq

        keep = set(last_detect.values()) | set(last_terminal.values()) \
            | set(last_moved.values())
        for seq, type_, finding_id, _payload in rows:
            if type_ == EventType.BASELINE_SNAPSHOT.value:
                keep.add(seq)

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
        for seq, type_, finding_id, _payload in rows:
            if type_ in queue_types and finding_id in queued_ids:
                keep.add(seq)
            if type_ in (EventType.TRIAGE_RECORDED.value,
                         EventType.CONSUMER_RUN_FINISHED.value,
                         EventType.RUN_FINISHED.value):
                latest_singleton[type_] = seq
            if type_ == EventType.CONSUMER_RUN_FINISHED.value:
                # Give-up counters (consumers.base.prior_note_count) read every
                # per-(consumer,item) row, not just the newest -- preserve them
                # all, else llm/mutation give-up history silently resets.
                try:
                    pl = json.loads(_payload)
                except (ValueError, TypeError):
                    pl = {}
                if pl.get("consumer") and pl.get("item_id"):
                    keep.add(seq)
        keep.update(latest_singleton.values())

        to_delete = [seq for seq, _, _, _ in rows if seq not in keep]
        if to_delete:
            self._c.executemany("DELETE FROM events WHERE seq=?", [(s,) for s in to_delete])
            self._c.commit()
        return len(to_delete)
