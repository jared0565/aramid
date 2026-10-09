"""triage -- the zero-token risk scorer (spec sections 2-3).

Pure computation: git plumbing text, regexes over the diff, ledger
lookups, and an optional read of graphite's graph-out/graph.json. It
must NEVER spawn a scan tool. Self-budgeted: score() checks elapsed
time between signals and stops early past budget_s, keeping whatever
partial score it has (the post-commit hook can never be slowed past
its fail-open ceiling). The clock starts at the FIRST signal, after the
diff has been fetched: the two git calls that feed the signals are the
input, not the work being budgeted, and counting them meant a slow git
(a loaded CI runner, a developer machine mid-drain) skipped every
signal -- the pure ones included -- and scored a risky commit 0, so it
was never queued. The watchdog (`--budget`) is the ceiling on git.
"""
import fnmatch
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from aramid import config as config_mod
from aramid import gitutil, queue
from aramid.fingerprint import normalize_path

PATH_WEIGHT = 30
CONTENT_WEIGHT = 25
NOVELTY_WEIGHT = 20
BLAST_MAX = 25
# Enough on its own to reach the default `min_score` of 40: a test-only push
# that maps to a recorded survivor is the one push carrying the evidence the
# survivor needs, and it scored nothing on path, content or blast radius.
SURVIVOR_WEIGHT = 40

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
    seen_norm = {normalize_path(s) for s in seen_paths}
    fresh = sorted(p for p in paths if normalize_path(p) not in seen_norm)
    if fresh:
        return NOVELTY_WEIGHT, [f"novelty: {len(fresh)} unseen path(s) incl. {fresh[0]}"]
    return 0, []


def _alias_ids(path: str) -> set[str]:
    # "src/aramid/queue.py" -> {"queue", "aramid_queue", "src_aramid_queue"}
    parts = normalize_path(path).rsplit(".", 1)[0].split("/")
    return {"_".join(parts[i:]) for i in range(len(parts))}


def dependents(root: Path, paths: list[str]) -> list[str]:
    """Sorted dependent-node names from graphite's graph (read-only input;
    spec section 8b). Fail-open: absent/corrupt/misshapen graphs return []."""
    graph_file = root / "graph-out" / "graph.json"
    if not graph_file.exists():
        return []
    # Two ways an edge can point INTO a changed file. Which one carries the
    # answer depends on the graph in front of us, not on this code:
    #   1. `source_file` -- any node (function, class, module) graphite
    #      placed in a changed path. Under graphite >= 0.5.0 nearly every
    #      edge lands on such a node, so this path finds nearly every
    #      dependent, and it is immune to id-scheme changes (0.5.0 re-keyed
    #      almost every id; this path did not move).
    #   2. alias ids derived from the path -- every path-suffix joined with
    #      "_", so "src/aramid/queue.py" -> queue, aramid_queue, ... This
    #      exists for import edges that land on PLACEHOLDER module-name
    #      nodes (kind "unknown", no source_file), which older schemas
    #      produced for every import and current ones still produce for
    #      some. Best-effort: a generically-named module ("queue") can
    #      collide with a same-named third-party/stdlib import and bias the
    #      signal upward -- acceptable for a 0-25 advisory weight.
    # An earlier version of this comment said edges NEVER target file nodes
    # and that the alias path was therefore the mechanism. Measured false on
    # 2026-08-26 (interop round 124): in this repo the alias path matched a
    # single id -- a true positive -- while source_file matched nearly every
    # file. A near-silent alias path is the expected shape, not a defect.
    try:
        data = json.loads(graph_file.read_text(encoding="utf-8"))
        changed = {normalize_path(p) for p in paths}
        file_node_ids = {n["id"] for n in data.get("nodes", [])
                         if normalize_path(n.get("source_file") or "") in changed}
        target_ids = set(file_node_ids)
        for p in paths:
            target_ids |= _alias_ids(p)
        deps = {e["source"] for e in data.get("edges", [])
                if e.get("target") in target_ids
                # exclude self-references: edges FROM a changed file
                and e.get("source") not in file_node_ids
                and normalize_path(e.get("source_file") or "") not in changed}
    except Exception:
        # Fail-open (spec section 6): the graph is optional read-only
        # input; absent, corrupt, or unexpectedly-shaped graphs contribute
        # 0 and must NEVER raise out of triage.
        return []
    return sorted(deps)


def blast_radius_signal(root: Path, paths: list[str]) -> tuple[int, list[str]]:
    n = len(dependents(root, paths))
    if n >= 10:
        return BLAST_MAX, [f"blast-radius: {n} dependents"]
    if n >= 3:
        return 18, [f"blast-radius: {n} dependents"]
    if n >= 1:
        return 10, [f"blast-radius: {n} dependents"]
    return 0, []


def survivor_signal(ledger, paths: list[str],
                    root: Path | None = None) -> tuple[int, list[str]]:
    """Does this push carry evidence for a recorded mutation survivor? Fires
    when a changed TEST maps (by the mutation gate's own stem rule) to the
    module of an open or `pending_retest` survivor, or when a changed source
    file holds one. The verified re-test runs only inside a drain, and a drain
    runs only for a push that scores -- without this, the push that could
    close a survivor was the push that never reached the consumer (measured:
    21 gate-time resolves, 20 never re-examined). Never raises.

    ANY CHANGED TEST, while a survivor is open and not suppressed (FN-37).
    The stem rule misses ordinary names: 1ff56f7 put the test that kills
    `runners/eslint.py:77` in `test_runner_eslint.py`, which maps to no
    module, so triage scored the commit 0 and the survivor waited for an
    unrelated source push. The consumer's re-test already holds that "the
    suite is the mapping" (`consumers.mutation._retest_candidates`): any
    changed test re-tests every open survivor. The trigger now agrees.
    Suppressed rows are left out (equivalent mutants; the re-test skips them
    too), read from `root`'s suppressions file -- None, or an unreadable
    file, reads no suppressions, the same permissive answer the re-test
    gives. `pending_retest` rows are left out of this rule: the drain
    already synthesizes an item for them when the queue is empty. Cost: one
    drain item per test-only push while a real survivor is open."""
    try:
        from aramid import mutation_gate
        state = ledger.open_findings()
        survivors = {rec.get("file") for rec in state.values()
                     if rec.get("tool") == "mutation"
                     and rec.get("status") in ("open", "pending_retest") and rec.get("file")}
        if not survivors:
            return 0, []
        changed_norm = {normalize_path(p) for p in paths}
        test_stems = [Path(p).stem for p in paths if gitutil.is_test_file(p)]
        hit = sorted(f for f in survivors
                     if normalize_path(f) in changed_norm
                     or any(mutation_gate._maps_to_module(s, f) for s in test_stems))
        if hit:
            return SURVIVOR_WEIGHT, [f"survivor-retest: {len(hit)} module(s) with a recorded "
                                     f"survivor incl. {hit[0]}"]
        if not test_stems:
            return 0, []
        suppressed = _suppressed_ids(root)
        # The consumer's own row filter (`_retest_candidates`): a survivor it
        # would skip -- suppressed, or with no file or line to regenerate
        # from -- must not queue a drain that re-tests nothing.
        reachable = sorted(rec.get("file") for fid, rec in state.items()
                           if rec.get("tool") == "mutation" and rec.get("status") == "open"
                           and rec.get("file") and rec.get("line") and fid not in suppressed)
        if not reachable:
            return 0, []
        return SURVIVOR_WEIGHT, [f"survivor-retest: a changed test may kill "
                                 f"{len(reachable)} open survivor(s) incl. {reachable[0]}"]
    except Exception:
        return 0, []


def _suppressed_ids(root: Path | None) -> set[str]:
    """Finding ids the tracked suppressions file binds; empty when there is
    no root or the file cannot be read (see `survivor_signal`)."""
    if root is None:
        return set()
    try:
        return {r.id for r in config_mod.load_suppressions(root)[0]}
    except Exception:
        return set()


def score(root: Path, base: str | None, head: str, cfg, ledger, *,
          budget_s: float = 2.0,
          monotonic: Callable[[], float] = time.monotonic) -> TriageResult:
    paths = gitutil.diff_paths(root, base, head)
    # spec section 8b: git-tracked graphite artifacts (graph-out/,
    # .graphite*, .cache/) must never be triaged as targets -- mirrors
    # every other file-listing path (pipeline.run_gate, regression_pack's
    # consume) which all filter through config.filter_paths.
    paths = config_mod.filter_paths(paths, cfg)
    # Scope the diff to the post-filter paths so a tracked graphite artifact's
    # body can't feed content_signal (mirrors review.build_packet). EMPTY-PATHS
    # GUARD: diff_text's pathspec is `["--", *paths] if paths else []`, so
    # passing an empty `paths` would fall back to the FULL diff -- reintroducing
    # the bug at its worst on an all-graphite changeset. When everything is
    # filtered out, use "" so content_signal sees nothing.
    diff = gitutil.diff_text(root, base, head, paths=paths) if paths else ""
    extra = list(cfg.triage.get("extra_security_paths", []))

    total, reasons = 0, []
    start = monotonic()     # the budget is for the signals, not the fetch
    signals: tuple[Callable[[], tuple[int, list[str]]], ...] = (
        lambda: path_signal(paths, extra),
        lambda: content_signal(diff, paths),
        lambda: novelty_signal(queue.triaged_paths(ledger), paths),
        lambda: blast_radius_signal(root, paths),
        lambda: survivor_signal(ledger, paths, root),
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
