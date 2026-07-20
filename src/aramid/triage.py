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

from aramid import config as config_mod
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
    # Graphite's real schema resolves "imports" edges to PLACEHOLDER
    # module-name nodes (kind "unknown", no source_file) -- edges never
    # target the file-node ids. So edge targets are matched against alias
    # ids derived from each changed path (every path-suffix joined with
    # "_"). Best-effort heuristic: a generically-named module (e.g.
    # "queue") can collide with same-named third-party/stdlib imports,
    # biasing the risk signal upward -- acceptable for a 0-25 advisory
    # weight.
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


def score(root: Path, base: str | None, head: str, cfg, ledger, *,
          budget_s: float = 2.0,
          monotonic: Callable[[], float] = time.monotonic) -> TriageResult:
    start = monotonic()
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
