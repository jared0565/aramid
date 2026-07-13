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
