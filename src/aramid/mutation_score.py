"""mutation_score -- read-only analyzer over the drain's per-function
mutation-outcome taxonomy (2a design spec). Derives each function's baseline
from CONSUMER_RUN_FINISHED history and computes two advisory signals: a
per-mutant transition (a mutant killed in the prior fully-mutated run that
now survives) and a per-function stage-1 rate-delta. No Verdict, no gate, no
ledger writes; fail-open on malformed/absent/wrong-schema history.

Run ordering is the position of the event in Ledger.events() (which exposes
no seq attribute); it is monotonic in true seq order and compaction-safe."""
from dataclasses import dataclass, field

from aramid.models import EventType

_SCHEMA = 1


@dataclass(frozen=True)
class TargetScore:
    target: str
    run_index: int
    killed_s1: int
    survived_s1: int
    fully_mutated: bool
    killed_fps: frozenset
    survivor_fps: frozenset

    @property
    def rate(self) -> float | None:
        d = self.killed_s1 + self.survived_s1
        return self.killed_s1 / d if d else None


def iter_target_scores(events) -> list[TargetScore]:
    out: list[TargetScore] = []
    for idx, e in enumerate(events):
        if e.type is not EventType.CONSUMER_RUN_FINISHED:
            continue
        ms = e.payload.get("mutation_scores")
        if not isinstance(ms, dict) or ms.get("schema") != _SCHEMA:
            continue
        targets = ms.get("targets")
        if not isinstance(targets, dict):
            continue
        for key, t in targets.items():
            if not isinstance(t, dict):
                continue
            try:
                out.append(TargetScore(
                    target=key, run_index=idx,
                    killed_s1=int(t["killed_s1"]),
                    survived_s1=int(t["survived_s1"]),
                    fully_mutated=bool(t["fully_mutated"]),
                    killed_fps=frozenset(t.get("killed_fps", [])),
                    survivor_fps=frozenset(t.get("survivor_fps", []))))
            except (KeyError, TypeError, ValueError):
                continue
    return out


@dataclass(frozen=True)
class Regression:
    target: str
    kind: str                    # "transition" | "rate"
    baseline_index: int
    current_index: int
    detail: str
    transition_fps: frozenset = field(default_factory=frozenset)


def baseline_for(scores, target, before_index):
    best = None
    for s in scores:
        if s.target == target and s.fully_mutated and s.run_index < before_index:
            if best is None or s.run_index > best.run_index:
                best = s
    return best


def latest_by_target(scores):
    latest: dict[str, TargetScore] = {}
    for s in scores:
        cur = latest.get(s.target)
        if cur is None or s.run_index > cur.run_index:
            latest[s.target] = s
    return latest


def detect(current, baseline):
    if baseline is None:
        return []
    out = []
    trans = baseline.killed_fps & current.survivor_fps
    if trans:
        out.append(Regression(
            target=current.target, kind="transition",
            baseline_index=baseline.run_index, current_index=current.run_index,
            detail=f"{len(trans)} mutant(s) regressed: " + ", ".join(sorted(trans)),
            transition_fps=frozenset(trans)))
    if current.fully_mutated and baseline.fully_mutated \
            and current.rate is not None and baseline.rate is not None \
            and current.rate < baseline.rate:
        out.append(Regression(
            target=current.target, kind="rate",
            baseline_index=baseline.run_index, current_index=current.run_index,
            detail=f"{baseline.rate:.2f} -> {current.rate:.2f}"))
    return out


def latest_regressions(events):
    scores = iter_target_scores(events)
    out = []
    for target, cur in latest_by_target(scores).items():
        out.extend(detect(cur, baseline_for(scores, target, cur.run_index)))
    return out
