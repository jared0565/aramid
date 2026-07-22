"""mutation_score -- read-only analyzer over the drain's per-function
mutation-outcome taxonomy (2a design spec). Derives each function's baseline
from CONSUMER_RUN_FINISHED history and computes two advisory signals: a
per-mutant transition (a mutant killed in the prior fully-mutated run that
now survives) and a per-function stage-1 rate-delta. No Verdict, no gate, no
ledger writes; fail-open on malformed/absent/wrong-schema history.

Run ordering is the position of the event in Ledger.events() (which exposes
no seq attribute); it is monotonic in true seq order and compaction-safe."""
from dataclasses import dataclass

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
