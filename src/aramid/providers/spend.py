"""spend -- the machine-global LLM spend log (spec section 3, "Recording &
metering"). Ledgers are per-repo but the OpenRouter monthly cap is
machine-global, so every provider call appends one JSON line here:
{"at", "provider", "model", "tokens_in", "tokens_out", "cost_usd"}.
Subscription-CLI calls log cost_usd 0.0 for observability.

`month_spend_usd` returns None when the log cannot be parsed -- the ONE
deliberate fail-closed path in 2b (spec section 6): a caller that cannot
compute spend must refuse paid calls, never guess.
"""
import json
from datetime import datetime
from pathlib import Path


def spend_path() -> Path:
    """Module-level seam: tests monkeypatch this rather than writing to the
    real ~/.aramid (mirrors registry.registry_path)."""
    return Path.home() / ".aramid" / "llm_spend.jsonl"


def append_spend(entry: dict) -> None:
    p = spend_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def month_spend_usd(provider: str, now_iso: str) -> float | None:
    p = spend_path()
    if not p.exists():
        return 0.0
    now = datetime.fromisoformat(now_iso)
    total = 0.0
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("provider") != provider:
                continue
            at = datetime.fromisoformat(rec["at"])
            if (at.year, at.month) == (now.year, now.month):
                total += float(rec.get("cost_usd", 0.0))
    except Exception:
        # The one fail-closed money path (spec section 6): ANY inability to
        # compute the sum -- malformed JSON, JSON-valid-but-misshapen lines
        # (bare scalars, wrong field types), I/O errors -- must return None.
        # Never crash, never guess a partial sum.
        return None
    return total
