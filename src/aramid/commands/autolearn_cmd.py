"""autolearn command -- read-only report over the machine-global learned
state, plus --rebuild (replay every registered repo's ledger from scratch;
the state file is derived, so rebuild is always safe -- autolearn spec
section 12)."""
import sys
from datetime import datetime, timezone
from pathlib import Path

from aramid import autolearn, registry
from aramid.fingerprint import normalize_path
from aramid.ledger import Ledger


def _mode_line(root: Path) -> str:
    from aramid import config as config_mod
    try:
        cfg = config_mod.load_config(root)
        al = cfg.llm.get("autolearn", {})
        if not isinstance(al, dict) or not al.get("enabled", True):
            return "mode: off (this repo)"
        return ("mode: armed (this repo)" if al.get("armed", False)
                else "mode: shadow (this repo)")
    except Exception:
        return "mode: unknown (config unreadable)"


def cmd_autolearn(root, rebuild: bool = False) -> int:
    now = datetime.now(timezone.utc).isoformat()

    if rebuild:
        state = autolearn.empty_state()
        for entry in registry.load_registry():
            repo = Path(entry["path"])
            db = repo / ".aramid" / "ledger.db"
            if not db.exists():
                print(f"aramid autolearn: {repo}: no ledger; skipped")
                continue
            try:
                led = Ledger(db)
                try:
                    events = led.events()
                finally:
                    led.close()
                state = autolearn.rollup(state, events,
                                         normalize_path(str(repo)))
                print(f"aramid autolearn: {repo}: {len(events)} event(s) replayed")
            except Exception as exc:
                print(f"aramid autolearn: {repo}: skipped ({exc})",
                      file=sys.stderr)
        autolearn.save_state(state, now)
        print(f"aramid autolearn: state rebuilt -> {autolearn.state_path()}")

    state = autolearn.load_state()
    lines = ["aramid autolearn:", f"  {_mode_line(Path(root))}",
             f"  state: {autolearn.state_path()} "
             f"(updated {state.get('updated_at') or 'never'})"]
    sh, au = state.get("shadow", {}), state.get("audits", {})
    lines.append(f"  shadow: would-uplift {sh.get('would_uplift', 0)}"
                 f"/{sh.get('decisions', 0)} decision(s)")
    lines.append(f"  audits: {au.get('performed', 0)} performed, "
                 f"{au.get('missed_criticals', 0)} missed critical(s)")
    posts = state.get("posteriors", {})
    if posts:
        lines.append("  posteriors (arm|band|bucket: misses/clean "
                     "[halluc malformed refuted survived overridden]):")
        for key in sorted(posts):
            c = posts[key]
            lines.append(
                f"    {key}: {c.get('misses', 0)}/{c.get('clean', 0)} "
                f"[{c.get('halluc', 0)} {c.get('malformed', 0)} "
                f"{c.get('refuted', 0)} {c.get('survived', 0)} "
                f"{c.get('overridden', 0)}]")
    else:
        lines.append("  posteriors: none yet (cold start -- ladder behavior)")
    print("\n".join(lines))
    return 0
