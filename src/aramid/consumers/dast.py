"""Drain-time DAST passive web-hygiene consumer (2c-3 spec). Scan a user-declared
base_url with the owned stdlib prober and report web-hygiene issues (headers /
cookies / transport / exposed paths / banner) as WARN-tier findings.

OK-not-DEGRADED for structural absence (disabled / no base_url / invalid
base_url) so a non-web repo never pins the queue item. DEGRADED + head-scoped
give-up (after 3) when the configured target is persistently unreachable -- the
app may simply not be up at drain time (findings are opportunistic by design).
Zero tokens (cost 0.0); PIN_OCCURRENCE because a live target is membership-
variable across drains. WARN-tier via policy.classify's catch-all."""
import sys
from urllib.parse import urlsplit

from aramid import dast_probe
from aramid.consumers import base
from aramid.consumers.base import ConsumerResult, DrainContext
from aramid.normalizer import RawFinding

NAME = "dast"
_UNREACHABLE_GIVE_UP = 3

# Live-target scans are membership-variable across drains (an app up one drain,
# down the next), so pin occurrence 0 -- one finding per (tool, rule, file).
PIN_OCCURRENCE = True


def consume(item, ctx: DrainContext) -> ConsumerResult:
    mcfg = getattr(ctx.cfg, "dast", None) or {}
    if not mcfg.get("enabled", True):
        return ConsumerResult(consumer=NAME, state="ok", note="disabled")

    base_url = str(mcfg.get("base_url", "")).strip()
    if not base_url:
        return ConsumerResult(consumer=NAME, state="ok",
                              note="no dast target configured")
    if urlsplit(base_url).scheme not in ("http", "https") or not urlsplit(base_url).hostname:
        # malformed target is a config mistake, not a transient fault -> OK-skip
        return ConsumerResult(consumer=NAME, state="ok",
                              note="invalid dast base_url (need http(s)://host)")

    paths = list(mcfg.get("paths", []))
    timeout_s = float(mcfg.get("timeout_s", 10))

    give_up_prefix = f"dast target unreachable @ {item.head[:12]}"
    if base.prior_note_count(ctx.ledger, NAME, item.id, give_up_prefix) >= _UNREACHABLE_GIVE_UP:
        # A persistently-unreachable target must stop pinning the queue item:
        # after 3 honest DEGRADED retries AT THIS HEAD this becomes a permanent
        # skip. Head-scoped so new commits get a fresh try. Load-bearing prefix.
        return ConsumerResult(consumer=NAME, state="ok",
                              note="dast giving up: target persistently unreachable")

    try:
        findings = dast_probe.probe(base_url, paths, timeout_s)
    except dast_probe.DastUnreachable:
        return ConsumerResult(consumer=NAME, state="degraded", note=give_up_prefix)
    except Exception as exc:  # a probe crash is transient -> degrade, never kill the drain
        return ConsumerResult(consumer=NAME, state="degraded",
                              note=f"dast probe error: {str(exc)[:150]}")

    raws = [RawFinding(tool="dast", rule=f.check, severity_raw=f.severity,
                       file=f"{f.method} {f.path}", line=0,
                       message=f.message, evidence=f.evidence)
            for f in findings]
    host = urlsplit(base_url).hostname
    return ConsumerResult(consumer=NAME, state="ok", findings=raws, cost=0.0,
                          note=f"{len(raws)} hygiene finding(s) on {host}",
                          extra={"target": host, "found": len(raws)})


base.CONSUMERS[NAME] = sys.modules[__name__]
