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
from aramid.fingerprint import compute_fingerprint
from aramid.normalizer import RawFinding

NAME = "dast"
TOOL = "dast"
_UNREACHABLE_GIVE_UP = 3


def _finding_fp(check: str, method: str, path: str) -> str:
    """The id `normalize` gives a dast finding for this (check, endpoint).

    Every dast finding carries `line=0` and a SYNTHETIC file ("GET /login"),
    which is not a path and never resolves to one -- so `normalize` reads no
    content for it and the line content is always the empty string. That makes
    the id exactly reproducible here, with no worktree and no file read.

    Pinned against `normalize` itself by
    `test_the_consumer_derives_the_same_id_normalize_gives_the_finding`, with
    one side from each computation. A test reading both sides from this
    function would only prove it is deterministic.
    """
    return compute_fingerprint(TOOL, check, f"{method} {path}", "", 0)

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
    try:
        parts = urlsplit(base_url)
        target_ok = parts.scheme in ("http", "https") and bool(parts.hostname)
        _ = parts.port   # an out-of-range / non-numeric port raises ValueError HERE
                         # (in the guard) instead of later crashing _fetch
    except ValueError:
        target_ok = False
    if not target_ok:
        # malformed target (bad scheme/host/port) is a config mistake, not a
        # transient fault -> OK-skip (a typo must never pin the queue item)
        return ConsumerResult(consumer=NAME, state="ok",
                              note="invalid dast base_url (need http(s)://host with a valid port)")

    paths = list(mcfg.get("paths", []))
    timeout_s = float(mcfg.get("timeout_s", 10))

    # Both a persistently-unreachable target AND a persistently-crashing probe
    # must stop pinning the queue item: after 3 honest DEGRADED retries AT THIS
    # HEAD each becomes a permanent OK-skip. Head-scoped so new commits get a
    # fresh try. Both prefixes are load-bearing -- each DEGRADED note below must
    # start with the exact string its give-up counter reads.
    # `(last seen @ ...)` rather than a bare `@`: these notes share the `status`
    # column with the mutation families, and one grammar down that column is the
    # whole point -- see consumers/mutation.py:failing_note_prefix. Both prefixes
    # stay head-scoped; only the wording moved.
    give_up_prefix = f"dast target unreachable (last seen @ {item.head[:12]})"
    crash_prefix = f"dast probe error (last seen @ {item.head[:12]})"
    if (base.prior_note_count(ctx.ledger, NAME, item.id, give_up_prefix) >= _UNREACHABLE_GIVE_UP
            or base.prior_note_count(ctx.ledger, NAME, item.id, crash_prefix) >= _UNREACHABLE_GIVE_UP):
        return ConsumerResult(consumer=NAME, state="ok",
                              note="dast giving up: target persistently unreachable or erroring")

    try:
        findings, probed = dast_probe.probe_scoped(base_url, paths, timeout_s)
    except dast_probe.DastUnreachable:
        return ConsumerResult(consumer=NAME, state="degraded", note=give_up_prefix)
    except Exception as exc:  # a probe crash degrades with a HEAD-SCOPED give-up prefix,
        # so a PERSISTENT crash (latent prober bug / bad-port redirect) can't pin forever
        return ConsumerResult(consumer=NAME, state="degraded",
                              note=f"{crash_prefix}: {str(exc)[:120]}")

    raws = [RawFinding(tool="dast", rule=f.check, severity_raw=f.severity,
                       file=f"{f.method} {f.path}", line=0,
                       message=f.message, evidence=f.evidence)
            for f in findings]

    # Repair claim. Every path that reaches here has a SUCCESSFUL probe behind
    # it -- an unreachable target and a crashing prober both returned above,
    # degraded, claiming nothing. That ordering is the guard: a down app must
    # never be able to resolve its own findings, which is the one direction a
    # security tool may not fail in.
    #
    # Scope comes from `probe_scoped`, i.e. endpoints that ANSWERED -- never
    # from the configured `paths`, which is merely what was attempted. Within
    # that scope a probe is a COMPLETE re-examination (every check family runs
    # against the one response), so a check that did not fire really is clean
    # rather than unlooked-at. Outside it nothing is claimed, which is also why
    # shrinking `paths` cannot clear anything: dropping a path stops examining
    # it, it does not absolve it.
    #
    # Anything re-reported right now is excluded here, and excluded again by
    # the drain's `present_ids`. Belt and braces on purpose: a producer that
    # claims repair for a finding it is simultaneously reporting is the worst
    # failure this mechanism can have, so it is not left to one filter.
    still_firing = {_finding_fp(f.check, f.method, f.path) for f in findings}
    repaired_ids = tuple(sorted(
        fid for fid, rec in base.open_findings_for(ctx.ledger, TOOL).items()
        if rec.get("file") in probed and fid not in still_firing))

    host = parts.hostname
    return ConsumerResult(consumer=NAME, state="ok", findings=raws, cost=0.0,
                          note=f"{len(raws)} hygiene finding(s) on {host}",
                          extra={"target": host, "found": len(raws),
                                 "probed": sorted(probed)},
                          repaired=base.Repaired(tool=TOOL,
                                                 reason="endpoint_reprobed",
                                                 ids=repaired_ids)
                          if repaired_ids else None)


base.CONSUMERS[NAME] = sys.modules[__name__]
