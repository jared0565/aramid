from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from aramid import gitutil
from aramid.fingerprint import compute_fingerprint, normalize_line
from aramid.models import Finding, Gate, Source
from aramid.redact import redact, scrub


@dataclass
class RawFinding:
    tool: str
    rule: str
    severity_raw: str
    file: str
    line: int
    message: str
    secret: str | None = None
    # The source line the RUNNER actually read, when the runner scanned bytes
    # it can vouch for. Set it and `normalize` fingerprints THIS string instead
    # of re-reading the line by number out of a git object.
    #
    # Why it exists: `line` comes from a scanner that read the WORKING TREE,
    # while `ref_for` picks a blob (the INDEX at pre-commit). Those two agree
    # right up until someone has an unstaged edit, and then
    # `lines[raw.line - 1]` is a different line of code than the one that was
    # flagged. Measured consequence: an unreviewed statement inherited a
    # SUPPRESSED finding's id and was downgraded to INFO -- a suppression
    # written for one line covering another. See tests/integration/
    # test_fingerprint_modes.py Part C.
    #
    # Additive on purpose. Adapters that leave it None keep today's ref lookup
    # exactly, which is what gitleaks' history scan needs: it reports lines out
    # of OLD COMMITS, so the working tree is the wrong place to read them and
    # `commit`/`ref_for` above is the right one.
    #
    # None therefore means "this runner does not participate", NOT "this runner
    # tried and failed". A converted runner always sets a string -- see
    # `runners/base.CONTENT_UNREADABLE`, which it uses when the file is gone or
    # the row is out of range. Keeping those two cases apart is load-bearing:
    # if a failed read fell through to the ref lookup, the rare failure path
    # would quietly reinstate the exact hazard this field removes, and nothing
    # in the output would say which source an id came from.
    line_content: str | None = None
    # Commit sha the finding was read from, when known (gitleaks' `git log`
    # history-scan path only -- see runners/gitleaks.py). Additive/optional:
    # every other adapter and every staged/protect-mode gitleaks finding
    # leaves this None. Consumed by commands/init.py's `_scan_history` to
    # build a ref_for that reads a historical secret's line from the commit
    # it actually lived in, instead of HEAD (where the line may have moved
    # or the secret may have been removed).
    commit: str | None = None
    # --- Phase 2b (spec section 3): LLM finding passthrough. All optional
    # and defaulted so every deterministic adapter is untouched.
    # `evidence` is the verbatim quote the reviewer cited (already verified
    # against the packet and head file by aramid.review); when set it is
    # stored as Finding.evidence INSTEAD of the message, because auto-resolve
    # (review.auto_resolve_llm) string-matches it against the head file.
    evidence: str | None = None
    source: Source = Source.DETERMINISTIC
    confirmed: bool = False
    refuted: bool = False


def normalize(raws: list[RawFinding], root: Path, ref_for: Callable[[str], str],
              salt: bytes, gate: Gate, classify, *,
              pin_occurrence: bool = False) -> list[Finding]:
    occurrence_counts: Counter = Counter()
    findings: list[Finding] = []

    for raw in raws:
        if raw.line_content is not None:
            # The runner handed us the bytes it scanned. Trust them over a
            # second lookup: re-reading `lines[raw.line - 1]` out of a
            # different revision is what let a finding be identified by a line
            # that was never flagged.
            line_content = raw.line_content
        else:
            content = gitutil.read_for_fingerprint(root, ref_for(raw.file), raw.file)
            lines = content.splitlines()
            idx = raw.line - 1
            line_content = lines[idx] if 0 <= idx < len(lines) else ""

        occ_key = (raw.tool, raw.rule, raw.file, normalize_line(line_content))
        # pin_occurrence (M5): variable-set drain consumers (mutation, fuzz)
        # have budget-truncated batches, so positional occurrence indices
        # drift across drains -> ghost never-resolving findings. Pinning
        # gives one finding per (tool, rule, file, line-content) -- the
        # llm_fingerprint precedent (review.py). Duplicates are COLLAPSED
        # here, not just id-collided: two same-id Findings reaching
        # record_run would double-append FINDING_DETECTED and _materialize
        # keeps only the last (silent loss -- review I1). Gate callers keep
        # the counter (default False): their batches are complete scans.
        if pin_occurrence and occurrence_counts[occ_key]:
            occurrence_counts[occ_key] += 1
            continue
        occurrence_index = 0 if pin_occurrence else occurrence_counts[occ_key]
        occurrence_counts[occ_key] += 1

        finding_id = compute_fingerprint(raw.tool, raw.rule, raw.file, line_content,
                                          occurrence_index)

        if raw.secret:
            preview, secret_hash = redact(raw.secret, salt)
            evidence = f"{preview} (sha256:{secret_hash})"
            message = scrub(raw.message, [raw.secret])
        elif raw.evidence is not None:
            evidence = raw.evidence
            message = raw.message
        else:
            evidence = raw.message
            message = raw.message

        severity, verdict = classify(raw.tool, raw.rule, raw.severity_raw, gate)

        findings.append(Finding(
            id=finding_id, tool=raw.tool, rule=raw.rule, severity_raw=raw.severity_raw,
            severity=severity, verdict=verdict, file=raw.file, line=raw.line,
            message=message, evidence=evidence, gate=gate,
            source=raw.source, confirmed=raw.confirmed, refuted=raw.refuted))

    return findings
