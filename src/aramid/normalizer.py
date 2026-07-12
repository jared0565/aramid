from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from aramid import gitutil
from aramid.fingerprint import compute_fingerprint, normalize_line
from aramid.models import Finding, Gate
from aramid.redact import redact, scrub


@dataclass
class RawFinding:
    tool: str; rule: str; severity_raw: str; file: str; line: int; message: str
    secret: str | None = None


def normalize(raws: list[RawFinding], root: Path, ref_for: Callable[[str], str],
              salt: bytes, gate: Gate, classify) -> list[Finding]:
    occurrence_counts: Counter = Counter()
    findings: list[Finding] = []

    for raw in raws:
        content = gitutil.read_for_fingerprint(root, ref_for(raw.file), raw.file)
        lines = content.splitlines()
        idx = raw.line - 1
        line_content = lines[idx] if 0 <= idx < len(lines) else ""

        occ_key = (raw.tool, raw.rule, raw.file, normalize_line(line_content))
        occurrence_index = occurrence_counts[occ_key]
        occurrence_counts[occ_key] += 1

        finding_id = compute_fingerprint(raw.tool, raw.rule, raw.file, line_content,
                                          occurrence_index)

        if raw.secret:
            preview, secret_hash = redact(raw.secret, salt)
            evidence = f"{preview} (sha256:{secret_hash})"
            message = scrub(raw.message, [raw.secret])
        else:
            evidence = raw.message
            message = raw.message

        severity, verdict = classify(raw.tool, raw.rule, raw.severity_raw, gate)

        findings.append(Finding(
            id=finding_id, tool=raw.tool, rule=raw.rule, severity_raw=raw.severity_raw,
            severity=severity, verdict=verdict, file=raw.file, line=raw.line,
            message=message, evidence=evidence, gate=gate))

    return findings
