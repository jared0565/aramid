"""review -- the 2b evidence-bound review protocol (spec section 3): packet
assembly, outbound redaction, prompt rendering, response verification,
refute handling, and the zero-token pre-push helpers (auto-resolve + gate
findings). Everything here is pure computation; provider calls live in
aramid.providers and are orchestrated by consumers.llm_review."""
import re
from dataclasses import dataclass
from pathlib import Path

from aramid import config as config_mod
from aramid import gitutil, triage

_BEGIN = "<<<UNTRUSTED_DATA_BEGIN>>>"
_END = "<<<UNTRUSTED_DATA_END>>>"

# Outbound redaction (spec section 3): drains review commits that may have
# BYPASSED gates, so never assume the diff is secret-free before shipping it
# to a third party. Shapes, not values -- gitleaks-grade coverage is not the
# goal; catching the obvious token formats is.
_REDACT_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
               re.S),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"""(?i)\b(api[_-]?key|secret|token|passw(?:or)?d)\b(\s*[:=]\s*["']?)"""
               r"""[A-Za-z0-9+/_\-]{16,}["']?"""),
]


def redact_packet(text: str) -> str:
    for rx in _REDACT_PATTERNS[:-1]:
        text = rx.sub("[REDACTED]", text)
    # keyed-assignment pattern keeps the key name, masks only the value
    text = _REDACT_PATTERNS[-1].sub(r"\1\2[REDACTED]", text)
    return text


@dataclass
class Packet:
    text: str
    files: list[str]
    truncated: bool


def _is_binary(content: str) -> bool:
    return "\x00" in content


def build_packet(root: Path, cfg, item) -> Packet | None:
    max_bytes = int(cfg.llm.get("packet_max_bytes", 120000))
    files = gitutil.diff_paths(root, item.base, item.head)
    files = config_mod.filter_paths(files, cfg)
    if not files:
        return None

    truncated = False
    # paths=files (post filter_paths): defense-in-depth (spec 8b) -- an
    # unscoped base..head diff would include graphite-artifact hunks even
    # though `files` already excludes them from the packet's file list.
    diff = gitutil.diff_text(root, item.base, item.head, max_bytes=max_bytes, paths=files)
    if len(diff.encode("utf-8", "replace")) >= max_bytes:
        truncated = True

    deps = triage.dependents(root, files)
    header = [
        "=== ARAMID REVIEW PACKET ===",
        f"repo: {root.name}",
        f"range: {item.range_str}",
        f"triage reasons: {', '.join(item.reasons) or 'none'}",
    ]
    parts = [*header, _BEGIN, "--- DIFF ---", diff]
    used = len("\n".join(parts).encode("utf-8", "replace"))

    included: list[str] = []
    for f in files:
        try:
            content = gitutil.read_for_fingerprint(root, item.head, f)
        except Exception:
            continue
        if not content or _is_binary(content):
            continue
        section = f"--- FILE: {f} (at {item.head[:12]}) ---\n{content}"
        section_bytes = len(section.encode("utf-8", "replace"))
        if used + section_bytes > max_bytes:
            truncated = True
            continue
        parts.append(section)
        used += section_bytes
        included.append(f)

    if deps:
        parts.append("--- DEPENDENTS (modules importing the changed files) ---")
        parts.append("\n".join(f"- {d}" for d in deps[:50]))
    if truncated:
        parts.append("--- NOTE: PACKET TRUNCATED at byte cap; some content omitted ---")
    parts.append(_END)
    return Packet(text=redact_packet("\n".join(parts)), files=files, truncated=truncated)
