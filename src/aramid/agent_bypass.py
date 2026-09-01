"""agent_bypass -- token-level detection of git hook-bypass invocations.

Spec: docs/superpowers/specs/2026-08-31-aramid-agent-enforcement-design.md §6.

Pure stdlib, imported by the pre-tool-use agent hook on EVERY Bash /
PowerShell tool call: no aramid imports, no I/O. Matching is on parsed
tokens, never substrings -- a commit message or filename that merely
CONTAINS "--no-verify" must not match, because that string never reaches
git as a flag token.

Best-effort by design (spec §6): a bypass this parser misses is caught by
nothing today, so a false NEGATIVE only fails back to the status quo; a
false POSITIVE while armed rejects a legitimate tool call, the expensive
direction. Every rule below is written to make false positives
structurally hard:

- tokens after a bare `--` are pathspecs, never flags -- not scanned;
- `-n` matches on `commit` only (`git push -n` is `--dry-run`, harmless);
- arguments of value-taking subcommand flags (`-m`, `-F`, `-o`, ...) are
  skipped, so a message that IS the literal flag text cannot match;
- bundled short flags (`git commit -an`) are NOT expanded -- a documented
  false-negative residual, indistinguishable at token level from an
  attached-argument token like `-mfix`.

Known residuals, all false-negative direction: bundled short flags, `git
config alias.*` indirection, commands built by shell variables or eval,
and PowerShell-only syntax shlex cannot lex (which fails open).
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass

# Characters shlex groups into operator tokens under punctuation_chars.
_PUNCT = set("();<>|&")

# Subcommand flags that take a SEPARATE value token: the value is skipped
# so it can never be read as a flag. `=`-attached forms are one token and
# self-contain their value, so they need no entry.
_ARG_FLAGS = {
    "commit": ("-m", "--message", "-F", "--file", "-t", "--template",
               "-C", "--reuse-message", "-c", "--reedit-message",
               "--fixup", "--squash", "--author", "--date", "--trailer"),
    "push": ("-o", "--push-option", "--receive-pack", "--exec", "--repo"),
}


@dataclass(frozen=True)
class Bypass:
    kind: str        # "no-verify" | "hooks-path"
    subcommand: str  # "commit" | "push"
    token: str       # the exact matched token / -c value, for messages


def _tokens(command: str) -> list[str] | None:
    lex = shlex.shlex(command, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        return list(lex)
    except ValueError:
        return None  # unbalanced quotes etc. -- fail open (spec §6)


def _segments(tokens: list[str]) -> list[list[str]]:
    """Split the token stream at shell operators (&&, ;, |, ...), so each
    simple command is scanned on its own."""
    segs: list[list[str]] = [[]]
    for tok in tokens:
        if tok and all(ch in _PUNCT for ch in tok):
            segs.append([])
        else:
            segs[-1].append(tok)
    return [s for s in segs if s]


def _is_git(token: str) -> bool:
    name = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name in ("git", "git.exe")


def _scan_one_git(seg: list[str], start: int) -> Bypass | None:
    """Scan the git invocation whose `git` token is seg[start].

    `start` must index into `seg` -- find_bypass only passes enumerate()
    indices, so this holds for every real caller. Guarded anyway (fuzz
    ledger a7bee49a: a negative `start` on an empty seg walked backwards
    into an IndexError): out-of-contract input fails OPEN, the module's
    one failure direction.
    """
    if not 0 <= start < len(seg):
        return None
    configs: list[str] = []
    i = start + 1
    subcommand = None
    while i < len(seg):
        tok = seg[i]
        if tok in ("-c", "-C"):
            if tok == "-c" and i + 1 < len(seg):
                configs.append(seg[i + 1])
            i += 2
            continue
        if tok.startswith("-c") and len(tok) > 2 and not tok.startswith("--"):
            configs.append(tok[2:])
            i += 1
            continue
        if tok.split("=", 1)[0] in ("--git-dir", "--work-tree",
                                    "--exec-path", "--namespace"):
            i += 1 if "=" in tok else 2
            continue
        if tok.startswith("-"):
            i += 1  # unknown global option; assume no separate argument
            continue
        subcommand = tok
        i += 1
        break
    if subcommand not in ("commit", "push"):
        return None
    for cfg in configs:
        if cfg.split("=", 1)[0].lower() == "core.hookspath":
            return Bypass("hooks-path", subcommand, cfg)
    skip = _ARG_FLAGS[subcommand]
    j = i
    while j < len(seg):
        tok = seg[j]
        if tok == "--":
            break
        if tok in skip:
            j += 2
            continue
        if tok == "--no-verify":
            return Bypass("no-verify", subcommand, tok)
        if tok == "-n" and subcommand == "commit":
            return Bypass("no-verify", subcommand, tok)
        j += 1
    return None


def find_bypass(command) -> Bypass | None:
    """The first git hook-bypass invocation in `command`, or None.

    Compound commands (&&, ;, |, ||) are scanned in full, not just the
    head (spec §6). One match is enough to decide the tool call.
    """
    if not isinstance(command, str) or "git" not in command.lower():
        return None
    tokens = _tokens(command)
    if tokens is None:
        return None
    for seg in _segments(tokens):
        for i, tok in enumerate(seg):
            if _is_git(tok):
                found = _scan_one_git(seg, i)
                if found is not None:
                    return found
    return None
