"""agent_bypass -- token-level detection of git hook-bypass invocations,
and of an evidenced close an agent makes without red proof.

Spec: docs/superpowers/specs/2026-08-31-aramid-agent-enforcement-design.md §6;
the close rule is docs/superpowers/specs/2026-10-09-aramid-evidenced-llm-close-design.md
section 9.3.

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

THE CLOSE RULE (FN-36). `aramid ledger resolve --fixed` closes an LLM
finding on a passing test. `--red-proof` is optional at the command line; an
agent's close has to carry it (operator decision, 2026-10-11), and this is
where that is read. Three choices, each the opposite of a git rule's for a
reason:

- the launch is read by SHAPE, not from a list of launchers: any token
  named `aramid` (with or without `.exe`, `.cmd`, `.bat`, `.ps1`, under any
  directory) starts an invocation, which covers `python -m aramid`,
  `py -m aramid`, `uv run aramid` and an absolute path alike;
- the flags are read as ARGPARSE reads them: `--fix` and `--red` are the
  flags they abbreviate, `--fixed=abc` carries its value, and a value that
  follows `--fixed`, `--test` or `--reason` is never a flag;
- nothing makes the scan give up. A token it does not know is stepped over
  and the scan goes on, because every early exit would be a way to hide a
  close from it. The cost is that a command argparse would reject anyway is
  answered too; the advice it gets is the same.

Residuals of the close rule, false-negative direction: an unquoted Windows
path (shlex eats the backslashes), and a close built inside `python -c`.
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


# Every long option of `aramid ledger resolve`, and whether a SEPARATE value
# token follows it. tests/unit/test_agent_bypass_resolve.py holds this equal
# to the real parser's table, so a flag added there cannot go unread here.
_RESOLVE_FLAGS = {"--help": False, "--out-of-scope": False, "--fixed": True,
                  "--test": True, "--red-proof": False, "--reason": True}

# What a token that launches aramid is called, under any directory.
_ARAMID_NAMES = ("aramid", "aramid.exe", "aramid.cmd", "aramid.bat", "aramid.ps1",
                 "aramid.__main__")


@dataclass(frozen=True)
class Bypass:
    kind: str        # "no-verify" | "hooks-path" | "no-red-proof"
    subcommand: str  # "commit" | "push" | "ledger resolve"
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
        # a bare "-c" was taken by the branch above, so anything left that
        # starts with "-c" carries its value attached
        if tok.startswith("-c") and not tok.startswith("--"):
            configs.append(tok[2:])
            i += 1
            continue
        if tok.partition("=")[0] in ("--git-dir", "--work-tree",
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
        if cfg.partition("=")[0].lower() == "core.hookspath":
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


def _is_aramid(token: str) -> bool:
    """A token that launches aramid: the program under any directory, or the
    module name `python -m` is given (attached, as `-maramid`, included)."""
    name = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name.removeprefix("-m") in _ARAMID_NAMES


def _resolve_flag(token: str) -> str | None:
    """The `ledger resolve` option `token` is, by argparse's rules: its name
    is what stands before a `=`, an exact name wins, and otherwise a prefix
    that fits exactly one option is that option. None for anything else: a
    positional or an unknown option fits none, and `--re` fits two. So does
    `-`, or no name at all, which every option starts with."""
    name = token.partition("=")[0]
    if name in _RESOLVE_FLAGS:
        return name
    fits = [flag for flag in _RESOLVE_FLAGS if flag.startswith(name)]
    return fits[0] if len(fits) == 1 else None


def _scan_one_aramid(seg: list[str], start: int) -> Bypass | None:
    """Scan the aramid invocation whose program token is seg[start]: a
    `ledger resolve` that carries `--fixed` and no `--red-proof`."""
    if not 0 <= start < len(seg):
        return None
    i = start + 1
    # Global options (`--version`): none takes a value.
    while i < len(seg) and seg[i].startswith("-"):
        i += 1
    if seg[i:i + 2] != ["ledger", "resolve"]:
        return None
    seen = set()
    j = i + 2
    while j < len(seg):
        tok = seg[j]
        if tok == "--":
            break       # argparse reads no option after it
        flag = _resolve_flag(tok)
        if flag is not None:
            seen.add(flag)
            if _RESOLVE_FLAGS[flag] and "=" not in tok:
                j += 1  # its value, whatever it says
        j += 1
    if "--fixed" in seen and "--red-proof" not in seen:
        return Bypass("no-red-proof", "ledger resolve", "--fixed")
    return None


def find_bypass(command) -> Bypass | None:
    """The first git hook-bypass invocation in `command`, or the first
    evidenced close without red proof, or None.

    Compound commands (&&, ;, |, ||) are scanned in full, not just the
    head (spec §6). One match is enough to decide the tool call.
    """
    if not isinstance(command, str):
        return None
    low = command.lower()
    if "git" not in low and "aramid" not in low:
        return None
    tokens = _tokens(command)
    if tokens is None:
        return None
    for seg in _segments(tokens):
        for i, tok in enumerate(seg):
            if _is_git(tok):
                found = _scan_one_git(seg, i)
            elif _is_aramid(tok):
                found = _scan_one_aramid(seg, i)
            else:
                continue
            if found is not None:
                return found
    return None
