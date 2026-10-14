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
and PowerShell-only syntax in a call the hook was not told is PowerShell's.

WHICH SHELL (FN-45). `find_bypass` takes the shell the hook was told runs
the command. A PowerShell call is cut up by `agent_bypass_powershell`, by
PowerShell's own rules, and what is said below about quotes, comments and
where a command ends is not about it; the flag rules are the same for every
shell. A Bash call is read the POSIX way, once. With no shell named a command
is read as every command was up to 0.20.8: the POSIX way, and a second time
with PowerShell's backtick for the close rule. For a known shell the git
rules also step over a word that starts with `$` in front of the subcommand,
as the close rule always has: the shell may make nothing of it, and `git
$(true) commit -n` commits.

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
path (shlex eats the backslashes; in a call known to be PowerShell's the
path is whole), and a close built inside `python -c`.

WHERE A COMMAND STARTS AND ENDS (`_shell_text`, `_segments`). The close rule
is the one rule here that looks for a flag that is ABSENT, so for it text
the reader takes in and the shell does not hand to aramid is not a false
alarm, it is a close let through: `--red-proof` on the next line, or after
a `#`. And text the shell does hand over, read as something else, hides
`--fixed`: a `#` in the middle of a word read as a comment, the words after
a redirection read as another command. The security review of 9b37b81
found this, and each case here was measured. So a command is cut up as the
shell cuts it, for every rule:

- a newline outside quotes ends the command, like `;`;
- `#` starts a comment only where a word starts, and the comment ends with
  its line. `fix#12` is one word;
- a backslash before a newline, or PowerShell's backtick before one,
  continues the line;
- a redirection does not end the command. It goes with the one word after
  it, and with the file descriptor number written in front of it (`2>&1`);
  the words after that are still arguments of the same program;
- `( )` holds commands of its own (`$( )`, `<( )`, a subshell), and the
  command around it goes on after the `)`;
- an operator character inside quotes, or escaped, is text.

For the git rules the same reading removes misses (`git commit -m fix#12
--no-verify`, `git commit -m x >/dev/null --no-verify`) and a false alarm
(`git commit -m x` with `git push -n` on the next line, which read as one
line was a refused commit).

TWO READINGS OF A BACKTICK, for the close rule, when no shell is named.
Inside double quotes
PowerShell's backtick escapes the next character, so a quote written with
one in front does not end the string; to a POSIX shell that quote does end
it. Whichever way the reader takes it, the other shell has a command whose
string ends somewhere else, and with it a `#` that is or is not a comment.
So the close rule reads the command both ways and answers if either reading
holds a close without red proof. The cost is a false alarm, in PowerShell,
for a reason that quotes something with escaped quotes and has a `#` or an
operator between them. The git rules keep the POSIX reading they always
had.

A QUOTE THAT NEVER CLOSES (`_tokens`). Until this fix a command shlex could
not lex was let through unread, whole. bash does not treat it so: it runs a
script line by line, so a close on the first line has been made by the time
an open quote on the third is a syntax error. And what does not pair up by
the POSIX rule can be a command that runs as written: a heredoc body with an
apostrophe in it, a PowerShell string that ends in a backslash. So the
command is read up to the quote that does not close. What comes after it is
not read. For the git rules that is a miss, as before; for the close rule a
`--red-proof` after it does not count, which is a false alarm when the shell
did pair the quotes.

The two readings are not treated alike here. The POSIX reading counts as far
as it gets, always: it is bash's own, and bash ran what it shows. The
reading with PowerShell's backtick counts when it gets to the end, or when
neither does. Cut off while the POSIX reading is whole it is left out,
because in bash that is an everyday command: in `--reason "by `whoami`"
--red-proof` the backtick before the last quote would escape it, the string
would never close, and a proper close would be answered.

What this leaves, for every rule. The quoting is POSIX quoting: where
PowerShell differs otherwise (a backslash escapes nothing there, a quote is
doubled inside single quotes, `<# #>` is a comment) a command whose shell
was not named is read by the POSIX rule. bash's `$'...'` is not followed
either, nor a heredoc body:
its lines are read as commands. And a command that is built when it runs
(backticks, a variable, `eval`, the output of `$( )`) is read as written,
not as built.
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass

# Characters shlex groups into operator tokens under punctuation_chars. A
# newline is one of them: outside quotes it ends a command.
_OPERATORS = "();<>|&\n"
_PUNCT = set(_OPERATORS)
# After one of these, outside quotes, the next character starts a word.
_BREAKS = " \t\r" + _OPERATORS
# The operators that are redirections, the longest first: `&>>` is one
# operator, not `&` and `>>`.
_REDIRECTS = ("&>>", "<<<", "&>", "<<", "<>", "<&", ">>", ">&", ">|", "<", ">")
# A process substitution opens with one of these, and is no redirection.
_SUBSTITUTIONS = ("<(", ">(")
# A quoted or escaped operator character is text. The lexer is handed a
# stand-in from the private-use area for it, so that no token it is part of
# reads as an operator, and the character is put back when the token is
# taken as a word.
_STAND_IN = {ord(ch): 0xE000 + i for i, ch in enumerate(_OPERATORS)}
# The stand-in for a double quote that PowerShell's backtick escapes.
_QUOTE = "\ue010"
_PUT_BACK = {stand_in: ord_ for ord_, stand_in in _STAND_IN.items()} | {ord(_QUOTE): ord('"')}
_DIGITS = "0123456789"

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


# The shells `find_bypass` can be told a command is for.
POSIX = "posix"
POWERSHELL = "powershell"
# What the POSIX reading takes out of a word on its way to being a program's
# name: the quotes, the backslash, and a line end (a backslash in front of one
# joins two lines). For `_may_name_a_program`.
_MARKS = {ord(ch): None for ch in "'\"\\\r\n"}


@dataclass(frozen=True)
class Bypass:
    kind: str        # "no-verify" | "hooks-path" | "no-red-proof" | "too-deep"
    subcommand: str  # "commit" | "push" | "ledger resolve"
    token: str       # the exact matched token / -c value, for messages


def _shell_text(command: str, backtick: bool) -> str:
    """`command` as the lexer is to read it: comments taken out, continued
    lines joined, the number in front of a redirection dropped, and every
    quoted or escaped operator character replaced by its stand-in. Quotes
    and escapes stay where they are, for shlex to read.

    `backtick` picks the reading of a backtick inside double quotes: True
    for PowerShell's, where it escapes the next character and a quote after
    it does not end the string; False for a character like any other.

    shlex has a comment rule of its own, and it is not the shell's: it ends
    the line at a `#` in the middle of a word, and it takes the newline with
    the comment, so the next line reads as more of this one. That is why
    the comments are taken out here. This walk cannot raise."""
    out: list[str] = []
    quote = ""      # the quote the walk is inside: "", "'" or '"'
    fresh = True    # the next character would start a word
    i, n = 0, len(command)
    while i < n:
        ch = command[i]
        if quote != "'" and ch in "\\`" and command.startswith(("\n", "\r\n"), i + 1):
            # a continued line: the shell's backslash, PowerShell's backtick
            i += 3 if command[i + 1] == "\r" else 2
            continue
        if quote != "'" and (ch == "\\" or (ch == "`" and quote and backtick)):
            # an escaped character: text, whatever it is
            escaped = command[i + 1:i + 2]
            out.append(ch + (_QUOTE if ch == "`" and escaped == '"'
                             else escaped.translate(_STAND_IN)))
            i, fresh = i + 2, False
            continue
        if quote:
            out.append(ch.translate(_STAND_IN))
            quote = "" if ch == quote else quote
            i += 1
            continue
        if ch == "#" and fresh:
            # a comment: to the end of its line, the newline not included
            while i < n and command[i] != "\n":
                i += 1
            continue
        if ch in _DIGITS and fresh:
            j = i
            while j < n and command[j] in _DIGITS:
                j += 1
            if command[j:j + 1] in ("<", ">"):
                i = j       # the file descriptor of a redirection: `2>&1`
                continue
        if ch in "'\"":
            quote = ch
        out.append(ch)
        fresh = ch in _BREAKS
        i += 1
    return "".join(out)


def _tokens(command: str, backtick: bool) -> tuple[list[str], bool]:
    """The words and operators of `command` as far as it can be read, and
    whether that was to its end. A quote that never closes (or a backslash
    with nothing after it) stops the lexer; the tokens before it are
    returned and the word it stopped in is not. They still count: bash has
    run every line before the one with the open quote by the time it finds
    it, and what does not pair up by the POSIX rule may pair up in the shell
    that runs it (a heredoc body, a PowerShell string that ends in a
    backslash). What follows the open quote is not read: for the git rules a
    flag there is missed, for the close rule a `--red-proof` there does not
    count."""
    lex = shlex.shlex(_shell_text(command, backtick), posix=True,
                      punctuation_chars=_OPERATORS)
    lex.whitespace_split = True
    lex.whitespace = " \t\r"   # not the newline: it is an operator here
    lex.commenters = ""         # `_shell_text` has taken the comments out
    tokens: list[str] = []
    try:
        for token in lex:
            tokens.append(token)
    except ValueError:
        return tokens, False
    return tokens, True


def _operators(token: str):
    """The operators an operator token is made of: shlex hands over a run of
    operator characters as one token, `)>` or `>;`, and each is read for
    itself."""
    i = 0
    while i < len(token):
        op = next((known for known in _SUBSTITUTIONS + _REDIRECTS
                   if token.startswith(known, i)), token[i])
        yield op
        i += len(op)


def _segments(tokens: list[str]) -> list[list[str]]:
    """The simple commands in the token stream, each to be scanned on its
    own, cut up as the shell cuts them (module docstring): `;`, `|`, `&`
    and a newline end a command; a redirection and the word after it are
    left out of it; `( )` holds commands of its own, and the command around
    it goes on after the `)`."""
    done: list[list[str]] = []
    nested: list[list[str]] = [[]]   # the command being read, per depth of ( )
    target = False                   # the next word is where a redirection goes
    for tok in tokens:
        if not (tok and all(ch in _PUNCT for ch in tok)):
            if not target:
                nested[-1].append(tok.translate(_PUT_BACK))
            target = False
            continue
        for op in _operators(tok):
            if op in _REDIRECTS:
                target = True
                continue
            if op in _SUBSTITUTIONS and not target:
                # `<( )` stands where a word would: it is one, to the
                # command around it, unless a redirection was waiting for it
                nested[-1].append(op)
            target = False
            if op == "(" or op in _SUBSTITUTIONS:
                nested.append([])
            elif op == ")" and len(nested) > 1:
                done.append(nested.pop())
            else:
                done.append(nested[-1])
                nested[-1] = []
    return [seg for seg in done + nested if seg]


def _is_git(token: str) -> bool:
    name = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name in ("git", "git.exe")


def _scan_one_git(seg: list[str], start: int, values: bool = False) -> Bypass | None:
    """Scan the git invocation whose `git` token is seg[start].

    `values` is for a reading by a known shell's rules: a word that starts
    with `$` in front of the subcommand is then stepped over, as the close
    rule steps over one, because the shell may make nothing of it
    (`git $(true) commit -n` runs the commit).

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
            # `-c` and a value after it (`!=` not `<`: with i inside seg the
            # two agree, and a `-c` that is the last word must not index past)
            if tok == "-c" and i + 1 != len(seg):
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
        if tok.startswith("-") or (values and tok.startswith("$")):
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
    # Up to `ledger`: global options (`--version`), none of which takes a
    # value. There and before `resolve`: words the shell may make nothing of
    # -- `$(true)`, an empty `$VAR` -- which would otherwise stand in between
    # and hide the close (found by running generated commands under bash).
    i = start + 1
    while i < len(seg) and seg[i].startswith(("-", "$")):
        i += 1
    if seg[i:i + 1] != ["ledger"]:
        return None
    i += 1
    while i < len(seg) and seg[i].startswith("$"):
        i += 1
    if seg[i:i + 1] != ["resolve"]:
        return None
    seen = set()
    j = i + 1
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


def _first(segments: list[list[str]], git_rules: bool, values: bool) -> Bypass | None:
    """The first match in `segments`: every word that launches aramid or git
    starts a scan of its own."""
    for seg in segments:
        for i, tok in enumerate(seg):
            if _is_aramid(tok):
                found = _scan_one_aramid(seg, i)
            elif git_rules and _is_git(tok):
                found = _scan_one_git(seg, i, values)
            else:
                continue
            if found is not None:
                return found
    return None


def _may_name_a_program(command: str) -> bool:
    """Whether `command` can hold a git or an aramid invocation at all, read
    the POSIX way (the second reading, with the backtick, takes nothing more
    out of a word): the cheap answer that keeps every other tool call from
    being tokenized. A wrong yes costs one reading and no answer. A wrong no
    is a bypass not seen, so the characters that reading takes out of a word
    are taken out first: `g"i"t`, `g\\it`
    and a `git` broken over a continued line are git in bash, and none of them
    holds the letters in a row. (Up to 0.20.8 the text was searched as
    written, and none of them was answered.)

    A PowerShell call is not asked here before it is read: it is always read.
    PowerShell makes a name out of more than a cheap test can follow
    (`` `u{67}it ``, `g$()it`). Only a reading cut off by the depth cap asks
    it of one, with the backticks taken out first (`find_bypass`), and those
    two spellings are not seen there."""
    low = command.lower().translate(_MARKS)
    return "git" in low or "aramid" in low


def find_bypass(command, shell: str | None = None) -> Bypass | None:
    """The first git hook-bypass invocation in `command`, or the first
    evidenced close without red proof, or None.

    Compound commands (&&, ;, |, ||) are scanned in full, not just the
    head (spec §6). One match is enough to decide the tool call.

    `shell` is the shell the caller knows will run the command: POSIX for a
    Bash tool call, POWERSHELL for a PowerShell one. Each gets one reading,
    by that shell's own rules, for every rule. With no shell named the
    command is read as every command was up to 0.20.8: the POSIX way, and a second
    time with PowerShell's backtick; only the close rule is asked on that
    second reading, and a second reading that stops at an open quote is left
    out when the first got to the end (module docstring).

    A PowerShell call nested deeper than its reader reads is refused as
    "too-deep" when its text names git or aramid, spelled with the quotes
    and backticks PowerShell takes out of a word: PowerShell runs what lies
    past the cap, and no real command nests that deep (the operator's
    decision, 2026-10-13). A bypass the reader did reach answers first.
    """
    if not isinstance(command, str):
        return None
    if shell == POWERSHELL:
        from aramid import agent_bypass_powershell
        done, end = agent_bypass_powershell.reading(command)
        found = _first(done, True, True)
        if found is None and end == "deep" and _may_name_a_program(command.replace("`", "")):
            return Bypass("too-deep", "", str(agent_bypass_powershell._DEPTH))
        return found
    if not _may_name_a_program(command):
        return None
    posix, posix_whole = _tokens(command, False)
    if shell == POSIX:
        return _first(_segments(posix), True, True)
    powershell, powershell_whole = _tokens(command, True)
    readings = [(False, posix)]
    if powershell_whole or not posix_whole:
        readings.append((True, powershell))
    for backtick, tokens in readings:
        found = _first(_segments(tokens), not backtick, False)
        if found is not None:
            return found
    return None
