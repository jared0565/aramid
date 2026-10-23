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

A STRING HANDED TO ANOTHER SHELL (FN-55). `bash -c "git commit -n"` hands
bash a string to run, `pwsh -c` hands PowerShell one, and `cmd /c` hands cmd
one. Such a string is read by the rules of the shell it is handed to, as a
command of its own (`_handed`), through as many as _HANDED_DEPTH shells within
shells; one more is refused. What reached git is in
tests/fixtures/handed-argv.json, from real shells and real git. The POSIX sh
family (bash, sh, zsh, dash, ksh, mksh, ash, yash, posh), PowerShell (pwsh,
powershell) and cmd are read; dash is the family's measured proof and the rest
share its `-c` grammar. cmd's string is read by `agent_bypass_cmd` (CMD, a
shell no tool call is): the words after `cmd` are put on one command line the
way the shell that runs them puts them, cmd runs the string after its `/c`,
`/k` or `/r`, and reads it by its own rules and then git's (`_cmd_string`,
and the three records tests/fixtures/cmd-*.json). A command fed to
such a shell on standard input is read too (`_from_stdin`, FN-55 fb16940): a
here-string (`bash <<< 'git commit -n'`) and the literal echoed or printed
into a POSIX pipe (`echo 'git commit -n' | bash`, `... | pwsh -`). A PowerShell
CALL pipes stdin the same way (`_from_stdin_powershell`): a bare quoted string
(`'git commit -n' | bash`) or an `echo`/`Write-Output` of one, into a shell
that reads stdin -- a POSIX shell with no `-c`/script, `pwsh -`, or
`pwsh -Command -`/`-c -`/`-File -`; the call operator keeps the pipe
(`'git commit -n' | & bash`). Not read: a command piped into `cmd` (cmd is
not a shell `_shell_launched` names, whose standard input is read by the POSIX
or the PowerShell grammar), a name cmd puts together from `%VAR%`, an
encoded command (`-EncodedCommand`), a `fish -c` string (fish's option grammar
is its own), a command handed through `su`, `script` or `flock -c`, a here-DOC
body or a non-echo/printf pipe upstream (`cat f | bash`), a PowerShell pipe
upstream that is unquoted (a command PowerShell RUNS) or more than one word (an
`echo` of several arguments lands one per line), a stdin handoff nested in a
group, and the arguments a string is given when it runs
(`bash -c 'git commit "$@"' x -n`).

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
was not named is read by the POSIX rule. bash's `$'...'` is read as bash
makes it (`_ansi_c`; FN-55 43dd71), but not its locale quoting, `$"..."`,
nor a heredoc body: its lines are read as commands. And a command that is built when it runs
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


# The shells `find_bypass` can be told a command is for. CMD is for the string
# a command hands cmd.exe (FN-55), which is read by cmd's rules: no tool call
# is cmd's own.
POSIX = "posix"
POWERSHELL = "powershell"
CMD = "cmd"
# How many times a command may hand a string to another shell, within the
# strings it hands, before the call is refused (FN-55).
_HANDED_DEPTH = 8
# What the POSIX reading takes out of a word on its way to being a program's
# name: the quotes, the backslash, and a line end (a backslash in front of one
# joins two lines). For `_may_name_a_program`.
_MARKS = {ord(ch): None for ch in "'\"\\\r\n"}
# bash's ANSI-C quoting, `$'...'`, as Git Bash 5.2.37 was measured (FN-55
# 43dd71; tests/unit/test_agent_bypass_shell.py): the escapes that are one
# character, and how many hex digits `\x`, `\u` and `\U` take at most.
_ANSI_C_LETTERS = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n",
                   "r": "\r", "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}
_ANSI_C_HEX = {"x": 2, "u": 4, "U": 8}
_HEX_DIGITS = "0123456789abcdefABCDEF"
_OCTAL_DIGITS = "01234567"


@dataclass(frozen=True)
class Bypass:
    kind: str        # "no-verify" | "hooks-path" | "no-red-proof" | "too-deep"
    subcommand: str  # "commit" | "push" | "ledger resolve"; for "too-deep", "" or "shells"
    token: str       # the exact matched token / -c value, for messages


def _ansi_c(command: str, i: int) -> tuple[str, int] | None:
    """What bash makes of the `$'...'` that starts at command[i], and the
    index just past its closing quote; None if it never closes, or there is
    no `$'` at `i`. Inside, a backslash escapes the next character, a quote
    as well; what the escapes make is `_ansi_c_body`'s."""
    if not (0 <= i < len(command) and command.startswith("$'", i)):
        return None
    j = i + 2
    while j < len(command):
        if command[j] == "'":
            return _ansi_c_body(command[i + 2:j]), j + 1
        j += 2 if command[j] == "\\" else 1
    return None


def _ansi_c_body(body: str) -> str:
    """The text bash makes of what is inside a `$'...'`. The one-character
    escapes are `_ANSI_C_LETTERS`. `\\nnn` takes one to three octal digits,
    kept to a byte (`\\455` is `-`). `\\x`, `\\u` and `\\U` take up to two,
    four and eight hex digits, and with none are kept as written, as is an
    escape bash does not know (`\\z`). `\\cX` is the control character of X:
    `\\c?` is DEL, `\\c\\\\` takes both backslashes, and a `\\c` at the end is
    kept. A character that comes to 0 ends the text, whatever follows it.
    Up to 0xFF a value is that character, as Git Bash's bash makes it; a
    `\\u` or `\\U` above that is written back as bash writes it (`\\uD800`,
    `\\U0001F600`), and from 0x80000000 up is nothing. No name or flag is
    spelled past ASCII. This walk cannot raise."""
    out: list[str] = []
    k, n = 0, len(body)
    while k < n:
        ch = body[k]
        if ch != "\\" or k + 1 >= n:
            out.append(ch)
            k += 1
            continue
        kind = body[k + 1]
        if kind in _ANSI_C_LETTERS:
            out.append(_ANSI_C_LETTERS[kind])
            k += 2
            continue
        if kind in _OCTAL_DIGITS:
            m = k + 2
            while m < min(k + 4, n) and body[m] in _OCTAL_DIGITS:
                m += 1
            value = int(body[k + 1:m], 8) & 0xFF
        elif kind in _ANSI_C_HEX:
            m = k + 2
            while m < min(k + 2 + _ANSI_C_HEX[kind], n) and body[m] in _HEX_DIGITS:
                m += 1
            if m == k + 2:
                out.append(body[k:m])       # no digit: kept as written
                k = m
                continue
            value = int(body[k + 2:m], 16)
        elif kind == "c" and k + 2 < n:
            x = body[k + 2]
            m = k + 4 if x == "\\" and body[k + 3:k + 4] == "\\" else k + 3
            value = 0x7F if x == "?" else ord(x.upper() if "a" <= x <= "z" else x) & 0x1F
        else:
            out.append(body[k:k + 2])
            k += 2
            continue
        k = m
        if value == 0:
            break
        if value < 0x100:
            out.append(chr(value))
        elif value < 0x80000000:
            out.append(f"\\u{value:04X}" if value <= 0xFFFF else f"\\U{value:08X}")
    return "".join(out)


def _shell_text(command: str, backtick: bool, ansi_c: bool = False) -> str:
    """`command` as the lexer is to read it: comments taken out, continued
    lines joined, the number in front of a redirection dropped, and every
    quoted or escaped operator character replaced by its stand-in. Quotes
    and escapes stay where they are, for shlex to read.

    `backtick` picks the reading of a backtick inside double quotes: True
    for PowerShell's, where it escapes the next character and a quote after
    it does not end the string; False for a character like any other.

    `ansi_c` is for bash's text: a `$'...'` there is handed over as the text
    bash makes of it (`_ansi_c`), each character escaped, and one that never
    closes ends the text, so the lexer stops at it as at any open quote.

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
        if ansi_c and ch == "$" and command.startswith("'", i + 1):
            made = _ansi_c(command, i)
            if made is None:
                out.append("$'")    # it never closes: the lexer stops here
                break
            text, i = made
            out.append("''" + "".join("\\" + c.translate(_STAND_IN) for c in text))
            fresh = False
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


def _tokens(command: str, backtick: bool, ansi_c: bool = False) -> tuple[list[str], bool]:
    """The words and operators of `command` as far as it can be read, and
    whether that was to its end. A quote that never closes (or a backslash
    with nothing after it) stops the lexer; the tokens before it are
    returned and the word it stopped in is not. They still count: bash has
    run every line before the one with the open quote by the time it finds
    it, and what does not pair up by the POSIX rule may pair up in the shell
    that runs it (a heredoc body, a PowerShell string that ends in a
    backslash). What follows the open quote is not read: for the git rules a
    flag there is missed, for the close rule a `--red-proof` there does not
    count. `ansi_c` reads bash's `$'...'` (`_shell_text`): for a command
    bash reads, not for the line a started program is handed, whose quotes
    are the runtime's."""
    lex = shlex.shlex(_shell_text(command, backtick, ansi_c), posix=True,
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


# The shells a command can hand a string to run (FN-55), by the program's
# name under any directory, with `.exe` or without and in any case: Windows
# finds `BASH` as well as `bash`. zsh is read as sh is; it was not measured.
# dash, ksh, mksh, ash, yash and posh share bash's `-c` grammar (FN-55
# 2fe1a4); only dash was measured on the recording machine (it is /bin/sh on
# most Linux), the rest are the same sh family. `ash` also catches
# `busybox ash -c` once the decoy scan (_handed) steps past busybox.
# RESIDUALS, documented, not here: fish has its own option grammar (`fish -c`
# takes the string but reads switches differently); and su/script/flock `-c`
# hand a command to a shell by a different route. Read as git's argv is: a
# string these run is not reached.
_POSIX_SHELLS = ("bash", "sh", "zsh", "dash", "ksh", "mksh", "ash", "yash", "posh")
_POWERSHELLS = ("pwsh", "powershell")
# PowerShell's switches that take the word after them as their value: by
# their whole names, of which a start of three letters or more is the switch,
# and by their short names. A switch not known here is taken to have none.
_PS_VALUES = ("executionpolicy", "workingdirectory", "inputformat", "outputformat",
              "windowstyle", "configurationname", "configurationfile", "custompipename",
              "settingsfile", "version", "psconsolefile", "encodedarguments")
_PS_SHORT_VALUES = ("ep", "ex", "wd", "if", "of", "o", "w", "v", "ea")
# What pwsh and Windows PowerShell take for the dash of one of their own
# switches: `-`, the en dash, the em dash and the horizontal bar, as well as a
# `/` (tests/fixtures/handed-argv.json; FN-55 1a03cd).
_PS_DASHES = "-–—―"


def _ps_switch(word: str) -> str:
    """The name, in lower case, of the switch `word` is to pwsh or powershell,
    asked of a word that starts with a dash of `_PS_DASHES` or a `/`: the word
    less that first character and a second of the same kind (`--Command`,
    `––Command`, `//c`). A name left starting with a dash or a `/` names no
    switch: pwsh ran nothing for `---Command`, `/-c` or `–-Command` (measured)."""
    rest = word[1:]
    return (rest[1:] if rest[:1] == word[:1] else rest).lower()


def _program(token: str) -> str:
    """The name of the program `token` starts: its last path part, in lower
    case, without `.exe`."""
    return token.replace("\\", "/").rpartition("/")[2].lower().removesuffix(".exe")


def _posix_string(seg: list[str], start: int) -> str | None:
    """The string the POSIX shell at seg[start] is handed to run, or None.
    As bash was measured (tests/fixtures/handed-argv.json): its options run
    up to the first word that is none, or to a `--` or `-`; a `c` among an
    option's letters, after `-` or `+` (`-c`, `-lc`, `+c`), makes that first
    word the command; a `+` alone is an option of no letters; `-o`, `-O`
    (with `+` as well), `--rcfile` and `--init-file` take the word after
    them. The words after the string are `$0`, `$1` ...: arguments, not
    commands. While the options are still being read a word that starts with
    `$` may be nothing (an empty `$var`) and is stepped over; but once a `c`
    has been seen the next word is the command, read even if it starts with
    `$` -- a quoted `'$(...)'` the shell runs, which shlex cannot tell from an
    empty `$var` (FN-55 b90d61).

    `start` is always a valid index into a non-empty `seg` from the public
    path (`_handed`'s enumerate); guarded all the same because the hook fails
    open, so a reader that raised would let the call through (FN-55 e660af)."""
    if not 0 <= start < len(seg):
        return None
    i, command = start + 1, False
    while i < len(seg):
        word = seg[i]
        if word in ("--", "-"):
            i += 1
            break
        if word.startswith("--"):
            i += 2 if word in ("--rcfile", "--init-file") else 1
            continue
        if word[:1] in ("-", "+"):
            command = command or "c" in word[1:]
            i += 1 + sum(ch in "oO" for ch in word[1:])
            continue
        if word.startswith("$") and not command:
            i += 1
            continue
        break
    return seg[i] if command and i < len(seg) else None


def _powershell_string(seg: list[str], start: int) -> str | None:
    """The command the PowerShell at seg[start] is handed, or None. As it was
    measured (tests/fixtures/handed-argv.json): a switch starts with `-`,
    `--` or `/`, or with an en dash, an em dash or a horizontal bar, one or two
    of a kind (`_ps_switch`), in any case, and any start of `command` is the command
    switch (`-c`, `-co`, `-Command`); the words after it, joined with a
    space, are the command, and so is the word after `-cwa` or
    `-CommandWithArgs` (a shorter start of that name is no switch). A first
    word that is no switch is a script to pwsh and the command to Windows
    PowerShell. `-File` takes a script, and `-EncodedCommand` (`-e`, `-ec`)
    a command this reading does not decode. A word that starts with `$` may be
    an empty `$var` in front of a pwsh's options and is stepped over; but
    Windows PowerShell takes its first word as the command, `$` and all, so a
    `$` word is read there rather than skipped (FN-55 b90d61).

    Guarded against an out-of-range `start` like _posix_string, and for the
    same reason: the public path never passes one, but the hook fails open so
    a raise here would be a silent bypass (FN-55 c7d64c)."""
    if not 0 <= start < len(seg):
        return None
    windows = _program(seg[start]) == "powershell"
    i = start + 1
    while i < len(seg):
        word = seg[i]
        if word.startswith("$") and not windows:
            i += 1
            continue
        if word[:1] not in _PS_DASHES and word[:1] != "/":
            return " ".join(seg[i:]) if windows else None
        name = _ps_switch(word)
        if not name:
            i += 1      # a dash alone: `-` is standard input (_reads_stdin_powershell)
            continue
        if "command".startswith(name):
            return " ".join(seg[i + 1:])
        if name in ("cwa", "commandwithargs"):
            return seg[i + 1] if i + 1 < len(seg) else None
        if "file".startswith(name) or name == "ec" or "encodedcommand".startswith(name):
            return None
        takes = name in _PS_SHORT_VALUES or (
            len(name) >= 3 and any(full.startswith(name) for full in _PS_VALUES))
        i += 2 if takes else 1
    return None


def _cmd_string(seg: list[str], start: int, outer: str) -> str | None:
    """The string the cmd at seg[start] is handed to run, or None. The words
    after it are not joined with a space: the shell `outer` that runs `seg`
    builds one command line from them, by its own rules (Git Bash and
    PowerShell differ, and cmd re-joins the words of a command it runs the
    PowerShell way), and cmd runs the string after the first `/c`, `/k` or
    `/r` switch it scans for in that line. See agent_bypass_cmd, and the
    records it names.

    Guarded against an out-of-range `start` like _posix_string, and for the
    same reason: the public path never passes one, but the hook fails open so
    a raise here would be a silent bypass. (A `start` past the end gives no
    words, so no string; only a negative one needs the guard.)"""
    if start < 0:
        return None
    from aramid import agent_bypass_cmd
    style = agent_bypass_cmd.MSYS if outer == POSIX else agent_bypass_cmd.POWERSHELL
    return agent_bypass_cmd.string_to_run(agent_bypass_cmd.command_line(seg[start + 1:], style))


def _handed(seg: list[str], outer: str):
    """Each string a shell launched in `seg` is handed to run, with the shell
    whose rules read it, in the order they appear. `outer` is the shell that
    runs `seg`: how it builds the command line for cmd (`_cmd_string`). More
    than one when a program launches several commands in one segment (`find
    ... -exec sh -c ... \\; -exec bash -c ... \\;`): a decoy shell earlier in
    the segment must not hide a real one after it (FN-55 2fe1a4). A shell
    handed no string yields nothing."""
    for i, tok in enumerate(seg):
        name = _program(tok)
        if name in _POSIX_SHELLS:
            text, shell = _posix_string(seg, i), POSIX
        elif name in _POWERSHELLS:
            text, shell = _powershell_string(seg, i), POWERSHELL
        elif name == "cmd":
            text, shell = _cmd_string(seg, i, outer), CMD
        else:
            continue
        if text is not None:
            yield text, shell


def _from_handed(segments: list[list[str]], depth: int, outer: str) -> Bypass | None:
    """The first match in a string a command in `segments` hands a shell,
    read by that shell's rules; `outer` is the shell that runs `segments`.
    Every shell handed a string in a segment is read, not just the first, so
    a decoy cannot hide a later one (FN-55 2fe1a4). `depth` counts the shells
    handed a string on the way here: past _HANDED_DEPTH the call is refused,
    as it is past the PowerShell reader's own cap -- no real command hands a
    string on that often, and a reading without a cap could go deep enough to
    raise."""
    for seg in segments:
        for text, shell in _handed(seg, outer):
            if depth >= _HANDED_DEPTH:
                return Bypass("too-deep", "shells", str(_HANDED_DEPTH))
            found = find_bypass(text, shell, _depth=depth + 1)
            if found is not None:
                return found
    return None


# A program whose last literal argument is what it writes to standard output,
# so a shell on the other end of a pipe runs it (FN-55 fb16940). echo's own
# flags are stripped; a printf with a format and arguments is read whole (the
# join still holds the literal, read toward detection), its exactness a
# residual.
_ECHOERS = ("echo", "printf")
_ECHO_FLAGS = ("-n", "-e", "-E", "-ne", "-nE", "-en", "-En")


def _simple_commands(tokens: list[str]) -> list[dict]:
    """The simple commands of `tokens`, each `{words, prev_op, here}`: the
    words (with redirect targets removed as `_segments` removes them), the
    operator just before the command (`''` for the first), and a here-string
    (`<<<`) target if one was redirected into it. Unlike `_segments` the here
    target and the connecting operator are KEPT, because for a shell fed on
    standard input they are the command. `( )` are read as separators (a stdin
    handoff nested in a group is a residual)."""
    out: list[dict] = []
    words: list[str] = []
    prev_op, here = "", None
    target = False      # the next word is a (non-here) redirect target: dropped
    here_next = False   # the next word is the here-string target
    for tok in tokens:
        if not (tok and all(ch in _PUNCT for ch in tok)):
            if here_next:
                here, here_next = tok.translate(_PUT_BACK), False
            elif not target:
                words.append(tok.translate(_PUT_BACK))
            target = False
            continue
        for op in _operators(tok):
            if op == "<<<":
                here_next, target = True, False
                continue
            # `<<` is a here-doc: the word after it is the DELIMITER, not the
            # command (the body is on later lines). Read as a plain redirect --
            # its delimiter dropped -- and the here-doc body left to `_first`
            # on the lines it becomes. A here-doc fed command is a residual.
            if op in _REDIRECTS:
                target = True
                continue
            if op in _SUBSTITUTIONS:
                target = False
                continue
            target = False
            if op in (";", "|", "&", "(", ")", "\n"):
                # `||` and `&&` are ONE operator, not a pipe: the second `|`/`&`
                # closes an empty command, and a lone `|` would otherwise make
                # the shell after it look fed on stdin (`echo x || bash` is not
                # a pipe -- bash gets nothing -- so it must not be read as one).
                if op in ("|", "&") and prev_op == op and not words and here is None:
                    prev_op = prev_op + op
                    continue
                out.append({"words": words, "prev_op": prev_op, "here": here})
                words, prev_op, here = [], op, None
    out.append({"words": words, "prev_op": prev_op, "here": here})
    return [c for c in out if c["words"] or c["here"] is not None]


def _shell_launched(words: list[str]) -> tuple[int | None, str | None]:
    """(index, the shell's rules) of the first shell `words` launches, or
    (None, None)."""
    for i, tok in enumerate(words):
        name = _program(tok)
        if name in _POSIX_SHELLS:
            return i, POSIX
        if name in _POWERSHELLS:
            return i, POWERSHELL
    return None, None


def _reads_stdin_posix(words: list[str], start: int) -> bool:
    """The POSIX shell at words[start] reads its COMMANDS from standard input:
    no `-c` string and no script file (`bash`, `bash -s`, `bash -` do;
    `bash -c x` and `bash script.sh` do not). The option walk is _posix_string's.
    `start` is guarded as there: the hook fails open, so a reader that raised
    would let the call through."""
    if not 0 <= start < len(words):
        return False
    i = start + 1
    while i < len(words):
        word = words[i]
        if word == "-":
            return True
        if word == "--":
            return i + 1 >= len(words)   # a script after `--` is not stdin
        if word.startswith("--"):
            i += 2 if word in ("--rcfile", "--init-file") else 1
            continue
        if word[:1] in ("-", "+"):
            if "c" in word[1:]:
                return False             # -c: a string, read by _handed
            i += 1 + sum(ch in "oO" for ch in word[1:])
            continue
        if word.startswith("$"):
            i += 1
            continue
        return False                     # a non-option word: a script file
    return True


def _reads_stdin_powershell(words: list[str], start: int) -> bool:
    """pwsh/powershell at words[start] reads its command from standard input:
    a lone `-` reached before any command switch, OR the value of its
    command/script switch is itself a lone `-` (`pwsh -Command -`, `-c -`,
    `-File -` all read the command from stdin). A `-Command`/`-File` with any
    other value is a string or a script file, read by `_handed`, not stdin.
    A switch may be written with any dash of `_PS_DASHES` (`–Command -`), but
    only a lone `-` is standard input: pwsh read none for a lone `--`, `/` or
    en dash (measured). `start` is guarded as in `_posix_string`."""
    if not 0 <= start < len(words):
        return False
    i = start + 1
    while i < len(words):
        word = words[i]
        if word == "-":
            return True                  # `-` alone: the command is on stdin
        if word[:1] in _PS_DASHES or word[:1] == "/":
            name = _ps_switch(word)
            if (name and ("command".startswith(name) or "file".startswith(name))):
                # a value-taking switch: stdin only when its value is `-`
                return i + 1 < len(words) and words[i + 1] == "-"
        i += 1
    return False


def _echoed(words: list[str]) -> str | None:
    """The command an `echo` or `printf` writes to its stdout, for a shell on
    the far end of a pipe, or None if `words` is not a bare echo/printf of a
    literal. echo's flags are dropped; the arguments are joined as echo joins
    them."""
    if not words or _program(words[0]) not in _ECHOERS:
        return None
    args = list(words[1:])
    if _program(words[0]) == "echo":
        while args and args[0] in _ECHO_FLAGS:
            args = args[1:]
    return " ".join(args) if args else None


def _from_stdin(tokens: list[str], depth: int) -> Bypass | None:
    """A match in a command a shell is fed on standard input (FN-55 fb16940),
    read by the receiving shell's rules: a here-string target
    (`bash <<< 'git commit -n'`), or the literal echoed or printed into a pipe
    (`echo 'git commit -n' | bash`, `... | pwsh -`). `depth` as in
    `_from_handed`: a command on stdin is one more shell handed a string."""
    cmds = _simple_commands(tokens)
    for idx, cmd in enumerate(cmds):
        start, shell = _shell_launched(cmd["words"])
        if start is None:
            continue
        reads = (_reads_stdin_posix(cmd["words"], start) if shell == POSIX
                 else _reads_stdin_powershell(cmd["words"], start))
        if not reads:
            continue
        if cmd["here"] is not None:
            text = cmd["here"]
        elif cmd["prev_op"] == "|" and idx > 0:
            text = _echoed(cmds[idx - 1]["words"])
        else:
            text = None
        if text is None:
            continue
        if depth >= _HANDED_DEPTH:
            return Bypass("too-deep", "shells", str(_HANDED_DEPTH))
        found = find_bypass(text, shell, _depth=depth + 1)
        if found is not None:
            return found
    return None


# PowerShell echo/Write-Output (the alias and the cmdlet, case-insensitive).
_PS_ECHOERS = ("echo", "write-output", "write")


def _ps_piped_text(upstream: dict) -> str | None:
    """The text a PowerShell pipe UPSTREAM writes to the next command's stdin:
    the one literal an `echo`/`Write-Output` emits, or a bare single quoted
    string that PowerShell sends down the pipeline (`'git commit -n' | bash`).
    A word PowerShell would RUN (unquoted, so a command/value) or more than one
    is not stdin text -- it is a documented residual, the safe-negative side.
    Multiple echo arguments each land on their own line (so joined they are not
    one command); that too is left a residual."""
    words, plains = upstream["words"], upstream["plains"]
    if words and words[0].lower() in _PS_ECHOERS:
        # echo/Write-Output of exactly ONE quoted literal argument
        if len(words) == 2 and len(plains) >= 2 and not plains[1]:
            return words[1]
        return None
    # a bare string expression emitted to the pipeline: one quoted word
    if len(words) == 1 and plains and not plains[0]:
        return words[0]
    return None


def _from_stdin_powershell(command: str, depth: int) -> Bypass | None:
    """A match in a command a shell is fed on standard input from a PowerShell
    pipeline (FN-55, the PowerShell half of fb16940): `'git commit -n' | bash`,
    `echo 'git commit -n' | bash`, `... | pwsh -`. The PowerShell tokenizer
    keeps each command's pipe `upstream`; a shell on the far end that reads its
    commands from stdin is handed the upstream's literal, read by that shell's
    rules. `depth` counts the shells handed a string, as `_from_handed`."""
    from aramid import agent_bypass_powershell
    cmds, _end = agent_bypass_powershell.simple_commands(command)
    for cmd in cmds:
        if cmd["upstream"] is None:
            continue
        start, shell = _shell_launched(cmd["words"])
        if start is None:
            continue
        reads = (_reads_stdin_posix(cmd["words"], start) if shell == POSIX
                 else _reads_stdin_powershell(cmd["words"], start))
        if not reads:
            continue
        text = _ps_piped_text(cmd["upstream"])
        if text is None:
            continue
        if depth >= _HANDED_DEPTH:
            return Bypass("too-deep", "shells", str(_HANDED_DEPTH))
        found = find_bypass(text, shell, _depth=depth + 1)
        if found is not None:
            return found
    return None


# Git Bash's runtime (msys), making the words of the line it is started with
# by a program that is not its own (`_msys_argv`): what ends a word, and what
# makes a word a pattern (`_msys_word`).
_MSYS_BLANKS = " \t\r\n"
_MSYS_PATTERN = "?*[\"'(){}"
_MSYS_DRIVES = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _msys_argv(line: str) -> list[str]:
    """The words Git Bash's runtime (msys) makes of the line a program that is
    not its own starts it with, as tests/fixtures/started-argv.json records
    them (git handed `"$@"`; FN-55). A blank outside quotes ends a word. A
    double or a single quote opens a quote wherever it stands, a backslash in
    front of it too (`\\'git commit -n'` is a quote, and bash runs it). A
    double quote is closed by the next one no backslash stands in front of,
    and `""` in it is a quote; a single quote by the next single quote. What
    the word is then made of is `_msys_word`'s."""
    out: list[str] = []
    n = len(line)
    i = 0
    while i < n:
        if line[i] in _MSYS_BLANKS:
            i += 1
            continue
        word: list[str] = []
        while i < n and line[i] not in _MSYS_BLANKS:
            ch = line[i]
            word.append(ch)
            i += 1
            if ch == "'":
                end = line.find("'", i) + 1 or n    # past the next one, or to the end
                word.append(line[i:end])
                i = max(end, i)                     # never back: the line bounds the walk
            elif ch == '"':
                while i < n:
                    ch = line[i]
                    if ch == "\\":
                        word.append(line[i:i + 2])
                        i += 2
                    elif ch == '"' and line[i + 1:i + 2] == '"':
                        word.append('\\"')      # a quote in the quote
                        i += 2
                    else:
                        word.append(ch)
                        i += 1
                        if ch == '"':
                            break
        out.append(_msys_word("".join(word)))
    return out


def _msys_word(word: str) -> str:
    """A word of `_msys_argv` as the program is handed it. A word with none
    of `?*["'(){}` in it and no `~` at its start is handed over as it stands,
    every backslash with it (`\\-c` is not `-c`). Any other is read as a
    pattern: in a quote, `\\\\` and a backslash in front of that quote are one
    character, and every other character, a backslash too, is itself; outside
    the quotes a backslash takes the character after it as it stands, unless
    the word starts with a drive (`C:`), where it is itself. Not modelled: what
    the runtime makes of a brace, of a pattern that matches a file, of a `~`,
    and of a word that starts with `@` (a file of arguments); the record holds
    `a\\x{` coming back `ax`."""
    if word[:1] != "~" and not any(ch in _MSYS_PATTERN for ch in word):
        return word
    drive = word[1:2] == ":" and word[:1] in _MSYS_DRIVES
    pattern: list[str] = []
    k, n = 0, len(word)
    while k < n:
        ch = word[k]
        k += 1
        if ch not in "\"'":
            pattern.append("\\\\" if drive and ch == "\\" else ch)
            continue
        while k < n and word[k] != ch:
            if word[k] == "\\" and word[k + 1:k + 2] in (ch, "\\"):
                k += 1
            pattern.append("\\" + word[k])
            k += 1
        k += 1                          # the quote that closes it
    text = "".join(pattern)
    out: list[str] = []
    k = 0
    while k < len(text):
        if text[k] == "\\" and k + 1 < len(text):
            k += 1                      # a backslash takes the next character
        out.append(text[k])
        k += 1
    return "".join(out)


def _from_started(command: str, depth: int) -> Bypass | None:
    """A match in a program a PowerShell command starts with Start-Process,
    `saps` or `start` (FN-55 0110f7, the operator's decision of 2026-10-23):
    the program is handed the one line Start-Process makes of its arguments
    (agent_bypass_powershell.started), and git reads it by the C runtime's
    rules (agent_bypass_cmd._argv), so it is judged as git's own words are. A
    shell started so is handed a string as `_from_handed` reads one: cmd runs
    what follows its switch on that line, pwsh and powershell read it by the
    C runtime's rules too, and a POSIX shell's line is read both as Git Bash's
    runtime makes its words (`_msys_argv`, measured word by word) and the
    POSIX way. The C runtime's reading of it decides none of the record's
    cases and is not asked (0f9de4b): Git Bash takes a single quote for a
    quote, as only the POSIX reading does, and a backslash outside quotes for
    itself, as neither does (`\\'git commit -n'` commits). Only Git Bash is
    measured, the bash PowerShell finds first here; WSL's is not.
    `depth` counts the shells handed a string, as `_from_handed`. No test of
    the text comes first: PowerShell makes the cmdlet's name out of more than
    one follows (`& "St`u{61}rt-Process" git 'commit -n'` commits; FN-55
    b996c0)."""
    from aramid import agent_bypass_powershell
    for program, line in agent_bypass_powershell.started(command):
        from aramid import agent_bypass_cmd
        line = line.partition("\0")[0]      # a NUL ends the line a program is started with
        argv = [program] + agent_bypass_cmd._argv(line)
        found = _first([argv], True, True)
        if found is not None:
            return found
        name = _program(program)
        if name == "cmd":
            strings = [(agent_bypass_cmd.string_to_run(line), CMD)]
        elif name in _POWERSHELLS:
            strings = [(_powershell_string(argv, 0), POWERSHELL)]
        elif name in _POSIX_SHELLS:
            strings = [(_posix_string([program] + _tokens(line, False)[0], 0), POSIX),
                       (_posix_string([program] + _msys_argv(line), 0), POSIX)]
        else:
            continue
        for text, shell in strings:
            if text is None:
                continue
            if depth >= _HANDED_DEPTH:
                return Bypass("too-deep", "shells", str(_HANDED_DEPTH))
            found = find_bypass(text, shell, _depth=depth + 1)
            if found is not None:
                return found
    return None


def _may_hand_a_string(command: str) -> bool:
    """Whether `command` can launch a shell that is handed a string, read the
    POSIX way: each of their names holds `sh`, or is `cmd`. Like
    `_may_name_a_program`, a wrong yes costs one reading; it is asked of a call
    whose own text need not spell git (`pwsh -c 'g`u{69}t commit -n'`,
    `cmd /c 'g^it commit -n'`)."""
    low = command.lower().translate(_MARKS)
    return "sh" in low or "cmd" in low


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

    A PowerShell call is never asked here: it is always read. PowerShell
    makes a name out of more than a cheap test can follow (`` `u{67}it ``,
    `& g$('i')t`, `& ("g" + "it")`), and a call cut off by the depth cap is
    refused without asking (`find_bypass`). With no shell named, a no from
    here leaves out the POSIX readings alone: what PowerShell hands, pipes
    and starts is read all the same (`saps "g`u{69}t" 'commit -n'` commits;
    FN-55 e623dc). Any `$'` is a yes: bash's ANSI-C quoting spells a name
    in escapes (`$'\\x67it'`; FN-55 43dd71)."""
    low = command.lower().translate(_MARKS)
    return "$'" in command or "git" in low or "aramid" in low


def find_bypass(command, shell: str | None = None, _depth: int = 0) -> Bypass | None:
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
    "too-deep", whatever it names: PowerShell runs what lies past the cap, no
    real command nests that deep, and a name can be built when the call runs
    (`& ("g" + "it")` is git), which no test of the text sees (the operator's
    decisions, 2026-10-13 and 2026-10-14). A bypass the reader did reach
    answers first.

    A string a command hands bash, sh or zsh with `-c`, or pwsh or
    powershell with `-Command`, or cmd with `/c`, is read by that shell's
    rules as a command of its own (FN-55, the operator's decision of
    2026-10-13), whichever shell runs the call and when none is named: then
    the call is taken apart, and cmd's line built, as each of POSIX and
    PowerShell would, and a command piped into a shell is read both ways too
    (FN-55 d57bcd). A string
    handed to cmd is read as `CMD`, which no tool call is: it is the shell
    named for that string alone, read by agent_bypass_cmd, for every rule.
    A program a PowerShell command starts with Start-Process is read as the
    line it is started with, and a shell started so as one handed a string,
    also when none is named (`_from_started`; FN-55 0110f7, the operator's
    decision of 2026-10-23).
    `_depth` counts the shells handed a string on the way to `command`; it is
    the reading's own.
    """
    if not isinstance(command, str):
        return None
    if shell == CMD:
        from aramid import agent_bypass_cmd
        done = agent_bypass_cmd.commands(command)
        return _first(done, True, False) or _from_handed(done, _depth, CMD)
    if shell == POWERSHELL:
        from aramid import agent_bypass_powershell
        done, end = agent_bypass_powershell.reading(command)
        found = (_first(done, True, True) or _from_handed(done, _depth, POWERSHELL)
                 or _from_stdin_powershell(command, _depth) or _from_started(command, _depth))
        if found is None and end == "deep":
            return Bypass("too-deep", "", str(agent_bypass_powershell._DEPTH))
        return found
    if not (_may_name_a_program(command) or _may_hand_a_string(command)):
        return None if shell == POSIX else _from_powershell(command, _depth)
    posix, posix_whole = _tokens(command, False, ansi_c=True)
    if shell == POSIX:
        segments = _segments(posix)
        return (_first(segments, True, True) or _from_handed(segments, _depth, POSIX)
                or _from_stdin(posix, _depth))
    powershell, powershell_whole = _tokens(command, True)
    readings = [(False, posix)]
    if powershell_whole or not posix_whole:
        readings.append((True, powershell))
    for backtick, tokens in readings:
        found = _first(_segments(tokens), not backtick, False)
        if found is not None:
            return found
    return (_from_handed(_segments(posix), _depth, POSIX) or _from_stdin(posix, _depth)
            or _from_powershell(command, _depth))


def _from_powershell(command: str, depth: int) -> Bypass | None:
    """What a call no shell is named for hands, pipes and starts, read the
    PowerShell way (FN-55 d57bcd, 0110f7), also when the cheap test said no
    (e623dc)."""
    from aramid import agent_bypass_powershell
    done, _end = agent_bypass_powershell.reading(command)
    return (_from_handed(done, depth, POWERSHELL) or _from_stdin_powershell(command, depth)
            or _from_started(command, depth))
