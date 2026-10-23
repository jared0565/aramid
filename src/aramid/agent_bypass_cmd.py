"""agent_bypass_cmd -- a string handed to `cmd /c`, read by cmd's rules (FN-55).

The measurements: FN-55 in docs/superpowers/plans/2026-09-21-aramid-1.0-blockers.md,
and three records made with the real cmd.exe and real git: tests/fixtures/cmd-argv.json
(a text given to cmd, and every git it started), cmd-line.json (the command line
Git Bash and PowerShell build for a program named cmd) and cmd-switch.json (which
command line makes cmd run a string at all).

`cmd /c "git commit -n"` hands cmd a string to run. Three readings stand between
that string and the argv git is handed, and each is done here:

  `command_line`   the outer shell builds ONE command line for cmd from the words of
                   its command, by its own rules for quoting (Git Bash and PowerShell
                   differ, and neither joins the words with a space);
  `string_to_run`  cmd scans that line for a switch -- `/c`, `/k` or `/r` -- and runs
                   what follows it;
  `commands`       cmd reads the string once itself (quotes, carets, `&` `&&` `||` `|`,
                   parentheses, redirections, `rem`), and starts each command with
                   what is left; the program reads that a second time, and for git
                   that is the C runtime's rules for a command line.

`commands` hands back each command as the words git would be handed, and
`agent_bypass` judges them with the same flag rules as ever.

Every rule here was read off the real cmd.exe, not written from memory.

Pure stdlib, no aramid imports, no I/O, and it cannot raise: it runs inside the
agent hook, which fails open, so a raise here would let a command through unread.
A call imports it only when a command hands cmd a string (or is cmd's own), or
starts a program with Start-Process, whose line `_argv` reads (FN-55 0110f7).

WHAT IS NOT KNOWN HERE. cmd expands `%VAR%` (and `!VAR!` when delayed expansion
is on) before it reads the line, so a name put together from variables
(`g%PATH:~0,0%it`, `set X=git && call %X%`) is out of reach, as is a command piped
into cmd on standard input. After `if` and `do` cmd skips a `;`, `,`, `=` or `@`
in front of the command; here that is done at the start of a command and right
after a first word `call` or `start` (those take no `@`), not after the condition
of an `if`, the `do` of a `for`, a second `call` or the options of a `start`.
A label there swallows the rest of the line as it does at the start of a
command; here only the start is seen. `for /f` runs the command in its
parentheses; they are text here. cmd reads the
command on the right of a pipe a second time when it is a group, so a caret in
it is gone twice; here once. It reads the arguments of a `call` a second time
too, so that `call git status ^& git commit -n` fails; here it is read once.
cmd runs one branch of an `if`, and both are read, as is a command that a `&&` or
a `||` may skip. The program's name ends at a
`,`, `;` or `=` (`git,commit,-n` runs git with `,commit,-n`); here it does not,
which changes no answer: that is no subcommand. And a line cmd refuses (a lone
`&` or `)` in front, an unclosed group, a redirection with no target) is read all
the same, as is any word named git, wherever it stands.

Git Bash makes a lone `/c` a path (`C:/`), and then cmd runs nothing; it is read
as the switch all the same, as the PowerShell reader reads `pwsh /c`. Windows
PowerShell 5.1 builds the line like PowerShell 7 but for the backslashes at the end
of a quoted word, which 7 doubles and 5.1 leaves; the reader does as 7 does.

A NUL ENDS THE LINE. A program is started with one line of text, which stops at a
NUL, so `commands` reads as far as one. A line ends at a newline too, outside
quotes or in them, and a caret in front of it does not continue the line; the
lines in front of the first one with something on it are empty.
"""
from __future__ import annotations

# How an outer shell builds the command line it hands a program named cmd.
MSYS = "msys"               # Git Bash
POWERSHELL = "powershell"   # PowerShell, which builds the line the same way for cmd.exe

# Characters that cmd skips in front of a command, and after `call` or `start`
# (where `@` is a word).
_LEAD = " \t,;=@"
_CALL_LEAD = " \t,;="
_CALLS = ("call", "start")
# Characters that end the first word of a command.
_FIRST_ENDS = " \t,;=&|<>("
# The words after which a `(` starts a group.
_OPENS = ("if", "for", "else", "do")
_DIGITS = "0123456789"
# Characters .NET does not call white space, though str.isspace does.
_NOT_BLANK = "\x1c\x1d\x1e\x1f"


def command_line(args: list[str], style: str) -> str:
    """The command line an outer shell builds for a program named cmd from the
    words after its name. `style` is MSYS or POWERSHELL (what builds a line for a
    program that cmd runs from cmd, the words of a `commands` command, is the
    PowerShell way too)."""
    word = _msys_word if style == MSYS else _legacy_word
    return " ".join(word(arg) for arg in args)


def _msys_word(arg: str) -> str:
    """A word as Git Bash puts it on a command line: a `//c` is turned into `/c`
    and a `///c` into `//c`, but a `//c//c` or a `//a/b` is left whole (Git Bash
    also leaves a `//` that a `*`, `:`, `?`, `[`, `]`, `~`, backtick or backslash
    follows, and none of those is a switch). A word with a space, a tab, a
    newline, a quote or nothing in it is wrapped in quotes, and in that a quote
    is written `\\"` and the backslashes in front of it, or of the closing quote,
    are doubled."""
    if arg[:3] == "///" or (arg[:2] == "//" and arg.count("/") == 2):
        arg = arg[1:]
    if arg and not any(ch in arg for ch in ' \t\n\r"'):
        return arg
    out: list[str] = []
    slashes = 0
    for ch in arg:
        if ch == "\\":
            slashes += 1
            continue
        out.append("\\" * (slashes * 2 + 1) if ch == '"' else "\\" * slashes)
        out.append(ch)
        slashes = 0
    out.append("\\" * (slashes * 2))
    return '"' + "".join(out) + '"'


def _legacy_word(arg: str) -> str:
    """A word as PowerShell puts it on a command line for cmd.exe: wrapped in
    quotes when it has white space outside balanced quotes, and then with the
    backslashes at its end doubled. A quote inside it is left as it is, and an
    empty word stays empty."""
    quotes = 0
    after_slash = False
    wrap = False
    for ch in arg:
        if ch == '"' and not after_slash:
            quotes += 1
        elif ch.isspace() and ch not in _NOT_BLANK and quotes % 2 == 0:
            wrap = True
        after_slash = ch == "\\"
    if not wrap:
        return arg
    return '"' + arg + "\\" * (len(arg) - len(arg.rstrip("\\"))) + '"'


def string_to_run(line: str) -> str | None:
    """The string cmd runs for the command line `line` (what follows its
    name), or None when it runs none. cmd looks at each `/` in turn, in or out
    of quotes and in any word: a `c`, `k` or `r` after it, in any case, is the
    switch and what follows it is the string; any other character is stepped
    over with the slash. So `/d/c x` and `foo/c x` run `x` and `//c x`, `-c x`
    and `/dc x` run nothing."""
    i, n = 0, len(line)
    while i < n:
        if line[i] != "/":
            i += 1
        elif line[i + 1:i + 2].lower() in ("c", "k", "r"):
            return line[i + 2:]
        else:
            i += 2
    return None


def commands(text: str) -> list[list[str]]:
    """The commands cmd runs for the string `text`, each as the words its
    program is handed, none of them empty."""
    return [words for words in (_argv(command) for command in _split(_line(text))) if words]


def _line(text: str) -> str:
    """The line cmd runs: the first with anything on it, as far as a NUL and
    without its CRs, and with a leading quote and the last one taken off (cmd's
    rule for a string that starts with one, which the record shows is the one
    that applies whenever a quoted program is named by a path with a space in it
    or not)."""
    text = text.partition("\0")[0].replace("\r", "")
    for row in text.split("\n"):
        if row.strip(" \t"):
            row = row.lstrip(" \t")
            if row[0] != '"':
                return row
            row = row[1:]
            last = row.rfind('"')
            return row if last < 0 else row[:last] + row[last + 1:]
    return ""


def _split(line: str) -> list[str]:
    """The commands of `line` as cmd's own reading leaves them, for the program to
    read: carets and the redirections gone, quotes kept. A quote opens and
    closes a stretch in which nothing is special. Outside one, a caret makes the
    next character plain, `&` `&&` `||` and `|` end the command, `<` and `>`
    take themselves and the word after them out of it, and a `(` that starts a
    command (or a word after `if`, `for`, `else` or `do`) opens a group, which a
    `)` closes while one is open. Leading `,` `;` `=` `@` and blanks are
    skipped (after `call` and `start`, all but the `@`), and a command whose
    first word is `rem`, or a label, swallows the rest of the line."""
    out: list[str] = []
    cur: list[str] = []
    quote = False       # inside a pair of quotes
    depth = 0           # groups open
    first = False       # the first word of the command has ended and been looked at
    head = ""           # that word, as cmd compares it with a keyword
    calling = False     # that word was `call` or `start`: the next may start with junk
    led = False         # the command began with a redirection, so is no label
    cond = False        # the command follows a `&&` or a `||`, so is no label
    i, n = 0, len(line)

    def end() -> None:
        nonlocal first, head, calling, led, cond
        if cur:
            out.append("".join(cur))
            cur.clear()
        first = calling = led = cond = False
        head = ""

    while i < n:
        ch = line[i]
        i += 1
        if quote:
            cur.append(ch)
            quote = ch != '"'
            continue
        if ch == "^":
            if i < n:
                cur.append(line[i])
                i += 1
                calling = False
            continue
        if ch == '"':
            cur.append(ch)
            quote = True
            calling = False
            continue
        if not first and cur and (ch in _FIRST_ENDS or (ch == ")" and depth > 0)):
            first = True
            head = _word(cur)
            if _swallows(head, led or cond):
                return out
            calling = head in _CALLS
            if calling:
                cur.append(" ")
        if ch in (_CALL_LEAD if calling else _LEAD if not cur else ""):
            continue
        if ch in "&|":
            doubled = line[i:i + 1] == ch
            i += doubled
            end()
            cond = doubled
        elif ch in "<>":
            _drop_digit(cur)
            if not cur:
                first = False
                led = True
            i = _after_redirect(line, i, depth)
        elif ch == "(" and (not cur or (cur[-1] in " \t" and head in _OPENS)):
            end()
            depth += 1
        elif ch == ")" and depth > 0:
            end()
            depth -= 1
        else:
            cur.append(ch)
            calling = False
    if not first and cur and _swallows(_word(cur), led or cond):
        cur.clear()     # a quote can keep the first word open to the end of the line
    end()
    return out


def _word(cur: list[str]) -> str:
    """The first word of a command, as cmd compares it with a keyword: in lower
    case and without its quotes."""
    return "".join(cur).replace('"', "").lower()


def _swallows(word: str, no_label: bool) -> bool:
    """Whether the first word of a command makes the rest of the line a comment:
    `rem`, or a label (`:x`, `::`) where one can stand: not after a redirection
    that came first, and not after a `&&` or a `||`."""
    return word == "rem" or (word.startswith(":") and not no_label)


def _drop_digit(cur: list[str]) -> None:
    """Take off the end of `cur` the one digit that stands alone in front of a
    redirection (`2>nul`): the handle it names is part of the redirection, but
    `-n2>nul`, `a1>nul` and `12>nul` keep theirs."""
    if cur and cur[-1] in _DIGITS and (len(cur) == 1 or cur[-2] in " \t"):
        cur.pop()


def _after_redirect(line: str, j: int, depth: int) -> int:
    """The index in `line` after the redirection whose operator (a `<` or `>`)
    ends just before line[j]: the `&` of a duplicated handle, and the word it
    names, quoted or not. A word ends at a blank or at `&` `|` `<` `>`, and at a
    `)` while a group is open, so a `>>` is two redirections, the first of them
    with no word.

    `j` is always from 1 to len(line) when `_split` calls this; a negative one
    reads as 0 all the same, because the hook fails open and a reader that raised
    would let the call through (FN-55; the drain's fuzzer calls it directly)."""
    n = len(line)
    j = max(j, 0)
    if line[j:j + 1] == "&":
        j += 1
    while j < n and line[j] in " \t":
        j += 1
    quote = False
    while j < n:
        ch = line[j]
        if ch == '"':
            quote = not quote
        elif not quote:
            if ch in " \t&|<>" or (ch == ")" and depth > 0):
                break
            if ch == "^":
                j += 1
        j += 1
    return min(j, n)


def _argv(command: str) -> list[str]:
    """The words a program started with the line `command` is handed, by the
    rules of the C runtime git for Windows is built with: white space ends a word
    outside quotes; a quote opens or closes a stretch and is not part of the
    word, but a quote inside one that is followed by another is written, and
    ends it; backslashes count only in front of a quote, where each pair is
    one and an odd one makes the quote itself plain."""
    words: list[str] = []
    i, n = 0, len(command)
    while True:
        while i < n and command[i] in " \t":
            i += 1
        if i >= n:
            break
        word: list[str] = []
        quote = False
        while True:
            slashes = 0
            while i < n and command[i] == "\\":
                slashes += 1
                i += 1
            keep = True
            if i < n and command[i] == '"':
                if slashes % 2 == 0:
                    if quote and command[i + 1:i + 2] == '"':
                        i += 1
                    else:
                        keep = False
                    quote = not quote
                slashes //= 2
            word.append("\\" * slashes)
            if i >= n or (not quote and command[i] in " \t"):
                break
            if keep:
                word.append(command[i])
            i += 1
        words.append("".join(word))
    return words
