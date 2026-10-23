"""agent_bypass_powershell -- a command read by PowerShell's rules (FN-45).

The measurements: FN-45 in docs/superpowers/plans/2026-09-21-aramid-1.0-blockers.md,
and the record tests/fixtures/powershell-argv.json. (A spec,
`docs/superpowers/specs/2026-10-12-aramid-powershell-reading-design.md`, was
cited here and never committed.)

`agent_bypass` reads a command the way a POSIX shell cuts it up. PowerShell
cuts it up differently, and each difference was a way to get a flag past the
hook or to be answered for a proper command: a backslash escapes nothing
there, the backtick does, a quote is doubled, `<# #>` is a comment, a word
that starts with a quote ends with it. So a PowerShell tool call gets a
reading of its own. `commands` hands back the simple commands in the text,
each as the words PowerShell would hand to the program, and `agent_bypass`
judges them with the same flag rules as ever.

Every rule here was read off PowerShell 7 with a program that records its
arguments, not written from memory; the record holds every command and what
PowerShell handed over.

Pure stdlib, no aramid imports, no I/O, and it cannot raise: it runs inside
the agent hook, which fails open, so a raise here would let a command
through unread. A Bash tool call imports it only to read a string it hands
to PowerShell (`pwsh -c`, FN-55); a call from a tool the hook does not know
imports it to read what it hands on the PowerShell way too.

START-PROCESS. `started` hands back each program a Start-Process command
starts and the line it is started with, as tests/fixtures/started-argv.json
records them (FN-55 0110f7). A cmdlet is handed a list as its elements, not
as the words a program would get, so each word keeps the commas that make it
a list (`parts`), and a `( )` among the words keeps the commands it holds
(`groups`); the words themselves are what they were.

WHAT IS NOT KNOWN HERE. A variable, a `$( )`, a `( )` or a `{ }` stands for
a value only the run will show. As a whole word it stays one word, written
`$`, which the flag rules step over or take as a value. Inside a longer
word it is taken to be empty, because it may be: `--no-verify$u` is read as
the flag. The cost is an answer for `--no-verify$x` when `$x` is set, a
word nobody has a use for. At the start of a word a value takes its members
with it (`$u.y`, `$x[0]`, `(a).Length`), and what follows them is a word of
its own: `git $u.y commit -n` commits.

A NUL ENDS THE LINE. A program is started with one line of text, and the
line stops at a NUL. So ``--no-verify`0`` is the flag, and a `--red-proof`
that stands after a NUL is not handed to aramid. `commands` hands back the
words as far as the NUL.

A READING THAT IS CUT OFF. An open quote, comment or group makes PowerShell
run none of the text. The commands read up to there are handed back all the
same, with the word it stopped in left out: this reader may be the one that
is wrong about where the quote closes, and what it lets through is caught
by nothing else.

A READING THAT GOES TOO DEEP. Past _DEPTH groups the reading stops as well,
BEFORE the command it was reaching, and `reading` says so ("deep"). The cap
is low on purpose -- going as deep as PowerShell (it runs the wrapped command
thousands of groups in) could raise, and this reader must not. Unlike an open
quote, PowerShell does run such a text, so `agent_bypass` refuses the call,
whatever it names (the operator's decisions, 2026-10-13 and 2026-10-14): no
real command nests that deep, and a name built when the call runs is out of
any reading's reach.
"""
from __future__ import annotations

_SINGLE = "'\u2018\u2019\u201a\u201b"
_DOUBLE = "\"\u201c\u201d\u201e"
_NEWLINE = "\r\n"
# What a backtick makes of the letter after it. Any other character after a
# backtick is that character.
_ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "n": "\n",
            "r": "\r", "t": "\t", "v": "\v"}
_HEX = "0123456789abcdefABCDEF"
# The streams a redirection can name in front of its `>`.
_STREAMS = ("1", "2", "3", "4", "5", "6", "*")
# The stop-parsing token: after it the rest of the line is handed over as written.
_STOP = "--%"
# How deep `( )`, `{ }` and `$( )` may nest before the reading is cut off.
_DEPTH = 40
# Stands in a word for a value that is not known here (module docstring).
_VALUE = "\ue011"


class _CutOff(Exception):
    """The text ends inside a quote, a comment or a group."""


class _TooDeep(_CutOff):
    """The groups nest deeper than _DEPTH: the reading stops, PowerShell does not."""


def simple_commands(text: str) -> tuple[list[dict], str]:
    """The simple commands in `text` as records -- `{words, plains, heads,
    upstream, parts, groups}` -- and how the reading ended ("end"/"cut"/"deep",
    as `reading`). `plains` marks each word that had no quote/escape/value,
    `heads` each that began as `-name` written plainly; `upstream` is the previous
    command at the same level when a single `|` fed this one its stdin (None
    otherwise), kept so agent_bypass._from_stdin can read a shell on stdin.
    `reading` is the words-only projection of this."""
    done: list[dict] = []
    try:
        _commands(text, 0, "", done, 0)
    except _TooDeep:
        return done, "deep"
    except _CutOff:
        return done, "cut"
    return done, "end"


def reading(text: str) -> tuple[list[list[str]], str]:
    """The simple commands in `text`, each a list of words, and how the
    reading ended: "end" (it got to the end of the text), "cut" (an open
    quote, comment or group, which PowerShell runs none of) or "deep" (more
    than _DEPTH groups, which PowerShell runs)."""
    done, end = simple_commands(text)
    return [cmd["words"] for cmd in done], end


def commands(text: str) -> tuple[list[list[str]], bool]:
    """The simple commands in `text`, each a list of words, and whether the
    reading got to the end of the text."""
    done, end = reading(text)
    return done, end == "end"


def _blank(ch: str) -> bool:
    """A character that separates words and does not end the line."""
    return ch.isspace() and ch not in "\r\n\x1c\x1d\x1e\x1f"


def _commands(text: str, i: int, closer: str, done: list, depth: int) -> int:
    """Read commands from text[i:] up to `closer`, or to the end of the text
    when there is none. Each finished command is appended to `done`. Returns
    the index after the closer."""
    if depth > _DEPTH:
        raise _TooDeep
    n = len(text)
    words: list[str] = []
    plains: list[bool] = []  # per word in `words`: True when it had no quote
    heads: list[bool] = []   # per word in `words`: True when it began as `-name`
    word: list[str] | None = None   # the word being read, None between words
    plain = True        # the word has no quote, escape or value in it
    named = False       # the word is `-name`: it ends at a `.` or a `[`
    head = False        # the word began as `-name`, written plainly: to a cmdlet,
                        # a parameter's name (`started`), and its value may follow
                        # a `:` quoted (`-ArgumentList:'commit -n'`)
    target = False      # the next word is where a redirection goes
    comma = False       # a comma was the last thing read: the line goes on
    prev: dict | None = None   # the previous simple command AT THIS LEVEL
    prev_op = ""        # the operator just before the command being read
    # A cmdlet is handed a list as its elements (`started`), so the word keeps
    # where a comma made it one and where a line end carried the list on.
    parts: list[list[str]] = []     # per word in `words`: its pieces (_parts)
    seps: list[int] = []            # in `word`: the commas that make a list
    gaps: list[int] = []            # in `word`: the line ends after one of them
    groups: dict[int, list] = {}    # a `( )` among the words, by its place: its commands

    def end_word() -> bool:
        """Close the word being read. True when it was the stop-parsing token,
        written plainly: the caller reads the rest of the line as it stands."""
        nonlocal word, plain, named, head, target, seps, gaps
        stop = False
        if word is not None:
            read = "".join(word)
            known = read.replace(_VALUE, "")
            if target:
                target = False
            elif known == _STOP:
                stop = plain    # quoted or escaped it is left out all the same
            else:
                words.append(_written(read))
                plains.append(plain)
                heads.append(head)
                parts.append(_parts(word, seps, gaps))
        word, plain, named, head, seps, gaps = None, True, False, False, [], []
        return stop

    def verbatim(at: int) -> int:
        """`_verbatim`, with a mark for each word it hands over: PowerShell
        reads no quote in them."""
        before = len(words)
        at = _verbatim(text, at, words)
        plains.extend([True] * (len(words) - before))
        heads.extend([False] * (len(words) - before))   # none is a parameter's name
        parts.extend([w] for w in words[before:])
        return at

    def end_command(op: str) -> None:
        """Close the current simple command. `op` is the operator that ended it
        (`|`, `&`, `;`, a newline, a group closer or `''` at the end). The
        command keeps its pipe UPSTREAM (the previous command at this level,
        when a single `|` joined them) so a shell fed on stdin can be read
        (agent_bypass._from_stdin). `||`/`&&` are one operator, not a pipe; `|
        &` (the call operator straight after a pipe) keeps the pipe."""
        nonlocal words, plains, heads, parts, groups, target, comma, prev, prev_op
        end_word()
        if op in ("|", "&") and not words:
            if prev_op == op:            # `||` / `&&`: one operator, not a pipe
                prev_op = prev_op + op
                plains, heads = [], []
                return
            if op == "&" and prev_op == "|":   # `| &`: the call operator keeps it
                plains, heads = [], []
                return
        if words:
            kept = _handed(words)
            entry = {"words": kept, "plains": plains[:len(kept)], "heads": heads[:len(kept)],
                     "upstream": prev if prev_op == "|" else None,
                     "parts": parts[:len(kept)], "groups": groups}
            done.append(entry)
            prev = entry
        prev_op = op
        words, plains, heads, parts, groups = [], [], [], [], {}
        target, comma = False, False

    try:
        # A turn for each character left, and every turn reads one at least:
        # the length of the text bounds the walk, whatever the text holds.
        for _ in range(i, n):
            if i >= n:
                break
            ch = text[i]
            if ch in _NEWLINE:
                if comma:
                    # after a comma the list goes on over the line end, and
                    # the line end is handed over as part of a word
                    if word is None:
                        word = []
                    gaps.append(len(word))
                    word.append("\n")
                else:
                    end_command("\n")
                i += 1
            elif _blank(ch):
                i = verbatim(i) if end_word() else i + 1
            elif ch == "`" and not named:
                nxt = text[i + 1:i + 2]
                if not nxt:
                    raise _CutOff
                made, i = _escape(text, i)
                if word is None and (nxt in _NEWLINE or _blank(nxt)):
                    continue    # between words: a continued line, or a blank
                if word is None:
                    word = []
                word.append(made)
                plain, comma = False, False
            elif ch in _SINGLE or ch in _DOUBLE:
                began = word is None
                if began:
                    word = []
                plain, named, comma = False, False, False
                if ch in _SINGLE:
                    i = _single(text, i + 1, word)
                else:
                    i = _double(text, i + 1, word, done, depth)
                if began:
                    end_word()  # a word that starts with a quote ends with it
            elif ch == "@" and word is None and _here_string_starts(text, i):
                word = []
                plain = False
                i = _here_string(text, i, word, done, depth)
                end_word()
            elif ch == "$" and not named and _value_starts(text, i):
                comma = False
                if text[i + 1:i + 2] == "(":
                    began = word is None
                    if began:
                        word = []
                    word.append(_VALUE)
                    plain = False
                    i = _commands(text, i + 2, ")", done, depth + 1)
                    if began:
                        i = _members(text, i, done, depth)
                        end_word()      # `$(a)b` is two words, `a$(b)c` one
                    continue
                i, null = _variable(text, i)
                if word is None:
                    after = _members(text, i, done, depth)
                    if after != i:
                        # `$x.y`, `$x[0]`: an expression, and a word by itself
                        # (`$u.y-n` hands over `-n`); even of `$null` the
                        # value is not known
                        i = after
                        word, plain = [_VALUE], False
                        end_word()
                        continue
                # `$null` is nothing wherever it stands, but for a
                # redirection it is where the output goes (`2>$null`)
                if not null or (target and word is None):
                    if word is None:
                        word = []
                    word.append(_VALUE)
                    plain = False
            elif ch in "({" or (ch == "@" and word is None
                                and text[i + 1:i + 2] in ("(", "{")):
                if ch == "@":
                    i += 1
                    ch = text[i]
                if end_word():
                    i = verbatim(i)
                    continue
                place = None
                if target:
                    target = False
                elif words:
                    words.append("$")   # a group among the arguments: a value
                    plains.append(False)
                    heads.append(False)
                    parts.append(["$"])
                    place = len(words) - 1
                comma = False
                before = len(done)
                i = _commands(text, i + 1, ")" if ch == "(" else "}", done, depth + 1)
                after = _members(text, i, done, depth)  # `(a).Length` is one value
                if place is not None and ch == "(" and after == i:
                    groups[place] = done[before:]
                i = after
            elif ch in ")}" or (ch == "]" and closer == "]"):
                end_command(")")
                if ch == closer:
                    return i + 1
                i += 1                  # one that closes nothing
            elif ch in ";|&":
                # `&&` and `||` are two of these in a row, and `| &` is the
                # call operator straight after a pipe: end_command coalesces
                # them (a `||`/`&&` is not a pipe; a `| &` keeps the pipe).
                end_command(ch)
                i += 1
            elif word is None and ch == "#":
                while i < n and text[i] not in _NEWLINE:
                    i += 1
            elif word is None and ch == "<" and text[i + 1:i + 2] == "#":
                end = text.find("#>", i + 2)
                if end == -1:
                    raise _CutOff
                i = end + 2
            elif ch in "<>" and (word is None or (ch == ">" and plain and len(word) == 1
                                                  and word[0] in _STREAMS)):
                word = None             # the stream in front of it, if any
                i, target = _redirection(text, i)
                comma = False
            else:
                if word is None:
                    word = []
                    nxt = text[i + 1:i + 2]
                    named = ch == "-" and (nxt.isalpha() or nxt in ("_", "?"))
                    head = named
                elif named and ch in ".[":
                    end_word()          # `-n.x` is `-n` and `.x`
                    word = []
                elif named and ch == ":":
                    named = False       # `-n:.x` is one word
                if ch == ",":
                    seps.append(len(word))
                word.append(ch)
                comma = ch == ","
                i += 1
        if closer or i < n:
            raise _CutOff       # a group left open, or a turn that read nothing
        end_command("")
        return n
    except _CutOff:
        if words:
            kept = _handed(words)
            done.append({"words": kept, "plains": plains[:len(kept)], "heads": heads[:len(kept)],
                         "upstream": prev if prev_op == "|" else None,
                         "parts": parts[:len(kept)], "groups": groups})
        raise


def _handed(words: list[str]) -> list[str]:
    """The words a program is handed. It is started with one line of text and
    a NUL ends that line: the word is cut there and the words after it are
    lost. ``--no-verify`0`` is the flag, and a `--red-proof` after a NUL is
    not handed over."""
    for k, word in enumerate(words):
        at = word.find("\0")
        if at >= 0:
            return words[:k] + ([word[:at]] if at else [])
    return words


def _written(read: str) -> str:
    """A word as it is handed over: a value inside it is taken out, and one
    that is all of it is written `$` (module docstring)."""
    known = read.replace(_VALUE, "")
    return known if known or _VALUE not in read else "$"


def _parts(word: list[str], seps: list[int], gaps: list[int]) -> list[str]:
    """The pieces of a word between the commas that make it a list (at `seps`
    in `word`), without the line ends a comma carried the list over (at
    `gaps`), each written as a word is: what a cmdlet is handed as the
    elements of an array. A word with no such comma is one piece."""
    pieces: list[list[str]] = [[]]
    for k, made in enumerate(word):
        if k in seps:
            pieces.append([])
        elif k not in gaps:
            pieces[-1].append(made)
    return [_written("".join(piece)) for piece in pieces]


# Start-Process, as pwsh 7.6.8 lists it (`(Get-Command Start-Process).Parameters`):
# each parameter by its names, its own first and then its aliases, and whether
# a value goes with it. FilePath and ArgumentList are also the first and the
# second positional ones.
_STARTERS = ("start-process", "saps", "start")
_START_PARAMETERS = (
    (("filepath", "pspath", "path"), True), (("argumentlist", "args"), True),
    (("credential", "runas"), True), (("workingdirectory",), True),
    (("loaduserprofile", "lup"), False), (("nonewwindow", "nnw"), False),
    (("passthru",), False), (("redirectstandarderror", "rse"), True),
    (("redirectstandardinput", "rsi"), True), (("redirectstandardoutput", "rso"), True),
    (("verb",), True), (("windowstyle",), True), (("wait",), False),
    (("usenewenvironment",), False), (("environment",), True),
    (("verbose", "vb"), False), (("debug", "db"), False),
    (("erroraction", "ea"), True), (("warningaction", "wa"), True),
    (("informationaction", "infa"), True), (("progressaction", "proga"), True),
    (("errorvariable", "ev"), True), (("warningvariable", "wv"), True),
    (("informationvariable", "iv"), True), (("outvariable", "ov"), True),
    (("outbuffer", "ob"), True), (("pipelinevariable", "pv"), True),
    (("whatif", "wi"), False), (("confirm", "cf"), False),
)


def started(text: str) -> list[tuple[str, str]]:
    """Each program a Start-Process command in `text` starts (`saps` and
    `start` are its aliases), as (the program as it is named, the line of
    arguments it is started with). As tests/fixtures/started-argv.json
    records it: the named parameters are bound first and then the positional
    ones, the program and then its arguments; a list of arguments is joined
    with single spaces and none of them is quoted; with a bare -WhatIf
    nothing is started. A word that names the cmdlet starts a reading
    wherever it stands, as a word named git does.

    A program or an argument that is a value (`$a`, an expression, what a
    command writes) is not known here: such a program starts nothing that is
    read, and such an argument is written `$`. A call PowerShell refuses -- a
    parameter it does not know, or given twice, or without its value -- is
    read as if it ran."""
    out: list[tuple[str, str]] = []
    for cmd in simple_commands(text)[0]:
        for k, word in enumerate(cmd["words"]):
            if word.rpartition("\\")[2].lower() in _STARTERS:
                found = _start(cmd, k + 1)
                if found is not None:
                    out.append(found)
    return out


def _start(cmd: dict, first: int) -> tuple[str, str] | None:
    """The program and the line of arguments of the Start-Process whose
    arguments are the words of `cmd` from `first` on, or None (`started`)."""
    bound: dict[str, list[str]] = {}
    positional: list[list[str]] = []
    args = _arguments(cmd, first)
    k = 0
    while k < len(args):
        word, plain, elements, head = args[k]
        k += 1
        if not _is_parameter(word, plain, head):
            positional.append(elements)
            continue
        name, colon, _ = word[1:].partition(":")
        found = _start_parameter(name)
        if found is None:
            continue
        own, takes = found
        if own == "whatif" and not colon:
            return None
        if colon:
            given = [elements[0].partition(":")[2]] + elements[1:]
        elif takes and k < len(args) and not _is_parameter(args[k][0], args[k][1], args[k][3]):
            given = args[k][2]
            k += 1
        else:
            continue
        bound.setdefault(own, given)
    for elements in positional:
        own = "filepath" if "filepath" not in bound else "argumentlist"
        if own in bound:
            break
        bound[own] = elements
    program = bound.get("filepath", [])
    if len(program) != 1 or program[0] in ("", "$"):
        return None
    return program[0], " ".join(bound.get("argumentlist", []))


def _is_parameter(word: str, plain: bool, head: bool) -> bool:
    """Whether a word is a parameter's name (`-Wait`, `-FilePath:git`) and not
    a value: it began as `-name` written plainly (`head`), and it is plain
    throughout or has its value after a colon (`-ArgumentList:'commit -n'`).
    A word that begins with a quote is a value, whatever it holds: the record
    hands git all of `'-C . commit -n -m a:b'`."""
    return (head and word[:1] == "-" and (word[1:2].isalpha() or word[1:2] in ("_", "?"))
            and (plain or ":" in word))


def _start_parameter(name: str) -> tuple[str, bool] | None:
    """The parameter of Start-Process `-name` names -- by a name or an alias of
    its own, or by the start of only one -- as (its own name, whether a value
    goes with it); None when it names none or more than one, and PowerShell
    refuses the call."""
    name = name.lower()
    found = [(names[0], takes) for names, takes in _START_PARAMETERS if name in names]
    if not found:
        found = [(names[0], takes) for names, takes in _START_PARAMETERS
                 if any(each.startswith(name) for each in names)]
    return found[0] if len(found) == 1 else None


def _arguments(cmd: dict, first: int) -> list[tuple[str, bool, list[str], bool]]:
    """The arguments of a cmdlet from the word of `cmd` at `first` on, each as
    (its first word, whether that is plain, its elements, whether that began
    as `-name`). A list is one argument though it is several words (`'a','b'`
    is `a` and `,b`): a word joins the one in front of it when a comma ends
    that one or starts this one. A `( )` that holds a list of strings is that
    list (`_listed`)."""
    words, plains, parts, groups = cmd["words"], cmd["plains"], cmd["parts"], cmd["groups"]
    heads = cmd["heads"]
    out: list[tuple[str, bool, list[str], bool]] = []
    joined = False      # the word in front ended with a comma
    for k in range(first, len(words)):
        own = parts[k] if k < len(parts) else [words[k]]
        pieces = (_listed(groups[k]) if k in groups else None) or list(own)
        if out and (joined or (len(own) > 1 and own[0] == "")):
            out[-1][2][-1] += pieces[0]
            out[-1][2].extend(pieces[1:])
        else:
            out.append((words[k], k < len(plains) and plains[k], pieces,
                        k < len(heads) and heads[k]))
        joined = len(own) > 1 and own[-1] == ""
    return out


def _listed(entries: list) -> list[str] | None:
    """The strings a `( )` among the words is, when its commands are nothing
    but strings and the commas between them (`@('commit', '-n')`, or one to a
    line); None when it holds anything else, a value only the run shows."""
    out: list[str] = []
    for entry in entries:
        args = _arguments(entry, 0)
        if len(args) != 1 or args[0][1]:
            return None
        if any(plain and word.strip(",\r\n") for word, plain in zip(entry["words"], entry["plains"])):
            return None
        out.extend(args[0][2])
    return out or None


def _escape(text: str, i: int) -> tuple[str, int]:
    """What the backtick at text[i] makes of what follows it, and the index
    after that."""
    nxt = text[i + 1:i + 2]
    if nxt == "u":
        # `u{`, one to six hex digits, `}`: a code point. Written any other
        # way PowerShell runs none of the text.
        if text[i + 2:i + 3] != "{":
            raise _CutOff
        end = i + 3
        while end < len(text) and text[end] in _HEX:
            end += 1
        digits = text[i + 3:end]
        if text[end:end + 1] != "}" or not digits or len(digits) > 6:
            raise _CutOff
        point = int(digits, 16)
        if point > 0x10FFFF:
            raise _CutOff
        # half of a surrogate pair is handed over as the replacement character
        return chr(0xFFFD if 0xD800 <= point <= 0xDFFF else point), end + 1
    if nxt and nxt in _NEWLINE:
        return "\n", i + (3 if text.startswith("\r\n", i + 1) else 2)
    return _ESCAPES.get(nxt, nxt), i + 2


def _single(text: str, i: int, word: list) -> int:
    """A single-quoted string from text[i] on: nothing is special in it but
    the quote, and two of them are one. The index after the closing quote."""
    n = len(text)
    while i < n:
        ch = text[i]
        if ch not in _SINGLE:
            word.append(ch)
            i += 1
        elif i + 1 < n and text[i + 1] in _SINGLE:
            word.append("'")
            i += 2
        else:
            return i + 1
    raise _CutOff


def _double(text: str, i: int, word: list, done: list, depth: int) -> int:
    """A double-quoted string from text[i] on: the backtick escapes, two
    quotes are one, a variable is a value, and `$( )` holds commands that
    run. The index after the closing quote."""
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "`":
            # a backtick that is the last character escapes nothing: the
            # index goes past the end and the string is left open
            made, i = _escape(text, i)
            word.append(made)
        elif ch in _DOUBLE:
            if not (i + 1 < n and text[i + 1] in _DOUBLE):
                return i + 1
            word.append('"')
            i += 2
        elif ch == "$" and text[i + 1:i + 2] == "(":
            word.append(_VALUE)
            i = _commands(text, i + 2, ")", done, depth + 1)
        elif ch == "$" and _value_starts(text, i):
            i, null = _variable(text, i)
            if not null:
                word.append(_VALUE)
        else:
            word.append(ch)
            i += 1
    raise _CutOff


def _name_char(ch: str) -> bool:
    return ch.isalnum() or ch in ("_", "?")


def _value_starts(text: str, i: int) -> bool:
    """Whether the `$` at text[i] starts a variable or a `$( )`, and is not a
    dollar sign that stands for itself."""
    nxt = text[i + 1:i + 2]
    return bool(nxt) and (nxt in "({$^" or _name_char(nxt))


def _variable(text: str, i: int) -> tuple[int, bool]:
    """The variable at text[i], a `$` that `_value_starts` accepted and that
    opens no `$( )`: the index after its name, and whether it is `$null`.

    Every caller asks `_value_starts` first; asked here all the same because
    the hook fails open, so a reader that raised would let the call through
    (FN-55 7e8088). Anything else is a `$` that stands for itself."""
    if i < 0 or not _value_starts(text, i):
        return i + 1, False
    n = len(text)
    nxt = text[i + 1]
    if nxt == "{":
        # `${name}`: anything up to the brace. `${}` names nothing, and then
        # PowerShell runs none of the text.
        end = text.find("}", i + 2)
        if end <= i + 2:
            raise _CutOff
        return end + 1, text[i + 2:end].lower() == "null"
    if nxt in "$^":
        return i + 2, False
    end = i + 2         # past the `$` and the first letter: `_value_starts` saw it
    while end < n and _name_char(text[end]):
        end += 1
    null = text[i + 1:end].lower() == "null"
    # a scope or a drive in front of the name: `$env:PATH`, `$global:x`
    if text[end:end + 1] == ":" and _name_char(text[end + 1:end + 2] or " "):
        end += 2        # past the `:` and the letter the test above saw
        while end < n and _name_char(text[end]):
            end += 1
        null = False
    return end, null


def _members(text: str, i: int, done: list, depth: int) -> int:
    """What follows a value at the start of a word and is part of it: `.name`,
    `::name`, `[index]`, and the `( )` of arguments after a name. What stands
    in the brackets is run, so it is read. The index after the last of them,
    which is `i` when there is none."""
    n = len(text)
    while True:
        if text[i:i + 1] == "[":
            i = _commands(text, i + 1, "]", done, depth + 1)
            continue
        if text.startswith("::", i):
            k = i + 2
        elif text[i:i + 1] == ".":
            k = i + 1
        else:
            return i
        if not _name_char(text[k:k + 1] or " "):
            return i
        while k < n and _name_char(text[k]):
            k += 1
        if text[k:k + 1] == "(":
            k = _commands(text, k + 1, ")", done, depth + 1)
        i = k


def _here_string_starts(text: str, i: int) -> bool:
    """Whether the `@` at text[i] opens a here-string: a quote after it, and
    nothing but blanks up to the end of the line."""
    # (an `@` that is the last character has no quote after it, and the line
    # end test below then says no)
    if text[i + 1:i + 2] not in _SINGLE + _DOUBLE:
        return False
    k = i + 2
    while k < len(text) and _blank(text[k]):
        k += 1
    return k < len(text) and text[k] in _NEWLINE


def _here_string(text: str, i: int, word: list, done: list, depth: int) -> int:
    """The here-string that opens at text[i]: it runs to a line that starts
    with its quote and an `@`. In the double-quoted kind `$( )` holds commands
    that run. The index after the closing `@`."""
    n = len(text)
    double = text[i + 1] in _DOUBLE
    quotes = _DOUBLE if double else _SINGLE
    i += 2
    while text[i] not in _NEWLINE:
        i += 1
    i += 2 if text.startswith("\r\n", i) else 1
    line_start = True
    ends = 0        # how many characters at the end of `word` are a line end
    while i < n:
        ch = text[i]
        if line_start and ch in quotes and text[i + 1:i + 2] == "@":
            # the line end in front of the closing line is not part of the
            # text: `@'`, a line holding `-n`, `'@` hands over `-n`
            del word[len(word) - ends:]
            return i + 2
        line_start = ch in _NEWLINE
        if double and ch == "`":
            # an escaped `$(` holds no command; a backtick that is the last
            # character goes past the end, and the here-string is left open
            made, i = _escape(text, i)
            word.append(made)
            ends = 0    # what an escape makes is text: `` `r `` is kept
        elif double and ch == "$" and text[i + 1:i + 2] == "(":
            # (no `ends` to set: the word now ends in a value, and the next
            # character is no closing line, since it does not start one)
            word.append(_VALUE)
            i = _commands(text, i + 2, ")", done, depth + 1)
        else:
            ends = 2 if ch == "\n" and ends == 1 and word[-1] == "\r" else int(line_start)
            word.append(ch)
            i += 1
    raise _CutOff


def _redirection(text: str, i: int) -> tuple[int, bool]:
    """The `>`, `>>` or `<` at text[i]: the index after it, and whether the
    next word is where it goes. `>&1` sends one stream into another and takes
    no word."""
    i += 2 if text.startswith(">>", i) else 1
    if text[i:i + 1] != "&":
        return i, True
    i += 1
    # the stream is ONE digit: `2>&12` hands over `2` [V, probe11]
    if text[i:i + 1].isdigit():
        i += 1
    return i, False


def _verbatim(text: str, i: int, words: list) -> int:
    """After the stop-parsing token: the rest of the line is cut at blanks
    and handed over as it stands, with its quotes, `#`, `;` and `>`. A line
    end, a `|` or a `&` ends it. The index of what ended it."""
    start = i
    while i < len(text) and text[i] not in "\r\n|&":
        i += 1
    words.extend(text[start:i].split())
    return i
