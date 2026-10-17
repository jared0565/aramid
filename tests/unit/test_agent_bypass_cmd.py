"""A string handed to `cmd /c` (FN-55 in
docs/superpowers/plans/2026-09-21-aramid-1.0-blockers.md).

`cmd /c "git commit -n"` hands cmd.exe a string to run, and cmd runs it by its
own rules: it reads the text once itself (quotes, carets, `&`, parentheses,
redirections) and starts what is left of each command, and the program it starts
reads that a second time (for git, the C runtime's rules for a command line).
What is right here is what git was handed. Three records are of that, from the
real cmd.exe and real git (each file says which), in a scratch repository with
nothing staged and git writing its own whole argv down (the trace2 start event):

  tests/fixtures/cmd-argv.json     a text given to cmd, and every git it started;
  tests/fixtures/cmd-line.json     the command line Git Bash and PowerShell build for a
                                   program named cmd from the words of a command;
  tests/fixtures/cmd-switch.json   which command line makes cmd run a string at all.

tests/fixtures/handed-argv.json holds the whole way, from a Bash or PowerShell
call to the argv of git, and test_agent_bypass_handed.py checks it.

Three lists for the texts of cmd-argv.json, each checked against the record on
every run:

  NOT_SEEN  a bypass git was handed that the hook lets through, with why;
  OVER      no bypass reached git and the hook answers all the same;
  DIFFERS   the words git was handed are not the words the reader reads from
            the text (NOT_SEEN and OVER are in it, and what changes no answer).

A text in none of them is answered exactly as git's own argv is judged."""
import json
from pathlib import Path

import pytest

from aramid import agent_bypass as ab
from aramid import agent_bypass_cmd as cmd
from aramid import agent_bypass_powershell as ps
from aramid.agent_bypass import CMD, POSIX, POWERSHELL, Bypass, find_bypass

FIXTURES = Path(__file__).parent.parent / "fixtures"
ARGV_RECORD = json.loads((FIXTURES / "cmd-argv.json").read_text(encoding="ascii"))
LINE_RECORD = json.loads((FIXTURES / "cmd-line.json").read_text(encoding="ascii"))
SWITCH_RECORD = json.loads((FIXTURES / "cmd-switch.json").read_text(encoding="ascii"))
ARGV = {case["text"]: case["argv"] for case in ARGV_RECORD["cases"]}
LINES = {(case["shell"], case["command"]): case["line"] for case in LINE_RECORD["cases"]}
SWITCH = {case["line"]: case["argv"] for case in SWITCH_RECORD["cases"]}

DASH_N = Bypass("no-verify", "commit", "-n")
TOO_MANY = Bypass("too-deep", "shells", str(ab._HANDED_DEPTH))


def _judged(argvs):
    """The hook's own flag rules on the words git was handed."""
    for argv in argvs:
        found = ab._scan_one_git(argv, 0)
        if found is not None:
            return found
    return None


def _launched(text):
    """The reader's words from each word that names git on, in the command it is
    in: what the recording program would have been handed."""
    return [["git", *words[i + 1:]]
            for words in cmd.commands(text) for i, word in enumerate(words) if ab._is_git(word)]


def test_the_records_are_the_ones_a_run_made():
    for record in (ARGV_RECORD, SWITCH_RECORD):
        assert record["provisional"] is False
        assert record["git"].startswith("git version 2.")
        assert record["cmd"].startswith("Microsoft Windows [Version 10.")
    assert LINE_RECORD["provisional"] is False
    assert LINE_RECORD["pwsh"].split(".")[0] == "7"
    assert LINE_RECORD["winps"].startswith("5.1")
    assert "msys" in LINE_RECORD["bash"]
    assert len(ARGV) == len(ARGV_RECORD["cases"]) >= 429
    assert len(LINES) == len(LINE_RECORD["cases"]) >= 124
    assert {shell for shell, _ in LINES} == {"posix", "powershell", "powershell5"}
    assert len(SWITCH) == len(SWITCH_RECORD["cases"]) >= 40
    # each holds both: what ran git with a bypass or at all, and what did not
    assert sum(1 for argvs in ARGV.values() if _judged(argvs)) >= 250
    assert sum(1 for argvs in ARGV.values() if not argvs) >= 40
    assert sum(1 for argvs in SWITCH.values() if argvs) >= 20
    assert sum(1 for argvs in SWITCH.values() if not argvs) >= 15


# ---- the command line an outer shell builds for cmd ----

STYLE = {"posix": cmd.MSYS, "powershell": cmd.POWERSHELL, "powershell5": cmd.POWERSHELL}
_MSYS_PATH = ("Git Bash makes a lone /c a path (C:/), which is no switch, so cmd runs nothing; "
              "the reader takes it as the switch")
_PS5_BACKSLASH = ("Windows PowerShell 5.1 leaves the backslashes at the end of a quoted word as "
                  "they are; PowerShell 7 doubles them, and the reader does as PowerShell 7 does")
NOT_MODELED = {
    ("posix", "cmd /c 'git commit -n'"): _MSYS_PATH,
    ("posix", "cmd /c git commit -n"): _MSYS_PATH,
    ("powershell5", "cmd /c 'a b\\'"): _PS5_BACKSLASH,
    ("powershell5", "cmd /c 'a b\\\\'"): _PS5_BACKSLASH,
}


def _words(shell, command):
    """The words the hook cuts a command of one program into."""
    if shell == "posix":
        tokens, _ = ab._tokens(command, False)
        return ab._segments(tokens)[0]
    return ps.reading(command)[0][0]


def test_the_line_an_outer_shell_builds_is_the_one_the_record_holds():
    wrong = {}
    for (shell, command), line in LINES.items():
        words = _words(shell, command)
        assert words[0] == "cmd", command
        built = cmd.command_line(words[1:], STYLE[shell])
        if built != line:
            wrong[(shell, command)] = built
    assert set(wrong) == set(NOT_MODELED)


def test_the_two_shells_build_the_line_in_their_own_ways():
    # PowerShell wraps a word that has a space and leaves a quote inside it as
    # it is; Git Bash wraps one that has a space, a quote or nothing at all, and
    # puts a backslash in front of each quote inside it (cmd-line.json)
    words = ["/c", "git commit -m", "a \"b\" c", ""]
    assert cmd.command_line(words, cmd.POWERSHELL) == '/c "git commit -m" "a "b" c" '
    assert cmd.command_line(words, cmd.MSYS) == '/c "git commit -m" "a \\"b\\" c" ""'


def test_git_bash_turns_a_double_slash_switch_into_a_single_one():
    # `//c` is how Git Bash is told not to make a path of /c (cmd-line.json)
    assert cmd.command_line(["//c", "x"], cmd.MSYS) == "/c x"
    assert cmd.command_line(["//V:ON", "//c", "x"], cmd.MSYS) == "/V:ON /c x"
    assert cmd.command_line(["//c//c", "x"], cmd.MSYS) == "//c//c x"
    assert cmd.command_line(["//a/b", "x"], cmd.MSYS) == "//a/b x"
    # a third slash is lost even when a path follows
    assert cmd.command_line(["///c", "x"], cmd.MSYS) == "//c x"
    assert cmd.command_line(["///c/d", "x"], cmd.MSYS) == "//c/d x"
    assert cmd.command_line(["//c", "x"], cmd.POWERSHELL) == "//c x"


# ---- which command line makes cmd run a string ----

def _runs(string):
    """Whether cmd starts git: the program of one of its commands is git."""
    return any(ab._is_git(words[0]) for words in cmd.commands(string))


def test_cmd_runs_the_string_after_the_first_switch_that_starts_one():
    wrong = {}
    for line, argvs in SWITCH.items():
        string = cmd.string_to_run(line)
        ran = string is not None and _runs(string)
        if ran != bool(argvs):
            wrong[line] = string
    assert wrong == {}


@pytest.mark.parametrize("line,string", [
    ("/d /c git commit -n", " git commit -n"),
    ("/C x", " x"), ("/k x", " x"), ("/K x", " x"), ("/r x", " x"), ("/R x", " x"),
    ("/cx", "x"), ("/d/c x", " x"), ("/c", ""),
    ("/d /s /v:on /c x", " x"),
    ('"/cgit commit -n"', 'git commit -n"'),     # PowerShell wraps `/cgit commit -n`
    ("/c git /c x", " git /c x"),                # a second switch is text
    ("a /z b/c d", " d"),                        # a word that is no switch, an unknown switch
    ('"/c" x', '" x'),
])
def test_the_string_is_what_follows_the_first_c_k_or_r_switch(line, string):
    assert cmd.string_to_run(line) == string


@pytest.mark.parametrize("line", [
    "", "x", "/", "/d", "-c x", "/dc x", "//c x", "/ c x", "\\c x", "c x", "/?", "/x /y"])
def test_a_line_with_no_such_switch_runs_no_string(line):
    assert cmd.string_to_run(line) is None


def test_the_switch_scan_agrees_with_how_the_text_of_the_record_was_given():
    # cmd-argv.json gave each text to `cmd /d /c <text>`
    for text in ARGV:
        assert cmd.string_to_run("/d /c " + text) == " " + text


# ---- the text, as cmd and then git read it ----

@pytest.mark.parametrize("text,commands", [
    ("git commit -n", [["git", "commit", "-n"]]),
    ("git.exe commit -n", [["git.exe", "commit", "-n"]]),
    ("  git   commit    -n  ", [["git", "commit", "-n"]]),
    ("git status & git commit -n", [["git", "status"], ["git", "commit", "-n"]]),
    ("git status&&git commit -n", [["git", "status"], ["git", "commit", "-n"]]),
    ("nosuchprog || git commit -n", [["nosuchprog"], ["git", "commit", "-n"]]),
    ("git commit -n | findstr x", [["git", "commit", "-n"], ["findstr", "x"]]),
    ("git commit -n &", [["git", "commit", "-n"]]),
    ('git commit -m "a & b" -n', [["git", "commit", "-m", "a & b", "-n"]]),
    ("git commit -m a & b -n", [["git", "commit", "-m", "a"], ["b", "-n"]]),
    ("git commit ^-n", [["git", "commit", "-n"]]),
    ("g^it commit -n", [["git", "commit", "-n"]]),
    ("git status ^& git commit -n", [["git", "status", "&", "git", "commit", "-n"]]),
    ('git commit "^-n"', [["git", "commit", "^-n"]]),
    ("git commit ^^-n", [["git", "commit", "^-n"]]),
    ("git commit -n >nul", [["git", "commit", "-n"]]),
    ("git commit -n 2>&1", [["git", "commit", "-n"]]),
    (">nul git commit -n", [["git", "commit", "-n"]]),
    ('git commit -m ">" -n', [["git", "commit", "-m", ">", "-n"]]),
    ("git commit -n2>nul", [["git", "commit", "-n2"]]),
    ("git commit -n 2>nul", [["git", "commit", "-n"]]),
    ("(git status & git commit -n)", [["git", "status"], ["git", "commit", "-n"]]),
    ("(git status)&git commit -n", [["git", "status"], ["git", "commit", "-n"]]),
    ("git commit (-n)", [["git", "commit", "(-n)"]]),
    ("echo a) & git commit -n", [["echo", "a)"], ["git", "commit", "-n"]]),
    ("rem git commit -n", []),
    ("rem x & git commit -n", []),
    ("git commit -n & rem x", [["git", "commit", "-n"]]),
    (":: x & git commit -n", []),
    ("@echo off & git commit -n", [["echo", "off"], ["git", "commit", "-n"]]),
    (";git commit -n", [["git", "commit", "-n"]]),
    ("git status\ngit commit -n", [["git", "status"]]),
    ("\ngit commit -n", [["git", "commit", "-n"]]),
    ("git status\rgit commit -n", [["git", "statusgit", "commit", "-n"]]),
    ('"git commit -n"', [["git", "commit", "-n"]]),
    ('"git commit" -n', [["git", "commit", "-n"]]),
    ('"git" "commit" "-n"', [["git commit -n"]]),
    (r'git commit -m \"a b\" -n', [["git", "commit", "-m", '"a', 'b"', "-n"]]),
    (r'git commit -m "C:\dir\\" -n', [["git", "commit", "-m", "C:\\dir\\", "-n"]]),
    ('git commit -m ""a b"" -n', [["git", "commit", "-m", "a", "b", "-n"]]),
    ('git commit -m "a ""b"" c" -n', [["git", "commit", "-m", 'a "b', "c -n"]]),
    ("git commit -n\0 git status", [["git", "commit", "-n"]]),
])
def test_cmd_cuts_a_text_into_commands_and_the_words_git_is_handed(text, commands):
    assert text.split("\0")[0] in ARGV or "\0" in text   # the record holds it
    assert cmd.commands(text) == commands


@pytest.mark.parametrize("text", [
    "", " ", "\t\n\r", "\0", "&", "&&", "|", "||", "(", ")", "()", "(((", ")))", '"', '""', "^", "^^",
    "^\n", ">", "<", ">>", "2>", "1>&", "@", "@@", ",;=", "%", "!", "rem", "REM", ":", "::", "@rem",
    "git", "git ", "git\0", "\0git commit -n", '"git', 'git commit -m "', "git commit -m '",
    # a backslash is the last character: a word, the end of a quoted word, the whole text
    "\\", "\\\\", "git \\", "git commit -n x\\", 'git "\\', 'git "x\\"', "(\\", ">\\", "^\\", ":x\\"])
def test_an_odd_text_is_read_without_raising_into_commands_of_words(text):
    read = cmd.commands(text)
    assert isinstance(read, list)
    assert all(isinstance(words, list) and words and all(isinstance(w, str) for w in words)
               for words in read)


@pytest.mark.parametrize("line,j,depth,after", [
    # an index inside the line, with a group open or not
    ("a>b", 0, 0, 1), (">nul", 0, 0, 0), (">nul", 1, 0, 4), (">&2 x", 1, 0, 3), (">^", 1, 0, 2),
    ("a)b", 0, 1, 1), ("a)b", 0, 0, 3), ("a)b", 0, -1, 3),
    # no index of the line: a negative one reads as 0, one past the end is the end
    ("", 0, 0, 0), ("", -1, 0, 0), ("", 5, 0, 0), ("ab", 2, 0, 2), ("ab", 3, 0, 2),
    ("ab", -1, 0, 2), ("ab", -3, 0, 2), ("ab", -5, 0, 2), ("ab", 9999, 0, 2),
    ("a>", -1, 0, 1), ("a>", -2, 0, 1), ("a>b", -100, 3, 1), ("a b", -4, 1, 1),
    ("a b", -9999, 0, 1), ("^", -1, -1, 1), ('"', 0, 2, 1), ('"', -7, 2, 1)])
def test_the_redirect_reader_never_raises_on_an_out_of_contract_index(line, j, depth, after):
    # find_bypass fails open (agent_hook.cmd_agent_hook catches every exception
    # and allows the call), so a reader that raised would be a silent bypass.
    # _split only ever passes an index from 1 to len(line), but the drain's
    # fuzzer calls the helpers directly: keep them total (FN-55).
    assert cmd._after_redirect(line, j, depth) == after


# ---- the record of cmd-argv.json ----

# What the reader does not see, and is not built to.
_BUILT = "the name is put together when cmd runs the line: it expands %VAR% first; the reader does not"
_JUNK = ("cmd skips ; , = and @ in front of the command that follows `if` or `do`, a second "
         "`call` and the options of a `start`; the reader does so at the start of a command, and "
         "after a first word `call` or `start`")
_FOR_F = "for /f runs the command in its parentheses; the reader takes them as text"
_PIPED = ("cmd reads the command on the right of a pipe a second time, so a caret in it "
          "is gone twice; the reader removes it once")
NOT_SEEN = {
    "g%PATH:~0,0%it commit -n": _BUILT,
    'set "X=git" && call %X% commit -n': _BUILT,
    "if 1==1 ;git commit -n": _JUNK,
    "if 1==1 @@git commit -n": _JUNK,
    "if 1==1 =git commit -n": _JUNK,
    "if 1==1 call ;git commit -n": _JUNK,
    "for %i in (a) do ;git commit -n": _JUNK,
    "for %i in (a) do @git commit -n": _JUNK,
    "call call ;git commit -n": _JUNK,
    "start /b ;git commit -n": _JUNK,
    'start "" ;git commit -n': _JUNK,
    "for /f %i in ('git commit -n') do echo x": _FOR_F,
    "echo x | (git commit ^^-n)": _PIPED,
}
_ANY_WORD = "a word named git starts a scan, as it does in any command"
_NO_LABEL = " (here :x is no label, but a program)"
_REFUSED = ("cmd refuses the whole line (a syntax error) before it runs anything; the "
            "reader reads the commands in it all the same")
_CALL_TWICE = ("cmd reads the arguments of a `call` a second time, and the & a caret kept is an "
               "operator then, so the line fails and nothing ran; the reader reads it once")
_LABEL = ("a label swallows the rest of the line after `if` and `do` too; the reader sees one at "
          "the start of a command only")
OVER = {
    "echo git commit -n": _ANY_WORD,
    "echo y & echo git commit -n": _ANY_WORD,
    "remx git commit -n": _ANY_WORD,
    "git status ^& git commit -n": _ANY_WORD + " (here the escaped & keeps it an argument of git)",
    "git status && :x git commit -n": _ANY_WORD + _NO_LABEL,
    '>nul :x\\" git commit -n': _ANY_WORD + _NO_LABEL,
    'echo y && :x\\" git commit -n': _ANY_WORD + _NO_LABEL,
    "call git status ^& git commit -n": _CALL_TWICE,
    "if 1==1 :x & git commit -n": _LABEL,
    "for %i in (1) do :x & git commit -n": _LABEL,
    "& git commit -n": _REFUSED,
    "&& git commit -n": _REFUSED,
    "(git commit -n": _REFUSED,
    "git commit -n >": _REFUSED,
    "git commit -n 2>": _REFUSED,
    "git commit -n &>nul": _REFUSED,
    "(echo a)(git commit -n)": _REFUSED,
    "(echo a) (git commit -n)": _REFUSED,
    "(git commit -n)) & git status": _REFUSED,
    "(git commit -n) (git status)": _REFUSED,
    "git commit -n <&0": _REFUSED,
    ") & git commit -n": _REFUSED,
    r'"C:\No Such\git.exe" commit -n': "there is no such program, so nothing ran; the reader goes by the name",
}
_CUT = ("cmd ends the program's name at , ; or =, so git got the rest as one word; that is no "
        "subcommand, so the answer is the same")
_STRING = "another cmd's string: read when the hub hands it over (find_bypass), not by commands"
_BRANCHES = "cmd runs one branch of an if; the reader cannot tell which, and reads both"
_EXPANDED = ("cmd expands %VAR% before it reads the line (to nothing, here); the reader keeps the "
             "word, which changes no answer")
DIFFERS = {
    **NOT_SEEN, **OVER,
    "git,commit,-n": _CUT, "git;commit;-n": _CUT, "git=commit=-n": _CUT, ",git,commit,-n": _CUT,
    'cmd /c "git commit -n"': _STRING,
    "if 1==1 (git commit -n) else (git status)": _BRANCHES,
    "if 1==2 (git status) else git commit -n": _BRANCHES,
    "git commit -n %PATH:~0,0%": _EXPANDED,
    'call git commit -m "a ^& b" -n': ("cmd doubles a caret in quotes in the arguments of a `call`; "
                                      "the answer is the same"),
}


def test_the_lists_name_texts_of_the_record():
    for listed in (NOT_SEEN, OVER, DIFFERS):
        assert set(listed) <= set(ARGV)
    assert all(_judged(ARGV[text]) for text in NOT_SEEN)
    assert not any(_judged(ARGV[text]) for text in OVER)


def test_the_words_the_reader_reads_are_the_words_git_was_handed():
    wrong = {text: _launched(text) for text, argvs in ARGV.items()
             if text not in DIFFERS and _launched(text) != argvs}
    assert wrong == {}
    # a text listed as different is
    assert {text for text in DIFFERS if _launched(text) == ARGV[text]} == set()


def test_nothing_cmd_handed_git_as_a_bypass_is_let_through():
    missed = {text for text, argvs in ARGV.items()
              if _judged(argvs) and find_bypass(text, CMD) is None}
    assert missed == set(NOT_SEEN)


def test_every_bypass_the_record_holds_is_answered_as_git_was_handed_it():
    wrong = {text: find_bypass(text, CMD) for text, argvs in ARGV.items()
             if _judged(argvs) and text not in NOT_SEEN
             and find_bypass(text, CMD) != _judged(argvs)}
    assert wrong == {}


def test_what_cmd_ran_without_a_bypass_is_answered_only_where_listed():
    over = {text for text, argvs in ARGV.items()
            if not _judged(argvs) and find_bypass(text, CMD) is not None}
    assert over == set(OVER)


# ---- the hub ----

def test_a_string_handed_to_cmd_is_read_from_a_call_whose_text_never_spells_git():
    # the caret is cmd's, so the call's own text has no `git` in it and no `sh`: the
    # cheap test that keeps a call from being read must not let this one go
    command = "cmd //c 'g^it commit -n'"
    assert not ab._may_name_a_program(command)
    assert find_bypass(command, POSIX) == DASH_N
    assert find_bypass(command) == DASH_N


def test_a_cmd_call_is_read_without_the_cheap_test(monkeypatch):
    def never(command):
        raise AssertionError("the cheap test was asked")
    monkeypatch.setattr(ab, "_may_name_a_program", never)
    assert find_bypass("g^it commit -n", CMD) == DASH_N
    assert find_bypass("echo hi", CMD) is None


def test_a_cmd_call_does_not_go_through_the_posix_reader(monkeypatch):
    def never(*a, **k):
        raise AssertionError("the POSIX reader was asked")
    monkeypatch.setattr(ab, "_tokens", never)
    assert find_bypass("git commit -n", CMD) == DASH_N


def test_a_string_in_a_cmd_string_is_read_by_cmd_too():
    assert find_bypass('cmd /c "git commit -n"', CMD) == DASH_N
    assert find_bypass('call cmd /d /c "git commit -n" & dir', CMD) == DASH_N
    assert find_bypass('cmd /c "git status"', CMD) is None


def test_a_call_that_hands_cmd_no_string_does_not_load_the_cmd_reader(monkeypatch):
    import sys

    import aramid
    monkeypatch.delitem(sys.modules, "aramid.agent_bypass_cmd", raising=False)
    monkeypatch.delattr(aramid, "agent_bypass_cmd", raising=False)
    assert find_bypass("git commit -n", POSIX) == DASH_N
    assert find_bypass("git commit -n", POWERSHELL) == DASH_N
    assert find_bypass("git commit -n") == DASH_N
    assert find_bypass("bash -c 'git commit -n'", POSIX) == DASH_N
    assert find_bypass("pwsh -c 'git commit -n'", POWERSHELL) == DASH_N
    assert "aramid.agent_bypass_cmd" not in sys.modules
    # a string handed to cmd is read by cmd's rules (FN-55)
    assert find_bypass("cmd //c 'git commit -n'", POSIX) == DASH_N
    assert "aramid.agent_bypass_cmd" in sys.modules
    monkeypatch.delitem(sys.modules, "aramid.agent_bypass_cmd")
    monkeypatch.delattr(aramid, "agent_bypass_cmd")
    assert find_bypass("git commit -n", CMD) == DASH_N
    assert "aramid.agent_bypass_cmd" in sys.modules


def test_a_string_handed_to_cmd_counts_against_the_cap_on_shells_within_shells():
    for command, shell in (("cmd //c 'git commit -n'", POSIX), ("cmd /c 'git commit -n'", POWERSHELL),
                           ('cmd /c "git commit -n"', CMD)):
        assert find_bypass(command, shell, _depth=ab._HANDED_DEPTH - 1) == DASH_N
        assert find_bypass(command, shell, _depth=ab._HANDED_DEPTH) == TOO_MANY


def test_cmd_is_not_a_shell_that_is_fed_on_standard_input():
    # _shell_launched hands the words of a shell to the readers of a command on its
    # standard input, which read the POSIX and the PowerShell grammars; cmd's is
    # neither. A command piped into cmd is a residual (NOT_SEEN in
    # test_agent_bypass_handed.py).
    assert ab._shell_launched(["cmd", "/c", "x"]) == (None, None)
    assert ab._shell_launched(["echo", "x", "|", "cmd"]) == (None, None)


def test_a_long_run_of_groups_and_commands_neither_raises_nor_takes_long():
    # the groups are read without recursion
    text = "(" * 5000 + "git commit -n" + ")" * 5000
    assert find_bypass(text, CMD) == DASH_N
    wide = " & ".join(["git status"] * 3000)
    assert find_bypass(wide, CMD) is None
    assert find_bypass(wide + " & git commit -n", CMD) == DASH_N


def test_a_command_that_is_not_a_string_is_let_through():
    for command in (None, 5, b"git commit -n", ["git", "commit", "-n"]):
        assert find_bypass(command, CMD) is None


def test_the_shell_that_runs_cmd_builds_the_line_cmd_scans():
    words = ["cmd", "/c", "git", "commit", "-m", 'a "b" c']
    assert ab._cmd_string(words, 0, POSIX) == ' git commit -m "a \\"b\\" c"'
    assert ab._cmd_string(words, 0, POWERSHELL) == ' git commit -m "a "b" c"'
    assert ab._cmd_string(words, 0, CMD) == ' git commit -m "a "b" c"'
    # the words before cmd are not its arguments, and without a switch it runs nothing
    assert ab._cmd_string(["env", "X=1", "cmd.exe", "//c", "x"], 2, POSIX) == " x"
    assert ab._cmd_string(["cmd", "git", "commit", "-n"], 0, POSIX) is None
    assert ab._cmd_string(["cmd"], 0, POWERSHELL) is None
    # an index outside the segment is no cmd; a negative one must not count from the end
    assert ab._cmd_string(words, -1, POSIX) is None
    assert ab._cmd_string(words, len(words), POSIX) is None
    assert ab._cmd_string(words, 9999, POSIX) is None


def test_a_close_without_red_proof_in_a_cmd_string_is_answered():
    close = "aramid ledger resolve id1 --fixed abc --test t --reason r"
    no_red = Bypass("no-red-proof", "ledger resolve", "--fixed")
    assert find_bypass(close, CMD) == no_red
    assert find_bypass(f'cmd //c "{close}"', POSIX) == no_red
    assert find_bypass(f'cmd /c "{close}"', POWERSHELL) == no_red
    assert find_bypass(f"{close} --red-proof", CMD) is None
    assert find_bypass(f'cmd //c "{close} --red-proof"', POSIX) is None


def test_random_texts_are_read_into_commands_of_words_without_raising():
    import random
    rng = random.Random(20261017)  # noqa: S311  -- seeded, reproducible, not crypto
    alphabet =' \t\n\r\0\\"\'^&|<>()@,;=:%!/-.0123456789abcdefgimnrstuy'
    for _ in range(3000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
        read = cmd.commands(text)
        assert all(words and all(isinstance(word, str) for word in words) for words in read)
        assert cmd.string_to_run(text) is None or isinstance(cmd.string_to_run(text), str)
        for style in (cmd.MSYS, cmd.POWERSHELL):
            assert isinstance(cmd.command_line(text.split(), style), str)
        for shell in (None, POSIX, POWERSHELL, CMD):
            find_bypass(text, shell)
