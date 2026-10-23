"""`find_bypass(command, shell)`: the reading is chosen by the shell the hook
was told (FN-45; spec docs/superpowers/specs/2026-10-12-aramid-powershell-
reading-design.md, section 3.2).

  no shell     the two readings of 0.20.8: the POSIX one, and a second with
               PowerShell's backtick for the close rule. Every other test
               file calls `find_bypass(command)` and none of them changed.
               One thing is new there: the cheap test in front of the
               readings no longer says no to a name written `g"i"t`.
  "posix"      the POSIX reading alone, for every rule
  "powershell" PowerShell's own reading (tests/unit/test_agent_bypass_
               powershell.py), for every rule

What bash does with the commands below was read off bash on 2026-10-12, with
a function that prints its arguments: an unset `$U`, `${U}` and `$(true)`
leave no word behind, `"$U"` leaves an empty one, and `g"i"t`, `g'i't`,
`g\\it` and a `git` broken over a continued line all run git."""
import pytest

from aramid import agent_bypass as ab
from aramid.agent_bypass import POSIX, POWERSHELL, Bypass, find_bypass

NO_VERIFY = Bypass("no-verify", "commit", "--no-verify")
DASH_N = Bypass("no-verify", "commit", "-n")
NO_RED = Bypass("no-red-proof", "ledger resolve", "--fixed")
CLOSE = "ledger resolve llm1 --fixed abc --test t --reason r"
BS = chr(92)


def test_the_shells_are_these_two_names():
    assert (POSIX, POWERSHELL) == ("posix", "powershell")


# ---- every shell sees the plain cases ----

@pytest.mark.parametrize("shell", [None, POSIX, POWERSHELL])
def test_the_plain_bypasses_are_answered_whatever_the_shell(shell):
    assert find_bypass("git commit -m x --no-verify", shell) == NO_VERIFY
    assert find_bypass("git status && git commit -n -m x", shell) == DASH_N
    assert find_bypass("git -c core.hooksPath=/tmp/h commit -m x", shell) == Bypass(
        "hooks-path", "commit", "core.hooksPath=/tmp/h")
    assert find_bypass(f"aramid {CLOSE}", shell) == NO_RED
    assert find_bypass(f"aramid {CLOSE} --red-proof", shell) is None
    assert find_bypass("pytest -q tests/unit", shell) is None
    assert find_bypass('echo "git commit --no-verify"', shell) is None
    assert find_bypass(["git", "commit", "--no-verify"], shell) is None
    assert find_bypass(None, shell) is None


def test_a_shell_this_version_does_not_know_is_read_as_none_named():
    for command in ("git commit -n", f"aramid {CLOSE}", 'g"i"t commit -n', "git $U commit -n"):
        assert find_bypass(command, "fish") == find_bypass(command)
        assert find_bypass(command, "") == find_bypass(command)


# ---- each shell's own quoting decides ----

def test_a_string_that_ends_in_a_backslash_is_read_by_the_shell_that_runs_it():
    # PowerShell ends the string at the quote; a POSIX shell does not
    command = 'git commit -m "C:' + BS + "src" + BS + '" --no-verify'
    assert find_bypass(command, POWERSHELL) == NO_VERIFY
    assert find_bypass(command, POSIX) is None
    assert find_bypass(command) is None                 # 0.20.8: a miss in PowerShell
    close = f'aramid {CLOSE} "C:' + BS + "src" + BS + '" --red-proof'
    assert find_bypass(close, POWERSHELL) is None
    assert find_bypass(close, POSIX) == NO_RED
    assert find_bypass(close) == NO_RED                 # 0.20.8: a false alarm in PowerShell


def test_a_backslash_in_front_of_a_quote_is_read_by_the_shell_that_runs_it():
    # bash: the second quote is escaped and the flag is inside the message.
    # PowerShell: the message ends at that quote and the flag is a word.
    command = "git commit -m " + '"a' + BS + '" --no-verify "b"'
    assert find_bypass(command, POSIX) is None
    assert find_bypass(command, POWERSHELL) == NO_VERIFY


def test_a_backtick_is_read_by_the_shell_that_runs_it():
    command = "git commit --no-ver`ify"
    assert find_bypass(command, POWERSHELL) == NO_VERIFY
    assert find_bypass(command, POSIX) is None
    assert find_bypass(command) is None


def test_a_bash_call_is_not_read_with_powershells_backtick():
    # Read with the backtick as an escape this holds a close, its --fixed
    # outside the string; read the POSIX way the --fixed is inside it. With
    # no shell named both readings are asked, and the second one answers.
    command = ('aramid ledger resolve llm1 --reason "see `"issue #12`" now" --fixed abc --test t'
               '\necho "C:' + BS + "src" + BS + '"')
    assert find_bypass(command) == NO_RED
    assert find_bypass(command, POSIX) is None
    assert find_bypass(command, POWERSHELL) == NO_RED


def test_a_powershell_call_is_not_read_the_posix_way():
    # the two false alarms 0.20.8 pins (test_agent_bypass_resolve.py): proper
    # closes in PowerShell, answered because the POSIX reading sees a comment
    for reason in ('"see `"issue #12`" now"', '"a `"b; c`" d"'):
        command = f"aramid ledger resolve llm1 --fixed abc --test t --reason {reason} --red-proof"
        assert find_bypass(command) == NO_RED
        assert find_bypass(command, POSIX) == NO_RED
        assert find_bypass(command, POWERSHELL) is None


# ---- a value in front of the subcommand (finding 4ce6a085) ----

@pytest.mark.parametrize("value", ["$(true)", "$U", "${U}", "$U$V", "$(echo)"])
def test_a_word_that_starts_with_a_dollar_sign_is_stepped_over_for_a_known_shell(value):
    for shell in (POSIX, POWERSHELL):
        assert find_bypass(f"git {value} commit -n", shell) == DASH_N
        assert find_bypass(f"git {value} push --no-verify", shell) == Bypass(
            "no-verify", "push", "--no-verify")
        assert find_bypass(f"git {value} -c core.hooksPath=h commit", shell) == Bypass(
            "hooks-path", "commit", "core.hooksPath=h")
        assert find_bypass(f"git {value} status", shell) is None
    # with no shell named it is 0.20.8: the word is taken for the subcommand
    assert find_bypass(f"git {value} commit -n") is None


def test_the_step_over_is_the_scanners_and_off_unless_asked_for():
    seg = ["git", "$U", "commit", "-n"]
    assert ab._scan_one_git(seg, 0) is None
    assert ab._scan_one_git(seg, 0, False) is None
    assert ab._scan_one_git(seg, 0, True) == DASH_N
    # only in front of the subcommand: after it a `$` word is an argument
    assert ab._scan_one_git(["git", "commit", "$U", "-n"], 0, True) == DASH_N
    assert ab._scan_one_git(["git", "commit", "-m", "$U"], 0, True) is None
    # and a word that only holds one is the subcommand
    assert ab._scan_one_git(["git", "x$U", "commit", "-n"], 0, True) is None


def test_the_close_rule_stepped_over_such_a_word_before_and_still_does():
    for shell in (None, POSIX, POWERSHELL):
        assert find_bypass(f"aramid $U {CLOSE}", shell) == NO_RED


# ---- the cheap answer in front of the reading ----

@pytest.mark.parametrize("name", ['g"i"t', "g'i't", "g" + BS + "it", "gi" + BS + "\nt",
                                  "gi" + BS + "\r\nt", '"g"it', "'git'"])
def test_bash_takes_quotes_and_backslashes_out_of_a_program_name(name):
    # Up to 0.20.8 none of these was answered: the cheap test looked for the
    # letters `git` in the text as written. With no shell named the POSIX
    # reading still answers, so the fix reaches a harness that names no tool.
    for shell in (POSIX, None):
        assert find_bypass(f"{name} commit --no-verify", shell) == NO_VERIFY
        assert find_bypass(f"{name} status", shell) is None


@pytest.mark.parametrize("name", ['ara"mi"d', "ara'mi'd", "ara" + BS + "mid", "ar" + BS + "\namid"])
def test_bash_takes_them_out_of_aramids_name_too(name):
    for shell in (POSIX, None):
        assert find_bypass(f"{name} {CLOSE}", shell) == NO_RED
        assert find_bypass(f"{name} {CLOSE} --red-proof", shell) is None


@pytest.mark.parametrize("name", ['g"i"t', "g'i't", "g`it", "`u{67}it", "G`IT"])
def test_powershell_takes_quotes_and_backticks_out_of_a_program_name(name):
    assert find_bypass(f"{name} commit --no-verify", POWERSHELL) == NO_VERIFY


def test_a_backslash_in_a_name_is_a_character_in_powershell():
    assert find_bypass("g" + BS + "it commit --no-verify", POWERSHELL) is None
    assert find_bypass("ara" + BS + f"mid {CLOSE}", POWERSHELL) is None


def test_a_backtick_in_a_name_is_powershells_to_take_out():
    # With no shell named the second reading takes a backtick for an escape
    # inside double quotes only, and leaves it in the word: a limit of that
    # reading, which a call the hook is told is PowerShell's does not have.
    assert find_bypass(f"ara`mid {CLOSE}", POWERSHELL) == NO_RED
    assert find_bypass(f"ara`mid {CLOSE}") is None
    assert find_bypass(f"ara`mid {CLOSE}", POSIX) is None
    assert find_bypass("g`it commit -n", POWERSHELL) == DASH_N
    assert find_bypass("g`it commit -n") is None


def test_the_cheap_test_takes_out_what_a_shell_takes_out_of_a_word():
    f = ab._may_name_a_program
    assert f("git commit") and f("GIT commit") and f("Aramid x") and f("x.git")
    assert not f("pytest -q") and not f("ls") and not f("")
    for mark in ("'", '"', BS, "\n", "\r"):
        assert f(f"g{mark}it x") and f(f"gi{mark}{mark}t x") and f(f"ara{mark}mid x"), mark
    # and nothing else: a blank, a dollar sign or a backtick parts the letters
    # for good (no token of the POSIX reading loses one of those)
    for other in (" ", "$", ";", "-", "`", chr(0x2019)):
        assert not f(f"g{other}it x") and not f(f"ara{other}mid x"), other


def test_the_cheap_test_never_costs_an_answer():
    """With the cheap test forced to yes the reading gives the same answer,
    for no shell and for POSIX: a no from it is never a bypass not seen. The
    commands are a bypass or a close with marks, blanks and joints dropped
    into them, the program's name included."""
    import random

    rng = random.Random(4545)  # noqa: S311  -- seeded, reproducible, not crypto
    bases = ["git commit -m x --no-verify", "git commit -n", "git push --no-verify",
             "git -c core.hooksPath=h commit", f"aramid {CLOSE}", f"aramid {CLOSE} --red-proof",
             "python -m aramid " + CLOSE, "$'" + BS + "x67it' commit -n"]
    pieces = ["'", '"', BS, "`", "\n", "\r\n", BS + "\n", " ", ";", "$", "$(true)", "#", "''",
              '""', "x", "|", "&&", "$U", "(", ")", "$'"]
    commands = []
    for _ in range(3000):
        text = rng.choice(bases)
        for _ in range(rng.randint(1, 4)):
            at = rng.randint(0, min(len(text), 8) if rng.random() < 0.7 else len(text))
            text = text[:at] + rng.choice(pieces) + text[at:]
        commands.append(text)
    asked = {shell: [find_bypass(c, shell) for c in commands] for shell in (None, POSIX)}
    refused = sum(not ab._may_name_a_program(c) for c in commands)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(ab, "_may_name_a_program", lambda command: True)
        for shell in (None, POSIX):
            assert [find_bypass(c, shell) for c in commands] == asked[shell]
    # the comparison had something to compare: the cheap test did say no
    # to some of these, and yes to some whose name is not written plainly
    assert 100 < refused < 2900
    assert sum(a is not None for a in asked[POSIX]) > 300


def test_a_powershell_call_is_read_without_the_cheap_test(monkeypatch):
    def never(command):
        raise AssertionError("the cheap test was asked")
    monkeypatch.setattr(ab, "_may_name_a_program", never)
    assert find_bypass("g`it commit -n", POWERSHELL) == DASH_N
    assert find_bypass("Get-ChildItem", POWERSHELL) is None


def test_a_powershell_call_does_not_go_through_the_posix_reader(monkeypatch):
    def never(*a, **k):
        raise AssertionError("the POSIX reader was asked")
    monkeypatch.setattr(ab, "_tokens", never)
    assert find_bypass("git commit -n", POWERSHELL) == DASH_N


def test_a_bash_call_does_not_load_the_powershell_reader(monkeypatch):
    import sys

    import aramid
    monkeypatch.delitem(sys.modules, "aramid.agent_bypass_powershell", raising=False)
    monkeypatch.delattr(aramid, "agent_bypass_powershell", raising=False)
    assert find_bypass("git commit -n", POSIX) == DASH_N
    assert find_bypass("git commit -n") == DASH_N
    assert find_bypass("bash -c 'git commit -n'", POSIX) == DASH_N
    # a Bash call that names nothing either: what PowerShell starts is read
    # for a call no shell is named for alone (FN-55 e623dc)
    assert find_bypass("ls -la", POSIX) is None
    assert "aramid.agent_bypass_powershell" not in sys.modules
    # a string a Bash call hands to PowerShell is read by PowerShell's rules (FN-55)
    assert find_bypass("pwsh -c 'git commit -n'", POSIX) == DASH_N
    assert "aramid.agent_bypass_powershell" in sys.modules
    monkeypatch.delitem(sys.modules, "aramid.agent_bypass_powershell")
    monkeypatch.delattr(aramid, "agent_bypass_powershell")
    assert find_bypass("git commit -n", POWERSHELL) == DASH_N
    assert "aramid.agent_bypass_powershell" in sys.modules


# ---- bash's ANSI-C quoting, $'...' (FN-55 43dd71) ----

# What git was handed for each command, read off real git (trace2) under Git Bash 5.2.37 on
# 2026-10-23, each command run twice with the same answer: the operator's decision that day
# was "Read $'...'". The table is written from the captures, not typed: a `\u` and four hex
# digits typed in was decoded on its way in.
ANSI_C = [
    ("$'\\x67it' commit -n",
     [['git', 'commit', '-n']]),
    ("$'\\147\\151\\164' commit -n",
     [['git', 'commit', '-n']]),
    ("$'\\U00000067it' commit -n",
     [['git', 'commit', '-n']]),
    ('g$\'\\x69\'"t" commit -n',
     [['git', 'commit', '-n']]),
    ("gi$'t' commit -n",
     [['git', 'commit', '-n']]),
    ("git commit $'--no-verify'",
     [['git', 'commit', '--no-verify']]),
    ("git commit $'-n'",
     [['git', 'commit', '-n']]),
    ("git commit -m $'it\\'s' --no-verify",
     [['git', 'commit', '-m', "it's", '--no-verify']]),
    ("git commit -m a$'b'c -n",
     [['git', 'commit', '-m', 'abc', '-n']]),
    ("git commit -m $'[\\x4][\\x41][\\x414]' -n",
     [['git', 'commit', '-m', '[\x04][A][A4]', '-n']]),
    ("git commit -m $'[\\1][\\101][\\1011][\\0101]' -n",
     [['git', 'commit', '-m', '[\x01][A][A1][\x081]', '-n']]),
    ("git commit -m $'[\\U41][\\U00000041][\\U000000411]' -n",
     [['git', 'commit', '-m', '[A][A][A1]', '-n']]),
    ("git commit -m $'[\\cA][\\ca][\\c?][\\c@]' -n",
     [['git', 'commit', '-m', '[\x01][\x01][\x7f][', '-n']]),
    ("git commit -m $'[\\e][\\E]' -n",
     [['git', 'commit', '-m', '[\x1b][\x1b]', '-n']]),
    ("git commit -m $'[\\a][\\b][\\f][\\n][\\r][\\t][\\v]' -n",
     [['git', 'commit', '-m', '[\x07][\x08][\x0c][\n][\r][\t][\x0b]', '-n']]),
    ('git commit -m $\'[\\\\][\\\'][\\"][\\?]\' -n',
     [['git', 'commit', '-m', '[\\][\']["][?]', '-n']]),
    ("git commit -m $'[\\-][\\z][\\ ]' -n",
     [['git', 'commit', '-m', '[\\-][\\z][\\ ]', '-n']]),
    ("git commit -m $'[\\x][\\xg][\\u][\\U][\\c]' -n",
     [['git', 'commit', '-m', '[\\x][\\xg][\\u][\\U][\x1d', '-n']]),
    ("git commit -m $'a\\0b' -n",
     [['git', 'commit', '-m', 'a', '-n']]),
    ("git commit -m $'a\\x00b' -n",
     [['git', 'commit', '-m', 'a', '-n']]),
    ('git commit -m "$\'\\x41\'" -n',
     [['git', 'commit', '-m', "$'\\x41'", '-n']]),
    ("git commit -m \\$'\\x41' -n",
     [['git', 'commit', '-m', '$\\x41', '-n']]),
    ("git commit -m '$'\\x41 -n",
     [['git', 'commit', '-m', '$x41', '-n']]),
    ("git commit $'--no-verify",
     []),
    ("git commit -m $'a\\' -n",
     []),
    ("$'\\u0067it' commit -n",
     [['git', 'commit', '-n']]),
    ("git commit -m $'[\\u41][\\u0041][\\u00411][\\u004]' -n",
     [['git', 'commit', '-m', '[A][A][A1][\x04]', '-n']]),
    ("git commit -m $'[\\uD800][\\u00e9][\\U0001F600][\\UFFFFFFFF]' -n",
     [['git', 'commit', '-m', '[\\uD800][\xe9][\\U0001F600][]', '-n']]),
    ("git commit -m $'[\\c\\\\]x' -n",
     [['git', 'commit', '-m', '[\x1c]x', '-n']]),
    ("git commit -m $'a\\0b'c -n",
     [['git', 'commit', '-m', 'ac', '-n']]),
    ("git commit -m $'a\\c@b'c -n",
     [['git', 'commit', '-m', 'ac', '-n']]),
    ("git commit -m $'[\\u007f][\\u0080][\\U00000080][\\u0081]' -n",
     [['git', 'commit', '-m', '[\x7f][\x80][\x80][\x81]', '-n']]),
    ("git commit -m $'[\\uFFFF][\\U0000FFFF][\\U00010000][\\uFFFE]' -n",
     [['git', 'commit', '-m', '[\\uFFFF][\\uFFFF][\\U00010000][\\uFFFE]', '-n']]),
    ("git commit -m $'a\\t' -n",
     [['git', 'commit', '-m', 'a\t', '-n']]),
    ("git commit -m $'a\\x' -n",
     [['git', 'commit', '-m', 'a\\x', '-n']]),
    ("git commit -m $'a\\x4' -n",
     [['git', 'commit', '-m', 'a\x04', '-n']]),
    ("git commit -m $'[\\u00ff][\\u0100][\\U000000FF][\\U00000100]' -n",
     [['git', 'commit', '-m', '[\xff][\\u0100][\xff][\\u0100]', '-n']]),
    ("git commit $'--no-verify\\UFFFFFFFF'",
     [['git', 'commit', '--no-verify']]),
    ("git commit $'--no-verify\\U00110000'",
     [['git', 'commit', '--no-verify\\U00110000']]),
    ("git commit $'--no-verify\\U7FFFFFFF'",
     [['git', 'commit', '--no-verify\\U7FFFFFFF']]),
    ("git commit $'--no-verify\\0junk'",
     [['git', 'commit', '--no-verify']]),
    ("git commit $'-n\\x00'",
     [['git', 'commit', '-n']]),
    ("git commit $'--no-verify\\uD800'",
     [['git', 'commit', '--no-verify\\uD800']]),
    ("git commit -m $'[\\U0010FFFF][\\U0000D800][\\xe9][\\351]' -n",
     [['git', 'commit', '-m', '[\\U0010FFFF][\\uD800][\xe9][\xe9]', '-n']]),
    ("git commit -m $'a\\c'b -n",
     [['git', 'commit', '-m', 'a\\cb', '-n']]),
    ("git commit -m $'[\\c\\x41]' -n",
     [['git', 'commit', '-m', '[\x1cx41]', '-n']]),
    ("git commit -m $'[\\U80000000][\\U7FFFFFFF][\\UF0000000][\\UFFFFFFFE][\\U8000000][\\Uffffffff]' -n",
     [['git', 'commit', '-m', '[][\\U7FFFFFFF][][][\\U08000000][]', '-n']]),
    ("git commit $'-n\\U80000000'",
     [['git', 'commit', '-n']]),
    ("git commit $'-n\\U8000000'",
     [['git', 'commit', '-n\\U08000000']]),
    ("git commit -m $'[\\400][\\401][\\555][\\777][\\377]' -n",
     [['git', 'commit', '-m', '[', '-n']]),
    ("git commit $'-n\\400'",
     [['git', 'commit', '-n']]),
    ("git commit $'-n\\500x'",
     [['git', 'commit', '-n@x']]),
    ("git commit $'\\455n'",
     [['git', 'commit', '-n']]),
    ('git commit "$\'\\x2dn\'" ',
     [['git', 'commit', "$'\\x2dn'"]]),
    ("git commit \\$'\\x2dn'",
     [['git', 'commit', '$\\x2dn']]),
    ("git commit '$'\\x2dn",
     [['git', 'commit', '$x2dn']]),
    ("git $'' commit -n",
     [['git', '', 'commit', '-n']]),
    ("git commit $'' -n",
     [['git', 'commit', '', '-n']]),
    ("echo $'x\\ngit commit -n'",
     []),
    ("echo $'x;git commit -n'",
     []),
    ("echo $'\\x3b' git commit -n",
     []),
    ("echo $'x\\x0agit commit -n'",
     []),
    ("git $'-c' $'core.hooksPath=h' commit -m x",
     [['git', '-c', 'core.hooksPath=h', 'commit', '-m', 'x']]),
    ("git -c $'core.hooks\\x50ath=h' commit -m x",
     [['git', '-c', 'core.hooksPath=h', 'commit', '-m', 'x']]),
]


def _judged(argvs):
    """The hook's own flag rules on the words git was handed."""
    for argv in argvs:
        found = ab._scan_one_git(argv, 0)
        if found is not None:
            return found
    return None


@pytest.mark.parametrize("command,argvs", ANSI_C)
def test_the_reading_makes_the_words_bash_makes_of_ansi_c_quoting(command, argvs):
    if argvs:
        tokens, whole = ab._tokens(command, False, ansi_c=True)
        assert whole and [t.translate(ab._PUT_BACK) for t in tokens] == argvs[0]


# Answered though bash ran no git: a word named git starts a scan, as it does in
# any command (`echo git commit -n`; OVER in tests/unit/test_agent_bypass_handed.py)
ANSI_C_OVER = {"echo $'" + BS + "x3b' git commit -n": DASH_N}


@pytest.mark.parametrize("command,argvs", ANSI_C)
def test_a_command_in_ansi_c_quoting_is_answered_as_what_git_was_handed(command, argvs):
    for shell in (POSIX, None):
        assert find_bypass(command, shell) == ANSI_C_OVER.get(command, _judged(argvs)), shell


def test_every_over_read_listed_for_ansi_c_quoting_is_in_the_table():
    assert set(ANSI_C_OVER) <= {command for command, _argvs in ANSI_C}


def test_the_ansi_c_readers_read_only_what_is_theirs():
    # `_ansi_c` reads only a `$'` at the index it is given, and
    # `_ansi_c_body` keeps a backslash at the end, which the drain's fuzzer
    # can hand it though no closed quote leaves one there
    assert ab._ansi_c("ab'c", 0) is None
    assert ab._ansi_c("x$'a'", 1) == ("a", 5)
    assert ab._ansi_c_body("a" + BS) == "a" + BS


def test_an_ansi_c_quote_that_never_closes_still_stops_the_reading():
    # bash runs nothing for either (in the table); the words in front are read
    assert ab._tokens("git commit $'--no-verify", False, ansi_c=True) == (["git", "commit"], False)
    assert ab._tokens("git commit -m $'a" + BS + "' -n", False, ansi_c=True) == (
        ["git", "commit", "-m"], False)


@pytest.mark.parametrize("shell", [POSIX, None])
def test_a_reason_in_ansi_c_quoting_ends_where_bash_ends_it(shell):
    # `$'it\'s'` is the one word it's (in the table, as git's -m): the
    # --red-proof after it counts, where up to now it was read as cut off
    close = "aramid ledger resolve llm1 --fixed abc --test t --reason $'it" + BS + "'s'"
    assert find_bypass(close + " --red-proof", shell) is None
    assert find_bypass(close, shell) == NO_RED


def test_the_cheap_test_says_yes_to_ansi_c_quoting():
    assert ab._may_name_a_program("$'" + BS + "x67it' commit -n")
    assert ab._may_name_a_program("x $'y'")


def test_the_line_a_started_shell_is_handed_is_not_read_for_ansi_c_quoting():
    # its quotes are the runtime's, not bash's (`_from_started`)
    assert ab._tokens("-c $'git'", False) == (["-c", "$git"], True)
