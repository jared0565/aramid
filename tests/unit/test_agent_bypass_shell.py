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
             "python -m aramid " + CLOSE]
    pieces = ["'", '"', BS, "`", "\n", "\r\n", BS + "\n", " ", ";", "$", "$(true)", "#", "''",
              '""', "x", "|", "&&", "$U", "(", ")"]
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
