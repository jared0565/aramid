"""A program a PowerShell call starts with Start-Process, `saps` or `start`
(FN-55, finding 0110f7 in docs/superpowers/plans/2026-09-21-aramid-1.0-blockers.md).

The operator's decision (2026-10-23, "A: read it"): the program Start-Process
starts and the arguments it is given are literal text, so they are read, as
the program would be read if the call named it itself.

What is right here is what git was handed. tests/fixtures/started-argv.json
is the record: each command run by PowerShell 7 in a scratch repository with
nothing staged, with real git writing its own whole argv down (the trace2
start event). It shows what the reading follows: Start-Process binds its
named parameters first and then the positional ones (the program, then the
arguments), joins a list of arguments with single spaces and quotes none of
them, and the program reads that one line by its own rules -- git by the C
runtime's.

Three lists, each checked against the record on every run, told the shell
and told none (as the hook is for a tool it does not know):

  NOT_SEEN  a bypass git was handed that the hook lets through, with why;
  ANSWERED  a bypass git was handed that the hook answers in another way;
  OVER      no bypass reached git and the hook answers all the same.

A command of the record in none of them is answered exactly as git's own
argv is judged, or let through when git was handed no bypass."""
import json
import random
from pathlib import Path

import pytest

from aramid import agent_bypass as ab
from aramid import agent_bypass_powershell as abp
from aramid.agent_bypass import POWERSHELL, Bypass, find_bypass
from aramid.agent_bypass_powershell import started

FIXTURE = Path(__file__).parent.parent / "fixtures" / "started-argv.json"
RECORD = {case["command"]: (case["status"], case["argv"])
          for case in json.loads(FIXTURE.read_text(encoding="ascii"))["cases"]}

DASH_N = Bypass("no-verify", "commit", "-n")
W = " -NoNewWindow -Wait"


def _judged(argvs):
    """The hook's own flag rules on the words git was handed."""
    for argv in argvs:
        found = ab._scan_one_git(argv, 0)
        if found is not None:
            return found
    return None


_VALUE = "a value only the run shows (the PowerShell reader's module docstring)"
NOT_SEEN = {
    "Start-Process git ('commit' + ' -n')" + W: _VALUE,
    "$a = 'commit -n'; Start-Process git $a" + W: _VALUE,
    "$a = 'commit','-n'; Start-Process git $a" + W: _VALUE,
    "Start-Process $env:ComSpec '/c git commit -n'" + W: _VALUE,
}
ANSWERED = {}
_REFUSED = "PowerShell refuses the call and starts nothing; read as if it ran"
_ANY_WORD = "a word named git starts a scan, as it does in any command"
_POSIX_TOO = ("a started POSIX shell's line is read the POSIX way as well as Git Bash's "
              "runtime makes it, and Git Bash keeps a backslash outside quotes")
OVER = {
    "Start-Process git 'commit -n' -W -NoNewWindow": _REFUSED + " (`-W` names more than one)",
    "Start-Process git 'commit -n' -Bogus" + W: _REFUSED + " (no such parameter)",
    "Start-Process -?x git 'commit -n'" + W: _REFUSED + " (no such parameter)",
    "Start-Process git -ArgumentList 'commit -n' -ArgumentList 'status'" + W:
        _REFUSED + " (a parameter given twice)",
    "Start-Process git 'commit -n' -Wait -NoNewWindow -RunAs": _REFUSED + " (no value)",
    "Start-Process git 'commit -n' -WhatIf:$true" + W:
        "-WhatIf with a value: the value is not read, so it is read as if it ran",
    "Write-Output Start-Process git 'commit -n'":
        "a word naming Start-Process starts a reading wherever it stands, as a word named git does",
    "Start-Process cmd '/c echo git commit -n'" + W: _ANY_WORD,
    "Start-Process git 'commit' '-n'" + W: _ANY_WORD + "; PowerShell refuses a third positional",
    "Start-Process git 'commit' -n -Wait": _ANY_WORD + "; the `-n` is Start-Process's -NoNewWindow",
    "Start-Process sh -ArgumentList '-c','git commit -n'" + W:
        _ANY_WORD + " (sh runs `git` alone: the words after its string are $0 and $1)",
    "Start-Process bash '-c git commit -n'" + W: _ANY_WORD + " (bash runs `git` alone)",
    "Start-Process bash '-c x\\''; git commit -n #'''" + W:
        _ANY_WORD + " (in the words the C runtime makes of the line)",
    "Start-Process bash '-c git\\ commit\\ -n'" + W: _POSIX_TOO + " (`\\ ` is a blank there)",
    "Start-Process bash '\\-c \"git commit -n\"'" + W: _POSIX_TOO + " (`\\-c` is `-c` there)",
    "Start-Process $null-FilePath:git 'commit -n'" + W:
        "the reader takes `$null` for nothing, so the rest is read as `-FilePath:git`; "
        "PowerShell started nothing",
}


def test_the_record_is_the_one_a_run_made():
    record = json.loads(FIXTURE.read_text(encoding="ascii"))
    assert record["provisional"] is False
    assert record["git"].startswith("git version 2.")
    assert record["pwsh"].split(".")[0] == "7"
    assert len(RECORD) == len(record["cases"]) >= 100
    assert {status for status, _ in RECORD.values()} == {"ran"}
    assert sum(1 for _, argvs in RECORD.values() if _judged(argvs)) >= 70
    assert sum(1 for _, argvs in RECORD.values() if not argvs) >= 5
    # every way to name the cmdlet is in it
    for name in ("Start-Process", "saps", "start", "START-PROCESS",
                 "Microsoft.PowerShell.Management\\Start-Process"):
        assert any(command.startswith(name + " ") for command in RECORD), name


def test_the_lists_name_commands_of_the_record():
    for listed in (NOT_SEEN, ANSWERED, OVER):
        assert set(listed) <= set(RECORD)
    assert all(_judged(RECORD[case][1]) for case in set(NOT_SEEN) | set(ANSWERED))
    assert not any(_judged(RECORD[case][1]) for case in OVER)


TOLD = pytest.mark.parametrize("told", [True, False], ids=["told", "not-told"])


def _answer(command, told):
    return find_bypass(command, POWERSHELL if told else None)


@TOLD
def test_nothing_started_with_a_bypass_is_let_through(told):
    missed = {command for command, (_, argvs) in RECORD.items()
              if _judged(argvs) and _answer(command, told) is None}
    assert missed == set(NOT_SEEN)


@TOLD
def test_every_bypass_the_record_holds_is_answered_as_git_was_handed_it(told):
    wrong = {command: _answer(command, told)
             for command, (_, argvs) in RECORD.items()
             if _judged(argvs) and command not in NOT_SEEN
             and _answer(command, told) != ANSWERED.get(command, _judged(argvs))}
    assert wrong == {}


@TOLD
def test_what_reached_git_as_no_bypass_is_answered_only_where_listed(told):
    over = {command for command, (_, argvs) in RECORD.items()
            if not _judged(argvs) and _answer(command, told) is not None}
    assert over == set(OVER)


_PROBE = "Start-Process bash '-c ''git commit \"$@\"'' x "
NOT_MODELLED = {
    _PROBE + "a\\x{'" + W: "a brace outside quotes, which the runtime expands: `{` alone vanished",
}


def test_git_bash_is_read_as_its_runtime_makes_its_words():
    # The record's probes start bash with `-c 'git commit "$@"' x TEST`: git is
    # handed the words Git Bash's runtime (msys) made of TEST, bash's own
    # reading of a script left out of it. Each probe pins one rule of
    # `_msys_argv`; the ones it does not model are listed, and still differ.
    probes = {command: argvs for command, (_, argvs) in RECORD.items()
              if command.startswith(_PROBE)}
    assert len(probes) >= 30 and set(NOT_MODELLED) <= set(probes)
    wrong = {}
    for command, argvs in probes.items():
        (program, line), = started(command)
        words = ab._msys_argv(line)
        assert program == "bash" and words[:3] == ["-c", 'git commit "$@"', "x"], command
        if (words[3:] == argvs[0][2:]) == (command in NOT_MODELLED):
            wrong[command] = (words[3:], argvs[0][2:])
    assert wrong == {}


# ---- what the record does not hold ----

def test_the_line_is_joined_from_the_list_and_cut_at_a_nul():
    assert started("Start-Process git -ArgumentList 'commit','-m','a b','-n' -Wait") == [
        ("git", "commit -m a b -n")]
    assert started("Start-Process git @('commit'; '-n')") == [("git", "commit -n")]
    assert started("Start-Process git 'commit,-n'") == [("git", "commit,-n")]
    assert started("Start-Process git commit, -n") == [("git", "commit -n")]
    assert started("Start-Process git 'commit','-n',$u") == [("git", "commit -n $")]
    assert started("Start-Process git ('commit' + ' -n')") == [("git", "$")]
    assert started("Start-Process $g 'commit -n'") == []
    assert started("Start-Process git 'commit -n' -WhatIf") == []
    assert started("Start-Process git 'commit -n' -WhatIf:$false") == [("git", "commit -n")]
    assert find_bypass('Start-Process git "commit`0 -n"', POWERSHELL) is None
    assert find_bypass('Start-Process git "commit --no-verify`0x"', POWERSHELL) == Bypass(
        "no-verify", "commit", "--no-verify")


def test_the_named_parameters_are_bound_before_the_positional_ones():
    assert started("Start-Process 'commit -n' -FilePath git") == [("git", "commit -n")]
    assert started("Start-Process -WorkingDirectory C:\\x git 'commit -n'") == [("git", "commit -n")]
    assert started("Start-Process -RunAs $c git 'commit -n'") == [("git", "commit -n")]
    assert started("Start-Process -Args:'commit','-n' git") == [("git", "commit -n")]
    # a name that is the start of only one, an alias, and one of several
    assert started("Start-Process -file git -arg 'commit -n'") == [("git", "commit -n")]
    assert started("Start-Process -lup git 'commit -n'") == [("git", "commit -n")]
    assert started("Start-Process -r x git 'commit -n'") == [("x", "git")]
    # a word that begins with a quote is a value, whatever it holds; a `-name:`
    # written plainly takes a quoted value (the record)
    assert started("Start-Process git '-C . commit -n -m a:b'") == [("git", "-C . commit -n -m a:b")]
    assert started("Start-Process '-FilePath:git' 'commit -n'") == [("-FilePath:git", "commit -n")]
    assert started('Start-Process git "-x:y" -Wait') == [("git", "-x:y")]
    assert started("Start-Process -ArgumentList:'commit -n' git") == [("git", "commit -n")]


def _nest(times, inner="g`u{69}t commit -n"):
    # the name is spelled so that only PowerShell's reading of the innermost
    # string makes it git: no word of an outer line names it
    text = inner
    for _ in range(times):
        text = "Start-Process pwsh '-c " + text.replace("'", "''") + "'"
    return text


def test_a_shell_started_within_started_shells_is_read_as_deep_as_the_cap():
    assert find_bypass(_nest(1), POWERSHELL) == DASH_N
    assert find_bypass(_nest(ab._HANDED_DEPTH), POWERSHELL) == DASH_N
    assert find_bypass(_nest(ab._HANDED_DEPTH), None) == DASH_N
    assert find_bypass(_nest(ab._HANDED_DEPTH, "g`u{69}t status"), POWERSHELL) is None


def test_one_started_shell_more_than_the_cap_is_refused_whatever_it_runs():
    too_many = Bypass("too-deep", "shells", str(ab._HANDED_DEPTH))
    assert find_bypass(_nest(ab._HANDED_DEPTH + 1), POWERSHELL) == too_many
    assert find_bypass(_nest(ab._HANDED_DEPTH + 1, "g`u{69}t status"), POWERSHELL) == too_many


def test_a_close_without_red_proof_started_is_answered():
    # Not in the record: a run of the real aramid writes its ledger. Its line
    # is read by the C runtime's rules, as git's is.
    close = "ledger resolve id1 --fixed abc --test t --reason r"
    no_red = Bypass("no-red-proof", "ledger resolve", "--fixed")
    assert find_bypass(f"Start-Process aramid '{close}' -Wait", POWERSHELL) == no_red
    assert find_bypass(f"saps aramid.exe -ArgumentList '{close}'", None) == no_red
    assert find_bypass(f"Start-Process aramid '{close} --red-proof' -Wait", POWERSHELL) is None


@pytest.mark.parametrize("command", [
    "npm start", "Start-Sleep 1", "Restart-Service x", "git commit -m 'start'",
    "Start-Process notepad 'x.txt'", "Start-Process git 'status'", "Start-Process",
    "start", "Start-Process -FilePath", "Start-Process git -ArgumentList", "saps ''"])
def test_a_start_that_starts_no_bypass_is_let_through(command):
    assert find_bypass(command, POWERSHELL) is None
    assert find_bypass(command) is None


def test_a_call_that_starts_nothing_does_not_load_the_cmd_reader(monkeypatch):
    import sys

    import aramid
    monkeypatch.delitem(sys.modules, "aramid.agent_bypass_cmd", raising=False)
    monkeypatch.delattr(aramid, "agent_bypass_cmd", raising=False)
    assert find_bypass("npm start", POWERSHELL) is None
    assert "aramid.agent_bypass_cmd" not in sys.modules
    # the C runtime's reading of the line is the cmd reader's
    assert find_bypass("Start-Process git 'commit -n'", POWERSHELL) == DASH_N
    assert "aramid.agent_bypass_cmd" in sys.modules


def test_no_text_makes_the_start_reader_raise():
    rng = random.Random(55)  # noqa: S311  -- seeded, reproducible, not crypto
    pieces = ["Start-Process", "saps", "start", "git", "pwsh", "cmd", "bash", "-FilePath",
              "-ArgumentList", "-a", "-f", "-Wait", "-WhatIf", "-WhatIf:$x", "-W", "-RunAs",
              "'commit -n'", "'commit','-n'", "@('a', 'b')", "('a'", ")", ",", ", ", "$x",
              "-c", "/c", "`0", "'", '"', "--%", "\n", ";", "|", "-n", "commit", "-Args:"]
    for _ in range(3000):
        text = " ".join(rng.choice(pieces) for _ in range(rng.randint(1, 10)))
        for program, line in started(text):
            assert isinstance(program, str) and isinstance(line, str), text
        find_bypass(text, POWERSHELL)
        find_bypass(text)


@pytest.mark.parametrize("word,seps,gaps,pieces", [
    ([], [], [], [""]), (["a", ",", "b"], [1], [], ["a", "b"]),
    (["a", ",", "\n", "b"], [1], [2], ["a", "b"]), (["a"], [-1, 2**63], [-2**63], ["a"]),
    ([",", "a"], [0], [], ["", "a"]), (["a", ","], [1], [], ["a", ""])])
def test_the_pieces_of_a_word_are_total_out_of_contract(word, seps, gaps, pieces):
    # the drain's fuzzer calls the reader's helpers directly (FN-55 7e8088)
    assert abp._parts(word, seps, gaps) == pieces


def test_the_parameter_names_are_total_out_of_contract():
    assert abp._start_parameter("") is None             # the start of every name
    assert abp._start_parameter("\0") is None
    assert abp._start_parameter("ARGS") == ("argumentlist", True)
    assert abp._start_parameter("w") is None             # Wait, WindowStyle, WhatIf ...
    assert abp._start_parameter("wa") == ("warningaction", True)   # an alias of its own
    assert abp._start_parameter("wai") == ("wait", False)
    assert not abp._is_parameter("", True, True)
    assert not abp._is_parameter("-", True, True)
    assert not abp._is_parameter("-1", True, True)
    assert not abp._is_parameter("-n", False, True)
    assert abp._is_parameter("-n:x", False, True)
    assert not abp._is_parameter("-n:x", False, False)    # it began with a quote
    assert not abp._is_parameter("-n", True, False)
    assert abp._is_parameter("-?", True, True)


@pytest.mark.parametrize("depth", [-2**63, -1, 0, ab._HANDED_DEPTH, 2**63])
def test_the_started_reader_is_total_at_any_depth(depth):
    assert ab._from_started("Start-Process git 'commit -n'", depth) == DASH_N
    inner = ab._from_started("Start-Process pwsh '-c g`u{69}t commit -n'", depth)
    too_many = Bypass("too-deep", "shells", str(ab._HANDED_DEPTH))
    assert inner == (too_many if depth >= ab._HANDED_DEPTH else DASH_N)
