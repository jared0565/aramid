"""A command handed to another shell as a string (FN-55 in
docs/superpowers/plans/2026-09-21-aramid-1.0-blockers.md).

The operator's decision (2026-10-13, "Read the string"): the fixed-string
argument of `bash`, `sh` or `zsh -c`, of `pwsh` or `powershell -c` /
`-Command`, and of `cmd /c` is read by that shell's rules as a command of its
own. A string built when the call runs stays out of reach, as for `eval`.

What is right here is what git was handed. tests/fixtures/handed-argv.json is
the record: each command run in the shell the hook names (Git Bash for a Bash
call, PowerShell 7 for a PowerShell call), in a scratch repository with nothing
staged, with real git writing its own whole argv down (the trace2 start event).
The file says which git, bash and PowerShell.

Three lists, each checked against the record on every run:

  NOT_SEEN  a bypass git was handed that the hook lets through, with why;
  ANSWERED  a bypass git was handed that the hook answers in another way;
  OVER      no bypass reached git and the hook answers all the same.

A command of the record in none of them is answered exactly as git's own
argv is judged, or let through when git was handed no bypass."""
import json
import shlex
from pathlib import Path

import pytest

from aramid import agent_bypass as ab
from aramid.agent_bypass import POSIX, POWERSHELL, Bypass, find_bypass
from aramid.agent_bypass_powershell import _DEPTH

FIXTURE = Path(__file__).parent.parent / "fixtures" / "handed-argv.json"
RECORD = {(case["shell"], case["command"]): (case["status"], case["argv"])
          for case in json.loads(FIXTURE.read_text(encoding="ascii"))["cases"]}

DASH_N = Bypass("no-verify", "commit", "-n")
NO_VERIFY = Bypass("no-verify", "commit", "--no-verify")
TOO_DEEP = Bypass("too-deep", "", str(_DEPTH))
TOO_MANY = Bypass("too-deep", "shells", str(ab._HANDED_DEPTH))
NO_RED = Bypass("no-red-proof", "ledger resolve", "--fixed")

G41 = "(" * 41 + "git commit -n" + ")" * 41
H41 = "(" * 41 + "Write-Output hi" + ")" * 41
ENC = "ZwBpAHQAIABjAG8AbQBtAGkAdAAgAC0AbgA="   # "git commit -n", UTF-16LE, base64


def _judged(argvs):
    """The hook's own flag rules on the words git was handed."""
    for argv in argvs:
        found = ab._scan_one_git(argv, 0)
        if found is not None:
            return found
    return None


def _case(shell):
    return POSIX if shell == "posix" else POWERSHELL


_LATER = "cmd's own reading of the string: the next commit"
_RUN_TIME = "the flag is an argument the string is handed when it runs"
_ENCODED = "an encoded command, which the decision does not name: put to the operator"
NOT_SEEN = {
    ("posix", "bash -c 'git commit \"$@\"' x -n"): _RUN_TIME,
    ("posix", "bash -c 'git commit $0' -n"): _RUN_TIME,
    ("posix", "pwsh -cwa 'git commit $args' -n"): _RUN_TIME,
    ("posix", "bash -c $'git commit -n'"): "bash's $'...' is not followed (module docstring)",
    ("posix", "pwsh -c '& g$(\"i\")t commit -n'"):
        "the name is worked out when it runs; the PowerShell reader takes a $( ) in a word"
        " as empty in any call (its module docstring)",
    ("posix", f"pwsh -EncodedCommand {ENC}"): _ENCODED,
    ("posix", f"pwsh -e {ENC}"): _ENCODED,
    ("powershell", f"pwsh -EncodedCommand {ENC}"): _ENCODED,
    ("posix", "cmd //c 'git commit -n'"): _LATER,
    ("posix", "cmd //C 'git commit -n'"): _LATER,
    ("posix", "cmd //k 'git commit -n'"): _LATER,
    ("posix", "cmd //r 'git commit -n'"): _LATER,
    ("posix", "cmd //c 'g^it commit -n'"): _LATER,
    ("posix", "cmd //s //c 'git commit -n'"): _LATER,
    ("posix", "cmd //c 'git status & git commit -n'"): _LATER,
    ("posix", "cmd.exe //c 'git commit -n'"): _LATER,
    ("posix", "MSYS_NO_PATHCONV=1 cmd /c 'git commit -n'"): _LATER,
    ("powershell", "cmd /c 'git commit -n'"): _LATER,
    ("powershell", 'cmd /c "git commit -n"'): _LATER,
    ("powershell", "cmd /C 'git commit -n'"): _LATER,
    ("powershell", "cmd /k 'git commit -n'"): _LATER,
    ("powershell", "cmd /r 'git commit -n'"): _LATER,
    ("powershell", "cmd /c 'g^it commit -n'"): _LATER,
    ("powershell", "cmd /s /c 'git commit -n'"): _LATER,
    ("powershell", "cmd /c 'git status & git commit -n'"): _LATER,
    ("powershell", "cmd.exe /c 'git commit -n'"): _LATER,
}
# A bypass git was handed, answered in another way than git's argv is judged.
HOOKS_DEV_NULL = Bypass("hooks-path", "commit", "core.hooksPath=/dev/null")
ANSWERED = {
    ("posix", f"pwsh -c '{G41}'"): TOO_DEEP,     # the inner reading is cut off by the cap
    ("powershell", f"pwsh -c '{G41}'"): TOO_DEEP,
    # Git Bash rewrote the path in the value for git.exe (`nul`); the hook
    # reads the value as written
    ("posix", "bash -c 'git -c core.hooksPath=/dev/null commit'"): HOOKS_DEV_NULL,
    ("powershell", "bash -c 'git -c core.hooksPath=/dev/null commit'"): HOOKS_DEV_NULL,
}
_ANY_WORD = "a word named git starts a scan, as it does in any command"
OVER = {
    ("posix", "bash -c 'echo git commit -n'"): _ANY_WORD,
    ("posix", "powershell -File x.ps1 git commit -n"): _ANY_WORD,
    ("posix", "pwsh /c 'git commit -n'"):
        "Git Bash makes a lone /c a path, so pwsh runs nothing; read as the switch",
    ("posix", f"pwsh -c '{H41}'"):
        "too deep to read: refused whatever it names (the operator's decision, 2026-10-14)",
}


def test_the_record_is_the_one_a_run_made():
    record = json.loads(FIXTURE.read_text(encoding="ascii"))
    assert record["provisional"] is False
    assert record["git"].startswith("git version 2.")
    assert "msys" in record["bash"]
    assert record["pwsh"].split(".")[0] == "7"
    assert record["powershell"].startswith("5.1")
    assert len(RECORD) == len(record["cases"]) >= 130
    assert {status for status, _ in RECORD.values()} == {"ran"}
    # the record holds both: commands that handed git a bypass, and ones that did not
    assert sum(1 for _, argvs in RECORD.values() if _judged(argvs)) >= 100
    assert sum(1 for _, argvs in RECORD.values() if not argvs) >= 10


def test_the_lists_name_commands_of_the_record():
    for listed in (NOT_SEEN, ANSWERED, OVER):
        assert set(listed) <= set(RECORD)
    assert all(_judged(RECORD[case][1]) for case in NOT_SEEN | ANSWERED)
    assert not any(_judged(RECORD[case][1]) for case in OVER)


def test_nothing_a_shell_handed_git_as_a_bypass_is_let_through():
    missed = {case for case, (_, argvs) in RECORD.items()
              if _judged(argvs) and find_bypass(case[1], _case(case[0])) is None}
    assert missed == set(NOT_SEEN)


def test_every_bypass_the_record_holds_is_answered_as_git_was_handed_it():
    wrong = {case: find_bypass(case[1], _case(case[0]))
             for case, (_, argvs) in RECORD.items()
             if _judged(argvs) and case not in NOT_SEEN
             and find_bypass(case[1], _case(case[0])) != ANSWERED.get(case, _judged(argvs))}
    assert wrong == {}


def test_what_reached_git_as_no_bypass_is_answered_only_where_listed():
    over = {case for case, (_, argvs) in RECORD.items()
            if not _judged(argvs) and find_bypass(case[1], _case(case[0])) is not None}
    assert over == set(OVER)


# ---- the parts the record shows, one at a time ----

@pytest.mark.parametrize("command", [
    "bash -c -e 'git commit -n'", "bash -ce 'git commit -n'", "bash -o pipefail -c 'git commit -n'",
    "bash +O extglob -c 'git commit -n'", "bash --rcfile /dev/null -c 'git commit -n'",
    "bash -c -- 'git commit -n'", "BASH -c 'git commit -n'", "b'a'sh -c 'git commit -n'",
    "env bash -c 'git commit -n'", "bash -c 'git commit -n' extra words"])
def test_a_posix_shell_runs_the_first_word_after_its_options_when_c_is_one_of_them(command):
    assert RECORD[("posix", command)][1] == [["git", "commit", "-n"]]
    assert find_bypass(command, POSIX) == DASH_N


@pytest.mark.parametrize("command", [
    "bash -c + 'git commit -n'", "bash + -c 'git commit -n'", "bash +e -c 'git commit -n'",
    "bash +c 'git commit -n'", "bash $u -c 'git commit -n'"])
def test_a_plus_is_an_option_and_c_after_it_too(command):
    # `+` alone is stepped over, `+c` is `-c`, and an empty value is nothing
    assert RECORD[("posix", command)][1] == [["git", "commit", "-n"]]
    assert find_bypass(command, POSIX) == DASH_N


@pytest.mark.parametrize("command", [
    "bash -- -c 'git commit -n'", "bash script.sh -c 'git commit -n'", "bash -e 'git commit -n'",
    "bash -c '' 'git commit -n'"])
def test_a_posix_shell_with_no_c_before_its_first_word_runs_a_script(command):
    assert RECORD[("posix", command)][1] == []
    assert find_bypass(command, POSIX) is None


@pytest.mark.parametrize("flag", ["-c", "-co", "-com", "-comm", "-comma", "-Command", "-command",
                                  "-COMMAND", "--command", "//c"])
def test_any_start_of_command_is_powershells_command_switch(flag):
    command = f"pwsh {flag} 'git commit -n'"
    assert RECORD[("posix", command)][1] == [["git", "commit", "-n"]]
    assert find_bypass(command, POSIX) == DASH_N


def test_the_words_after_the_command_switch_are_one_command():
    for command in ("pwsh -c git commit -n", "pwsh -c 'git commit' -n"):
        assert RECORD[("posix", command)][1] == [["git", "commit", "-n"]]
        assert find_bypass(command, POSIX) == DASH_N
    assert RECORD[("powershell", "pwsh -c 'git commit' -n")][1] == [["git", "commit", "-n"]]
    assert find_bypass("pwsh -c 'git commit' -n", POWERSHELL) == DASH_N


def test_a_first_word_that_is_no_switch_is_a_script_to_pwsh_and_the_command_to_powershell():
    assert RECORD[("posix", "pwsh 'git commit -n'")][1] == []
    assert RECORD[("posix", "powershell 'git commit -n'")][1] == [["git", "commit", "-n"]]
    assert find_bypass("pwsh 'git commit -n'", POSIX) is None
    assert find_bypass("powershell 'git commit -n'", POSIX) == DASH_N
    assert find_bypass("pwsh 'git commit -n'", POWERSHELL) is None
    assert find_bypass("powershell 'git commit -n'", POWERSHELL) == DASH_N


@pytest.mark.parametrize("command", [
    "pwsh -ExecutionPolicy Bypass -c 'git commit -n'", "pwsh -exe Bypass -c 'git commit -n'",
    "pwsh -wd . -c 'git commit -n'", "pwsh -o Text -c 'git commit -n'",
    "pwsh -nop -c 'git commit -n'", "pwsh - -c 'git commit -n'", "pwsh $u -c 'git commit -n'"])
def test_a_switch_that_takes_a_value_is_stepped_over_with_it(command):
    # and one that takes none, a `-` alone and an empty value, without it
    assert RECORD[("posix", command)][1] == [["git", "commit", "-n"]]
    assert find_bypass(command, POSIX) == DASH_N


@pytest.mark.parametrize("command,want", [
    ("pwsh -cwa 'git commit -n'", DASH_N), ("pwsh -cwa 'git commit -n' x", DASH_N),
    ("pwsh -CommandWithArgs 'git commit -n'", DASH_N), ("pwsh -commandw 'git commit -n'", None),
    ("pwsh -cwa", None)])
def test_the_string_after_cwa_is_read(command, want):
    assert bool(RECORD[("posix", command)][1]) == (want is not None)
    assert find_bypass(command, POSIX) == want


def test_what_follows_file_is_a_script_and_its_arguments():
    # `powershell -File x.ps1 git commit -n` ran no git (the record); the words
    # after the script are its arguments, even to Windows PowerShell
    assert RECORD[("posix", "powershell -File x.ps1 git commit -n")][1] == []
    for name in ("powershell", "pwsh"):
        assert ab._powershell_string([name, "-File", "x.ps1", "git commit -n"], 0) is None
        assert ab._powershell_string([name, "-f", "x.ps1", "git commit -n"], 0) is None


@pytest.mark.parametrize("seg,start", [
    ([], -2), ([], 0), ([], 5), (["a"], 1), (["a"], 9999), (["bash"], -5),
    (["pwsh"], 2)])
def test_the_handed_readers_never_raise_on_an_out_of_contract_index(seg, start):
    # find_bypass fails open (agent_hook.cmd_agent_hook catches every exception
    # and allows the call), so a reader that raises is a silent bypass. The
    # public path only ever calls these with a valid index into a non-empty
    # segment, but the drain's fuzzer calls them directly: keep them total
    # (FN-55 e660af/c7d64c).
    assert ab._posix_string(seg, start) is None
    assert ab._powershell_string(seg, start) is None


@pytest.mark.parametrize("shell", ["ksh", "mksh", "ash", "yash", "posh"])
def test_a_posix_sh_family_shell_hands_its_c_string_like_bash(shell):
    # dash, ksh, mksh, ash, yash and posh share bash's -c grammar (FN-55
    # 2fe1a4). dash is installed here and carries the authentic handed-argv.json
    # proof for the family (dash -c 'git commit -n'); the rest are absent on the
    # recording machine, so they are covered by a direct assertion on the
    # shared reader rather than a record case.
    assert find_bypass(f"{shell} -c 'git commit -n'", POSIX) == DASH_N


def test_busybox_ash_is_reached_past_the_busybox_word():
    # busybox is not itself a shell; the decoy scan (FN-55 2fe1a4) steps past it
    # to the `ash` it launches, which is read like bash.
    assert find_bypass("busybox ash -c 'git commit -n'", POSIX) == DASH_N


def test_fish_c_is_a_documented_residual():
    # fish -c runs its string, but fish's option grammar is not bash's and fish
    # is absent on the recording machine, so it is a documented residual (module
    # docstring / _POSIX_SHELLS comment), not read. If fish is ever added with
    # its own rules, this assertion is the reminder to retire the residual.
    assert find_bypass("fish -c 'git commit -n'", POSIX) is None


@pytest.mark.parametrize("command,want", [
    ("echo -n 'git commit -n' | bash", DASH_N),        # echo's own flag is stripped
    ("echo 'git commit -n' | bash $u", DASH_N),         # a maybe-empty $-word before stdin
    ("echo 'git commit -n' | bash -c 'git status'", None),  # -c wins; piped stdin ignored
    ("echo 'git commit -n' | bash script.sh", None),   # bash runs the script, not stdin
    ("cat f | bash", None),                            # a non-echo/printf upstream: residual
    ("bash << EOF", None),                             # a here-DOC delimiter is not the command
    ("echo 'git commit -n' || bash", None),            # `||` is logical-or, not a pipe: no stdin
    ("echo 'git commit -n' && bash", None),            # `&&` is and-then, not a pipe: no stdin
])
def test_the_stdin_fed_reader_edges(command, want):
    # The main stdin forms (echo|shell, bash <<< ..., ... | pwsh -) are pinned by
    # the record (test_nothing / test_every); these pin the reader's edges
    # directly (FN-55 fb16940).
    assert find_bypass(command, POSIX) == want


def _nest_stdin(times, inner="git commit -n"):
    text = "echo " + shlex.quote(inner) + " | bash"
    for _ in range(times - 1):
        text = "echo " + shlex.quote(text) + " | bash"
    return text


def test_a_stdin_handoff_is_read_to_the_cap_and_refused_past_it():
    # the shell-handoff depth cap counts a command fed on stdin like any other
    assert find_bypass(_nest_stdin(ab._HANDED_DEPTH), POSIX) == DASH_N
    assert find_bypass(_nest_stdin(ab._HANDED_DEPTH + 1), POSIX) == TOO_MANY


def test_a_name_powershell_builds_in_the_string_is_seen_from_a_bash_call():
    # The Bash call's own text never spells git: the cheap test that keeps a
    # Bash call untokenized must not let it go (it costs one reading).
    command = "pwsh -c 'g`u{69}t commit -n'"
    assert RECORD[("posix", command)][1] == [["git", "commit", "-n"]]
    assert not ab._may_name_a_program(command)
    assert find_bypass(command, POSIX) == DASH_N


def test_a_string_too_deep_for_the_powershell_reader_is_refused_from_a_bash_call():
    # the 2026-10-14 decision holds for a PowerShell string a Bash call hands over
    assert find_bypass(f"pwsh -c '{G41}'", POSIX) == TOO_DEEP
    assert find_bypass(f"pwsh -c '{H41}'", POSIX) == TOO_DEEP


def test_a_global_git_option_in_the_string_is_read():
    # the trace2 record keeps the options git reads before its subcommand
    bash = "bash -c 'git -c core.hooksPath=/dev/null commit'"
    assert RECORD[("posix", bash)][1] == [["git", "-c", "core.hooksPath=nul", "commit"]]
    assert find_bypass(bash, POSIX) == HOOKS_DEV_NULL
    pwsh = "pwsh -c 'git -c core.hooksPath=x commit'"
    assert RECORD[("powershell", pwsh)][1] == [["git", "-c", "core.hooksPath=x", "commit"]]
    assert find_bypass(pwsh, POWERSHELL) == Bypass("hooks-path", "commit", "core.hooksPath=x")


# ---- strings within strings ----

def _nest(times, inner="git commit -n"):
    text = inner
    for _ in range(times):
        text = "bash -c " + shlex.quote(text)
    return text


def test_a_string_within_strings_is_read_as_deep_as_the_cap():
    assert find_bypass(_nest(ab._HANDED_DEPTH), POSIX) == DASH_N
    assert find_bypass(_nest(ab._HANDED_DEPTH, "git status"), POSIX) is None


def test_one_shell_more_than_the_cap_is_refused_whatever_it_runs():
    # as for the reader's own cap: no real command hands a string on that often
    assert find_bypass(_nest(ab._HANDED_DEPTH + 1), POSIX) == TOO_MANY
    assert find_bypass(_nest(ab._HANDED_DEPTH + 1, "git status"), POSIX) == TOO_MANY


def test_a_long_chain_of_shells_neither_raises_nor_takes_long():
    chain = "pwsh -c " * 2000 + "Write-Output hi"
    assert find_bypass(chain, POWERSHELL) == TOO_MANY
    assert find_bypass(chain, POSIX) == TOO_MANY
    wide = " ; ".join(["bash -c 'pwsh -c Write-Output'"] * 300)
    assert find_bypass(wide, POSIX) is None


# ---- what is not a string handed to a shell ----

@pytest.mark.parametrize("command", [
    'ssh host "git commit -n"', "grep -c 'git commit -n' f", "git -c user.name=x commit -m 'a'",
    "python -c 'print(1)'", "bash script.sh -c x", "sh ./configure -c", "printf %s -c 'git commit -n'",
    "bash -c 'git commit -m x'", "pwsh -c 'git status'", "pwsh -File x.ps1 -c 'git commit -n'",
    "bash -c", "pwsh -c", "pwsh -", "bash -"])
@pytest.mark.parametrize("shell", [POSIX, POWERSHELL])
def test_a_command_that_hands_no_shell_a_bypass_is_let_through(command, shell):
    assert find_bypass(command, shell) is None


def test_a_close_without_red_proof_in_a_string_is_answered():
    close = "aramid ledger resolve id1 --fixed abc --test t --reason r"
    assert find_bypass(f"bash -c '{close}'", POSIX) == NO_RED
    assert find_bypass(f"pwsh -c '{close}'", POWERSHELL) == NO_RED
    assert find_bypass(f"bash -c '{close} --red-proof'", POSIX) is None


def test_a_string_is_read_when_the_hook_is_not_told_the_shell():
    # the shell the string is handed to is named in the command itself
    assert find_bypass("bash -c 'git commit -n'") == DASH_N
    assert find_bypass("pwsh -c 'g`u{69}t commit -n'") == DASH_N
