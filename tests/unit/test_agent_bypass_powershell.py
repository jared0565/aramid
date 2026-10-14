"""A PowerShell tool call read by PowerShell's rules (FN-45 in
docs/superpowers/plans/2026-09-21-aramid-1.0-blockers.md).

What is right here is not this reader's opinion and not mine: it is what
PowerShell 7 handed a program. tests/fixtures/powershell-argv.json is the
record of that, made by running each command in PowerShell with a program
that writes down its arguments standing in for git and for aramid (the
file says which PowerShell, and what the session held).

Four kinds of assertion, by what the record says and what the reader does:

  handed(command, argv...)  PowerShell handed the program exactly these
                            words, and the reader reads the same words. The
                            words are written out below and checked against
                            the record on every run.
  seen(command, bypass)     a bypass reached the program, and the reader
                            answers it. Its words may differ: a value only
                            the run shows is written `$`.
  clear(command)            no bypass reached the program, and the reader
                            is silent.
  OVER                      no bypass reached the program and the reader
                            answers all the same. Every such command of the
                            record is listed, with why; one that is not
                            listed fails, and so does one that stops.

And one test over the whole record: nothing PowerShell handed over as a
bypass is let through."""
import json
import random
from pathlib import Path

import pytest

from aramid import agent_bypass as ab
from aramid.agent_bypass import POWERSHELL, Bypass, find_bypass
from aramid.agent_bypass_powershell import _DEPTH, commands, reading, spelled

FIXTURE = Path(__file__).parent.parent / "fixtures" / "powershell-argv.json"
RECORD = {case["command"]: (case["status"], case["argv"])
          for case in json.loads(FIXTURE.read_text(encoding="ascii"))["cases"]}

NO_VERIFY = Bypass("no-verify", "commit", "--no-verify")
DASH_N = Bypass("no-verify", "commit", "-n")
PUSH = Bypass("no-verify", "push", "--no-verify")
NO_RED = Bypass("no-red-proof", "ledger resolve", "--fixed")
R = "ledger resolve id1 --fixed abc --test t --reason r"
RAN_R = ["aramid", "ledger", "resolve", "id1", "--fixed", "abc", "--test", "t", "--reason", "r"]

# characters a keyboard does not have, by number so that no tool rewrites them
LDQ, RDQ, RSQ = chr(0x201c), chr(0x201d), chr(0x2019)
EN_DASH, EM_DASH = chr(0x2013), chr(0x2014)
NBSP, EM_SPACE = chr(0xa0), chr(0x2003)


def _judged(argvs):
    """The hook's own flag rules on the words a program was handed."""
    for argv in argvs:
        scan = ab._scan_one_git if argv[0] == "git" else ab._scan_one_aramid
        found = scan(argv, 0)
        if found is not None:
            return found
    return None


def _launched(segments):
    """The reader's words from each word that names git or aramid on, the
    name written plainly: what the recording program would have been handed."""
    out = []
    for seg in segments:
        for i, tok in enumerate(seg):
            if ab._is_git(tok) or ab._is_aramid(tok):
                out.append(["git" if ab._is_git(tok) else "aramid", *seg[i + 1:]])
                break
    return out


def handed(command, *argvs):
    want = [list(argv) for argv in argvs]
    assert RECORD.get(command) == ("ran", want), f"the record says otherwise: {command!r}"
    read, whole = commands(command)
    assert whole, command
    assert _launched(read) == want, command
    assert find_bypass(command, POWERSHELL) == _judged(want), command


def seen(command, bypass):
    status, argvs = RECORD[command]
    assert status == "ran" and _judged(argvs) == bypass, f"the record says otherwise: {command!r}"
    assert find_bypass(command, POWERSHELL) == bypass, command


def clear(command):
    status, argvs = RECORD[command]
    assert _judged(argvs) is None, f"the record says otherwise: {command!r}"
    assert find_bypass(command, POWERSHELL) is None, command


# ---- the whole record ----

def test_the_record_is_the_one_a_run_made():
    record = json.loads(FIXTURE.read_text(encoding="ascii"))
    assert record["provisional"] is False
    assert record["powershell"].split(".")[0] == "7"
    assert record["native_argument_passing"] == "Windows"
    assert len(RECORD) == len(record["cases"]) >= 450
    assert {status for status, _ in RECORD.values()} == {"ran", "parse-error"}
    assert all(not argvs for status, argvs in RECORD.values() if status == "parse-error")


# What the reader does not see, and is not built to: a program or an
# argument that is put together when the command runs. The record holds some
# so that the limit is written down, run and counted, not only described.
NOT_SEEN = {
    "& ('g'+'it') commit -n": "the name is worked out",
    '& ("git") commit -n': "the name is worked out",
    "$g = 'git'; & $g commit -n": "the name is in a variable",
    "Invoke-Expression 'git commit -n'": "the command is a string that is run",
    'iex "git commit -n"': "the command is a string that is run",
    'cmd /c "git commit -n"': "the command is a string another shell runs",
    "Start-Process git -ArgumentList 'commit','-n' -Wait -NoNewWindow": "the arguments are a list",
}


def test_nothing_powershell_handed_over_as_a_bypass_is_let_through():
    missed = {command for command, (_, argvs) in RECORD.items()
              if _judged(argvs) is not None
              and find_bypass(command, POWERSHELL) != _judged(argvs)}
    assert missed == set(NOT_SEEN)
    assert all(find_bypass(command, POWERSHELL) is None for command in NOT_SEEN)
    # and the record does hold bypasses, of each kind
    kinds = {_judged(argvs).kind for _, argvs in RECORD.values() if _judged(argvs)}
    assert kinds == {"no-verify", "hooks-path", "no-red-proof"}


def test_most_of_the_record_is_read_into_the_very_words_handed_over():
    # The rest hold a value only the run shows, or are listed in OVER.
    same = [command for command, (status, argvs) in RECORD.items()
            if status == "ran" and _launched(commands(command)[0]) == argvs]
    assert len(same) >= SAME_WORDS


SAME_WORDS = 473   # the actual count on 2026-10-12's record (687 cases, 619 ran)


# ---- quotes ----

def test_a_word_that_starts_with_a_quote_ends_where_the_quote_closes():
    handed('git commit "--no-"verify', ["git", "commit", "--no-", "verify"])
    handed("git commit '--no-'verify", ["git", "commit", "--no-", "verify"])
    handed('git commit -m "x" "--no-verify"', ["git", "commit", "-m", "x", "--no-verify"])
    handed("git commit '-n'", ["git", "commit", "-n"])


def test_a_quote_inside_a_word_is_part_of_the_word():
    handed('git commit --no-"verify"', ["git", "commit", "--no-verify"])
    handed("git commit --no-'verify'", ["git", "commit", "--no-verify"])


def test_two_quotes_in_a_string_are_one_and_the_other_kind_is_itself():
    handed('git commit -m "a""b" --no-verify', ["git", "commit", "-m", 'a"b', "--no-verify"])
    handed("git commit -m 'a''b' --no-verify", ["git", "commit", "-m", "a'b", "--no-verify"])
    handed('git commit -m "a\'b" --no-verify', ["git", "commit", "-m", "a'b", "--no-verify"])
    handed("git commit -m 'a\"b' --no-verify", ["git", "commit", "-m", 'a"b', "--no-verify"])


def test_a_backslash_is_a_character():
    # the six misses of FN-45 began here: by the POSIX rule this quote is
    # escaped, the string never ends and nothing after it is read
    path = '"in C:\\src\\"'
    handed(f"aramid ledger resolve id1 --reason {path} --fixed abc --test t",
           ["aramid", "ledger", "resolve", "id1", "--reason", "in C:\\src\\",
            "--fixed", "abc", "--test", "t"])
    handed(f"aramid ledger resolve id1 --fixed abc --test t --reason {path} --red-proof",
           ["aramid", "ledger", "resolve", "id1", "--fixed", "abc", "--test", "t",
            "--reason", "in C:\\src\\", "--red-proof"])
    handed('git commit -m "C:\\src\\" --no-verify',
           ["git", "commit", "-m", "C:\\src\\", "--no-verify"])


def test_the_six_bypasses_fn_45_recorded_are_seen():
    seen('git commit -m "C:\\src\\" --no-verify', NO_VERIFY)
    seen('aramid ledger resolve id1 --reason "in C:\\src\\" --fixed abc --test t', NO_RED)
    seen('git commit -m "5`" disk" --no-verify', NO_VERIFY)
    seen("aramid ledger resolve id1 --reason a`;b --fixed abc --test t", NO_RED)
    seen('git commit -m "say `" # hi`" now" --no-verify', NO_VERIFY)
    seen("git commit -m <# c #> x --no-verify", NO_VERIFY)


def test_the_five_proper_closes_fn_45_recorded_are_let_through():
    close = "aramid ledger resolve id1 --fixed abc --test t --reason "
    clear(close + '"in C:\\src\\" --red-proof')
    clear(close + '"5`" disk" --red-proof')
    clear(f"aramid {R} <# note #> --red-proof")
    clear(close + '"see `"issue #12`" now" --red-proof')
    clear(close + '"a `"b; c`" d" --red-proof')
    # and each of them was a close: aramid was handed --fixed and --red-proof
    for command in (close + '"in C:\\src\\" --red-proof', close + '"a `"b; c`" d" --red-proof'):
        argv = RECORD[command][1][0]
        assert "--fixed" in argv and argv[-1] == "--red-proof"


def test_the_curly_quotes_are_quotes_and_close_a_straight_one():
    want = ["git", "commit", "-m", "x y", "--no-verify"]
    handed(f"git commit -m {LDQ}x y{RDQ} --no-verify", want)
    handed(f"git commit -m {LDQ}x y\" --no-verify", want)
    handed(f"git commit -m 'x y{RSQ} --no-verify", want)


def test_a_long_dash_is_handed_over_as_written_and_is_no_flag():
    handed(f"git commit {EN_DASH}n", ["git", "commit", f"{EN_DASH}n"])
    handed(f"git commit {EM_DASH}no-verify", ["git", "commit", f"{EM_DASH}no-verify"])


def test_every_blank_parts_words():
    for blank in (NBSP, "\x0b", "\x0c", EM_SPACE, chr(0x85), chr(0x2028), chr(0x2029),
                  chr(0x3000), chr(0x1680), chr(0x202f), chr(0x205f), chr(0x2000), chr(0x200a)):
        handed(f"git commit{blank}-n", ["git", "commit", "-n"])


def test_what_only_looks_like_a_blank_is_part_of_the_word():
    for char in (chr(0x1c), chr(0x1d), chr(0xfeff), chr(0x200b), chr(0x180e), chr(0xad),
                 chr(0x7f), chr(1), chr(0x1b), chr(8)):
        handed(f"git commit{char}-n", ["git", f"commit{char}-n"])
    # 0x1E and 0x1F as well (python calls all four of 0x1C to 0x1F a space).
    # The record cannot hold these two: the recording program parts its
    # records and fields with them. Two in a row told them apart from a blank.
    for char in (chr(0x1e), chr(0x1f)):
        assert commands(f"git commit{char}-n") == ([["git", f"commit{char}-n"]], True)


def test_a_blank_is_not_a_line_end():
    # the push is an argument of `git status` here; it is answered all the
    # same, since every word that names git starts a scan (they are in OVER)
    for blank in (chr(0x85), chr(0x2028), "\x0c"):
        assert RECORD[f"git status{blank}git push --no-verify"] == (
            "ran", [["git", "status", "git", "push", "--no-verify"]])
        handed(f"git commit -m x # c{blank} --no-verify", ["git", "commit", "-m", "x"])


def test_the_program_is_named_in_any_case():
    handed("GIT commit -n", ["git", "commit", "-n"])
    handed("Git.EXE commit -n", ["git", "commit", "-n"])


@pytest.mark.parametrize("name", [
    "g`it", 'g"i"t', "g'i't", "git.exe", "& git", "&git", '& "git"', "& 'git'", "& g`it", ". git",
    # by a path: a backslash is a character here, so the path is whole (read
    # the POSIX way an unquoted one loses its separators, and git is not seen)
    ".\\sub\\git.exe", "sub\\git.exe", "sub\\git", "./sub/git", "sub/git.exe", ".\\sub\\GIT.EXE",
    "sub\\\\git.exe", "sub\\.\\git.exe", "& .\\sub\\git.exe", '& "sub\\git.exe"',
    "& 'p q\\git.exe'", '& "p q/git"', "& p` q\\git", "p` q\\git.exe",
])
def test_git_is_git_however_it_is_named(name):
    handed(f"{name} commit -n", ["git", "commit", "-n"])


@pytest.mark.parametrize("name", ["ara`mid", 'ara"mi"d', "& aramid", ".\\sub\\aramid.exe",
                                  '& "p q\\aramid.exe"'])
def test_aramid_is_aramid_however_it_is_named(name):
    handed(f"{name} {R}", RAN_R)
    assert find_bypass(f"{name} {R}", POWERSHELL) == NO_RED
    assert find_bypass(f"{name} {R} --red-proof", POWERSHELL) is None


@pytest.mark.parametrize("name", ["g\\it", "g`\nit", ".\\sub\\git.exe.old", "sub\\gitx",
                                  "sub\\git.exe`0"])
def test_a_name_that_is_not_gits_starts_no_git(name):
    assert RECORD[f"{name} commit -n"] == ("ran", [])
    assert find_bypass(f"{name} commit -n", POWERSHELL) is None


def test_a_value_that_is_nothing_inside_the_name_leaves_the_name():
    # after the call operator PowerShell works the name out, and it is git.
    # No cheap test on the text as written would let these be read at all.
    for command in ("& g$()it commit -n", '& "g$()it" commit -n', '& "g${u}it" commit -n',
                    '& "git$u" commit -n'):
        handed(command, ["git", "commit", "-n"])
    handed(f'& "ara${{u}}mid" {R}', RAN_R)


# ---- the backtick ----

def test_a_backtick_in_a_word_is_taken_out_and_the_flag_is_whole():
    handed("git commit --no-ver`ify", ["git", "commit", "--no-verify"])
    handed("git commit `--no-verify", ["git", "commit", "--no-verify"])
    handed("aramid ledger resolve id1 --fixe`d abc --test t --reason r", RAN_R)
    handed(f"aramid {R} --red-`proof", [*RAN_R, "--red-proof"])


def test_a_backtick_before_a_letter_it_knows_makes_a_control_character():
    handed("git commit --`no-verify", ["git", "commit", "--\no-verify"])
    handed("git commit -`n", ["git", "commit", "-\n"])
    handed('git commit -m "a`nb" -n', ["git", "commit", "-m", "a\nb", "-n"])


def test_a_backtick_before_a_line_end_continues_the_line_between_words_only():
    handed("git commit -m x `\n--no-verify", ["git", "commit", "-m", "x", "--no-verify"])
    handed("git commit -m x `\r\n--no-verify", ["git", "commit", "-m", "x", "--no-verify"])
    handed("git commit --no-`\nverify", ["git", "commit", "--no-\nverify"])


def test_a_backtick_takes_the_meaning_from_what_follows_it():
    handed("git commit -m a` b -n", ["git", "commit", "-m", "a b", "-n"])
    handed("git commit -m x`;git push --no-verify",
           ["git", "commit", "-m", "x;git", "push", "--no-verify"])
    handed("git commit -m x `# --no-verify", ["git", "commit", "-m", "x", "#", "--no-verify"])
    handed("git commit -m `'x --no-verify", ["git", "commit", "-m", "'x", "--no-verify"])
    handed('git commit -m "5`" disk" --no-verify', ["git", "commit", "-m", '5" disk', "--no-verify"])
    # between words, before a blank, it is the blank
    handed('git commit -m "a b"` --no-verify', ["git", "commit", "-m", "a b", "--no-verify"])
    handed("git commit -m x ` --no-verify", ["git", "commit", "-m", "x", "--no-verify"])
    handed("git commit -m x `\t-n", ["git", "commit", "-m", "x", "-n"])


def test_a_backtick_inside_single_quotes_is_a_character():
    handed("git commit -m 'a`' --no-verify", ["git", "commit", "-m", "a`", "--no-verify"])


def test_a_code_point_escape_is_the_character():
    handed("`u{67}it commit -n", ["git", "commit", "-n"])
    handed("git commit `u{2d}n", ["git", "commit", "-n"])
    handed("git commit `u{2D}`u{6e}", ["git", "commit", "-n"])
    handed('git commit "`u{2d}n"', ["git", "commit", "-n"])
    handed("git commit `u{00002d}n", ["git", "commit", "-n"])
    # half of a surrogate pair: the record has the replacement character for it
    handed("git commit `u{d800} -n", ["git", "commit", chr(0xFFFD), "-n"])


def test_a_code_point_escape_written_any_other_way_is_not_powershell():
    for command in ("git commit `u{110000}", "git commit `u{zz}", "git commit `u{",
                    "git commit `u{} -n", "git commit `u{1234567} -n", "git commit `u2d -n"):
        assert RECORD[command] == ("parse-error", [])
        assert commands(command) == ([["git", "commit"]], False)
    # the words before it are judged all the same
    assert find_bypass("git commit -n `u{zz}", POWERSHELL) == DASH_N
    assert find_bypass('git commit -n "`u{zz}"', POWERSHELL) == DASH_N


def test_a_nul_ends_the_line_a_program_is_started_with():
    # the flag is whole in front of it
    for command in ("git commit --no-verify`0", "git commit --no-verify`0x",
                    'git commit "--no-verify`0"', 'git commit "--no-verify`0junk" -m x',
                    "git commit --no-verify`u{0}x", 'git commit @"\n--no-verify`0x\n"@'):
        handed(command, ["git", "commit", "--no-verify"])
    # and what stands after it is not handed over: a flag, or the proof of a close
    handed("git commit -m x`0 --no-verify", ["git", "commit", "-m", "x"])
    handed("git commit `0--no-verify", ["git", "commit"])
    handed("git commit `0 -n", ["git", "commit"])
    handed('git commit "`0" -n', ["git", "commit"])
    handed('git commit -m "a`0b" -n', ["git", "commit", "-m", "a"])
    handed("git `0 commit -n", ["git"])
    handed(f"aramid {R}`0 --red-proof", RAN_R)
    handed(f"aramid {R} `0 --red-proof", RAN_R)
    handed(f'aramid {R} "x`0" --red-proof', [*RAN_R, "x"])
    handed(f"aramid {R} --red-proof`0", [*RAN_R, "--red-proof"])
    # the command after it is a command of its own
    handed("git commit -m x `0; git push --no-verify",
           ["git", "commit", "-m", "x"], ["git", "push", "--no-verify"])
    # in single quotes and in a dash word the backtick is a character, and no NUL is made
    handed("git commit '--no-verify`0'", ["git", "commit", "--no-verify`0"])
    handed("git commit -n`0 -m x", ["git", "commit", "-n`0", "-m", "x"])
    # a NUL written into the text itself does the same
    nul = chr(0)
    handed(f"git commit --no-verify{nul}x", ["git", "commit", "--no-verify"])
    handed(f"git commit -m x {nul} --no-verify", ["git", "commit", "-m", "x"])
    handed(f"git commit -m 'a{nul}b' --no-verify", ["git", "commit", "-m", "a"])
    handed(f"git{nul} commit -n", ["git"])
    clear("git`0 commit -n")        # no program has that name


# ---- where a command ends ----

def test_a_semicolon_and_a_line_end_start_another_command():
    handed("git commit -m x;git push --no-verify",
           ["git", "commit", "-m", "x"], ["git", "push", "--no-verify"])
    handed("git commit -n;", ["git", "commit", "-n"])
    for line_end in ("\n", "\r"):
        handed(f"git status{line_end}git push --no-verify",
               ["git", "status"], ["git", "push", "--no-verify"])


def test_a_flag_on_a_line_of_its_own_is_not_the_commits():
    # PowerShell runs none of this text: `--` in front of a word is an operator
    for command in ("git commit -m x\n--no-verify", "git commit -m x\r--no-verify"):
        assert RECORD[command] == ("parse-error", [])
        assert find_bypass(command, POWERSHELL) is None


@pytest.mark.parametrize("joint", [" | ", " && ", " & ", ";", "\n"])
def test_what_stands_after_a_joint_is_a_command(joint):
    handed(f"zq{joint}git commit -n", ["git", "commit", "-n"])
    handed(f"git status{joint}zq --no-verify", ["git", "status"])


def test_a_command_behind_a_double_bar_is_read_as_if_it_ran():
    # it runs when the one in front fails, which the text does not say
    handed("git status || zq --no-verify", ["git", "status"])
    assert RECORD["zq || git commit -n"] == ("ran", [])
    assert find_bypass("zq || git commit -n", POWERSHELL) == DASH_N


# ---- comments ----

def test_a_hash_starts_a_comment_where_a_word_starts():
    handed("git commit -m x #y --no-verify", ["git", "commit", "-m", "x"])
    handed("git commit -m x#y --no-verify", ["git", "commit", "-m", "x#y", "--no-verify"])
    handed("git commit --no-verify#x", ["git", "commit", "--no-verify#x"])
    handed("git commit -m x # c\ngit push --no-verify",
           ["git", "commit", "-m", "x"], ["git", "push", "--no-verify"])


def test_a_block_comment_is_taken_out_where_a_word_starts():
    handed("git commit -m x <# c #> --no-verify", ["git", "commit", "-m", "x", "--no-verify"])
    handed("git commit -m <# c #> x --no-verify", ["git", "commit", "-m", "x", "--no-verify"])
    handed("git commit <# a #> <# b #> -n", ["git", "commit", "-n"])
    handed("git commit <##> -n", ["git", "commit", "-n"])
    # inside a word it is text, and the `#` after it starts a comment
    handed("git commit -m x<# c #>--no-verify", ["git", "commit", "-m", "x<#", "c"])
    handed(f"aramid {R} <# note #> --red-proof", [*RAN_R, "--red-proof"])


# ---- redirections ----

def test_a_redirection_is_no_argument_and_takes_the_word_after_it():
    want = ["git", "commit", "-m", "x", "--no-verify"]
    for redirection in ("2>&1", "*> f", "2> f", ">f", ">> f", "3>&1", "*>&1", "2>$null",
                        "2>&1>f"):
        handed(f"git commit -m x {redirection} --no-verify", want)
    handed("git 2>f commit --no-verify", ["git", "commit", "--no-verify"])
    handed("git commit -m 2 > f --no-verify", ["git", "commit", "-m", "2", "--no-verify"])
    handed("git commit -m 2>f --no-verify", ["git", "commit", "-m", "--no-verify"])


def test_a_flag_a_redirection_writes_to_is_not_handed_over():
    handed("git commit -m x > --no-verify", ["git", "commit", "-m", "x"])
    handed("git commit -m x 2>> --no-verify", ["git", "commit", "-m", "x"])


def test_an_angle_bracket_inside_a_word_is_a_character():
    handed("git commit -m x> f --no-verify", ["git", "commit", "-m", "x>", "f", "--no-verify"])
    handed("git commit -m x2>f --no-verify", ["git", "commit", "-m", "x2>f", "--no-verify"])
    handed("git commit --no-verify2>f", ["git", "commit", "--no-verify2>f"])
    handed("git commit -m x 7>f --no-verify", ["git", "commit", "-m", "x", "7>f", "--no-verify"])


# ---- a word that starts with one dash ----

def test_a_dash_word_ends_at_a_dot_or_a_bracket():
    handed("git commit -n.x", ["git", "commit", "-n", ".x"])
    handed("git -ccore.hooksPath=x commit", ["git", "-ccore", ".hooksPath=x", "commit"])
    handed("git commit --no-verify.x", ["git", "commit", "--no-verify.x"])
    handed("git commit -m 1.5 -n", ["git", "commit", "-m", "1.5", "-n"])
    handed("git commit -m -1 -n", ["git", "commit", "-m", "-1", "-n"])


def test_a_quote_or_a_colon_ends_the_dash_words_own_rules():
    handed('git commit -"n"', ["git", "commit", "-n"])
    handed('git commit -n"x"', ["git", "commit", "-nx"])
    handed("git commit -n:.x", ["git", "commit", "-n:.x"])
    handed("git commit -m:x -n", ["git", "commit", "-m:x", "-n"])


def test_the_hooks_path_rule_reads_the_same_words():
    want = ["git", "-c", "core.hooksPath=x", "commit"]
    for command in ("git -c core.hooksPath=x commit", 'git -c "core.hooksPath=x" commit',
                    "git -c core.hooks`Path=x commit"):
        handed(command, want)
        assert find_bypass(command, POWERSHELL) == Bypass(
            "hooks-path", "commit", "core.hooksPath=x")
    handed("git -c:core.hooksPath=x commit", ["git", "-c:core.hooksPath=x", "commit"])


# ---- groups hold commands of their own ----

@pytest.mark.parametrize("command", [
    "(git commit -n)", "$(git commit -n)", "& { git commit -n }", "& git commit -n",
    '& "git" commit -n', ". git commit -n", "$null = git commit -n", "[void](git commit -n)",
    "if ($true) { git commit -n }", "foreach ($i in 1) { git commit -n }",
    "try { git commit -n } catch { }", "1..1 | ForEach-Object { git commit -n }",
    '"$(git commit -n)"', "git commit -n | Out-Null", "&git commit -n",
])
def test_a_commit_inside_a_group_or_behind_an_operator_is_read(command):
    handed(command, ["git", "commit", "-n"])


def test_a_command_inside_a_string_runs_and_is_read():
    seen('git commit -m "$(git commit -n)"', DASH_N)
    seen('git commit -m "$("$(git commit -n)")"', DASH_N)
    seen('git commit -m @"\nx $(git commit -n)\n"@', DASH_N)
    # in single quotes it is text, and so is an escaped one
    handed("git commit -m '$(git commit -n)'", ["git", "commit", "-m", "$(git commit -n)"])
    handed('git commit -m "`$(git commit -n)"', ["git", "commit", "-m", "$(git commit -n)"])


def test_a_flag_inside_another_commands_group_is_not_the_commits():
    clear("git commit -m (zq --no-verify)")
    clear('git commit -m "$(zq --no-verify)"')
    clear("git commit -m $(zq --no-verify)")


TOO_DEEP = Bypass("too-deep", "", str(_DEPTH))


def _nest(inner, depth=_DEPTH + 1):
    return "(" * depth + inner + ")" * depth


def test_nesting_deeper_than_the_limit_is_cut_off_and_not_an_error():
    # The boundary is exact: _DEPTH groups are read, one more is cut off. The cap
    # is NOT a match to PowerShell -- PowerShell 7 runs the wrapped command
    # thousands of groups deep (probe10, 2026-10-12) -- so a reading cut off
    # there is refused when the call names git or aramid (the tests below). The
    # cap is kept low because deeper recursion could raise, and this reader must
    # never raise (the module's note, "A READING THAT GOES TOO DEEP").
    at = _nest("git commit -n", _DEPTH)
    assert commands(at) == ([["git", "commit", "-n"]], True)
    assert reading(at) == ([["git", "commit", "-n"]], "end")
    assert find_bypass(at, POWERSHELL) == DASH_N
    over = _nest("git commit -n")
    assert commands(over) == ([], False)
    assert reading(over) == ([], "deep")
    deep = _nest("git commit -n", _DEPTH + 5000)
    assert reading(deep) == ([], "deep")   # never a RecursionError
    # what was read before the deep part still counts, and answers first
    assert find_bypass("git commit -n; " + over, POWERSHELL) == DASH_N


@pytest.mark.parametrize("inner", [
    "git commit -n", "git status", "aramid ledger resolve id1 --fixed abc", "& git commit",
    "g`it commit -n", 'g"i"t commit -n', "GIT commit -n",
    # names PowerShell builds (the record: `u{67}it commit -n ran git)
    "`u{67}it commit -n", '& "`u{67}it" commit -n', "g$()it commit -n", "g${u}it commit -n",
    "gi${null}t commit -n", "`u{61}ramid ledger resolve id1 --fixed abc"])
def test_a_reading_cut_off_by_the_depth_limit_is_refused_when_the_call_names_git_or_aramid(inner):
    # The operator's decision (2026-10-13, "Refuse at the cap"): PowerShell runs
    # what lies past the cap, so the cut-off is not like an open quote, which it
    # does not run. No real command nests that deep, so the call is refused,
    # whatever it was going to do, once its text names git or aramid -- spelled
    # with the quotes and backticks PowerShell takes out of a word.
    assert find_bypass(_nest(inner), POWERSHELL) == TOO_DEEP
    assert find_bypass(_nest(inner, _DEPTH + 5000), POWERSHELL) == TOO_DEEP


@pytest.mark.parametrize("text,word", [
    ("`u{67}it", "git"), ("g`u{69}t", "git"), ("`u{1F600}", "\U0001F600"),
    ("`u{zz}x", "u{zz}x"), ("`ux", "ux"), ("x`", "x"), ("g`tit", "g\tit"), ("g``it", "g`it"),
    ("g$()it", "git"), ("g$(a (b) c)it", "git"), ("g$(open", "g"), ("g${a b}it", "git"),
    ("g$xit", "g"), ("g$env:PATH", "g"), ("$?", ""), ("a $ b", "a $ b"), ("a$", "a$"),
    ("a$x-b", "a-b"), ("a$xy-b", "a-b"),   # a name ends where its characters do
    ("'g'it", "git"), ('"g"i’t', "git"), ("plain words", "plain words")])
def test_spelled_reads_text_as_powershell_builds_a_word(text, word):
    assert spelled(text) == word


def test_spelled_never_raises():
    rng = random.Random(14)
    alphabet = "`$(){}u0123456789abcdefgiz '\"’\r\n:?^"
    for _ in range(3000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 24)))
        assert isinstance(spelled(text), str)


@pytest.mark.parametrize("inner", ["Write-Output hi", "Write-Output `u{68}i", "Write-Output g$x"])
def test_a_reading_cut_off_by_the_depth_limit_is_let_through_when_the_call_names_neither(inner):
    # `$x` is a value taken to be empty: `g$x` does not spell git.
    assert find_bypass(_nest(inner), POWERSHELL) is None


def test_a_name_outside_the_nest_counts_too():
    # The text is what is asked, not what was read: the reader stopped before
    # the nest, so a name in it is never in what was read.
    assert find_bypass("git status; " + _nest("Write-Output hi"), POWERSHELL) == TOO_DEEP


@pytest.mark.parametrize("text", ['git commit -m "x', "git commit <# x", _nest('git commit -m "x', 10)])
def test_a_reading_cut_off_by_an_open_quote_or_comment_is_not_refused(text):
    # PowerShell runs none of such a text: what was read is judged as before.
    assert reading(text)[1] == "cut"
    assert find_bypass(text, POWERSHELL) is None


def test_the_cap_is_asked_of_a_powershell_call_alone():
    # A Bash call, and a call from a tool the hook does not name, are read by
    # rules that have no such cap.
    assert find_bypass(_nest("git status"), "posix") is None
    assert find_bypass(_nest("git status")) is None


# ---- a value only the run shows ----

def test_a_value_inside_a_word_is_taken_to_be_empty_because_it_may_be():
    handed("git commit --no-verify$null", ["git", "commit", "--no-verify"])
    handed("git commit --no-verify$()", ["git", "commit", "--no-verify"])
    handed("git commit --no-verify$u", ["git", "commit", "--no-verify"])
    handed("git commit $u-n", ["git", "commit", "-n"])
    handed("git commit $u--no-verify", ["git", "commit", "--no-verify"])
    handed("git commit -$u-no-verify", ["git", "commit", "--no-verify"])
    handed("git commit --no$u-verify", ["git", "commit", "--no-verify"])
    handed('git commit --no-$u"verify"', ["git", "commit", "--no-verify"])


def test_in_a_dash_word_a_dollar_sign_and_a_backtick_are_themselves():
    handed("git commit -n$x", ["git", "commit", "-n$x"])
    handed("git commit -n`", ["git", "commit", "-n`"])


def test_a_value_as_a_whole_word_is_one_word_or_none():
    # written `$`; the flag after it is handed over when the value holds something
    for command in ("git commit -m $x -n", 'git commit -m "$x" -n', "git commit -m @{a=1} -n"):
        seen(command, DASH_N)
    assert commands("git commit -m $x -n")[0] == [["git", "commit", "-m", "$", "-n"]]
    assert commands('git commit -m "$x" -n')[0] == [["git", "commit", "-m", "$", "-n"]]
    assert commands("git commit -m ${a b} -n")[0] == [["git", "commit", "-m", "$", "-n"]]
    assert commands("git commit -m $env:X -n")[0] == [["git", "commit", "-m", "$", "-n"]]
    assert commands("git commit -m (zq) -n")[0] == [["zq"], ["git", "commit", "-m", "$", "-n"]]
    assert commands("git commit -m @{a=1} -n")[0] == [["a=1"], ["git", "commit", "-m", "$", "-n"]]
    # `$null` is nothing at all, wherever it stands
    handed(f"aramid $null {R}", RAN_R)
    handed("git $null commit -n", ["git", "commit", "-n"])
    # an empty string is a word
    handed(f"aramid '' {R}", ["aramid", "", *RAN_R[1:]])


def test_a_member_of_a_value_at_the_start_of_a_word_is_part_of_the_value():
    # `$u.y` is nothing, so the commit is what git is handed
    seen("git $u.y commit -n", DASH_N)
    seen("git $x.y commit -n", DASH_N)
    seen(f"aramid $u.y {R}", NO_RED)
    # and what follows the member is a word of its own
    seen("git commit $u.y-n", DASH_N)
    seen("git commit $x[0]-n", DASH_N)
    seen("git commit $(zq).y-n", DASH_N)
    seen("git (zq).y commit -n", DASH_N)
    for command in ("git commit $x.y.z -n", "git commit $x::y -n", "git commit $x.Length.x -n"):
        seen(command, DASH_N)
        assert commands(command)[0] == [["git", "commit", "$", "-n"]]
    for command in ("git commit (zq).Length -n", "git commit $(zq).Length -n"):
        seen(command, DASH_N)
        assert commands(command)[0] == [["zq"], ["git", "commit", "$", "-n"]]
    seen("git commit $x.Substring(0,1) -n", DASH_N)
    assert commands("git commit $x.Substring(0,1) -n")[0] == [
        ["0,1"], ["git", "commit", "$", "-n"]]
    # what stands in the brackets is run
    handed("Write-Output $x[(git commit -n)]", ["git", "commit", "-n"])
    handed("Write-Output $x.Trim((git commit -n))", ["git", "commit", "-n"])
    # inside a longer word a dot is a character
    handed("git commit --no-verify$u.y", ["git", "commit", "--no-verify.y"])
    # a dot with no name after it belongs to no member
    assert commands("git commit $x. -n")[0] == [["git", "commit", ".", "-n"]]
    # an index that never closes: PowerShell runs nothing, and the word it
    # stopped in is left out
    assert RECORD["git commit $x[0 -n"] == ("parse-error", [])
    assert commands("git commit $x[0 -n") == ([["0"], ["git", "commit"]], False)


def test_a_value_in_front_of_the_subcommand_is_stepped_over():
    # finding 4ce6a085: PowerShell makes nothing of these, and git commits
    seen("git $u commit -n", DASH_N)
    seen("git $() commit -n", DASH_N)
    seen("git @() commit -n", DASH_N)
    seen("git ${u} commit -n", DASH_N)
    seen("git $env:u commit -n", DASH_N)
    seen("aramid $u ledger $u resolve id1 --fixed abc --test t --reason r", NO_RED)


# ---- here-strings ----

def test_a_here_string_is_one_word_without_its_last_line_end():
    handed("git commit -m @'\nx\n'@ --no-verify", ["git", "commit", "-m", "x", "--no-verify"])
    handed('git commit -m @"\nx\n"@ --no-verify', ["git", "commit", "-m", "x", "--no-verify"])
    handed("git commit -m @'\r\nx\r\n'@ --no-verify", ["git", "commit", "-m", "x", "--no-verify"])
    handed("git commit -m @' \nx\n'@ --no-verify", ["git", "commit", "-m", "x", "--no-verify"])
    handed("git commit -m @'\nit's\n'@ --no-verify", ["git", "commit", "-m", "it's", "--no-verify"])
    handed("git commit -m @'\nx '@\n'@ --no-verify", ["git", "commit", "-m", "x '@", "--no-verify"])
    handed('git commit -m @"\na `"@\n"@ -n', ["git", "commit", "-m", 'a "@', "-n"])
    handed("git commit @'\n\n'@ -m x", ["git", "commit", "", "-m", "x"])
    handed("git commit @'\n'@ -m x", ["git", "commit", "", "-m", "x"])


def test_a_flag_written_as_a_here_string_is_the_flag():
    handed("git commit @'\n--no-verify\n'@", ["git", "commit", "--no-verify"])
    handed('git commit @"\n--no-verify\n"@', ["git", "commit", "--no-verify"])
    handed("git commit @'\n-n\n'@ -m x", ["git", "commit", "-n", "-m", "x"])
    handed("git commit -m x @'\r\n--no-verify\r\n'@", ["git", "commit", "-m", "x", "--no-verify"])
    handed("git commit @'\n--no-verify\n'@x", ["git", "commit", "--no-verify", "x"])
    handed("aramid ledger resolve id1 @'\n--fixed\n'@ abc --test t --reason r", RAN_R)
    # as the value of -m it is the message
    handed("git commit -m @'\n--no-verify\n'@", ["git", "commit", "-m", "--no-verify"])
    # with a second line end, or a line end inside, it is not the flag
    handed("git commit @'\n--no-verify\n\n'@", ["git", "commit", "--no-verify\n"])
    handed("git commit @'\n--no-\nverify\n'@", ["git", "commit", "--no-\nverify"])


def test_a_here_string_ends_only_at_a_line_that_starts_with_its_close():
    handed("git commit -m @'\nx\n'@\ngit push --no-verify",
           ["git", "commit", "-m", "x"], ["git", "push", "--no-verify"])
    # the opening needs the line end; without it the `@` is a character
    handed("git commit --no-@'\nverify\n'@", ["git", "commit", "--no-@\nverify\n@"])
    # an open one: PowerShell runs nothing; the words before it are judged
    assert commands("git commit -n -m @'\nx") == ([["git", "commit", "-n", "-m"]], False)
    assert find_bypass("git commit -n -m @'\nx", POWERSHELL) == DASH_N


# ---- the stop-parsing token ----

def test_after_the_stop_token_the_line_is_handed_over_as_written():
    handed("git commit --% a ; git commit -n", ["git", "commit", "a", ";", "git", "commit", "-n"])
    handed("git commit --% x > f --no-verify", ["git", "commit", "x", ">", "f", "--no-verify"])
    handed('git commit --% -m "a b" --no-verify', ["git", "commit", "-m", '"a', 'b"', "--no-verify"])
    handed("git commit --% -m 'a --no-verify'", ["git", "commit", "-m", "'a", "--no-verify'"])
    # a `#` is no comment there: the flag is handed over
    handed("git commit --% -m x # --no-verify", ["git", "commit", "-m", "x", "#", "--no-verify"])


def test_the_stop_token_ends_at_a_line_end_and_at_a_joint():
    handed("git commit --% -m x\ngit push --no-verify",
           ["git", "commit", "-m", "x"], ["git", "push", "--no-verify"])
    handed("git commit --% x && git push --no-verify",
           ["git", "commit", "x"], ["git", "push", "--no-verify"])
    handed("git commit --%x -n", ["git", "commit", "--%x", "-n"])     # not the token


# ---- a comma at the end of a word ----

def test_a_comma_carries_the_command_over_a_line_end():
    seen("git commit -m x,\n -n", DASH_N)
    seen("git commit -m x,\r\n -n", DASH_N)
    handed("git commit -m x, --no-verify", ["git", "commit", "-m", "x,", "--no-verify"])
    handed("git commit -m x,--no-verify", ["git", "commit", "-m", "x,--no-verify"])
    handed("git commit -m x ,--no-verify", ["git", "commit", "-m", "x", ",--no-verify"])
    handed("git commit -m x,\n--no-verify", ["git", "commit", "-m", "x,\n--no-verify"])


# ---- text PowerShell does not run ----

def test_a_reading_that_is_cut_off_still_judges_the_words_before_it():
    for command in ("git commit -m x `", 'git commit -m "x`', "git commit -m (zq --no-verify",
                    "git commit -m x <# c \n --no-verify"):
        assert RECORD[command] == ("parse-error", [])
        assert commands(command)[1] is False
        assert find_bypass(command, POWERSHELL) is None
    # PowerShell runs none of these either. They are answered: this reader may
    # be the one that is wrong about where a quote closes (they are in OVER)
    for command in ('git commit -n -m "open', "git commit -n -m 'open", "git commit -n <# open",
                    "git commit -n ${open", "git commit -n -m @'\nx"):
        assert RECORD[command] == ("parse-error", [])
        assert commands(command)[1] is False
        assert find_bypass(command, POWERSHELL) == DASH_N
    assert find_bypass(f"aramid {R} 'open --red-proof", POWERSHELL) == NO_RED
    # nothing after the open quote is read
    clear("git commit -m 'open --no-verify")


def test_a_bracket_that_closes_nothing_ends_the_command():
    for command in ("git commit -m x }", "git commit -m x ) --no-verify"):
        assert RECORD[command] == ("parse-error", [])
        assert find_bypass(command, POWERSHELL) is None


# ---- edges no test held: what the mutant sweep of 2026-10-12 found ----

def cut(command, *read):
    """PowerShell ran none of the text, and the reader stops there and hands
    back exactly the commands it read before it."""
    assert RECORD.get(command) == ("parse-error", []), f"the record says otherwise: {command!r}"
    assert commands(command) == ([list(words) for words in read], False), command


def test_every_kind_of_group_is_one_level_of_nesting():
    # Each kind, outermost around _DEPTH - 1 parentheses, is read to the end:
    # a `$( )`, a string's `$( )`, an index, a member's arguments and a
    # here-string's `$( )` each count one level toward the limit, no more.
    inner = "(" * (_DEPTH - 1) + "git commit -n" + ")" * (_DEPTH - 1)
    for opener, closer in (("$(", ")"), ('"$(', ')"'), ("$x[", "]"), ("$x.m(", ")"),
                           ('@"\n$(', ')\n"@')):
        text = opener + inner + closer
        assert find_bypass(text, POWERSHELL) == DASH_N, opener
        assert commands(text)[1], opener


def test_a_closer_that_closes_nothing_ends_the_command_and_the_reading_goes_on():
    # PowerShell runs none of this (it is listed in OVER); the reader reads on
    assert RECORD["x)git commit -n"] == ("parse-error", [])
    assert commands("x)git commit -n") == ([["x"], ["git", "commit", "-n"]], True)


def test_an_operator_with_no_blank_after_it_ends_the_command_all_the_same():
    handed("git status;git commit -n", ["git", "status"], ["git", "commit", "-n"])
    handed("git status&&git commit -n", ["git", "status"], ["git", "commit", "-n"])
    handed("git status|git commit -n", ["git", "status"], ["git", "commit", "-n"])


def test_a_comment_may_be_empty_or_hold_half_a_closer():
    handed("<##>git commit -n", ["git", "commit", "-n"])
    handed("<#>x#>git commit -n", ["git", "commit", "-n"])
    cut("git status <# x", ["git", "status"])


def test_a_code_point_is_one_to_six_hex_digits_in_braces_and_nothing_else():
    handed('git commit "`u{041}" -n', ["git", "commit", "A", "-n"])
    handed('git commit "`u{000041}" -n', ["git", "commit", "A", "-n"])
    handed("git commit -`u{06e}", ["git", "commit", "-n"])
    handed('git commit -m "x`u{10FFFF}" -n', ["git", "commit", "-m", "x" + chr(0x10FFFF), "-n"])
    handed('git commit -m "x`u{E000}" -n', ["git", "commit", "-m", "x" + chr(0xE000), "-n"])
    handed('git commit -m "x`u{DFFF}" -n', ["git", "commit", "-m", "x" + chr(0xFFFD), "-n"])
    cut('git commit "`u{0000041}" -n', ["git", "commit"])
    cut('git commit -m "x`u{110000}" -n', ["git", "commit", "-m"])
    cut('git commit -m "x`u{x1}" -n', ["git", "commit", "-m"])
    cut('git commit -m "`u{41" -n', ["git", "commit", "-m"])
    cut('git commit "`uab}" -n', ["git", "commit"])
    cut("git commit `uab} -n", ["git", "commit"])
    # open at the very end of the text, as the record's `"`u{41"` is open:
    # cut off, and not an error
    assert commands("x `u{41") == ([["x"]], False)


def test_a_quote_doubled_at_the_very_end_leaves_the_string_open():
    cut("git commit -m x 'a''", ["git", "commit", "-m", "x"])
    cut('git commit -m x "a""', ["git", "commit", "-m", "x"])
    handed("git commit -m 'a''b' -n", ["git", "commit", "-m", "a'b", "-n"])


def test_a_braced_variable_needs_a_name():
    cut("git commit ${} -n", ["git", "commit"])
    cut("git commit ${}a} -n", ["git", "commit"])
    handed("git commit ${null} -n", ["git", "commit", "-n"])
    handed("git commit ${NULL} -n", ["git", "commit", "-n"])
    handed("git commit x${null}y -n", ["git", "commit", "xy", "-n"])
    # an unset one is a value only the run shows: a word of its own, `$`
    seen("git commit ${a} -n", DASH_N)
    assert commands("git commit ${a} -n") == ([["git", "commit", "$", "-n"]], True)


def test_a_name_runs_as_far_as_its_letters_and_a_scope_as_far_as_its_own():
    seen("git commit $$-n", DASH_N)
    seen("git commit $^-n", DASH_N)
    handed("git commit $env:x-n", ["git", "commit", "-n"])
    handed("git commit $env:xy-n", ["git", "commit", "-n"])   # a name of two letters
    seen("git commit $env:x -n", DASH_N)
    seen("git commit $a:b -n", DASH_N)
    assert commands("git commit $a:b -n") == ([["git", "commit", "$", "-n"]], True)


def test_a_here_string_keeps_an_escaped_line_end_and_drops_the_last_raw_one():
    handed('git commit -m @"\nx`r\n"@ -n', ["git", "commit", "-m", "x\r", "-n"])
    handed('git commit -m @"\nx`n\n"@ -n', ["git", "commit", "-m", "x\n", "-n"])
    handed("git commit -m @'   \na\n'@ -n", ["git", "commit", "-m", "a", "-n"])
    handed("@(\ngit commit -n\n)", ["git", "commit", "-n"])
    cut("x @'", ["x"])


def test_a_redirection_takes_one_word_and_its_stream_one_digit():
    handed("git commit >>x -n", ["git", "commit", "-n"])
    handed("git commit >x -n", ["git", "commit", "-n"])
    handed("git commit 2>&1 -n", ["git", "commit", "-n"])
    handed("git commit 2>&12 -n", ["git", "commit", "2", "-n"])


# ---- what the reader answers and PowerShell did not run ----

# Each line is a choice. The reader cannot know a value, a failure or a branch
# the run decides, so it answers as if the flag were handed over.
OVER = {
    # the text is not PowerShell: nothing of it is run
    "git commit -m x < f --no-verify": "not parsed",
    "git commit -m @'x\n'@ --no-verify": "not parsed",
    "git commit @ -n": "not parsed",
    "git commit -m x >&1 -n": "not parsed",
    "git commit -m x >f -n >g": "not parsed",
    "git commit -m x 2>&2 -n": "not parsed",
    "git commit -m x 2>&3 -n": "not parsed",
    "git commit -m x > > f -n": "not parsed",
    "git commit -m x,\n,\n -n": "not parsed",
    '"git" commit -n': "not parsed",
    '"sub\\git.exe" commit -n': "not parsed",
    "$()git commit -n": "not parsed",
    "$u git commit -n": "not parsed",
    'git commit -n -m "open': "not parsed",
    "git commit -n -m 'open": "not parsed",
    "git commit -n <# open": "not parsed",
    "git commit -n ${open": "not parsed",
    "git commit -n -m @'\nx": "not parsed",
    "aramid " + R + " 'open --red-proof": "not parsed",
    "git commit 2>&-n": "not parsed",
    # a closer that closes nothing: the reader reads on rather than stop,
    # because it may be the one that miscounted (see the cut-off rule)
    "x)git commit -n": "not parsed",
    # it fails when it runs, before git is started
    "git commit -m x >f>g --no-verify": "fails at run time",
    "git commit -m a(b)c --no-verify": "fails at run time",
    "git commit -m x *> f*>g -n": "fails at run time",
    "git commit $u[0] -n": "fails at run time",
    "git commit $x.y(1) -n": "fails at run time",
    # a block that is not run, and a command behind `||`
    "{ git commit -n }": "not run",
    "while ($false) { git commit -n }": "not run",
    "function f { git commit -n }": "not run",
    "zq || git commit -n": "not run",
    "Write-Output x || git commit -n": "not run",
    "git status||git commit -n": "not run",
    # a value: it holds something, so the word is not the flag or git has a
    # subcommand; or it holds nothing, and the flag is the message
    "git commit --no-verify$x": "a value",
    "git commit -m ${x y} --no-verify": "a value",
    "git commit -m $x.y --no-verify": "a value",
    "git commit -m ${a b} -n": "a value",
    "git commit -m $env:X -n": "a value",
    "git commit -m (zq).y -n": "a value",
    "git $x commit -n": "a value",
    "git $x[0] commit -n": "a value",
    "git $x.Length commit -n": "a value",
    "git (zq) commit -n": "a value",
    "git $(zq) commit -n": "a value",
    'git "$u" commit -n': "a value",
    "git $u$u commit -n": "a value",
    "git commit $x-n": "a value",
    f"aramid $(zq) {R}": "a value",
    # a value inside the program's own name: written bare PowerShell starts
    # nothing, after `&` it starts git (`& g$()it commit -n` is in the record)
    "g$()it commit -n": "a value in the name",
    "g${u}it commit -n": "a value in the name",
    "g$($null)it commit -n": "a value in the name",
    "g$u''it commit -n": "a value in the name",
    "g$null''it commit -n": "a value in the name",
    "g$u`it commit -n": "a value in the name",
    "git$() commit -n": "a value in the name",
    "git$u commit -n": "a value in the name",
    f"ara$()mid {R}": "a value in the name",
    # git named among another git's arguments: these characters are blanks,
    # not line ends, and every word that names git starts a scan
    f"git status{chr(0x85)}git push --no-verify": "named in an argument",
    f"git status{chr(0x2028)}git push --no-verify": "named in an argument",
    f"git status{chr(0x2029)}git push --no-verify": "named in an argument",
    "git status\x0cgit push --no-verify": "named in an argument",
    "git status\x0bgit push --no-verify": "named in an argument",
    # a quoted stop token, and a comma, a line end and a tab in a row
    'git commit "--%" -n': "read by the ordinary rules",
    "git commit '--%' -n": "read by the ordinary rules",
    "git commit -m x,\n\t-n": "read by the ordinary rules",
}


def test_the_reader_answers_more_than_powershell_ran_only_where_listed():
    over = {command for command, (_, argvs) in RECORD.items()
            if _judged(argvs) is None and find_bypass(command, POWERSHELL) is not None}
    assert over == set(OVER)
    for command, why in OVER.items():
        assert (RECORD[command][0] == "parse-error") == (why == "not parsed"), command


# ---- it cannot raise, and it comes back ----

def test_a_turn_that_reads_nothing_cannot_hold_the_walk(monkeypatch):
    # No rule of the reader reads nothing. The walk is bounded by the length
    # of the text all the same: a hook that does not come back has not answered.
    from aramid import agent_bypass_powershell as abp

    monkeypatch.setattr(abp, "_redirection", lambda text, i: (i, True))
    assert commands("git commit -n > f") == ([["git", "commit", "-n"]], False)
    assert find_bypass("git commit -n > f", POWERSHELL) == DASH_N



def test_no_text_makes_the_reader_raise():
    rng = random.Random(45)  # noqa: S311  -- seeded, reproducible, not crypto
    alphabet = "`'\"$(){}@<>#;|&,.-:[]=%\\ \n\r\tgitx" + LDQ + RSQ
    for _ in range(4000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 16)))
        words, whole = commands(text)
        assert isinstance(whole, bool)
        assert all(isinstance(word, str) for seg in words for word in seg), text
        find_bypass("git " + text, POWERSHELL)


@pytest.mark.parametrize("text", ["", " ", "`", "$", "@", "$(", "${", "@'", "@'\n", "<#", "-", "--%",
                                  "git commit --%", "$x[", "$x.", "(", "{", ")", "}", "]", "'", '"',
                                  "git `", "git $", "a`\n", ",\n", "$x.y(", "@(", "@{", ">", "2>", "<"])
def test_the_shortest_texts_are_read_without_an_error(text):
    words, whole = commands(text)
    assert isinstance(words, list) and isinstance(whole, bool)
    assert find_bypass(text, POWERSHELL) is None
