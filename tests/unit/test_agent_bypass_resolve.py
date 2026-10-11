"""The agent hook's rule for `aramid ledger resolve --fixed` (FN-36, spec
section 9.3): an agent's close has to show red proof.

At the command line `--red-proof` is optional for an ordinary finding. For an
agent it is not, by the operator's decision of 2026-10-11, and the hook is
where that is held: `find_bypass` reads the command a Bash or PowerShell tool
call is about to run, and a close that carries `--fixed` and no `--red-proof`
is answered like a hook bypass.

Token-level, like the git rules. The cases below are grouped by what they
decide: which launches are read, which spellings of the flags argparse takes,
what cannot count as a flag, and which residuals are accepted."""
import pytest

from aramid import cli
from aramid.agent_bypass import _RESOLVE_FLAGS, Bypass, find_bypass

NO_RED = Bypass("no-red-proof", "ledger resolve", "--fixed")
CLOSE = 'ledger resolve llm1 --fixed abc123 --test "python -m pytest tests/t.py" --reason r'


# ---- which launches are read ----

@pytest.mark.parametrize("launch", [
    "aramid",
    "aramid.exe",
    "ARAMID.EXE",                     # Windows does not match case
    "aramid.cmd",
    "aramid.bat",
    "./aramid.ps1",
    "./aramid",
    "/usr/local/bin/aramid",
    '"C:/Users/x/AppData/Roaming/Python/Python314/Scripts/aramid.exe"',
    '"C:\\Program Files\\Python314\\Scripts\\aramid.exe"',
    "python -m aramid",
    "python -P -m aramid",
    "python3 -m aramid",
    "py -3.14 -m aramid",
    "python -maramid",
    "python -m aramid.__main__",
    "uv run aramid",
    "uv run python -m aramid",
    "FOO=1 aramid",
    "env FOO=1 aramid",
    "& aramid",                       # PowerShell's call operator
    "cd repo && aramid",
    "git status; aramid",
    "aramid ledger filter --status open | cat; aramid",
])
def test_a_close_without_red_proof_is_read_however_aramid_is_launched(launch):
    assert find_bypass(f"{launch} {CLOSE}") == NO_RED


def test_a_global_option_before_the_subcommand_is_stepped_over():
    assert find_bypass(f"aramid --version {CLOSE}") == NO_RED


# ---- the flags, as argparse takes them ----

@pytest.mark.parametrize("fixed", ["--fixed abc", "--fixed=abc", "--fix abc", "--f abc",
                                   "--fi=abc"])
def test_every_spelling_of_fixed_argparse_accepts_is_the_flag(fixed):
    assert find_bypass(f"aramid ledger resolve llm1 {fixed} --test t --reason r") == NO_RED


@pytest.mark.parametrize("red", ["--red-proof", "--red", "--red-", "--red-p", "--red-proo"])
def test_every_spelling_of_red_proof_argparse_accepts_allows_the_close(red):
    assert find_bypass(f"aramid {CLOSE} {red}") is None
    assert find_bypass(f"aramid ledger resolve {red} llm1 --fixed abc --test t --reason r") is None


def test_the_flags_may_come_in_any_order_around_the_id():
    assert find_bypass("aramid ledger resolve --fixed abc llm1 --test t --reason r") == NO_RED
    assert find_bypass("aramid ledger resolve --reason r --test t --fixed abc llm1") == NO_RED
    assert find_bypass(
        "aramid ledger resolve --reason r --red-proof --test t --fixed abc llm1") is None


def test_a_value_attached_with_an_equals_sign_takes_no_second_token():
    """`--fixed=abc` carries its value, so the token after it is read on its
    own. Skipped as a value, this `--red-proof` would go unseen."""
    assert find_bypass(
        "aramid ledger resolve llm1 --fixed=abc --red-proof --test t --reason r") is None
    assert find_bypass(
        "aramid ledger resolve llm1 --test=t --reason=r --fixed abc --red-proof") is None


def test_a_flag_without_a_value_takes_no_second_token():
    assert find_bypass(
        "aramid ledger resolve llm1 --out-of-scope --fixed abc --test t --reason r") == NO_RED
    assert find_bypass(
        "aramid ledger resolve llm1 --red-proof --fixed abc --test t --reason r") is None


def test_an_exact_name_wins_over_a_longer_option_it_begins(monkeypatch):
    """No option of today's parser begins another. argparse's rule for when
    one does is that the exact name is that option, and a close must not
    slip past because a later flag made `--fixed` look like a prefix of two."""
    from aramid import agent_bypass

    monkeypatch.setattr(agent_bypass, "_RESOLVE_FLAGS",
                        {**_RESOLVE_FLAGS, "--fixed-by": True})

    assert agent_bypass._resolve_flag("--fixed") == "--fixed"
    assert agent_bypass._resolve_flag("--fixed=abc") == "--fixed"
    assert agent_bypass._resolve_flag("--fixed-") == "--fixed-by"
    assert agent_bypass._resolve_flag("--fix") is None
    assert find_bypass("aramid ledger resolve llm1 --fixed abc --test t --reason r") == NO_RED


@pytest.mark.parametrize("token", ["llm1", "-", "", "=abc", "--bogus", "--re", "--r", "-h",
                                   "--red proof"])
def test_a_token_that_is_no_option_of_the_parser_is_none(token):
    from aramid.agent_bypass import _resolve_flag

    assert _resolve_flag(token) is None


# ---- what cannot count as a flag ----

@pytest.mark.parametrize("command", [
    # the value of --test, --reason or --fixed is skipped, whatever it says
    'aramid ledger resolve llm1 --fixed abc --test "--red-proof" --reason r',
    'aramid ledger resolve llm1 --fixed abc --test t --reason "--red-proof"',
    "aramid ledger resolve llm1 --fixed --red-proof --test t --reason r",
    "aramid ledger resolve llm1 --fix abc --tes --red-proof --rea r",
    # ... and so is one attached with `=`
    "aramid ledger resolve llm1 --fixed abc --test t --reason=--red-proof",
    # a quoted command line is one token
    'aramid ledger resolve llm1 --fixed abc --test "pytest t.py --red-proof" --reason r',
    # after a bare `--` argparse reads no options
    "aramid ledger resolve llm1 --fixed abc --test t --reason r -- --red-proof",
    # argparse matches case, and `--r` and `--re` name two flags, so neither is one
    "aramid ledger resolve llm1 --fixed abc --test t --reason r --RED-PROOF",
    "aramid ledger resolve llm1 --fixed abc --test t --reason r --re",
    # a token with a space in it is never an abbreviation
    'aramid ledger resolve llm1 --fixed abc --test t --reason r "--red proof"',
])
def test_text_that_only_looks_like_red_proof_does_not_allow_the_close(command):
    assert find_bypass(command) == NO_RED


@pytest.mark.parametrize("command", [
    'aramid ledger resolve llm1 --out-of-scope --reason "--fixed"',
    'aramid ledger resolve llm1 --out-of-scope --reason r -- --fixed abc',
    'aramid ledger resolve llm1 --out-of-scope --reason r "--fixed abc"',
    "aramid ledger resolve llm1 --out-of-scope --reason r --FIXED abc",
    "aramid ledger resolve llm1 --out-of-scope --reason r -fixed abc",
])
def test_text_that_only_looks_like_fixed_is_not_a_close(command):
    assert find_bypass(command) is None


# ---- not this rule's business ----

@pytest.mark.parametrize("command", [
    "aramid ledger resolve llm1 --out-of-scope --reason r",
    "aramid ledger resolve",
    "aramid ledger resolve --help",
    "aramid ledger show llm1",
    "aramid ledger filter --status open",
    "aramid check --staged",
    "aramid resolve llm1 --fixed abc",          # no such subcommand: argparse exits 2
    "aramid ledger --fixed abc resolve llm1",   # `--fixed` is not a `ledger` option
    "aramid ledger --help resolve llm1 --fixed abc --test t --reason r",  # prints help, exits
    "aramid ledger show llm1 --fixed abc",      # ... nor one of another subcommand
    "aramid ledger filter --fixed abc",
    "aramid fleet resolve llm1 --fixed abc",    # `resolve` belongs to `ledger` alone
    "aramid $(true) ledger show llm1 --fixed abc",
    "aramid ledger $X show resolve --fixed abc",
    "aramid $X",
    "aramid",
    "aramid ledger",
    "python -m aramid",
    'echo "aramid ledger resolve llm1 --fixed abc --test t --reason r"',
    'git commit -m "aramid ledger resolve llm1 --fixed abc"',
    'grep -n "resolve --fixed" docs/user-guide.md',
    "cat aramid.toml",
    "cd aramid && ls",
    "git -C /x/aramid log --oneline",
    "pytest -q tests/unit",
])
def test_everything_else_is_let_through(command):
    assert find_bypass(command) is None


def test_a_git_bypass_in_the_same_command_is_still_found():
    assert find_bypass(f"aramid {CLOSE} --red-proof && git commit -n -m x") == Bypass(
        "no-verify", "commit", "-n")
    assert find_bypass(f"git commit -m x && aramid {CLOSE}") == NO_RED


# ---- accepted residuals, each a choice ----

def test_an_unquoted_windows_path_is_a_documented_false_negative():
    # shlex reads a backslash as an escape, so the path loses its separators
    # and no token is named aramid. The same holds for git.exe today.
    assert find_bypass(f"C:\\Scripts\\aramid.exe {CLOSE}") is None


def test_a_close_built_inside_python_is_a_documented_false_negative():
    assert find_bypass(
        'python -c "from aramid.cli import main; main([\'ledger\', \'resolve\'])"') is None


def test_reading_a_backtick_both_ways_costs_a_false_alarm_in_powershell():
    # PowerShell does hand aramid --red-proof here: the reason goes on to its
    # last quote. To a POSIX shell the string ends at the first escaped quote,
    # and what follows is a comment, or another command. The close is answered
    # if either reading holds one without red proof.
    assert find_bypass('aramid ledger resolve llm1 --fixed abc --test t '
                       '--reason "see `"issue #12`" now" --red-proof') == NO_RED
    assert find_bypass('aramid ledger resolve llm1 --fixed abc --test t '
                       '--reason "a `"b; c`" d" --red-proof') == NO_RED


def test_a_flag_inside_backticks_is_a_documented_false_negative():
    # the shell hands aramid no --red-proof here: it is the argument of `true`.
    # Written with $( ) it is a command of its own, and is read right.
    assert find_bypass(f"aramid {CLOSE} `true --red-proof `") is None
    # nor here, inside double quotes: read the POSIX way the flag stands
    # outside them, and that reading gets to the end
    assert find_bypass(
        'aramid ledger resolve llm1 --fixed abc --test t --reason "x`" --red-proof "`y"'
    ) is None


def test_a_powershell_string_that_ends_in_a_backslash_hides_what_follows_it():
    # PowerShell ends the string at the quote; by the POSIX rule it is escaped
    # and the string never ends. The words before it are read, and nothing
    # after it: a --fixed there is a miss, a --red-proof there a false alarm.
    ends_in_a_backslash = '--reason "in C:\\src\\"'
    assert find_bypass(
        f"aramid ledger resolve llm1 {ends_in_a_backslash} --fixed abc --test t") is None
    assert find_bypass(
        f"aramid ledger resolve llm1 --fixed abc --test t {ends_in_a_backslash}") == NO_RED
    assert find_bypass(
        f"aramid ledger resolve llm1 --fixed abc --test t --red-proof {ends_in_a_backslash}"
    ) is None
    assert find_bypass(
        f"aramid ledger resolve llm1 --fixed abc --test t {ends_in_a_backslash} --red-proof"
    ) == NO_RED


def test_an_odd_escaped_quote_costs_a_false_alarm_in_powershell_when_the_flag_follows():
    # PowerShell's string is `5" disk`. Read the POSIX way it ends at the
    # escaped quote and the last quote opens one that never closes, so the
    # --red-proof after it is not read. Before the reason, it is.
    reason = '--reason "5`" disk"'
    assert find_bypass(
        f"aramid ledger resolve llm1 --fixed abc --test t {reason} --red-proof") == NO_RED
    assert find_bypass(
        f"aramid ledger resolve llm1 --fixed abc --test t --red-proof {reason}") is None


def test_a_close_argparse_would_reject_gets_the_same_answer():
    # Missing --test and --reason: argparse exits 2 and nothing closes. The
    # advice is the same either way, so the rule does not try to tell.
    assert find_bypass("aramid ledger resolve llm1 --fixed abc") == NO_RED


def test_a_close_on_a_line_before_an_open_quote_is_answered():
    # bash has made the close by the time the open quote is a syntax error;
    # found by running generated commands under bash (the second one).
    assert find_bypass(f"aramid {CLOSE}\necho 'oops") == NO_RED
    assert find_bypass(
        "aramid ledger resolve llm1 --fixed abc --test # 'a\nb' t --reason r") == NO_RED
    assert find_bypass(f"aramid {CLOSE}\ngit commit -F - <<'EOF'\nit's done\nEOF") == NO_RED
    assert find_bypass(f"aramid {CLOSE} --red-proof\necho 'oops") is None


def test_a_close_is_read_up_to_a_quote_that_never_closes():
    assert find_bypass('aramid ledger resolve llm1 --fixed abc --test "unclosed') == NO_RED
    assert find_bypass(f"aramid {CLOSE} --red-proof 'unclosed") is None
    # after the quote nothing is read: no --fixed, so no close; and no --red-proof
    assert find_bypass(
        "aramid ledger resolve llm1 --reason 'unclosed --fixed abc --test t") is None
    assert find_bypass(f"aramid {CLOSE} 'unclosed --red-proof") == NO_RED
    # a backslash with nothing after it: the word it ends is not read
    assert find_bypass(f"aramid {CLOSE} \\") == NO_RED
    assert find_bypass(f"aramid {CLOSE} --red-proof\\") == NO_RED
    assert find_bypass("aramid '") is None


def test_a_cut_off_second_reading_is_left_out_when_the_first_gets_to_the_end():
    # bash, and proper closes: aramid is handed --red-proof. Read with
    # PowerShell's backtick, the backtick before the last quote escapes it and
    # the string never closes; cut off there, that reading holds a close
    # without red proof every time.
    for reason in ('"by `whoami`"', '"ran `echo "hi"`"', '"at `date` by `whoami`"'):
        assert find_bypass(
            f"aramid ledger resolve llm1 --fixed abc --test t --reason {reason} --red-proof"
        ) is None, reason


def test_a_cut_off_first_reading_still_counts_when_the_second_gets_to_the_end():
    # bash. The first line is a close without red proof, its flag in a comment,
    # and bash has made it by the time the second line is a syntax error. Read
    # with PowerShell's backtick both lines pair up and the flag is a word, so
    # leaving out the cut-off POSIX reading would let this through. (It is the
    # same choice that costs the false alarm for an odd escaped quote, above.)
    assert find_bypass(
        f'aramid {CLOSE} --reason "by `whoami`" # 5" wide --red-proof\necho "a`"b"') == NO_RED


def test_a_cut_off_second_reading_counts_when_the_first_is_cut_off_too():
    # PowerShell. The reason hides --fixed from the POSIX reading, where its #
    # starts a comment; and the string on the next line ends in a backslash, so
    # neither reading gets to the end.
    assert find_bypass(
        'aramid ledger resolve llm1 --reason "see `"issue #12`" now" --fixed abc --test t'
        '\necho "C:\\src\\"') == NO_RED


def test_an_out_of_contract_start_fails_open():
    # As for the git scanner (fuzz ledger a7bee49a): `find_bypass` only ever
    # passes an index into the segment, and anything else answers None.
    from aramid.agent_bypass import _scan_one_aramid

    close = ["aramid", "ledger", "resolve", "llm1", "--fixed", "abc"]
    assert _scan_one_aramid(close, 0) == NO_RED
    assert _scan_one_aramid([], 0) is None
    assert _scan_one_aramid(close, 6) is None
    assert _scan_one_aramid(close, -6) is None
    assert _scan_one_aramid([], -9223372036854775808) is None


# ---- the flag table is the parser's own ----

def _resolve_parser():
    parser = cli.build_parser()
    for name in ("ledger", "resolve"):
        choices = next(a.choices for a in parser._actions
                       if isinstance(getattr(a, "choices", None), dict) and name in a.choices)
        parser = choices[name]
    return parser


def test_the_flag_table_matches_the_real_parser():
    """`agent_bypass` is pure stdlib and cannot import the CLI, so it carries
    its own table of `ledger resolve`'s options and whether each takes a value.
    A flag added to the parser and not to the table would be read as unknown,
    and its value as a token of its own."""
    parser = _resolve_parser()
    real = {opt: action.nargs != 0
            for action in parser._actions for opt in action.option_strings
            if opt.startswith("--")}

    assert real == _RESOLVE_FLAGS
    # Abbreviations are read because this parser accepts them.
    assert parser.allow_abbrev is True


def test_no_global_option_takes_a_value():
    """A global option before `ledger` is stepped over as ONE token. That
    holds while none of them takes a value."""
    parser = cli.build_parser()
    assert all(action.nargs == 0 for action in parser._actions if action.option_strings)


# ---- what the shell hands to aramid, and what it does not ----
#
# Every other rule in this module looks for a flag that is PRESENT, so text
# the hook reads and the shell does not pass on can only cost a false alarm.
# This rule looks for a flag that is ABSENT. Read the same way, such text
# would let a close through (the security review of 9b37b81).

@pytest.mark.parametrize("tail", [
    "\necho --red-proof",                        # the next line is another command
    "\r\necho --red-proof",
    "\n\n  echo --red-proof",
    " # --red-proof",                            # a comment
    " #--red-proof",
    " # see below\necho --red-proof",            # a comment, then another command
    "\n# --red-proof",
    "; echo --red-proof",
    ";# --red-proof",
    " && echo --red-proof",
    " | tee --red-proof",
    " > --red-proof",                            # where a redirection goes
    " 2> --red-proof",
    " >log; echo --red-proof",
    " $(true --red-proof)",                      # a command of its own
    " <(echo --red-proof)",
    " `date` # --red-proof",                     # outside quotes a backtick escapes nothing
    ' --reason "by `whoami`" # --red-proof',     # bash ends that string at its quote
    # the same with a quote in the comment: read with PowerShell's backtick the
    # string ends there, and the flag after it is a word
    ' --reason "by `whoami`" # 5" wide --red-proof',
    "\naramid ledger resolve llm2 --fixed abc --test t --reason r --red-proof",
])
def test_a_red_proof_the_shell_does_not_hand_to_aramid_does_not_count(tail):
    assert find_bypass(f"aramid {CLOSE}{tail}") == NO_RED


@pytest.mark.parametrize("command", [
    f"aramid {CLOSE} \\\n  --red-proof",         # a line continued with a backslash
    f"aramid {CLOSE} \\\r\n  --red-proof",
    f"aramid {CLOSE} `\n  --red-proof",          # and with PowerShell's backtick
    "aramid ledger resolve llm1 --fixed abc --test t --reason 'two\nlines' --red-proof",
    'aramid ledger resolve llm1 --fixed abc --test t --reason "two\nlines" --red-proof',
    'aramid ledger resolve llm1 --fixed abc --test t --reason "see #12" --red-proof',
    "aramid ledger resolve llm1 --fixed abc --test t --reason '#12' --red-proof",
    "aramid ledger resolve llm1 --fixed abc --test t --reason issue#12 --red-proof",
    'aramid ledger resolve llm1 --fixed abc --test t --reason "a \\" # b" --red-proof',
    # quotes PowerShell escapes with a backtick, read either way
    'aramid ledger resolve llm1 --fixed abc --test t --reason "say `"hi`" now" --red-proof',
    # a redirection does not end the command: what follows it is still handed over
    f"aramid {CLOSE} >log --red-proof",
    f"aramid {CLOSE} > log 2>&1 --red-proof",
    f"aramid {CLOSE} 2>/dev/null --red-proof",
    f"aramid {CLOSE} &>>log --red-proof",
    f"aramid {CLOSE} --red-proof 2>&1 | tail -n 3",
    # and neither do parentheses
    "aramid ledger resolve llm1 --fixed $(git rev-parse HEAD) --test t --reason r --red-proof",
    "aramid ledger resolve llm1 --fixed abc --test t --reason $(cat why; echo) --red-proof",
    "aramid ledger resolve llm1 --fixed abc --test t --reason <(cat why) --red-proof",
    'aramid ledger resolve llm1 --fixed abc --test t --reason ";" --red-proof',
    "aramid ledger resolve llm1 --fixed abc --test t --reason 'a | b' --red-proof",
    f"# close it\naramid {CLOSE} --red-proof",
    f"aramid {CLOSE} --red-proof # with red proof",
    f"aramid {CLOSE} --red-proof\ngit status",
    f"cd repo\naramid {CLOSE} --red-proof\n",
])
def test_a_red_proof_that_does_reach_aramid_still_counts(command):
    assert find_bypass(command) is None


@pytest.mark.parametrize("command", [
    # `#` inside a word is no comment to the shell, so what follows is live
    "aramid ledger resolve llm1 --reason issue#12 --fixed abc --test t",
    "aramid ledger resolve llm1 --reason '#12' --fixed abc --test t",
    # PowerShell's escaped quotes: there the reason goes on to its last quote
    'aramid ledger resolve llm1 --reason "see `"issue #12`" now" --fixed abc --test t',
    'aramid ledger resolve llm1 --reason "5`" wide" --fixed abc --test t',
    'aramid ledger resolve llm1 --reason "a `"b; c`" d" --fixed abc --test t',
    "aramid ledger resolve llm1 --reason r \\\n  --fixed abc --test t",
    # the words after a redirection are still arguments of the same program
    "aramid ledger resolve llm1 >log --fixed abc --test t --reason r",
    "aramid ledger resolve llm1 > log --fixed abc --test t --reason r",
    "aramid ledger resolve llm1 2>&1 --fixed abc --test t --reason r",
    "aramid ledger resolve llm1 >>log --fixed abc --test t --reason r",
    "aramid ledger resolve llm1 <in --fixed abc --test t --reason r",
    "aramid ledger resolve llm1 &>log --fixed abc --test t --reason r",
    "aramid ledger resolve llm1 2>log --fixed abc --test t --reason r",
    "aramid 2>/dev/null ledger resolve llm1 --fixed abc --test t --reason r",
    "aramid >log ledger resolve llm1 --fixed abc --test t --reason r",
    # and so are the words after a closing parenthesis
    "aramid ledger resolve llm1 --reason $(cat why) --fixed abc --test t",
    "aramid ledger resolve llm1 --reason <(cat why) --fixed abc --test t",
    "aramid ledger resolve llm1 --reason $(cat a; cat b) --fixed abc --test t",
    # a word the shell may make nothing of does not part `aramid ledger resolve`
    "aramid $(true) ledger resolve llm1 --fixed abc --test t --reason r",
    "aramid ledger $(true) resolve llm1 --fixed abc --test t --reason r",
    "aramid --version $EMPTY ledger ${EMPTY} resolve llm1 --fixed abc --test t --reason r",
    'aramid "$@" ledger resolve llm1 --fixed abc --test t --reason r',
    # a quoted operator is a value, not the end of the command
    'aramid ledger resolve llm1 --reason "|" --fixed abc --test t',
    "aramid ledger resolve llm1 --reason ';' --fixed abc --test t",
    'aramid ledger resolve llm1 --reason ">" --fixed abc --test t',
    'aramid ledger resolve llm1 --reason "\n" --fixed abc --test t',
    "aramid ledger resolve llm1 --reason \\; --fixed abc --test t",
    "git status\naramid ledger resolve llm1 --fixed abc --test t --reason r",
    "echo done # then\naramid ledger resolve llm1 --fixed abc --test t --reason r",
])
def test_text_the_shell_does_hand_over_cannot_hide_the_close(command):
    assert find_bypass(command) == NO_RED


@pytest.mark.parametrize("command", [
    "aramid ledger resolve llm1 --out-of-scope --reason r # not --fixed abc",
    "# aramid ledger resolve llm1 --fixed abc --test t --reason r",
    "git status # aramid ledger resolve llm1 --fixed abc --test t --reason r",
    # outside quotes a backtick escapes nothing, on either reading
    "aramid ledger resolve llm1 --out-of-scope --reason r `date` # not --fixed abc",
])
def test_a_close_that_only_a_comment_holds_is_not_a_close(command):
    assert find_bypass(command) is None
