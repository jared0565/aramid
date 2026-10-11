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
    "aramid ledger show llm1 --fixed abc",      # ... nor one of another subcommand
    "aramid ledger filter --fixed abc",
    "aramid fleet resolve llm1 --fixed abc",    # `resolve` belongs to `ledger` alone
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


def test_a_close_argparse_would_reject_gets_the_same_answer():
    # Missing --test and --reason: argparse exits 2 and nothing closes. The
    # advice is the same either way, so the rule does not try to tell.
    assert find_bypass("aramid ledger resolve llm1 --fixed abc") == NO_RED


def test_an_unlexable_command_fails_open():
    assert find_bypass('aramid ledger resolve llm1 --fixed abc --test "unclosed') is None


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
