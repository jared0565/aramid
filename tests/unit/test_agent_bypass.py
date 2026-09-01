"""Token-level git bypass detection (spec §6). Matching is on parsed
tokens, never substrings; false positives are the expensive direction."""
from aramid.agent_bypass import Bypass, find_bypass


# ---- matches (spec §6 red-first cases) ----

def test_commit_no_verify_matches():
    assert find_bypass("git commit --no-verify -m x") == Bypass(
        "no-verify", "commit", "--no-verify")


def test_commit_short_n_matches():
    assert find_bypass("git commit -n -m x") == Bypass(
        "no-verify", "commit", "-n")


def test_push_no_verify_matches():
    assert find_bypass("git push --no-verify origin main") == Bypass(
        "no-verify", "push", "--no-verify")


def test_hookspath_wrapping_commit_matches():
    assert find_bypass('git -c core.hooksPath=/tmp/x commit -m x') == Bypass(
        "hooks-path", "commit", "core.hooksPath=/tmp/x")


def test_hookspath_case_insensitive_key():
    assert find_bypass("git -c CORE.HooksPath=/x push") == Bypass(
        "hooks-path", "push", "CORE.HooksPath=/x")


def test_hookspath_attached_spelling_matches():
    assert find_bypass("git -ccore.hookspath=/x commit") == Bypass(
        "hooks-path", "commit", "core.hookspath=/x")


def test_compound_command_tail_matches():
    assert find_bypass('pytest -q && git commit -n -m "wip"') == Bypass(
        "no-verify", "commit", "-n")


def test_piped_git_matches():
    assert find_bypass("echo hi | git push --no-verify") == Bypass(
        "no-verify", "push", "--no-verify")


def test_absolute_git_path_matches():
    assert find_bypass("/usr/bin/git commit -n") == Bypass(
        "no-verify", "commit", "-n")


def test_git_exe_matches():
    assert find_bypass("git.exe commit --no-verify") == Bypass(
        "no-verify", "commit", "--no-verify")


def test_global_dash_capital_c_arg_is_skipped_not_subcommand():
    assert find_bypass("git -C /some/path commit -n") == Bypass(
        "no-verify", "commit", "-n")


def test_git_dir_equals_form_is_skipped():
    assert find_bypass("git --git-dir=.git commit -n") == Bypass(
        "no-verify", "commit", "-n")


# ---- non-matches: the expensive direction, structurally excluded ----

def test_push_short_n_is_dry_run_not_bypass():
    assert find_bypass("git push -n origin main") is None


def test_plain_commit_and_push_allowed():
    assert find_bypass("git commit -m x") is None
    assert find_bypass("git push origin main") is None


def test_message_containing_flag_text_never_matches():
    assert find_bypass('git commit -m "do not pass --no-verify"') is None


def test_single_word_message_equal_to_flag_never_matches():
    # shlex strips the quotes, so only the -m arg-skip prevents this one.
    assert find_bypass('git commit -m "--no-verify"') is None


def test_pathspec_after_double_dash_never_matches():
    assert find_bypass("git commit -- --no-verify") is None


def test_other_subcommands_never_match():
    assert find_bypass("git log --no-verify") is None
    assert find_bypass("git merge --no-verify main") is None


def test_other_config_keys_never_match():
    assert find_bypass("git -c user.name=x commit -m y") is None


def test_hookspath_on_non_commit_push_never_matches():
    assert find_bypass("git -c core.hooksPath=/x status") is None


def test_no_git_in_command():
    assert find_bypass("pytest -q tests/unit") is None


def test_bundled_short_flags_are_a_documented_false_negative():
    # -an bundles -a and -n but is NOT expanded: at token level it cannot
    # be told apart from an attached-argument token. Pinned so the residual
    # is a choice, not an accident.
    assert find_bypass("git commit -an") is None


# ---- fail-open ----

def test_unbalanced_quote_fails_open():
    assert find_bypass('git commit -n "unclosed') is None


def test_non_string_fails_open():
    assert find_bypass(None) is None
    assert find_bypass(42) is None


def test_scan_one_git_out_of_contract_start_fails_open():
    # Fuzz ledger a7bee49a: seg=[] with a huge negative start walked
    # backwards into seg[i] and raised IndexError. Out-of-contract input
    # fails open, like every other malformed input in this module.
    from aramid.agent_bypass import _scan_one_git
    assert _scan_one_git([], -9223372036854775808) is None
    assert _scan_one_git([], 0) is None
    assert _scan_one_git(["git"], 5) is None
    assert _scan_one_git(["git", "commit", "-n"], -1) is None
