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


# ---- mutation-ledger kills, _scan_one_git ----

def test_scan_one_git_loop_bound_is_strict():
    # ledger 1d3924d1: `while i < len(seg)` mutated to `<=` walks one index
    # past the segment's end and raises IndexError instead of returning
    # None. `git` alone hits i == len(seg) on the very first check; `git -c
    # x=y` reaches i == len(seg) after consuming the -c/value pair. Both
    # must return None cleanly under the real `<`.
    assert find_bypass("git") is None
    assert find_bypass("git -c x=y") is None


def test_scan_one_git_dash_c_requires_both_the_flag_and_a_next_token():
    # ledger 4ce40a5b: `tok == "-c" and i + 1 < len(seg)` mutated to `or`.
    # `git -c` (the flag with no following token): the real `and` short-
    # circuits to False and returns None; the mutant's `or` is True from
    # `tok == "-c"` alone and indexes past the segment -> IndexError.
    assert find_bypass("git -c") is None
    # Behavioral arm, pinning the FALSE-POSITIVE direction: under the
    # mutant, `tok == "-C" or i + 1 < len(seg)` is True purely from the
    # second clause, so -C's directory argument gets appended to `configs`
    # as if it were a `-c key=value` pair. When that directory string
    # happens to look like `core.hookspath=...`, the mutant manufactures a
    # bogus hooks-path Bypass for a plain `git -C <dir> commit`. The real
    # `and` never treats -C's argument as a config value, so this is None.
    assert find_bypass("git -C core.hookspath=x commit") is None


# ---- a quote that never closes ----

def test_a_quote_that_never_closes_does_not_let_the_lines_before_it_through():
    """bash runs a script line by line: the commit on the first line is made
    by the time the open quote on the second is a syntax error. Until the
    review of 9b37b81 a command shlex could not lex was let through whole."""
    assert find_bypass("git commit --no-verify -m x\necho 'oops") == Bypass(
        "no-verify", "commit", "--no-verify")
    assert find_bypass('git commit -m x -n\necho "oops') == Bypass("no-verify", "commit", "-n")
    assert find_bypass("git status\ngit push --no-verify\necho 'oops") == Bypass(
        "no-verify", "push", "--no-verify")


def test_the_words_before_the_open_quote_are_read_on_its_own_line_too():
    """What does not pair up by the POSIX rule can pair up in the shell that
    runs it: a heredoc body with an apostrophe, a PowerShell string that ends
    in a backslash. (`git commit -n "unclosed` runs in no shell, and is
    refused all the same.)"""
    assert find_bypass("git commit --no-verify -F - <<'EOF'\nit's done\nEOF") == Bypass(
        "no-verify", "commit", "--no-verify")
    assert find_bypass('git commit --no-verify -m "C:\\src\\"') == Bypass(
        "no-verify", "commit", "--no-verify")
    assert find_bypass('git commit -n "unclosed') == Bypass("no-verify", "commit", "-n")


def test_what_follows_the_open_quote_is_not_read():
    assert find_bypass("git commit -m 'unclosed --no-verify") is None
    assert find_bypass("git commit -F - <<'EOF'\nit's done\nEOF") is None
    # a miss in PowerShell, which ends this string at its quote
    assert find_bypass('git commit -m "C:\\src\\" --no-verify') is None
    # nor is the word the quote opened in
    assert find_bypass("git commit --no-verify'") is None


def test_a_backslash_with_nothing_after_it_ends_the_reading_the_same_way():
    assert find_bypass("git commit --no-verify -m x \\") == Bypass(
        "no-verify", "commit", "--no-verify")
    assert find_bypass("git commit -m x --no-verify\\") is None


def test_nothing_but_an_open_quote_is_no_command():
    for command in ("git '", 'git "', "git commit '", "git \\"):
        assert find_bypass(command) is None, command


# ---- fail-open ----

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


def test_a_global_option_with_a_separate_argument_is_skipped_whole():
    """The drain confirms a mutant against the unit suite alone, and
    `i += 1 if "=" in tok else 2` -- the two-token form of --git-dir and
    friends -- was reached only through tests/integration: skipping one
    token too many would read the subcommand as the option's value."""
    assert find_bypass("git --git-dir /x/.git commit --no-verify") == \
        Bypass("no-verify", "commit", "--no-verify")
    assert find_bypass("git --work-tree=/x commit -n") == Bypass("no-verify", "commit", "-n")
    assert find_bypass("git --git-dir --no-verify status") is None, \
        "the option's own value is not a flag, and status is not gated"


def test_every_token_walk_advances_by_exactly_the_tokens_it_consumed():
    """Each `i += 1` / `j += 2` of the scanner, pinned by a command where one
    step too many would skip the subcommand or the bypass flag: an unknown
    global option before `commit`, an `-m msg` pair before `--no-verify`, and
    a bare flag before it (the derive drew each increment one higher)."""
    assert find_bypass("git --no-pager commit --no-verify") == Bypass(
        "no-verify", "commit", "--no-verify")
    assert find_bypass("git commit -m fix --no-verify") == Bypass(
        "no-verify", "commit", "--no-verify")
    assert find_bypass("git commit --amend --no-verify") == Bypass(
        "no-verify", "commit", "--no-verify")
    assert find_bypass("git push -o ci.skip origin main --no-verify") == Bypass(
        "no-verify", "push", "--no-verify")


# ---- lines, comments and continuations, read as the shell reads them ----

NO_VERIFY = Bypass("no-verify", "commit", "--no-verify")


def test_a_hash_inside_a_word_is_not_a_comment():
    # the shell passes `fix#12` whole, and the flag after it
    assert find_bypass("git commit -m fix#12 --no-verify") == NO_VERIFY
    assert find_bypass("curl http://x/y#frag && git push --no-verify") == Bypass(
        "no-verify", "push", "--no-verify")
    # an escaped space is part of a word, so the `#` after it is inside one
    assert find_bypass("git commit -m \\ #x --no-verify") == NO_VERIFY


def test_a_hash_inside_quotes_is_text():
    assert find_bypass('git commit -m "# heading" --no-verify') == NO_VERIFY
    assert find_bypass("git commit -m '#12' -n") == Bypass("no-verify", "commit", "-n")
    assert find_bypass('git commit -m "a \\" # b" --no-verify') == NO_VERIFY
    # the other kind of quote does not end this one
    assert find_bypass('git commit -m "it\'s # heading" --no-verify') == NO_VERIFY
    assert find_bypass("git commit -m 'a # b' --no-verify") == NO_VERIFY


def test_the_git_rules_read_a_backtick_as_a_posix_shell_does():
    # PowerShell escapes a quote with a backtick, so there the message goes on
    # to the last quote and the flag is live. The git rules keep the reading
    # they always had (the close rule reads both): a documented miss.
    assert find_bypass('git commit -m "say `" # hi`" now" --no-verify') is None
    # and bash ends this string at its quote, substitution or not
    assert find_bypass('git commit -m "by `whoami`" --no-verify') == NO_VERIFY
    assert find_bypass('git commit -m "by `whoami`" # --no-verify') is None


def test_an_escaped_character_reaches_the_lexer_with_its_escape():
    assert find_bypass("git commit \\--no-verify") == NO_VERIFY


# ---- where a command ends: redirections, parentheses, quoted operators ----

def test_a_redirection_does_not_end_the_command():
    assert find_bypass("git commit -m x >/dev/null --no-verify") == NO_VERIFY
    assert find_bypass("git commit -m x > /dev/null --no-verify") == NO_VERIFY
    assert find_bypass("git commit -m x 2>&1 --no-verify") == NO_VERIFY
    assert find_bypass("git commit >>log -n") == Bypass("no-verify", "commit", "-n")
    for operator in ("<", ">", ">>", "<<", "<<<", "<>", ">|", ">&", "<&", "&>", "&>>"):
        assert find_bypass(f"git commit -m x {operator} f --no-verify") == NO_VERIFY, operator
    assert find_bypass("git commit -m x >f;git push --no-verify") == Bypass(
        "no-verify", "push", "--no-verify")
    assert find_bypass("git status >f&&git commit -m x -n") == Bypass("no-verify", "commit", "-n")
    # the lexer hands over `)>` as one token: two operators, each read for itself
    assert find_bypass("git commit -m $(cat a)>f --no-verify") == NO_VERIFY


def test_the_word_after_a_redirection_is_where_it_goes_not_a_flag():
    assert find_bypass("git commit -m x > --no-verify") is None
    assert find_bypass("git commit -m x 2> -n") is None
    # one word, and no more
    assert find_bypass("git commit -m x > f --no-verify") == NO_VERIFY
    # and after the end of the command there is no redirection waiting
    assert find_bypass("git status > f; git commit --no-verify") == NO_VERIFY
    assert find_bypass("git status >; git commit --no-verify") == NO_VERIFY


def test_the_number_in_front_of_a_redirection_goes_with_it():
    assert find_bypass("git 2>f commit --no-verify") == NO_VERIFY
    assert find_bypass("git 12>&1 commit --no-verify") == NO_VERIFY
    assert find_bypass("git 0<f commit --no-verify") == NO_VERIFY
    # so here `-m` has no word of its own yet, and takes the next one
    assert find_bypass("git commit -m 2>f --no-verify") is None
    # a number that is a word of its own stays one
    assert find_bypass("git commit -m 2 --no-verify") == NO_VERIFY
    assert find_bypass("git commit -m 2 >f --no-verify") == NO_VERIFY
    assert find_bypass("git commit -m '2>f' --no-verify") == NO_VERIFY
    # and so do digits at the end of a word
    assert find_bypass("git commit --no-verify2>f") is None


def test_the_command_around_parentheses_goes_on_after_them():
    assert find_bypass("git commit -m $(cat msg) --no-verify") == NO_VERIFY
    assert find_bypass("git commit -m $(cat a; cat b) --no-verify") == NO_VERIFY
    assert find_bypass("git commit -m $(echo $(date)) --no-verify") == NO_VERIFY


def test_a_process_substitution_is_one_word_of_the_command():
    # `<( )` stands where a file name would: here it is what `-F` takes
    assert find_bypass("git commit -F <(cat msg) -n") == Bypass("no-verify", "commit", "-n")
    assert find_bypass("git commit -F >(cat) -n") == Bypass("no-verify", "commit", "-n")
    assert find_bypass("git commit -F <(cat msg)") is None
    # and after a redirection it is where the redirection goes
    assert find_bypass("git commit -m x > >(tee log) --no-verify") == NO_VERIFY
    assert find_bypass("git commit -m < <(cat msg) --no-verify") is None


def test_a_command_inside_parentheses_is_scanned_as_one_of_its_own():
    inner = Bypass("no-verify", "commit", "-n")
    assert find_bypass("diff <(git commit -n) x") == inner
    assert find_bypass("echo $(git commit -n)") == inner
    assert find_bypass("(cd repo && git commit -n)") == inner
    assert find_bypass("(cd repo && git commit -n") == inner, "never closed"
    # its words are not the outer command's, and the outer's are not its own
    assert find_bypass("git commit -m x $(echo --no-verify)") is None
    assert find_bypass("echo $(git commit -m x) --no-verify") is None
    # a `)` that closes nothing ends the command, as it always did
    assert find_bypass("git commit -m x ) --no-verify") is None


def test_an_operator_character_inside_quotes_or_escaped_is_text():
    assert find_bypass('git commit -m "|" --no-verify') == NO_VERIFY
    assert find_bypass("git commit -m ';' --no-verify") == NO_VERIFY
    assert find_bypass('git commit -m ">" --no-verify') == NO_VERIFY
    assert find_bypass('git commit -m "(" --no-verify') == NO_VERIFY
    assert find_bypass('git commit -m "\n" --no-verify') == NO_VERIFY
    assert find_bypass("git commit -m \\; --no-verify") == NO_VERIFY
    assert find_bypass('git commit -m "a \\| b" --no-verify') == NO_VERIFY
    # and the word is handed on with the character it was written with
    assert find_bypass('git -c "core.hooksPath=/a;b|c" commit') == Bypass(
        "hooks-path", "commit", "core.hooksPath=/a;b|c")
    assert find_bypass("git -c core.hooksPath=/a\\;b commit") == Bypass(
        "hooks-path", "commit", "core.hooksPath=/a;b")


def test_a_comment_is_not_scanned():
    assert find_bypass("git commit -m x # --no-verify") is None
    assert find_bypass("git commit -m x #--no-verify") is None
    assert find_bypass("git commit -m x;# --no-verify") is None
    assert find_bypass("# git commit --no-verify") is None
    assert find_bypass("git status\n  # git commit --no-verify\ngit log") is None
    # straight after an operator a word starts too, a newline included
    assert find_bypass("git status\n# git commit --no-verify") is None
    assert find_bypass("git status;# git commit --no-verify") is None
    # inside single quotes a backslash escapes nothing: the quote ends here
    assert find_bypass("git commit -m 'a\\' # --no-verify") is None
    # a word starts wherever the lexer would start one
    assert find_bypass("git commit -m x\t# --no-verify") is None
    assert find_bypass("git commit -m x\r# --no-verify") is None
    for operator in "();<>|&":
        assert find_bypass(f"git status {operator}# git commit --no-verify") is None, operator


def test_a_comment_ends_with_its_line():
    assert find_bypass("git status # first\ngit commit -m x --no-verify") == NO_VERIFY
    assert find_bypass("# first\r\ngit commit -m x --no-verify") == NO_VERIFY


def test_each_line_is_a_command_of_its_own():
    assert find_bypass("git add -A\ngit commit -m x --no-verify") == NO_VERIFY
    assert find_bypass("git commit -m x\ngit push --no-verify") == Bypass(
        "no-verify", "push", "--no-verify")
    # a flag on the next line belongs to the next command: `git push -n` is a
    # dry run, and read as one line with the commit it was a refused commit
    assert find_bypass("git commit -m x\ngit push -n") is None
    assert find_bypass("git commit -m x\r\necho -n hello") is None
    assert find_bypass("git commit -m x\necho --no-verify") is None


def test_a_continued_line_is_one_command():
    assert find_bypass("git commit -m x \\\n  --no-verify") == NO_VERIFY
    assert find_bypass("git commit -m x \\\r\n  --no-verify") == NO_VERIFY
    assert find_bypass("git commit -m x `\n  --no-verify") == NO_VERIFY
    assert find_bypass("git \\\n commit \\\n -n") == Bypass("no-verify", "commit", "-n")
    # the next line starts where it starts: nothing of it is taken with the join
    assert find_bypass("git commit -m x \\\n--no-verify") == NO_VERIFY
    # inside double quotes a line is continued too, inside single quotes not
    assert find_bypass('git commit "--no-\\\nverify"') == NO_VERIFY
    assert find_bypass("git commit '--no-\\\nverify'") is None


def test_a_message_over_several_lines_is_one_value():
    assert find_bypass('git commit -m "first\n\n--no-verify is not used here"') is None
    assert find_bypass("git commit -m 'a\n-n\nb'") is None
    assert find_bypass('git commit -m "first\n# not a comment" --no-verify') == NO_VERIFY


def test_nothing_in_a_command_makes_the_reader_raise():
    # `find_bypass` runs on every tool call and fails open; a reader of its own
    # in front of shlex must not be the thing that raises.
    for command in ("git '", 'git "', "git \\", "git `", "git #", "#", "\\\n", "`\n",
                    "git commit -m 'unclosed # x\n--no-verify", 'git "a\\', "git\n\n\n",
                    "git commit \\\n", "git commit `\r\n", "'#' git", "\\# git commit -n",
                    "git commit )", ")", "git ) commit", "git commit >", "git 2", "git 2>",
                    "git ((", "git ))", "git commit &>>", 'git "`', 'git "a`"', "git \ue003"):
        find_bypass(command)
