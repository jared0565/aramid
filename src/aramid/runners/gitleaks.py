"""gitleaks adapter -- secrets scanning.

gitleaks' --report-path is a filesystem path, not a stdout sentinel: passing
"-" would create a literal file named "-" rather than writing to stdout. We
always write to a real temp file and read it back afterwards.

gitleaks exits non-zero when it finds leaks (that is the whole point of the
tool) -- that is NOT a crash. gitleaks' own documented exit codes are 0 (no
leaks) and 1 (leaks found); anything else (bad --log-opts range, not-a-git-
repo, permission error, ...) means gitleaks errored before/instead of
producing a trustworthy report. An errored run typically leaves the report
file missing or empty, which parses just as cleanly as a genuinely-clean
"[]" -- so the returncode is checked explicitly and BEFORE trusting an
empty/absent report as "no leaks"; without that check a crashed gitleaks
(a BLOCK-tier secrets gate) would silently read as "scanned clean".

`--all` (full_tree) does NOT point `gitleaks dir` at the repo root. `dir`
takes one path and walks everything under it -- there is no exclude flag,
and a global-allowlist `paths` entry stops the regexes, not the walk
(measured 65.6 s with one against 67.7 s without). Pointed at the root it
therefore walks every gitignored cache too. Measured 2026-09-04 on aramid's
own checkout: `.cache/` held 15,388 files / 418 MB and cost 63 s of a 68 s
scan against TIMEOUT_S = 120; a concurrent drain pushed it past the budget,
the pre-push gate degraded gitleaks, and `--strict` refused a push whose
gate had blocking 0 -- twice in a morning. The 381 tracked files scan in
1.4 s. So `run` copies `ctx.files` (what `--all` means: `gitutil.
all_tracked_files`) into a temporary directory and scans THAT, then rewrites
each reported `File` back to its path under the repo -- the only files a
push can ship and the only place a reported leak can be fixed.
"""
import json
import os
import shutil
import tempfile
from dataclasses import replace
from pathlib import Path

from aramid import gitutil
from aramid.normalizer import RawFinding
from aramid.runners import inline
from aramid.runners.base import RunnerResult, ToolState, run_subprocess
from aramid.fingerprint import normalize_path
from aramid.runners._util import relativize

NAME = "gitleaks"
TIMEOUT_S = 120.0

# gitleaks' own documented exit-code contract: 0 = ran clean, no leaks;
# 1 = ran clean, leaks found. Anything else is an error, not a verdict.
_OK_RETURNCODES = frozenset({0, 1})

# FN-53: gitleaks takes its config from either variable before the repo's own
# file. Set in the environment of whoever commits -- `VAR=... git commit` gets
# past the agent hook -- one replaced every rule in every scan mode, and the
# gate reported a clean scan. The committer's environment is not the gate's
# configuration, so every gitleaks this runner starts runs without them
# (a None value removes a variable: `base._child_env`).
_CLEARED_ENV = {"GITLEAKS_CONFIG": None, "GITLEAKS_CONFIG_TOML": None}

# FN-40: the two files gitleaks honours on its own, read from the directory it
# scans. Either one hid a BLOCK-tier hit from the commit and push scans with
# nothing reported, untracked as well as tracked (measured on 0.20.9), and no
# flag turns `.gitleaksignore` off. When the repo root holds either, the
# second pass runs a third gitleaks that cannot read them (`_files_pass`).
_IGNORE_FILE = ".gitleaksignore"
_CONFIG_FILE = ".gitleaks.toml"
# gitleaks' own rules and nothing else: what the files pass scans with.
_DEFAULT_RULES = "[extend]\nuseDefault = true\n"
# Where `_files_pass` puts the file that hid an item, for `_raw_findings`.
_HIDDEN_BY = "aramid_hidden_by"
_MARKER = "a `gitleaks:allow` comment"

# gitleaks doesn't emit a per-finding severity in its report; a discovered
# secret is treated as high severity by default (documented assumption --
# the real severity/verdict split for secrets is a policy.classify decision,
# task 5.1, keyed off tool+rule, not this raw string).
_SEVERITY_RAW = "high"


def _stage_tracked(ctx, staging: Path) -> Path:
    """Copy `ctx.files` (root-relative) under `staging`, keeping their
    relative paths, and return `staging` for `gitleaks dir` (module
    docstring: why the root itself is never walked).

    Only regular files are copied: `git ls-files` also lists a submodule (a
    directory), a path deleted in the working tree, and symlinks -- which
    gitleaks skips by itself. A file that vanishes or cannot be read between
    the listing and the copy is one gitleaks could not have scanned in place
    either, and is skipped rather than failing a BLOCK-tier scanner.
    """
    staging.mkdir(parents=True, exist_ok=True)
    root = Path(ctx.root)
    for rel in ctx.files:
        src = root / rel
        if src.is_symlink() or not src.is_file():
            continue
        dst = staging / rel
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
        except OSError:
            continue
    return staging


def _unstage(items: list, staging: Path, root: Path) -> list:
    """Rewrite each report item's `File` from the staging copy back to the
    same file under `root` -- absolute, the way `gitleaks dir <root>` itself
    reports -- so `parse` (and everything after it: `relativize`, the
    fingerprint's line read-back) sees repo paths and nothing downstream
    knows a copy existed."""
    for item in items:
        path = item.get("File")
        if path:
            item["File"] = str(Path(root) / relativize(path, staging))
    return items


def _build_argv(ctx, report_path: Path, scan_root: Path | None = None) -> list[str]:
    # `ctx.rng is not None`, NOT truthiness: `pipeline.FULL_HISTORY_RNG`
    # ("") is a deliberately falsy-but-not-None sentinel meaning "range
    # mode, no @{u}/origin/HEAD yet -- scan every commit reachable from
    # HEAD" (first push of a brand-new repo, spec §3). `git log`/gitleaks'
    # `--log-opts` with an empty options string defaults to walking every
    # commit reachable from HEAD -- exactly that. Only a genuine `None`
    # (staged mode -- `RunContext.rng`'s other documented meaning) falls
    # back to `git --staged`.
    if ctx.rng is not None:
        return [
            "gitleaks", "git", "--log-opts", ctx.rng,
            "--report-format", "json", "--report-path", str(report_path),
        ]
    # `--all` (mode "all") also arrives here with rng None, because None was
    # overloaded to mean both "staged" and "not range-based". Scanning the
    # index in that mode means scanning an EMPTY index -- and reporting OK
    # for it, which is worse than useless: OK puts gitleaks in `scope_tools`,
    # so `record_run` then resolves open secret findings across the whole
    # tracked tree. Measured on the 0.2.0 wheel: two committed secrets that
    # gitleaks finds when run directly were invisible to `check --all`, and
    # both prior BLOCK findings were written `finding_resolved` while the
    # secrets sat untouched in the files. Committing a leak marked it fixed.
    #
    # `dir` is gitleaks' working-tree scan. It cannot attribute a leak to the
    # commit that introduced it, which is why range mode above still wins --
    # that attribution is the whole value of the pre-push path. `scan_root`
    # is the staging copy of the tracked files `run` builds (module
    # docstring); the repo root only when no copy was made.
    if getattr(ctx, "full_tree", False):
        return [
            "gitleaks", "dir", str(scan_root or ctx.root),
            "--report-format", "json", "--report-path", str(report_path),
        ]
    return [
        "gitleaks", "git", "--staged",
        "--report-format", "json", "--report-path", str(report_path),
    ]


def run(ctx) -> RunnerResult:
    # ignore_cleanup_errors: the directory now holds a copy of the tracked
    # tree, and a gitleaks killed on timeout can still hold a file open on
    # Windows for a moment. A leftover temp directory beats a BLOCK-tier
    # runner raising out of its own cleanup.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        report_path = Path(td) / "gitleaks-report.json"
        scan_root = None
        if ctx.rng is None and getattr(ctx, "full_tree", False):
            scan_root = _stage_tracked(ctx, Path(td) / "tree")
        argv = _build_argv(ctx, report_path, scan_root)
        result = run_subprocess(argv, ctx.root, TIMEOUT_S, env=dict(_CLEARED_ENV))
        if result.state in (ToolState.MISSING, ToolState.TIMEOUT):
            return result

        text = report_path.read_text() if report_path.exists() else ""

        if result.returncode not in _OK_RETURNCODES:
            return RunnerResult(NAME, ToolState.CRASHED, raw=text, stderr=result.stderr,
                                 duration_s=result.duration_s, returncode=result.returncode)
        try:
            items = json.loads(text or "[]")
        except json.JSONDecodeError:
            return RunnerResult(NAME, ToolState.CRASHED, raw=text, stderr=result.stderr,
                                 duration_s=result.duration_s, returncode=result.returncode)
        if scan_root is not None:
            text = json.dumps(_unstage(items, scan_root, ctx.root))
        own = RunnerResult(NAME, ToolState.OK, raw=text or "[]", stderr=result.stderr,
                           duration_s=result.duration_s, returncode=result.returncode)
        if not ctx.inline_pass:
            return own
        return inline.bundle(own, inline.within_deadline(
            ctx, inline.GITLEAKS, lambda: _run_inline(ctx, Path(td), items, scan_root)))


def _key(item: dict) -> tuple:
    return (item.get("RuleID"), item.get("File"), item.get("StartLine"),
            item.get("Commit") or "")


def _run_inline(ctx, td: Path, own_items: list, scan_root: Path | None) -> RunnerResult:
    """FN-38's second pass: the same scan path (staged / range / the staged
    copy of the tracked tree) with `--ignore-gitleaks-allow`, keeping the leaks
    the first run did not report, matched by (rule, file, line, commit).

    The report it reads holds the secrets themselves. The OK result carries
    them on purpose (parse puts each on `RawFinding.secret`, so the evidence
    is redacted and the log scrubber knows it), and `pipeline._NO_STDOUT_TOOLS`
    names this label so no log ever persists that raw. A failed run carries
    none of it.

    FN-40: then `_files_pass`, when the repo root holds a gitleaks file, adds
    the hits those files hide. One label for both: the push ratchet exempts it,
    and a new label would make every such hit a BLOCK."""
    timeout = inline.second_pass_timeout(ctx, TIMEOUT_S)
    if timeout is None:
        return inline.skipped(inline.GITLEAKS)
    report_path = td / "gitleaks-inline-report.json"
    argv = [*_build_argv(ctx, report_path, scan_root), "--ignore-gitleaks-allow"]
    got = _read_pass(ctx, argv, ctx.root, timeout, dict(_CLEARED_ENV), report_path, scan_root)
    if isinstance(got, RunnerResult):
        return got
    items, result = got
    seen = {_key(item) for item in own_items}
    hidden = [item for item in items if _key(item) not in seen]
    by_files = _files_pass(ctx, td, scan_root, [*own_items, *items])
    if isinstance(by_files, RunnerResult):
        return by_files
    return RunnerResult(inline.GITLEAKS, ToolState.OK, raw=json.dumps(hidden + by_files),
                        stderr=result.stderr, duration_s=result.duration_s,
                        returncode=result.returncode)


def _read_pass(ctx, argv, cwd: Path, timeout: float, env: dict, report_path: Path,
               scan_root: Path | None):
    """One extra gitleaks run under the inline label: (its report's items,
    its result), or the result that says why there are none."""
    result = run_subprocess(argv, cwd, timeout, env=env)
    if result.state in (ToolState.MISSING, ToolState.TIMEOUT):
        return replace(result, tool=inline.GITLEAKS, raw="")
    failed = RunnerResult(inline.GITLEAKS, ToolState.CRASHED, stderr=result.stderr,
                          duration_s=result.duration_s, returncode=result.returncode)
    # rc 1 is gitleaks' "leaks found OR an error", so with no report file it
    # proves nothing: read as `[]`, it would say no marker hides anything.
    if result.returncode not in _OK_RETURNCODES or (
            result.returncode == 1 and not report_path.exists()):
        return failed
    try:
        items = json.loads((report_path.read_text() if report_path.exists() else "") or "[]")
    except json.JSONDecodeError:
        return failed
    if scan_root is not None:
        _unstage(items, scan_root, ctx.root)
    return items, result


def _files_pass(ctx, td: Path, scan_root: Path | None, reported: list):
    """FN-40: every hit the repo's `.gitleaksignore` or `.gitleaks.toml` hides,
    each tagged with the file that hid it; [] when the root holds neither, or
    the result that says why the run failed.

    gitleaks reads both files from the directory it scans, and the ignore file
    from its working directory too; no flag turns that one off (measured). So
    this run has an empty directory for both, gitleaks' own rules as its
    `--config`, and `--ignore-gitleaks-allow`. A git scan reaches the repo
    through GIT_DIR and GIT_WORK_TREE, with a relative GIT_INDEX_FILE made
    absolute: git hands a pre-commit hook `.git/index`, which from the empty
    directory names no index, and gitleaks then reported an empty scan
    (measured). `--all` scans its copy as before: the fingerprints there carry
    a temp path that no entry names, so the config is all it could read.

    A hit is hidden when no run reported its place (file, line, commit): by
    place, because a repo's own rule can report the same hit under its name."""
    root = Path(ctx.root)
    has_config = (root / _CONFIG_FILE).is_file()
    if not (has_config or (root / _IGNORE_FILE).is_file()):
        return []
    timeout = inline.second_pass_timeout(ctx, TIMEOUT_S)
    if timeout is None:
        return inline.skipped(inline.GITLEAKS)
    empty = td / "files-pass"
    empty.mkdir()
    rules = td / "gitleaks-default-rules.toml"
    rules.write_text(_DEFAULT_RULES)
    report_path = td / "gitleaks-files-report.json"
    argv = [*_build_argv(ctx, report_path, scan_root), "--ignore-gitleaks-allow",
            "--config", str(rules)]
    env = dict(_CLEARED_ENV)
    if scan_root is None:
        env.update(GIT_DIR=str(gitutil.git_dir(root)), GIT_WORK_TREE=str(root))
        index = os.environ.get("GIT_INDEX_FILE")
        if index and not os.path.isabs(index):
            env["GIT_INDEX_FILE"] = str(root / index)
        argv.append(str(empty))
    got = _read_pass(ctx, argv, empty, timeout, env, report_path, scan_root)
    if isinstance(got, RunnerResult):
        return got
    places = {_place(item) for item in reported}
    entries = _ignore_entries(root)
    hidden = []
    for item in got[0]:
        if _place(item) not in places:
            item[_HIDDEN_BY] = _hidden_by(item, entries, has_config)
            hidden.append(item)
    return hidden


def _place(item: dict) -> tuple:
    return (item.get("File"), item.get("StartLine"), item.get("Commit") or "")


def _ignore_entries(root: Path) -> set[str]:
    try:
        text = (root / _IGNORE_FILE).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    return {line.strip() for line in text.splitlines()}


def _hidden_by(item: dict, entries: set[str], has_config: bool) -> str:
    """The file that hid `item`: the ignore file when an entry names its
    fingerprint, as gitleaks writes it (`commit:file:rule:line` in a history
    scan) or without the commit (gitleaks applies that form to every commit,
    measured), or when there is no config to have hidden it; else the config."""
    fingerprint = item.get("Fingerprint", "")
    commit = item.get("Commit") or ""
    plain = fingerprint.removeprefix(f"{commit}:") if commit else fingerprint
    if fingerprint in entries or plain in entries or not has_config:
        return f"a `{_IGNORE_FILE}` entry"
    return f"the repo's `{_CONFIG_FILE}`"


def parse(result: RunnerResult, ctx) -> list[RawFinding]:
    if result.state is not ToolState.OK:
        return []
    found = _raw_findings(json.loads(result.raw or "[]"), ctx, hidden=False)
    for sub in getattr(result, "sub_results", None) or ():
        if sub.tool == inline.GITLEAKS and sub.state is ToolState.OK:
            found.extend(_raw_findings(json.loads(sub.raw or "[]"), ctx, hidden=True))
    return found


def _raw_findings(items: list, ctx, *, hidden: bool) -> list[RawFinding]:
    """One gitleaks report -> RawFindings. `hidden` marks the second pass's
    report: each leak a `gitleaks:allow` comment or a repo file hid, under the
    inline label, its message naming which (`_HIDDEN_BY`, else the comment)."""
    # Only the `gitleaks git ...` history path (ctx.rng is not None, per
    # _build_argv above -- matches its is-not-None check, not truthiness, so
    # the FULL_HISTORY_RNG "" sentinel counts as a history scan too) can
    # attribute a leak to a specific historical commit; the `git --staged`
    # path scans the working tree/index, not commits, so it
    # always leaves RawFinding.commit as None (its Commit field, if present
    # at all, carries no meaningful ref there).
    is_history_scan = ctx.rng is not None
    # REPORT NARROW, whatever was scanned. `--all` is defined as all TRACKED
    # files (`all_tracked_files`), and a finding in a path that can never be
    # committed is a finding nobody can ever fix or retire. Measured on this
    # repo before the scan itself was narrowed: 24 hits, of which 14 were in
    # `.superpowers/` local review artifacts and `__pycache__/`.
    #
    # `run` now scans a copy holding exactly `ctx.files` (module docstring),
    # so this filter should drop nothing -- it stays as the guarantee that a
    # report naming anything else (a root scan when no copy was made) is
    # still reported on tracked files only. `gitleaks dir` accepts one path;
    # passing a file list is silently ignored and it rescans the whole tree,
    # which is how the copy became the mechanism rather than a file list.
    scope = None
    if getattr(ctx, "full_tree", False) and ctx.files:
        scope = {normalize_path(f) for f in ctx.files}
    out = []
    for item in items:
        rel = relativize(item["File"], ctx.root)
        if scope is not None and normalize_path(rel) not in scope:
            continue
        description = item.get("Description") or item["RuleID"]
        out.append(RawFinding(
            tool=inline.GITLEAKS if hidden else NAME,
            rule=inline.RULE if hidden else item["RuleID"],
            severity_raw=_SEVERITY_RAW,
            file=rel,
            line=item["StartLine"],
            message=(inline.message(NAME, item["RuleID"], item.get(_HIDDEN_BY, _MARKER),
                                    description) if hidden else description),
            secret=item["Secret"],
            commit=(item.get("Commit") or None) if is_history_scan else None,
            subject=(NAME, item["RuleID"]) if hidden else None,
        ))
    return out
