"""init -- onboarding orchestration that arms a repo (design doc section 8,
brief Task 6.2). Resolve the true repo root, gate on `doctor`, write
config/docs/gitignore, install git hook shims, run a one-time full-history
secrets scan, seed the findings baseline, and print a summary.

Idempotency contract (design doc section 7, brief global constraints):
  - `aramid.toml`: written ONLY if absent -- a second `init` never touches a
    user-edited stub.
  - `ARAMID.md`: ALWAYS regenerated (aramid-owned, marker-tagged) -- it
    tracks the current template, never accumulates hand-edits.
  - `.gitignore` entries: appended only if missing -- no duplicate lines on
    re-init.
  - CLAUDE.md/AGENTS.md managed block: fence-scoped -- refreshed in place
    when stale, left untouched when it already matches the current
    template, and content outside the fence (or the whole file, when the
    fence is damaged or unreadable) is never touched.
  - baseline: written ONCE, guarded by `Ledger.has_baseline()` -- a second
    `init` must never re-snapshot (that would silently accept anything
    introduced between the two `init` runs as "pre-existing").
  - hook shims: `hooks.install` is itself idempotent (marker-detected,
    chains a foreign hook at most once) -- re-running `init` just
    regenerates aramid's own shim in place.

Doctor-gate-fail is a FULL abort, not a partial write: the brief's "(do NOT
install hooks)" parenthetical for step 3 is emphasis on the single most
dangerous step (arming an enforcement mechanism the toolchain can't yet
satisfy), not permission to scatter aramid.toml/ARAMID.md/gitignore edits
into a repo that isn't actually armed. Returning 3 before step 4 keeps the
"no half-initialization" guarantee (brief step 1) uniform across both
refusal paths (non-repo, doctor-gate-fail) rather than special-casing it.
"""
import dataclasses
import functools
import re
import sys
import uuid
from collections import defaultdict, deque
from datetime import date, datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Callable

from aramid import agent_files, config as config_mod
from aramid import gitutil, hooks, policy, redact
from aramid.commands import doctor as doctor_mod
from aramid.commands.doctor import cmd_doctor
from aramid.detectors import (detect_package_manager, detect_stacks, nested_git_dirs,
                              unrooted_stack_notices)
from aramid.ledger import Ledger
from aramid.models import Gate
from aramid.normalizer import normalize
from aramid.pipeline import run_gate
from aramid.runners import gitleaks as gitleaks_runner
from aramid.runners.base import RunContext, ToolState

GITIGNORE_ENTRIES = (".aramid/", "graph-out/", ".graphite*", ".cache/")

# Directories `--discover`'s walk never descends into, by name, regardless of
# depth (brief: "skipping node_modules, _tools, .venv, and the built-in
# ignore paths"). ".git" is included so discover doesn't walk INTO a found
# repo's own git internals; the built-in aramid/graphite state dirs are
# included so a previously-initted repo's `.aramid`/`.cache` don't get
# mistaken for interesting subtrees.
_DISCOVER_SKIP_NAMES = frozenset({
    "node_modules", "_tools", ".venv", ".git", "__pycache__",
    ".aramid", ".cache", "graph-out",
})
_DISCOVER_SKIP_GLOBS = (".graphite*",)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------- ARAMID.md ---

def _render_aramid_md(stack: set[str], pkg_mgr: str | None) -> str:
    tmpl = resources.files("aramid").joinpath("data", "ARAMID.md.tmpl").read_text(encoding="utf-8")
    stack_note = ", ".join(sorted(stack)) if stack else "unknown"
    return (tmpl
            .replace("__STACK__", stack_note)
            .replace("__PKG_MGR__", pkg_mgr or "none")
            .replace("__DATE__", date.today().isoformat()))


# Horizontal-whitespace-only trailing class ([^\S\n], NOT \s), for the reason
# aramid.commands.arm's own key-rewrite family documents: `\s` matches newlines,
# so `\s*$` under MULTILINE runs past the end of this line and swallows the
# blank line separating the header block from the next section -- and `sub`
# then deletes it. Caught by regenerating ARAMID.md and diffing, not by the
# date assertions, which were all still green with the separator gone.
_ONBOARDED_RE = re.compile(r"(?m)^- \*\*Onboarded:\*\* (\d{4}-\d{2}-\d{2})[^\S\n]*$")


def _existing_onboarded(path: Path) -> str | None:
    """The onboarding date already recorded in ARAMID.md, if any.

    "Onboarded" is a HISTORICAL FACT -- the day aramid was first armed in
    this repo -- but `_render_aramid_md` stamps `date.today()` and
    ARAMID.md is ALWAYS regenerated, so every later `init` re-run used to
    overwrite that fact with a build stamp. Silent, and unrecoverable from
    the file itself once done.

    Found in a consumer repo (operation-firewall interop round 24): a
    re-run moved its date forward a day, and only the ledger's earliest
    event could still prove the original. aramid's own repo had pinned its
    date with a unit test since the same thing happened here twice -- but a
    test in THIS repo guards only this repo, which is the local-workaround
    trap: it removed the symptom that would have driven the fix while every
    consumer stayed exposed.

    Returns None when there is no file, no parseable date, or the file was
    hand-mangled -- in all of which there is no history to preserve and
    today is the honest answer.

    A GENUINE re-onboarding still gets a fresh date with no extra flag:
    `aramid uninstall` removes ARAMID.md, so uninstall-then-init takes the
    no-file branch above. Preservation therefore applies only to re-running
    `init` on a repo that is still armed, which is the case that was
    rewriting history.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    m = _ONBOARDED_RE.search(text)
    return m.group(1) if m else None


def render_aramid_md_notice(root: Path) -> str:
    """The one line `init` owes the operator about its own tracked artifact.

    `_write_aramid_md` ALWAYS regenerates ARAMID.md, and the file is TRACKED --
    so a template change leaves a consumer's tree dirty with a file they did
    not write, and until now `init` printed nothing about it at all. In one
    consumer it stayed uncommitted long enough that a different repo's agent
    raised it as an open item, which is the tool making its own housekeeping
    somebody else's chore.

    A NOTICE, and deliberately not an auto-commit. Committing inside a
    consumer's repo picks their branch, author and signing policy for them,
    and would need `--no-verify` to stop `init` re-entering aramid's own
    pre-commit gate -- shipping a hook bypass in the tool whose whole purpose
    is that the hook runs. Interop round 117 asked for shadow-resistance to be
    "automated"; the answer there was report it every run, not remediate it,
    and the same reading applies here. Auto-commit is strictly more intrusive
    than a BLOCK verdict, and `shadow` ships DISARMED.

    Returns "" when there is nothing to say -- a line on every re-init is
    noise that trains people to skip the whole summary. Silent, too, when git
    cannot answer: telling someone to commit a file in a directory git does
    not manage is worse than saying nothing.
    """
    path = root / "ARAMID.md"
    if not path.is_file():
        return ""
    try:
        on_disk = path.read_text(encoding="utf-8")
    except OSError:
        return ""
    if gitutil._run(root, "rev-parse", "--is-inside-work-tree").returncode != 0:
        return ""
    if gitutil.is_tracked(root, "ARAMID.md"):
        if gitutil.read_blob(root, "HEAD", "ARAMID.md") == on_disk:
            return ""
        state = "differs from the committed copy"
    else:
        state = "is not tracked yet"
    lines = [
        f"aramid: init: ARAMID.md {state} -- aramid owns and regenerates it,",
        "aramid: init:   and other machines and agents read it from the repo:",
        'aramid: init:       git add ARAMID.md && git commit -m "chore: sync ARAMID.md"',
    ]
    return "\n".join(lines)


def _write_aramid_md(root: Path, stack: set[str], pkg_mgr: str | None) -> None:
    path = root / "ARAMID.md"
    rendered = _render_aramid_md(stack, pkg_mgr)
    # Regeneration stays wholesale (hand-edits to an aramid-owned file are
    # still discarded, as the docstring at the top of this module promises);
    # only the recorded onboarding date survives it.
    previous = _existing_onboarded(path)
    if previous is not None:
        rendered = _ONBOARDED_RE.sub(f"- **Onboarded:** {previous}", rendered, count=1)
    path.write_text(rendered, encoding="utf-8")


# --------------------------------------------------------------- gitignore ---

def _update_gitignore(root: Path) -> tuple[list[str], bool]:
    """Append aramid's ignore entries; return (entries added, file created).

    Returns what it did so `init` can SAY what it did. aramid writes this file
    into a consumer's tree and printed nothing about it, which is the tool
    making its own housekeeping somebody else's chore -- the same defect
    `render_aramid_md_notice` was added for, measured on the same fresh
    onboard (interop round 121 section 4).

    Only ever writes entries that are MISSING, and that is what makes the
    notice one-time rather than recurring: a second `init` has nothing to add
    and so says nothing, by construction rather than by a guard.
    """
    path = root / ".gitignore"
    existed = path.exists()
    text = path.read_text(encoding="utf-8") if existed else ""
    existing = {line.strip() for line in text.splitlines()}
    missing = [entry for entry in GITIGNORE_ENTRIES if entry not in existing]
    if not missing:
        return [], False
    prefix = "" if not text or text.endswith("\n") else "\n"
    path.write_text(text + prefix + "\n".join(missing) + "\n", encoding="utf-8")
    return missing, not existed


def render_gitignore_notice(root: Path, added: list[str], created: bool) -> str:
    """The line `init` owes the operator about the .gitignore it just wrote.

    Sibling of `render_aramid_md_notice`, and it follows the same three rules:
    name the artifact, give the command rather than a complaint, and stay
    silent when git cannot answer -- telling someone to commit a file in a
    directory git does not manage is worse than saying nothing.

    Lists the entries it ACTUALLY added rather than GITIGNORE_ENTRIES
    wholesale. A notice naming a line that was already in the file sends a
    teammate looking for it in a diff that does not contain it, and that is
    the kind of claim which reads as true until somebody checks.

    Distinguishes creating the file from appending to it because the two leave
    the operator's `git status` looking different -- one new untracked file
    versus one tracked file gone dirty.
    """
    if not added:
        return ""
    if gitutil._run(root, "rev-parse", "--is-inside-work-tree").returncode != 0:
        return ""
    plural = "y" if len(added) == 1 else "ies"
    what = ("created .gitignore" if created
            else f"added {len(added)} entr{plural} to .gitignore")
    return "\n".join([
        f"aramid: init: {what} -- aramid's machine-local state must not be",
        f"aramid: init:   committed, and teammates need the same entries "
        f"({', '.join(added)}):",
        'aramid: init:       git add .gitignore && git commit -m "chore: ignore aramid state"',
    ])


def render_agent_blocks_notice(root: Path,
                               actions: list[tuple[str, str]]) -> str:
    """Sibling of render_aramid_md_notice / render_gitignore_notice; same
    three rules for the changed-files line. The damaged/unreadable lines are
    different in kind: each reports a REFUSED write (an untrustworthy aramid
    fence, or a file that isn't valid UTF-8), which is worth saying even
    outside a git work tree -- it is a defect in the file, not a
    housekeeping chore."""
    lines: list[str] = []
    for name, action in actions:
        if action == "damaged":
            lines.append(
                f"aramid: init: {name} has a damaged aramid fence"
                f" (unterminated or duplicated begin marker) -- left"
                f" untouched; repair or delete the fence and re-run"
                f" `aramid init`")
        elif action == "unreadable":
            lines.append(
                f"aramid: init: {name} could not be read (not valid UTF-8,"
                f" or an I/O error) -- left untouched; fix the file and"
                f" re-run `aramid init`")
    changed = [n for n, a in actions
               if a in ("created", "appended", "replaced")]
    if changed and gitutil._run(
            root, "rev-parse", "--is-inside-work-tree").returncode == 0:
        names = ", ".join(changed)
        lines.append(
            f"aramid: init: wrote the managed agent block into {names}"
            f" -- agent coders read these files from the repo:")
        lines.append(
            f'aramid: init:       git add {" ".join(changed)} && '
            f'git commit -m "chore: aramid agent block"')
    return "\n".join(lines)


# ------------------------------------------------------- full-history scan ---

def _historical_ref_for(raws: list) -> Callable[[str], str]:
    """Per-finding ref lookup keyed off each raw's own commit sha, NOT HEAD.

    A historical secret must be fingerprinted from the commit it actually
    lived in: reading the flagged line from HEAD is wrong once the file has
    changed or the secret has been removed there entirely -- that produces
    an unstable/incorrect fingerprint (and, worse, a non-idempotent second
    `init`, since the "same" secret would fingerprint differently run to
    run as HEAD moves).

    `normalize()` calls `ref_for(raw.file)` exactly once per raw, in `raws`
    order (its body is a single `for raw in raws:` loop) -- so a per-file
    FIFO queue, popped in that same order, correctly disambiguates multiple
    findings that share a file but come from different commits (e.g. two
    separate secrets added to the same file in two different commits of a
    `--all` history scan); a flat `{file: commit}` dict would silently
    collapse that to one commit and reintroduce the same class of bug for
    the second finding.
    """
    queues: dict[str, deque] = defaultdict(deque)
    for r in raws:
        queues[r.file].append(r.commit or "HEAD")

    def ref_for(file: str) -> str:
        return queues[file].popleft()

    return ref_for


def _scan_history(root: Path, ledger: Ledger, cfg: config_mod.Config) -> int:
    """One-time-in-spirit full-history secrets scan (brief step 6, design
    doc section 6/8): the gitleaks runner in git-log mode, walking every ref
    (`--log-opts --all`, i.e. `git log --all`) rather than just HEAD's
    ancestry, so a secret committed on a branch other than the current one
    is still caught. NOTE: `--all` as the raw `--log-opts` value is gitleaks'
    documented git-log-flags passthrough, not independently verified against
    a real gitleaks binary in this environment (none is installed here --
    see the module docstring in tests/integration/test_init.py); if this
    turns out to need `--log-opts=--all` as a single token, that's a
    one-line fix to `gitleaks_runner._build_argv`, not to this function.

    Hits are recorded as historical, non-blocking `FINDING_DETECTED` events
    -- never contributes to init's own exit code (surfaced later by
    `aramid status` with rotation guidance).

    Routed through `ledger.record_run` (not a raw per-finding `append` loop)
    so this stays safe to re-run on every `init`, not just the first one: a
    fingerprint that repeats on a later scan is already `status=historical`
    in ledger state, so `record_run`'s own "already known" check skips
    re-appending it. `scope_files=set()` disables `record_run`'s resolution
    sweep (which would otherwise be free to mark previously-detected
    historical hits "resolved" the moment they don't happen to reappear in a
    literal `scope_files` match) -- a full-history scan re-examines the same
    commits every time, it does not narrow scope like a normal gate run."""
    ctx = RunContext(root=root, files=[], rng="--all")
    result = gitleaks_runner.run(ctx)
    if result.state is not ToolState.OK:
        print(f"aramid: init: full-history gitleaks scan skipped ({result.state.value})",
              file=sys.stderr)
        return 0

    raws = gitleaks_runner.parse(result, ctx)
    # §8b hard requirement: graphite artifacts (graph-out/, .graphite*,
    # .cache/, ...) are NEVER scanned/fingerprinted/recorded, in any mode --
    # gitleaks scans by git-log range, not by a pre-filtered file list, so a
    # hit under one of those paths can surface here even though it was never
    # in any discovered file set. Mirrors pipeline.run_gate's own post-parse
    # ignore-path filter (same `config.is_ignored`, same built-in-unremovable
    # `cfg.ignore_paths`) so a historical finding gets exactly the same
    # treatment a live gate run's finding would.
    raws = [r for r in raws if not config_mod.is_ignored(r.file, cfg.ignore_paths)]
    if not raws:
        return 0

    salt = redact.load_or_create_salt(root / ".aramid")
    classify = functools.partial(policy.classify, cfg=cfg)
    findings = normalize(raws, root, _historical_ref_for(raws), salt, Gate.ALL, classify)
    historical = [dataclasses.replace(f, historical=True) for f in findings]

    # A committed `.aramid-suppressions.toml` entry is the ONE reviewable,
    # shareable way to record "this history hit is a fixture, not a
    # credential". The scan used to bypass it -- applying only the path-level
    # ignore filter above -- which left `ledger mark-not-a-secret` as the only
    # remedy. That writes to the gitignored ledger, so the judgement could
    # never travel between clones and every new maintainer running `init`
    # re-discovered the same fixtures as unrotated secrets.
    #
    # An entry with no `reason` is dropped by load_suppressions and therefore
    # suppresses nothing -- the fail-safe direction.
    #
    # The count is PRINTED, never silent: quietly discarding secret findings is
    # precisely the behaviour a security tool must not have, even when the
    # discarding was asked for in version control.
    suppress_ids = {s.id for s in config_mod.load_suppressions(root)[0]}
    if suppress_ids:
        kept = [f for f in historical if f.id not in suppress_ids]
        if len(kept) != len(historical):
            print(f"aramid: init: {len(historical) - len(kept)} historical finding(s) "
                  "suppressed by .aramid-suppressions.toml")
        historical = kept

    ledger.record_run(uuid.uuid4().hex, _now(), "historical-scan",
                       {"gitleaks"}, set(), historical)
    return len(historical)


# --------------------------------------------------------- hook validation ---

def _validate_hook_shim(root: Path) -> bool:
    """Lighter validation than a scratch commit through git's real dispatch
    (brief step 8's documented alternative): confirm the installed shim
    files exist and carry aramid's marker. The e2e suite
    (`tests/e2e/test_hook_fires.py`, Task 6.1) already proves the shim
    mechanism fires correctly through REAL git hook dispatch on this
    platform (fake-engine exit-code matrix, chaining, uninstall-restore) --
    re-proving that on every single `init` call would mean spawning a real
    `git commit`/`git push` (mutating the just-onboarded repo's history)
    purely to re-confirm a property already covered durably elsewhere.
    A file-existence + marker check is the right-sized check for THIS call
    site: it catches "install() silently didn't write a file" or "wrote to
    the wrong hooksPath", which is what could actually go wrong here."""
    hdir = hooks.hooks_dir(root)
    ok = True
    for hook in [g.value for g in hooks.GATES] + [hooks.TRIAGE_HOOK]:
        shim = hdir / hook
        if shim.exists() and hooks.MARKER_START.encode() in shim.read_bytes():
            continue
        # A slot owned by ANOTHER managing tool is not a gap when aramid's
        # own shim survives relocated beside it. `install()` refuses that
        # slot deliberately (chaining a foreign trampoline would double-run
        # both tools' gates) and reports "not stale, nothing to resolve" --
        # this check used to contradict that three lines later, because a
        # foreign-managed slot never carries aramid's marker. Every
        # graphite-managed repo therefore printed "hooks armed: NO" while
        # being fully armed, whose obvious "fix" is to clobber the other
        # tool's hook. Measured against a live repo, 2026-07-31.
        #
        # Both halves are required. A foreign trampoline with no surviving
        # relocation is a real gap, and so is a MISSING slot even when a
        # relocated sibling exists -- with no trampoline in the slot, git
        # never dispatches to that sibling at all.
        if (hooks._foreign_managed_tool(shim) is not None
                and hooks._find_chained_aramid_shim(hdir, hook) is not None):
            continue
        ok = False
        print(f"aramid: init: WARNING -- {shim} missing or not aramid-managed "
              f"after install; hooks may not be armed", file=sys.stderr)
    return ok


# ------------------------------------------------------------------ single ---

def _init_one(target: Path) -> int:
    target = Path(target).resolve()
    try:
        root = gitutil.repo_root(target)
    except gitutil.NotARepo:
        print(f"aramid: init: {target} is not inside a git repository "
              f"(`git rev-parse --show-toplevel` failed) -- refusing to "
              f"half-initialize.", file=sys.stderr)
        return 3

    print(f"aramid: init: {root}")

    # step 2: scope subpath + nested .git exclusions.
    scope_subpath = target.relative_to(root).as_posix() if target != root else None
    nested = nested_git_dirs(root)
    extra_ignores = [f"{p.relative_to(root).as_posix()}/" for p in nested]

    # step 3: doctor gate -- refuse to arm hooks (full abort) if a BLOCK-tier
    # tool is missing.
    #
    # Ask that question DIRECTLY; do not key on `cmd_doctor`'s exit code.
    # doctor returns 2 for more than one condition, and one of them is
    # "aramid.toml present but hooks missing" -- precisely the state init
    # exists to fix, and precisely what a fresh CLONE of an onboarded repo
    # looks like (`.git/hooks` is not version-controlled). Gating on the
    # aggregate code made init refuse to install the very hooks whose absence
    # produced the 2, while blaming a BLOCK-tier tool that was present --
    # and doctor's own remedy line for that state says "run `aramid init .`".
    # Reached through the module, not a from-import: the suite monkeypatches
    # `doctor.probe_toolchain`, and a direct import would bind past the patch.
    cmd_doctor(root, during_init=True)     # print the report for the operator
    statuses = doctor_mod.probe_toolchain(root)
    missing_block = [n for n in doctor_mod.BLOCK_TIER if not statuses[n].present]
    if missing_block:
        print(f"aramid: init: refusing to arm hooks -- BLOCK-tier tool(s) "
              f"missing: {', '.join(missing_block)}; run `aramid doctor` (or "
              f"`aramid doctor --fix`) and re-run init.", file=sys.stderr)
        return 3

    # step 4: aramid.toml (only if absent) + ARAMID.md (always) + agent
    # blocks (CLAUDE.md/AGENTS.md, fence-scoped refresh) + gitignore.
    scope_root = target if target != root else root
    stack = detect_stacks(root, scope_root)
    pkg_mgr = detect_package_manager(root)

    toml_path = root / "aramid.toml"
    if toml_path.exists():
        print(f"aramid: init: {toml_path} already exists -- left untouched")
    else:
        toml_path.write_text(
            config_mod.render_repo_stub(stack, pkg_mgr, scope_subpath=scope_subpath,
                                         extra_ignore_paths=extra_ignores),
            encoding="utf-8")
        print(f"aramid: init: wrote {toml_path}")

    _write_aramid_md(root, stack, pkg_mgr)
    agent_actions = agent_files.write_agent_blocks(root)
    gi_added, gi_created = _update_gitignore(root)

    # step 5: install (idempotent, chain-never-clobber) hook shims.
    interpreter = Path(sys.executable)
    hooks.install(root, interpreter)

    from aramid import registry
    registry.register(root, _now())

    cfg = config_mod.load_config(root)
    ledger = Ledger(root / ".aramid" / "ledger.db")
    try:
        # step 6: one-time-in-spirit full-history secrets scan.
        historical_count = _scan_history(root, ledger, cfg)

        # step 7: baseline, written ONCE.
        if ledger.has_baseline():
            print("aramid: init: baseline already exists -- left untouched")
            baseline_count = len(ledger.baseline_ids())
        else:
            result = run_gate(root, Gate.ALL, "all", cfg, ledger)
            ledger.write_baseline(result.run_id, _now(), {f.id for f in result.findings})
            baseline_count = len(result.findings)
            print(f"aramid: init: baseline written ({baseline_count} finding(s))")

        # step 8: validate the installed shim (lighter validation, see
        # _validate_hook_shim's docstring for why).
        shim_ok = _validate_hook_shim(root)
    finally:
        ledger.close()

    # step 9: summary.
    # Three renderers report here now, covering four artifacts aramid owns
    # and wrote into someone else's tree (ARAMID.md, .gitignore, CLAUDE.md,
    # AGENTS.md). Most of what they print is one shared "here's the commit
    # chore" housekeeping notice -- but render_agent_blocks_notice's
    # damaged/unreadable lines are a different kind of thing: a REFUSED
    # write being reported, not a chore to commit.
    for notice in (render_aramid_md_notice(root),
                   render_gitignore_notice(root, gi_added, gi_created),
                   render_agent_blocks_notice(root, agent_actions)):
        if notice:
            print(notice, file=sys.stderr)

    print("aramid: init: summary")
    print(f"  root:              {root}")
    if scope_subpath:
        print(f"  scan scope:        {scope_subpath}")
    if extra_ignores:
        print(f"  nested repos excl: {', '.join(extra_ignores)}")
    print(f"  stack:             {', '.join(sorted(stack)) or 'unknown'}")
    # Printed from init itself, NOT left to the run_gate above: step 7 only
    # calls run_gate when no baseline exists, so on a re-init the notice
    # run_gate emits never fires -- and re-init is precisely when this tends
    # to be new information, because the subdirectory crate was usually added
    # after the repo was first onboarded. Sits against the `stack:` line it
    # qualifies: that line is what the operator reads, and ARAMID.md and
    # aramid.toml were both just written from the same incomplete set.
    # A fresh init therefore says this twice (once during the baseline gate);
    # accepted, in exchange for a single shared string that cannot drift.
    for notice in unrooted_stack_notices(root):
        print(notice, file=sys.stderr)
    print(f"  hooks armed:       {'yes' if shim_ok else 'NO -- see warning above'}")
    print(f"  baseline findings: {baseline_count}")
    print(f"  historical secrets:{historical_count}")
    print("aramid: init: done. Run `aramid status` any time to see open findings.")

    return 0


# --------------------------------------------------------------- discover ---

def _skip_discover_dir(name: str) -> bool:
    import fnmatch
    return name in _DISCOVER_SKIP_NAMES or any(
        fnmatch.fnmatch(name, pattern) for pattern in _DISCOVER_SKIP_GLOBS)


def _find_repos(base: Path, max_depth: int = 3) -> list[Path]:
    """Marker-based walk: a directory is a repo iff it has a `.git` entry.
    Skips the built-in ignore/tooling directory names at any depth. Does NOT
    descend into a directory once it's identified as a repo -- a nested
    `.git` inside a discovered repo is that repo's own concern
    (`detectors.nested_git_dirs`, applied during ITS `init`), not a second
    top-level discovery."""
    found: list[Path] = []

    def _walk(d: Path, depth: int) -> None:
        if not d.is_dir() or _skip_discover_dir(d.name):
            return
        if (d / ".git").exists():
            found.append(d)
            return
        if depth >= max_depth:
            return
        try:
            children = sorted(p for p in d.iterdir() if p.is_dir())
        except OSError:
            return
        for child in children:
            _walk(child, depth + 1)

    _walk(Path(base).resolve(), 0)
    return found


def _discover(base: Path) -> int:
    repos = _find_repos(base)
    print(f"aramid: init --discover: found {len(repos)} repo(s) under {base}:")
    for r in repos:
        print(f"  - {r}")

    worst = 0
    for r in repos:
        print(f"\naramid: init --discover: onboarding {r}")
        worst = max(worst, _init_one(r))
    return worst


# ---------------------------------------------------------------- public ---

def cmd_init(target: Path, discover: bool = False) -> int:
    if discover:
        return _discover(target)
    return _init_one(target)
