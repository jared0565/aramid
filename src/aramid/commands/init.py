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
import sys
import uuid
from collections import defaultdict, deque
from datetime import date, datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Callable

from aramid import config as config_mod
from aramid import gitutil, hooks, policy, redact
from aramid.commands.doctor import cmd_doctor
from aramid.detectors import detect_package_manager, detect_stacks, nested_git_dirs
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


def _write_aramid_md(root: Path, stack: set[str], pkg_mgr: str | None) -> None:
    (root / "ARAMID.md").write_text(_render_aramid_md(stack, pkg_mgr), encoding="utf-8")


# --------------------------------------------------------------- gitignore ---

def _update_gitignore(root: Path) -> None:
    path = root / ".gitignore"
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    existing = {line.strip() for line in text.splitlines()}
    missing = [entry for entry in GITIGNORE_ENTRIES if entry not in existing]
    if not missing:
        return
    prefix = "" if not text or text.endswith("\n") else "\n"
    path.write_text(text + prefix + "\n".join(missing) + "\n", encoding="utf-8")


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
    for gate in hooks.GATES:
        shim = hdir / gate.value
        if not shim.exists() or hooks.MARKER_START.encode() not in shim.read_bytes():
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
    if cmd_doctor(root) != 0:
        print("aramid: init: refusing to arm hooks -- a BLOCK-tier tool "
              "(gitleaks/semgrep) is missing; run `aramid doctor` (or "
              "`aramid doctor --fix`) and re-run init.", file=sys.stderr)
        return 3

    # step 4: aramid.toml (only if absent) + ARAMID.md (always) + gitignore.
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
    _update_gitignore(root)

    # step 5: install (idempotent, chain-never-clobber) hook shims.
    interpreter = Path(sys.executable)
    hooks.install(root, interpreter)

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
    print("aramid: init: summary")
    print(f"  root:              {root}")
    if scope_subpath:
        print(f"  scan scope:        {scope_subpath}")
    if extra_ignores:
        print(f"  nested repos excl: {', '.join(extra_ignores)}")
    print(f"  stack:             {', '.join(sorted(stack)) or 'unknown'}")
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
