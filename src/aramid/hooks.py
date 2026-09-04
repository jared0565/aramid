"""hooks -- git hook shim generation, chaining, install/uninstall.

Windows correctness is the whole point. The shims are `sh` scripts executed
by Git-for-Windows' bundled `sh`, which chokes on a bare CR in the exec
line -- shim bytes are therefore rendered with `\n` line endings ONLY and
always written via a *binary* file write (`Path.write_bytes`), never a
text-mode Windows write (which would silently reintroduce CRLF). The
blessed interpreter's ABSOLUTE path is baked into the shim, converted to
Git-for-Windows' `/c/...` form (`win_sh_path`) and double-quoted; a
`command -v py` / `py -3` fallback covers the case where that baked path
has since gone stale -- never invoke a bare `python` (this machine has up
to five different `python`s visible to hook `sh`, including the
WindowsApps store stub).

Exit-code mapping (spec §3, exhaustive -- the shim applies exactly this and
nothing else):
  pre-commit: {2,3} -> 0   (fail-open, always, including engine errors)
  pre-push:   2 -> 0; 1 and 3 pass through and block (an engine that
              couldn't run didn't run gitleaks -- fail-closed)

Hooks inherit the parent process' environment already (git does not
sanitize it), so `ARAMID_ACCEPT_DEGRADED` reaches the engine with no
special forwarding logic needed here.
"""
import re
import stat
import subprocess
import sys
from pathlib import Path

from aramid.models import Gate

MARKER_START = "# >>> aramid managed >>>"
MARKER_END = "# <<< aramid managed <<<"

# The two gates that get a git hook. Gate.ALL is a scan mode (`--all`), not
# a hook.
GATES: tuple[Gate, ...] = (Gate.PRE_COMMIT, Gate.PRE_PUSH)

TRIAGE_HOOK = "post-commit"  # Phase 2a: fail-open triage enqueue (spec section 2)

CHAINED_SUFFIX = ".aramid-chained"


def win_sh_path(p: Path) -> str:
    """`C:\\x\\y` -> `/c/x/y` (Git-for-Windows `sh` form). A path with no
    drive letter (already POSIX-shaped) passes through unchanged, forward
    slashes only."""
    p = Path(p)
    drive = p.drive
    if len(drive) == 2 and drive[1] == ":":
        posix = p.as_posix()
        rest = posix[len(drive):]
        if not rest.startswith("/"):
            rest = "/" + rest
        return f"/{drive[0].lower()}{rest}"
    return p.as_posix()


def _git_config(root: Path, key: str) -> str | None:
    try:
        # S603/S607 justification: "git" is a fixed literal and `key`
        # is always a hardcoded config key passed by this module's own
        # callers (currently only "core.hooksPath") -- never external input.
        # Relying on PATH to resolve "git" matches every other git invoker.
        cp = subprocess.run(["git", "config", key], cwd=str(root),  # noqa: S603,S607
                             capture_output=True, text=True,
                             encoding="utf-8", errors="replace")
    except OSError:
        # git not on PATH (or otherwise unspawnable) -- treat as "unset"
        # rather than propagating a raw exception up through hooks_dir /
        # install / uninstall / probe_interpreter.
        return None
    if cp.returncode == 0 and cp.stdout.strip():
        return cp.stdout.strip()
    return None


def hooks_dir(root: Path) -> Path:
    """Respects `git config core.hooksPath` (husky et al.); else the
    standard `<root>/.git/hooks`. A relative `core.hooksPath` is resolved
    against `root` (git resolves it against the working-tree top level)."""
    configured = _git_config(root, "core.hooksPath")
    if configured:
        p = Path(configured)
        return p.resolve() if p.is_absolute() else (root / p).resolve()
    return root / ".git" / "hooks"


def _exit_case_lines(gate: Gate, match_ci: bool = False) -> list[str]:
    if gate is Gate.PRE_COMMIT:
        return ['case "$status" in', "  2|3) exit 0 ;;", '  *) exit "$status" ;;', "esac"]
    if match_ci:
        # CI parity: nothing is softened. Note this only ever changes the
        # WARN-tier case -- a degraded BLOCK-tier tool already exits 1 via
        # policy.escalate_degraded, so `2) exit 0` was never swallowing a
        # gitleaks/semgrep/tests degradation. An ACCEPTED degradation
        # (`--accept-degraded` / `ARAMID_ACCEPT_DEGRADED`) exits 0 from the
        # gate itself with its `infrastructure_bypass` row, so it needs no
        # arm here either -- it used to exit 2, which `--strict` remapped to
        # 1 and this case then refused (2026-09-04).
        return ['case "$status" in', '  *) exit "$status" ;;', "esac"]
    return ['case "$status" in', "  2) exit 0 ;;", '  *) exit "$status" ;;', "esac"]


def _check_args(gate: Gate, match_ci: bool) -> str:
    """Argv tail for the shim's `aramid check` call.

    Default is bare `--gate <hook>`, which cli._check_mode resolves to
    `range` -- changed files only. `[hooks].pre_push_match_ci = true` swaps in
    the argv CI step 8 uses verbatim, so the two cannot drift apart by
    accident.

    OPT-IN ON PURPOSE. Moving a repo from range to `--all` surfaces every
    previously-unscanned finding at once, and the ledger has never seen those
    ids -- the ratchet reads them as NEW and escalates to BLOCK, so the next
    push is blocked by findings the developer did not introduce.
    `aramid rebaseline` is the remedy, and it has to be a deliberate step
    rather than something an upgrade inflicts.

    THE SECOND CONSEQUENCE, which this docstring did not mention until
    2026-08-10 and which is exactly why it hid: `--all` resolves to
    `mode == "all"`, and every range-scoped auto-resolver used to sit behind
    `if mode == "range"`. Turning CI parity ON therefore turned mutation, tdd
    and red-proof auto-resolution OFF -- silently, with no output saying so,
    for as long as the flag was set. Measured on aramid's own ledger:
    `gap_addressed` and `test_added` had fired zero times across 182
    resolutions while the resolvers deriving no range had all fired.
    `pipeline._resolution_scope` now computes the push's real delta
    independently of the scan mode, so the two are decoupled and this flag
    costs nothing but scan breadth. A ratchet consequence was documented and a
    resolution consequence was not, which is the asymmetry to watch for when
    one flag feeds two subsystems.
    """
    hook = "pre-commit" if gate is Gate.PRE_COMMIT else "pre-push"
    if match_ci and gate is not Gate.PRE_COMMIT:
        return f"--gate {hook} --all --strict"
    return f"--gate {hook}"


def render_shim(gate: Gate, interpreter: Path, match_ci: bool = False) -> bytes:
    """Render the `sh` shim for `gate`. Returns BYTES with `\n` line
    endings ONLY -- never route this through a text-mode write on Windows.

    Always includes a chain-check block that execs a sibling
    `<hook>.aramid-chained` file first, if present -- `install()` is what
    decides whether that sibling exists (rename-on-chain); `render_shim`
    itself is agnostic and this makes re-generation via `install()` safe
    and idempotent (no chaining state is baked into the rendered bytes)."""
    hook = gate.value
    interp_sh = win_sh_path(interpreter)
    lines = [
        "#!/bin/sh",
        MARKER_START,
        f"# aramid managed git hook -- gate: {hook}",
        "# regenerated by `aramid init` -- do not edit by hand.",
        "",
        'DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)',
        f'CHAINED="$DIR/{hook}{CHAINED_SUFFIX}"',
        'if [ -f "$CHAINED" ]; then',
        '    "$CHAINED" "$@" || exit $?',
        "fi",
        "",
        f'INTERP="{interp_sh}"',
        'if [ -x "$INTERP" ]; then',
        # ARAMID_HOOK=<gate>: the gate reads the pre-push ref lines git
        # writes to this hook's stdin ONLY under this marker -- by hand and
        # in CI the process has an empty non-tty stdin too, and reading it
        # there would turn CI's pre-push-tier run into "nothing to push"
        # (interop round 176; pushrefs.read_hook_stdin).
        f'    ARAMID_HOOK={hook} "$INTERP" -P -m aramid check {_check_args(gate, match_ci)}',
        "    status=$?",
        "elif command -v py >/dev/null 2>&1; then",
        f"    ARAMID_HOOK={hook} py -3 -P -m aramid check {_check_args(gate, match_ci)}",
        "    status=$?",
        "else",
        '    echo "aramid: no usable python interpreter (tried $INTERP and py -3)" >&2',
        "    status=3",
        "fi",
        "",
        *_exit_case_lines(gate, match_ci),
        MARKER_END,
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def render_template_shim(gate: Gate, interpreter: Path) -> bytes:
    """Render the GLOBAL-TEMPLATE variant of `gate`'s shim, for git's
    `init.templateDir`. Deliberately a mirror of `render_shim` rather than a
    parameterization of it: the two have different safety contracts and the
    exit-code mapping must stay byte-identical between them, so they share
    `_exit_case_lines` and nothing else.

    The difference is the opt-in guard. Git copies templateDir hooks into
    EVERY new `git init`/`git clone`, including repos nobody onboarded, so
    this variant must prove the repo is onboarded before it does anything.
    `aramid.toml` at the repo root is that proof -- and because it is
    COMMITTED, a fresh clone of an onboarded repo has it, which is precisely
    the hole this exists to close (`.git/hooks` is not version-controlled, so
    a clone otherwise silently has config-but-no-enforcement).

    The guard fails OPEN in every ambiguous case -- no git, not a repo, no
    `aramid.toml` -- because a machine-wide template hook that errors would
    break unrelated repos."""
    hook = gate.value
    interp_sh = win_sh_path(interpreter)
    lines = [
        "#!/bin/sh",
        MARKER_START,
        f"# aramid managed git hook (GLOBAL TEMPLATE) -- gate: {hook}",
        "# installed by `aramid hooks install` into git's init.templateDir, so git",
        "# copies it into every NEW `git init` / `git clone`. Do not edit by hand.",
        "",
        "# Opt-in guard: this lands in EVERY new repo, so no-op unless the repo is",
        "# actually onboarded. Fails OPEN (exit 0) on every ambiguity -- a template",
        "# hook that errors would break unrelated repos machine-wide.",
        'ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0',
        '[ -n "$ROOT" ] || exit 0',
        '[ -f "$ROOT/aramid.toml" ] || exit 0',
        "",
        'DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)',
        f'CHAINED="$DIR/{hook}{CHAINED_SUFFIX}"',
        'if [ -f "$CHAINED" ]; then',
        '    "$CHAINED" "$@" || exit $?',
        "fi",
        "",
        f'INTERP="{interp_sh}"',
        'if [ -x "$INTERP" ]; then',
        # Same marker as the managed shim (see render_shim): git is on stdin.
        f'    ARAMID_HOOK={hook} "$INTERP" -P -m aramid check --gate {hook}',
        "    status=$?",
        "elif command -v py >/dev/null 2>&1; then",
        f"    ARAMID_HOOK={hook} py -3 -P -m aramid check --gate {hook}",
        "    status=$?",
        "else",
        '    echo "aramid: no usable python interpreter (tried $INTERP and py -3)" >&2',
        "    status=3",
        "fi",
        "",
        *_exit_case_lines(gate),
        MARKER_END,
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def template_dir() -> Path:
    """Default `init.templateDir` target. Sibling of the drain registry
    (`~/.aramid/repos.toml`) -- machine-level aramid state lives together."""
    return Path.home() / ".aramid" / "git-template"


def install_template(template_root: Path, interpreter: Path) -> list[Path]:
    """Write the guarded gate shims into `<template_root>/hooks/` and return
    the paths written. Git requires the `hooks/` subdirectory -- it copies
    `<templateDir>/hooks/<name>`, not `<templateDir>/<name>`.

    Writing the files is deliberately separated from `git config --global
    init.templateDir`: this half is pure filesystem and testable, and the
    caller owns the machine-wide config change.

    The triage post-commit hook is NOT templated. It is an enqueue-only
    convenience whose work the drain's catch-up sweep recovers anyway, so
    there is no reason to put it in every repo on the machine."""
    hdir = template_root / "hooks"
    hdir.mkdir(parents=True, exist_ok=True)

    written = []
    for gate in GATES:
        p = hdir / gate.value
        p.write_bytes(render_template_shim(gate, interpreter))
        _make_executable(p)
        written.append(p)
    return written


def render_triage_shim(interpreter: Path) -> bytes:
    """Post-commit shim: run triage, swallow EVERYTHING, exit 0. A commit
    can never be blocked or noisy-failed by triage (spec section 6); the
    drain's catch-up sweep recovers anything this shim misses."""
    interp_sh = win_sh_path(interpreter)
    lines = [
        "#!/bin/sh",
        MARKER_START,
        'DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)',
        f'CHAINED="$DIR/{TRIAGE_HOOK}{CHAINED_SUFFIX}"',
        'if [ -f "$CHAINED" ]; then',
        '    "$CHAINED" "$@" || true',
        "fi",
        f'INTERP="{interp_sh}"',
        'if [ -x "$INTERP" ]; then',
        '    "$INTERP" -P -m aramid triage HEAD --budget 15 >/dev/null 2>&1 || true',
        "elif command -v py >/dev/null 2>&1; then",
        "    py -3 -P -m aramid triage HEAD --budget 15 >/dev/null 2>&1 || true",
        "fi",
        MARKER_END,
        "exit 0",
        "",
    ]
    return "\n".join(lines).encode()


def _make_executable(path: Path) -> None:
    """`chmod +x` where the platform supports it. Never fatal: NTFS has no
    POSIX permission bits, so this is a best-effort no-op on a bare Windows
    filesystem, but costs nothing and matters on any POSIX-permission
    filesystem the repo might be cloned onto (WSL, a Linux CI runner)."""
    try:
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass


def _is_aramid_shim(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        return MARKER_START.encode() in path.read_bytes()
    except OSError:
        return False


# Any tool's managed-hook marker, generalized from aramid's own
# `# >>> aramid managed >>>` (MARKER_START). Other managing tools (e.g.
# graphite, `docs/superpowers/specs/2026-07-28-autonomous-repo-hooks-design.md`
# section "Shim rendering") follow the same "`# >>> <tool> managed >>>`"
# convention deliberately, precisely so this pattern can recognize them.
_MANAGED_MARKER_RE = re.compile(rb"# >>> (\S+) managed >>>")


def _foreign_managed_tool(path: Path) -> str | None:
    """The owning tool's name if `path` carries a `<tool> managed` marker for
    some tool OTHER than aramid -- i.e. not a plain foreign (human-authored)
    hook, but another managing tool's own trampoline that itself chains
    onward. `install()` must refuse to chain such a file the way it chains an
    ordinary foreign hook: rename-and-exec-first would run the OTHER tool's
    gate via the chain AND aramid's own new shim a second time afterward
    (double execution), and later make `uninstall()`'s restore put that live
    trampoline back in the hook slot while reporting a clean uninstall --
    silently leaving enforcement running. Returns None for a plain foreign
    hook (no marker at all) or for aramid's own shim."""
    if not path.exists():
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    m = _MANAGED_MARKER_RE.search(data)
    if m is None:
        return None
    tool = m.group(1).decode("ascii", errors="replace")
    return None if tool == "aramid" else tool


def _find_chained_aramid_shim(hdir: Path, hook: str) -> Path | None:
    """A sibling of `hdir / hook` that still carries aramid's OWN marker --
    e.g. another tool's byte-identical relocation of aramid's shim under its
    own suffix convention (graphite's `.local`; a future tool may pick a
    different one). Detected by marker content, not by hardcoding any other
    tool's suffix, so this recognizes any such relocation generically.
    Its existence means aramid's gate is not actually stopped by
    `install()`'s foreign-managed refusal below -- the OTHER tool's
    trampoline chains to this file, so aramid's shim keeps running; only
    `install()`'s own regeneration of the `hook` slot is skipped. Returns
    None if no such sibling exists, in which case the refusal may be a
    genuine gap rather than a fail-open one."""
    if not hdir.is_dir():
        return None
    for candidate in hdir.iterdir():
        if candidate.name == hook or not candidate.name.startswith(hook):
            continue
        if candidate.is_file() and _is_aramid_shim(candidate):
            return candidate
    return None


def _refresh_relocated_shim(relocated: Path | None, hook: str,
                            current: bytes) -> str:
    """Regenerate aramid's OWN relocated shim in place. Returns what actually
    happened: "refreshed", "current", "stale" (differs and could NOT be
    rewritten) or "skipped".

    THREE states, not two, and the third is the point. Regeneration is
    best-effort -- a read-only or locked file must not fail the whole install
    -- but "we could not rewrite it" and "it did not need rewriting" are
    different facts. Collapsing them into one boolean reports an unrepaired
    pre-`-P` shim as current, which is the very lie this change set exists to
    remove; the first draft of this function did exactly that.

    `install()` refuses the FOREIGN slot -- correctly, since chaining a
    managed hook double-runs both tools' gates. But the relocated sibling is
    aramid's own file, and skipping it at the SLOT level meant it could never
    receive a template fix for as long as the other tool occupied the slot:
    the round-57 `-P` guard never reached it, on a hook that fires on every
    commit and swallows all output. Refusing the foreign slot and refreshing
    our own sibling are different decisions; only the first was ever intended
    (interop round 112).

    NEVER rewrites `<hook>.aramid-chained`. That path is what a shim EXECS,
    so writing a shim into it would make it exec itself -- an unbounded loop
    on every commit. `_find_chained_aramid_shim` matches it on the same
    `startswith(hook)` + marker test as a real relocation, so the exclusion
    has to be explicit here rather than implied by the search. (In practice
    `install()` only ever moves FOREIGN hooks there, so it should not carry
    aramid's marker at all -- this is a guard against the case where it
    somehow does, not a routine path.)"""
    if relocated is None or relocated.name == f"{hook}{CHAINED_SUFFIX}":
        return "skipped"
    try:
        if relocated.read_bytes() == current:
            return "current"
        relocated.write_bytes(current)
    except OSError:
        # Never fatal -- a shim we cannot refresh is still the ARMED shim it
        # was a moment ago, and failing the whole install over it is a worse
        # outcome. But it IS stale, and the notice must say so.
        return "stale"
    _make_executable(relocated)
    return "refreshed"


_RELOCATED_STATE_TEXT = {
    "refreshed": "REGENERATED in place to the current template",
    "current": "already current",
    "stale": ("STALE and could NOT be regenerated (write refused) -- "
              "resolve it manually"),
    "skipped": "left as-is",
}


def _warn_foreign_managed_conflict(
    hook: str, foreign_tool: str, chained_via: Path | None = None,
    state: str = "skipped",
) -> None:
    if chained_via is not None:
        print(f"aramid: install: {hook}: already managed by '{foreign_tool}' -- "
              f"refusing to chain another tool's managed hook (chaining it would "
              f"silently double-run both tools' gates on every {hook}). aramid's "
              f"own {hook} shim survives at '{chained_via.name}' and still runs "
              f"via '{foreign_tool}'s chain -- "
              + _RELOCATED_STATE_TEXT.get(state, "left as-is")
              + f"; this slot itself stays untouched until '{foreign_tool}' "
              f"no longer occupies it.", file=sys.stderr)
        return
    print(f"aramid: install: {hook}: already managed by '{foreign_tool}' -- "
          f"refusing to chain another tool's managed hook (chaining it would "
          f"silently double-run both tools' gates on every {hook}). Left "
          f"'{foreign_tool}'s hook untouched; aramid's {hook} gate is NOT "
          f"installed until this is resolved manually.", file=sys.stderr)


def _match_ci(root: Path) -> bool:
    """Read `[hooks].pre_push_match_ci`. Fails CLOSED: an unparseable or
    absent config yields the narrow default shim, never the wider one -- a
    broken aramid.toml must not silently widen a gate's scope."""
    try:
        from aramid import config as config_mod
        return bool((config_mod.load_config(root).hooks or {}).get(
            "pre_push_match_ci", False))
    except Exception:  # noqa: BLE001 - hook generation must never hard-fail here
        return False


def install(root: Path, interpreter: Path) -> None:
    """Install (or idempotently regenerate) the pre-commit/pre-push shims.

    A foreign (non-aramid) hook already occupying a gate's slot is renamed
    to `<hook>.aramid-chained` and the new shim execs it first (see
    `render_shim`'s always-present chain-check block) -- never clobbered.
    Idempotent: marker detection means a second `install()` regenerates
    aramid's own shim in place and never double-chains (an aramid shim
    already at `<hook>` is never itself treated as "foreign").

    A hook already carrying ANOTHER tool's `# >>> <tool> managed >>>` marker
    is not an ordinary foreign hook -- chaining it (rename-and-exec-first)
    would double-run both tools' gates, since a managed hook already forwards
    onward itself. `install()` refuses instead: leaves that hook completely
    untouched, skips installing aramid's shim for that one hook, and prints a
    diagnostic naming the conflict (see `_foreign_managed_tool`). If the OTHER
    tool relocated aramid's own shim byte-identically under its own suffix
    (e.g. graphite's `.local`) rather than wrapping it, that sibling is still
    aramid's live shim -- `_find_chained_aramid_shim` detects it by marker
    content (no other tool's suffix is hardcoded) and the diagnostic is
    softened accordingly, since nothing there actually needs manual
    resolution."""
    hdir = hooks_dir(root)
    hdir.mkdir(parents=True, exist_ok=True)
    # Read ONCE per install, not per gate: both shims must be rendered from
    # the same view of the config, and one unparseable read must not produce
    # a half-widened pair.
    match_ci = _match_ci(root)

    for gate in GATES:
        hook = gate.value
        shim_path = hdir / hook
        chained_path = hdir / f"{hook}{CHAINED_SUFFIX}"

        if shim_path.exists() and not _is_aramid_shim(shim_path):
            foreign_tool = _foreign_managed_tool(shim_path)
            if foreign_tool is not None:
                relocated = _find_chained_aramid_shim(hdir, hook)
                state = _refresh_relocated_shim(
                    relocated, hook, render_shim(gate, interpreter, match_ci))
                _warn_foreign_managed_conflict(
                    hook, foreign_tool, relocated, state)
                continue

            # A real foreign hook (not ours) occupies this slot -- chain it.
            # If a stale .aramid-chained sibling exists too (e.g. a previous
            # uninstall didn't run to completion), the current foreign hook
            # wins as the thing that gets chained.
            if chained_path.exists():
                chained_path.unlink()
            shim_path.replace(chained_path)
            _make_executable(chained_path)

        shim_path.write_bytes(render_shim(gate, interpreter, match_ci))
        _make_executable(shim_path)

    hook = TRIAGE_HOOK
    shim_path = hdir / hook
    chained_path = hdir / f"{hook}{CHAINED_SUFFIX}"
    skip_triage = False

    if shim_path.exists() and not _is_aramid_shim(shim_path):
        foreign_tool = _foreign_managed_tool(shim_path)
        if foreign_tool is not None:
            relocated = _find_chained_aramid_shim(hdir, hook)
            state = _refresh_relocated_shim(
                relocated, hook, render_triage_shim(interpreter))
            _warn_foreign_managed_conflict(
                hook, foreign_tool, relocated, state)
            skip_triage = True
        else:
            # A real foreign hook (not ours) occupies this slot -- chain it.
            # If a stale .aramid-chained sibling exists too (e.g. a previous
            # uninstall didn't run to completion), the current foreign hook
            # wins as the thing that gets chained.
            if chained_path.exists():
                chained_path.unlink()
            shim_path.replace(chained_path)
            _make_executable(chained_path)

    if not skip_triage:
        shim_path.write_bytes(render_triage_shim(interpreter))
        _make_executable(shim_path)


def uninstall(root: Path) -> None:
    """Remove aramid's own shims and restore any `.aramid-chained`
    originals back to their original hook names. A repo that was never
    `install()`-ed is a no-op.

    Guard against losing a hook: the restore step only fires when the
    current `<hook>` file is still aramid's own shim (or absent). If a
    third-party hook manager (e.g. husky's `prepare` script) rewrote
    `<hook>` directly after aramid installed -- so a LIVE foreign hook now
    occupies the slot, with no aramid marker -- restoring the stale
    `.aramid-chained` original over it would silently destroy that live
    hook. In that case the live foreign hook is left untouched and the
    now-orphaned `.aramid-chained` backup is discarded instead, with a
    printed notice.

    If the `.aramid-chained` backup itself carries ANOTHER tool's managed
    marker (a state `install()` now refuses to create, but which can still
    predate this guard or arise from manual editing): still restore it --
    discarding it instead would silently break that other tool's live hook
    -- but print a diagnostic rather than claim a silent clean uninstall,
    since aramid cannot verify whether its own gate is still reachable
    through that hook's own internal chain."""
    hdir = hooks_dir(root)
    if not hdir.exists():
        return

    for hook in [g.value for g in GATES] + [TRIAGE_HOOK]:
        shim_path = hdir / hook
        chained_path = hdir / f"{hook}{CHAINED_SUFFIX}"

        was_ours = _is_aramid_shim(shim_path)
        if was_ours:
            shim_path.unlink()

        if not chained_path.exists():
            continue

        if was_ours or not shim_path.exists():
            foreign_tool = _foreign_managed_tool(chained_path)
            if foreign_tool is not None:
                print(f"aramid: uninstall: {hook}: the chained original is "
                      f"itself managed by '{foreign_tool}' -- restoring it "
                      f"(discarding it would break '{foreign_tool}'s hook), "
                      f"but aramid cannot verify its own gate is fully gone "
                      f"from this hook's chain -- verify manually.",
                      file=sys.stderr)
            chained_path.replace(shim_path)
            _make_executable(shim_path)
        else:
            # shim_path exists and is NOT aramid's shim: a foreign hook
            # manager replaced it after install. Never overwrite a live
            # foreign hook -- discard the orphaned chained backup instead.
            chained_path.unlink()
            print(f"aramid: uninstall: {hook}: a foreign hook replaced aramid's "
                  f"shim after install -- left the live foreign hook in place "
                  f"and discarded the stale chained backup.", file=sys.stderr)
