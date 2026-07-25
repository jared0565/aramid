"""aramid hooks install|remove|status -- the machine-wide git hook template.

`aramid init` installs shims into ONE repo's `.git/hooks`. That directory is
not version-controlled, so it does not survive a clone and does not exist on
another machine: the committed `aramid.toml` arrives, the enforcement does
not, and nothing says so. This command closes that hole from the other side by
pointing git's `init.templateDir` at aramid's guarded shims, which git then
copies into every NEW `git init` / `git clone`.

Two boundaries worth stating plainly, because both are easy to over-read:

- **New repos only.** git consults templateDir at init/clone time. Repos
  already on disk are unaffected forever; they still need `aramid init`.
- **The shims are opt-in.** `render_template_shim`'s guard no-ops unless the
  repo has an `aramid.toml`, so landing them machine-wide does not start
  gating repos nobody onboarded.

Cross-platform: unlike `aramid schedule` (Windows Task Scheduler), nothing
here is OS-specific -- `git config --global` and file writes work everywhere.
"""
import subprocess
import sys
from pathlib import Path

from aramid import hooks

CONFIG_KEY = "init.templateDir"
_ACTIONS = ("install", "remove", "status")


def _git_config_get(key: str) -> str | None:
    """Read a global git config value. None when unset -- git exits 1 for a
    missing key, which is not an error here."""
    try:
        cp = subprocess.run(["git", "config", "--global", "--get", key],
                            capture_output=True, text=True, check=False)
    except OSError:
        return None
    value = cp.stdout.strip()
    return value or None


def _git_config_set(key: str, value: str) -> None:
    subprocess.run(["git", "config", "--global", key, value],
                   capture_output=True, text=True, check=False)


def _git_config_unset(key: str) -> None:
    subprocess.run(["git", "config", "--global", "--unset", key],
                   capture_output=True, text=True, check=False)


def _same_path(a: str | None, b: Path) -> bool:
    """Whether a configured templateDir is OURS. Compared resolved, so
    `~/.aramid/git-template` and its absolute form are not treated as two
    different directories (which would make `remove` refuse to clean up)."""
    if not a:
        return False
    try:
        return Path(a).expanduser().resolve() == b.expanduser().resolve()
    except OSError:
        return str(a) == str(b)


def cmd_hooks(action: str, template_root: Path | None = None,
              interpreter: Path | None = None) -> int:
    """Returns 0 on success, 2 on refusal or an unknown action.

    `template_root`/`interpreter` are injectable so tests never touch the
    real `~/.aramid/git-template` or the developer's global git config."""
    root = template_root if template_root is not None else hooks.template_dir()
    interp = interpreter if interpreter is not None else Path(sys.executable)
    current = _git_config_get(CONFIG_KEY)

    if action == "install":
        # git supports exactly ONE templateDir. Overwriting someone else's is
        # destructive and unrecoverable from here, so refuse and say whose.
        if current and not _same_path(current, root):
            print(f"aramid: hooks: {CONFIG_KEY} is already set to {current!r} "
                  f"-- refusing to overwrite it. git supports only one template "
                  f"directory; copy aramid's shims from {root / 'hooks'} into "
                  f"that directory instead, or unset it first.", file=sys.stderr)
            return 2

        written = hooks.install_template(root, interp)
        _git_config_set(CONFIG_KEY, str(root))
        print(f"aramid hooks: installed {len(written)} guarded shim(s) into {root / 'hooks'}")
        print(f"aramid hooks: {CONFIG_KEY} -> {root}")
        print("aramid hooks: applies to NEW `git init` / `git clone` only; "
              "existing repos still need `aramid init`.")
        return 0

    if action == "remove":
        # Key on WHOSE dir it is, not merely on the key being set -- unsetting
        # a foreign templateDir would silently disable the user's own hooks.
        if _same_path(current, root):
            _git_config_unset(CONFIG_KEY)
            print(f"aramid hooks: unset {CONFIG_KEY}")
        elif current:
            print(f"aramid hooks: {CONFIG_KEY} points at {current!r}, not aramid's "
                  f"-- left untouched.")
        else:
            print(f"aramid hooks: {CONFIG_KEY} is not set -- nothing to remove.")
        # The shim files are left on disk deliberately: they are inert once
        # git no longer consults them, and keeping them makes re-install cheap.
        return 0

    if action == "status":
        shims = root / "hooks"
        have_shims = (shims / "pre-commit").exists() and (shims / "pre-push").exists()
        if _same_path(current, root) and have_shims:
            print(f"aramid hooks: installed -- {CONFIG_KEY} -> {root}")
            print("aramid hooks: seeds NEW `git init` / `git clone` only; repos "
                  "already on disk are unaffected and still need `aramid init`.")
        elif _same_path(current, root):
            print(f"aramid hooks: not installed -- {CONFIG_KEY} points at {root} "
                  f"but the shims are missing. Run `aramid hooks install`.")
        elif current:
            print(f"aramid hooks: not installed -- {CONFIG_KEY} points at {current!r} "
                  f"(not aramid's).")
        else:
            print(f"aramid hooks: not installed -- {CONFIG_KEY} is unset.")
        return 0

    print(f"aramid: hooks: unknown action {action!r} "
          f"(expected one of {', '.join(_ACTIONS)})", file=sys.stderr)
    return 2
