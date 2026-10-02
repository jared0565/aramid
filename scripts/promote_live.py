#!/usr/bin/env python3
"""Promote a released aramid to the LIVE tool other repos on this machine run.

    python scripts/promote_live.py 0.3.1 --confirm

WHY THIS EXISTS. Two aramids share this machine and must not be the same one:

  * the LIVE tool -- an installed wheel in site-packages, resolved by every
    other repo's git hooks and by `aramid` on PATH;
  * this CHECKOUT -- edited constantly, and gating its own pushes with the
    live tool rather than with itself (see RELEASING.md).

`pip install -e .` collapses those two in one command, silently, and every
consumer starts running uncommitted edits. This script is the sanctioned way
across the gap: it installs a BUILT, RELEASED, HASH-VERIFIED wheel and nothing
else. `aramid doctor` reports the editable case if it ever happens anyway.

WHY IT DOWNLOADS RATHER THAN BUILDS. The GitHub release asset is the artifact
CI produced and published, and its digest is recorded server-side. Building
locally would produce a wheel that is probably equivalent and cannot be proven
identical -- and "probably the same as what the tag says" is not a claim worth
making about the thing every repo on the machine is about to run.

WHY IT IS A SCRIPT AND NOT `aramid promote`. A subcommand would be resolved
through `python -m aramid`, which finds the LIVE tool -- the old one, which by
definition does not have the new subcommand. Promotion would then require
PYTHONPATH gymnastics to reach the checkout's copy, which is the exact
confusion this separation exists to remove. A script has no such problem.

NOT AUTOMATED, DELIBERATELY. It changes what other repos run, so it refuses
without `--confirm`, and it prints what a consumer needs to be told afterwards.

IT PROMOTES ARAMID, NOT ITS DEPENDENCIES (FN-26). It used to run
`pip install --force-reinstall <wheel>`, which re-resolves aramid's whole
dependency tree to the newest versions allowed. On 2026-10-02 that built
semgrep 1.179.0 -- published hours earlier with no Windows wheel -- from its
sdist, without semgrep-core.exe, and every semgrep run on the machine exited 2
until it was rolled back by hand, while this script printed OK. The analyzers
ARE the verdict for every repo here, so: aramid is reinstalled with
`--no-deps`; any dependency version pip would change is shown first and
refused unless named with `--allow-dep-change`; and an analyzer that ran
before promotion and does not after, or a new `pip check` conflict, fails it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

WHEEL_ASSET = "aramid-{version}-py3-none-any.whl"

# The analyzers the post-install check requires. One tuple feeds both the probe
# source and the check, so a tool added to one cannot go unchecked by the other.
PROBED_TOOLS = ("semgrep", "ruff", "pip-audit")

# What the post-install probe runs, resolved exactly as the gate resolves it
# (`aramid.toolpath.resolve`, through the LIVE install in a clean interpreter).
# `--version` is enough for the failure this exists for: semgrep 1.179.0 built
# without its core exits 2 on `--version` too (doctor's probe on CI run
# 36983535922, and pawscout-worker's own read at 06:45Z on 2026-10-02).
_TOOL_PROBE = (
    "import json, subprocess\n"
    "from aramid import toolpath\n"
    "out = {}\n"
    f"for name in {PROBED_TOOLS!r}:\n"
    "    exe = toolpath.resolve(name)\n"
    "    if exe is None:\n"
    "        out[name] = [None, 'not found']\n"
    "        continue\n"
    "    try:\n"
    "        r = subprocess.run([str(exe), '--version'], capture_output=True,\n"
    "                           text=True, timeout=120)\n"
    "    except (OSError, subprocess.SubprocessError) as e:\n"
    "        out[name] = [False, repr(e)]\n"
    "        continue\n"
    "    lines = (r.stdout + r.stderr).strip().splitlines()\n"
    "    out[name] = [r.returncode == 0, lines[-1] if lines else f'exit {r.returncode}']\n"
    "print(json.dumps(out))\n")

_INSTALLED_PROBE = (
    "import json, sys, importlib.metadata as m\n"
    "out = {}\n"
    "for n in json.loads(sys.argv[1]):\n"
    "    try:\n"
    "        out[n] = m.version(n)\n"
    "    except m.PackageNotFoundError:\n"
    "        out[n] = None\n"
    "print(json.dumps(out))\n")


def _run(argv: list[str], **kw) -> subprocess.CompletedProcess:
    # noqa convention matches runners/base.py: every argv here is built from
    # literals plus a version string the operator typed, and is passed as a
    # LIST with no shell, so there is nothing for an injection to reach.
    # Every `-m pip` passed here carries -P: this script runs from the repo
    # root, and `python -m X` puts the cwd at sys.path[0], where a `pip.py`
    # (or `pip/__init__.py`) would run instead of pip, with these arguments.
    return subprocess.run(argv, capture_output=True, text=True, **kw)  # noqa: S603


def _drain_lock() -> Path:
    """aramid's drain singleton lock (`commands/drain.py`, `_lock_path`): it
    exists only while a drain runs. Seam for tests."""
    return Path.home() / ".aramid" / "drain.lock"


def _clean_env() -> dict:
    """An environment with PYTHONPATH stripped.

    Every verification below has to answer "what will OTHER processes
    resolve?", and this session very likely has PYTHONPATH pointed at
    `src/`. Measuring under that would report the checkout and call it the
    live tool -- the precise mistake this script exists to prevent.
    """
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return env


def _live() -> tuple[str | None, str | None, bool | None]:
    """(version, path, editable) of the installed aramid, as a clean
    interpreter sees it. All three are None when the probe fails, whatever it
    managed to print.

    `editable` is read from the installed distribution's `direct_url.json`
    (`dir_info.editable`, the key `aramid doctor` keys on) because the path
    check in `_not_promoted` cannot see an editable install of some OTHER
    clone of aramid -- that resolves outside this checkout and looks
    promoted. None when there is no distribution metadata to read: that is
    not evidence of a wheel, so the caller treats it as unconfirmed.
    """
    probe = (
        "import aramid, json, importlib.metadata as m\n"
        "try:\n"
        "    raw = m.distribution('aramid').read_text('direct_url.json')\n"
        "except m.PackageNotFoundError:\n"
        "    editable = None\n"
        "else:\n"
        "    editable = False\n"
        "    if raw:\n"
        "        try:\n"
        "            editable = bool(json.loads(raw).get('dir_info', {}).get('editable'))\n"
        "        except (ValueError, AttributeError):\n"
        "            editable = None\n"
        "print(json.dumps([aramid.__version__, aramid.__file__, editable]))\n")
    r = _run([sys.executable, "-P", "-c", probe], env=_clean_env())
    if r.returncode != 0:
        return None, None, None
    try:
        version, path, editable = json.loads(r.stdout.strip())
        return version, path, editable
    except (ValueError, TypeError):
        return None, None, None


def _not_promoted(path: str | None, editable: bool | None, repo: Path) -> str | None:
    """Why what is live is NOT a promoted wheel, or None if it is.

    Version equality says nothing here: an editable install of this checkout
    carries the released `__version__` the moment the bump commit lands, and
    that is the state this script exists to replace, not to accept. Found by
    the llm-review consumer (ledger be79fea8): the pre-check returned 0 on
    the version alone, so the one time anyone would run this -- to undo an
    accidental `pip install -e .` right after a release -- it said "already
    live. Nothing to do." and left every consumer on the working tree.
    """
    if path and repo in Path(path).resolve().parents:
        return f"it resolves INSIDE this checkout ({path}); consumers run the working tree"
    if editable:
        return "the installed distribution is editable (direct_url.json: dir_info.editable)"
    if editable is None:
        return "the installed distribution has no metadata that vouches for a wheel"
    return None


def _canon(name: str) -> str:
    """PEP 503 normalized name: `PyJWT`, `pyjwt` and `py_jwt` are one project."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _installed_versions(names: list[str]) -> dict[str, str | None] | None:
    """Installed version of each name as a clean interpreter sees it (None
    for not installed), or None when the probe itself failed."""
    r = _run([sys.executable, "-P", "-c", _INSTALLED_PROBE, json.dumps(names)],
             env=_clean_env())
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout.strip())
    except ValueError:
        return None


def _dep_changes(wheel: Path) -> list[tuple[str, str | None, str]] | None:
    """What a plain `pip install <wheel>` would install or change, aramid
    itself excluded, as (name, installed version or None, new version).

    Read from pip's own `--dry-run --report`, so it is pip's resolution and
    not a guess at it. None when it cannot be computed: the caller refuses
    rather than installing blind."""
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        r = _run([sys.executable, "-P", "-m", "pip", "install", "--dry-run", "--quiet",
                  "--report", str(report), str(wheel)], env=_clean_env())
        if r.returncode != 0 or not report.exists():
            return None
        try:
            items = json.loads(report.read_text(encoding="utf-8")).get("install", [])
            planned = [(it["metadata"]["name"], it["metadata"]["version"]) for it in items]
        except (ValueError, KeyError, TypeError, AttributeError):
            return None
    planned = [(name, new) for name, new in planned if _canon(name) != "aramid"]
    if not planned:
        return []
    installed = _installed_versions([name for name, _ in planned])
    if installed is None:
        return None
    return [(name, installed.get(name), new) for name, new in planned]


def _probe_tools() -> dict[str, tuple[bool | None, str]]:
    """{tool: (runs?, last output line)} through the live install; True runs,
    False fails, None not found. Empty when the probe itself could not run --
    "nothing was checked", which the caller must not read as healthy."""
    r = _run([sys.executable, "-P", "-c", _TOOL_PROBE], env=_clean_env())
    if r.returncode != 0:
        return {}
    try:
        raw = json.loads(r.stdout.strip().splitlines()[-1])
        return {name: (ok, str(detail)) for name, (ok, detail) in raw.items()}
    except (ValueError, IndexError, TypeError, AttributeError):
        return {}


def _pip_check() -> set[str] | None:
    """The conflicts `pip check` reports, one line each. Its exit code is 1
    whenever ANY conflict exists, including ones that predate this promotion,
    so the caller compares before with after rather than reading rc alone."""
    r = _run([sys.executable, "-P", "-m", "pip", "check"], env=_clean_env())
    if r.returncode not in (0, 1):
        return None
    return {line.strip() for line in r.stdout.splitlines()
            if line.strip() and not line.startswith("No broken requirements")}


def _release_digest(tag: str, asset: str) -> str | None:
    """The sha256 GitHub recorded for the asset, or None."""
    r = _run(["gh", "release", "view", tag, "--json", "assets"])
    if r.returncode != 0:
        return None
    for entry in json.loads(r.stdout).get("assets", []):
        if entry.get("name") == asset:
            digest = entry.get("digest", "")
            return digest.split("sha256:", 1)[-1] if "sha256:" in digest else None
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("version", help="released version to promote, e.g. 0.3.1")
    ap.add_argument("--confirm", action="store_true",
                    help="required; without it this only reports what it would do")
    ap.add_argument("--allow-dep-change", action="append", default=[], metavar="NAME",
                    help="let promotion change this dependency's installed version "
                         "(repeatable); any other change is refused")
    args = ap.parse_args()

    tag = f"v{args.version}"
    asset = WHEEL_ASSET.format(version=args.version)

    repo = Path(__file__).resolve().parent.parent
    cur_version, cur_path, cur_editable = _live()
    print(f"live now : {cur_version or 'not installed'}")
    print(f"           {cur_path or '-'}")
    print(f"promoting: {args.version}  (from release {tag})")

    if cur_version == args.version:
        problem = _not_promoted(cur_path, cur_editable, repo)
        if not problem:
            print(f"\nalready live: {args.version} is installed. Nothing to do.")
            return 0
        print(f"\n{args.version} is live but NOT as a promoted wheel: {problem}.\n"
              f"  Reinstalling the released wheel over it.")

    digest = _release_digest(tag, asset)
    if not digest:
        print(f"\nrefusing: no sha256 for {asset} on release {tag}.\n"
              f"  Promotion installs a RELEASED artifact, never a local build --\n"
              f"  cut and publish the release first (see RELEASING.md).", file=sys.stderr)
        return 3
    print(f"release sha256: {digest}")

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        r = _run(["gh", "release", "download", tag, "--pattern", asset, "--dir", str(out)])
        if r.returncode != 0:
            print(f"\nrefusing: download failed\n{r.stderr}", file=sys.stderr)
            return 3
        wheel = out / asset
        actual = hashlib.sha256(wheel.read_bytes()).hexdigest()
        if actual != digest:
            # Never install past this. A mismatch means the bytes are not the
            # release, and the whole point of promoting a released artifact is
            # that what runs is what was published and tested.
            print(f"\nrefusing: sha256 mismatch\n  release {digest}\n  file    {actual}",
                  file=sys.stderr)
            return 3
        print("verified : downloaded wheel matches the release digest")

        changes = _dep_changes(wheel)
        if changes is None:
            print("\nrefusing: could not work out which dependencies pip would change\n"
                  "  (`pip install --dry-run --report` failed). Promotion never installs\n"
                  "  without knowing what else it moves.", file=sys.stderr)
            return 3
        allowed = {_canon(name) for name in args.allow_dep_change}
        blocked = [name for name, _, _ in changes if _canon(name) not in allowed]
        if not changes:
            print("deps     : no installed dependency version changes")
        for name, old, new in changes:
            mark = "allowed" if _canon(name) in allowed else "NOT allowed"
            print(f"would change: {name} {old or '(not installed)'} -> {new}  [{mark}]")
        flags = " ".join(f"--allow-dep-change {name}" for name in blocked)

        # The dry run stops HERE rather than before the download, deliberately.
        # Everything above is the part that can be wrong in a way that matters
        # -- resolving the release, finding the asset, comparing the digest,
        # what pip would move -- and a rehearsal that skips it only rehearses
        # argument parsing.
        if not args.confirm:
            print("\n--confirm not given; verified but NOT installed.\n"
                  "This changes what EVERY repo on this machine runs, so it is opt-in.")
            if blocked:
                print(f"--confirm would refuse: it would change {', '.join(blocked)}.\n"
                      f"  To accept that, add: {flags}")
            return 0
        if blocked:
            print(f"\nrefusing: promoting would change {', '.join(blocked)} (above).\n"
                  f"  Every repo on this machine gets its verdicts from these tools, and a\n"
                  f"  new release of one can be broken on this platform. Check it first;\n"
                  f"  to accept it, re-run with: {flags}", file=sys.stderr)
            return 3
        # A drain runs the LIVE tool; swapping packages under it can hand it a
        # half-installed one. (A running gate in another repo is not detected:
        # check for one by hand -- see RELEASING.md.)
        if _drain_lock().exists():
            print(f"\nrefusing: a drain is running ({_drain_lock()} exists).\n"
                  f"  Promotion swaps the packages it is running; wait for it to finish.",
                  file=sys.stderr)
            return 3

        tools_before = _probe_tools()
        conflicts_before = _pip_check()
        # aramid alone, forced (that also repairs an editable install at the
        # same version); then a plain install, which adds only what is missing.
        for argv in (["--force-reinstall", "--no-deps", str(wheel)], [str(wheel)]):
            r = _run([sys.executable, "-P", "-m", "pip", "install", *argv], env=_clean_env())
            if r.returncode != 0:
                print(f"\ninstall failed\n{r.stdout}\n{r.stderr}", file=sys.stderr)
                return 3

    new_version, new_path, new_editable = _live()
    print(f"\nlive now : {new_version}")
    print(f"           {new_path}")

    # Post-verify, all of it. Version alone would pass for an editable
    # install of a checkout that happens to carry the same __version__ --
    # which is exactly the state this script exists to keep out -- and the
    # same predicate the pre-check used decides here, so the two cannot drift.
    if new_version != args.version:
        print(f"\nFAILED: expected {args.version}, got {new_version}", file=sys.stderr)
        return 3
    problem = _not_promoted(new_path, new_editable, repo)
    if problem:
        print(f"\nFAILED: {problem}.\n  Consumers would not be running the released wheel.",
              file=sys.stderr)
        return 3

    # Do the analyzers every consumer's gate runs still RUN? A tool that ran
    # before and does not now was broken by this promotion; one that was
    # already broken is reported, not blamed.
    tools_after = _probe_tools()
    if not tools_after:
        print("\nFAILED: could not check that the analyzers still run (the probe\n"
              "  through the live install failed). Check semgrep, ruff and pip-audit\n"
              "  by hand before telling anyone this promotion is done.", file=sys.stderr)
        return 3
    broken = []
    # Every required tool, not just the ones the answer named: an answer that
    # omits a tool is not evidence it runs (llm-review, 2026-10-02).
    for name in PROBED_TOOLS:
        ok, detail = tools_after.get(name, (None, "not reported by the probe"))
        if ok:
            continue
        before = tools_before.get(name)
        if before is not None and before[0] is not True:
            print(f"WARNING: {name} did not run before promotion either: {detail}")
        else:
            broken.append(f"{name}: {detail}")
    conflicts_after = _pip_check()
    if conflicts_after is None:
        # "Could not check" is not "clean", the same rule as the tool probe.
        broken.append("pip check: could not run after install")
    new_conflicts = sorted((conflicts_after or set()) - (conflicts_before or set()))
    if broken or new_conflicts:
        lines = "\n".join(f"  {line}" for line in [*broken, *new_conflicts])
        print(f"\nFAILED: promotion broke what consumers run:\n{lines}\n"
              f"  Roll back whatever pip changed (see above) before any gate runs.",
              file=sys.stderr)
        return 3

    print(f"\nOK. Consumers now run {args.version}.")
    print("Tell them: their pinned version moved, what changed, and that anything\n"
          "they measured against the old one is a lead rather than a fact.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
