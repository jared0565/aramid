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
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

WHEEL_ASSET = "aramid-{version}-py3-none-any.whl"


def _run(argv: list[str], **kw) -> subprocess.CompletedProcess:
    # noqa convention matches runners/base.py: every argv here is built from
    # literals plus a version string the operator typed, and is passed as a
    # LIST with no shell, so there is nothing for an injection to reach.
    return subprocess.run(argv, capture_output=True, text=True, **kw)  # noqa: S603


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

        # The dry run stops HERE rather than before the download, deliberately.
        # Everything above is the part that can be wrong in a way that matters
        # -- resolving the release, finding the asset, comparing the digest --
        # and a rehearsal that skips it only rehearses argument parsing.
        if not args.confirm:
            print("\n--confirm not given; verified but NOT installed.\n"
                  "This changes what EVERY repo on this machine runs, so it is opt-in.")
            return 0

        r = _run([sys.executable, "-m", "pip", "install", "--force-reinstall", str(wheel)],
                 env=_clean_env())
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

    print(f"\nOK. Consumers now run {args.version}.")
    print("Tell them: their pinned version moved, what changed, and that anything\n"
          "they measured against the old one is a lead rather than a fact.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
