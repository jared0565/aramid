"""Go red the day a semgrep release lets mcp past 1.29.0.

WHY THIS EXISTS. aramid depends on semgrep, and semgrep pins `mcp==1.29.0`, so
every install of aramid carries mcp 1.29.0 and the advisories against it. aramid
never imports mcp (src/aramid/mcp.py is a stdlib-only stdio server), so those
ledger rows were overridden as unreachable, with a plan (the operator,
2026-10-30): once a semgrep release admits mcp 1.30 or later, raise this repo's
semgrep floor to that release, which clears the advisories for every consumer.
Until this script, "has semgrep moved?" was a manual check at the start of each
session -- a reminder that lives only in whoever remembers it.

WHAT IT READS. The newest semgrep release on PyPI and the Requires-Dist lines
in EVERY one of its wheels (PEP 658 metadata files). The JSON API's
`requires_dist` comes from a single file, and each wheel carries its own
metadata, so one wheel is not evidence about the others. Then mcp's list of
final, non-yanked releases, to ask whether the semgrep line admits any of them
that is clear of the advisories (AFFECTED below). A line that only admits a
release candidate does not count: a floor can only move to something
installable. An mcp line gated on an extra (`; extra == "..."`) is not a
dependency of a plain install, so a semgrep whose only mcp line is one has
dropped mcp as far as aramid is concerned.

WHY A FILE AND NOT AN INLINE STEP. So tests/unit/test_semgrep_mcp_watch.py can
run it against a `--snapshot` of what it would read and pin every outcome
without the network.

EXIT CODES. 0 -- still blocked (green, the normal day). 1 -- act: the newest
semgrep admits a fixed mcp, or no longer depends on mcp at all; raise the floor
(and widen pyproject.toml's semgrep bounds if the release falls outside them).
2 -- could not tell: PyPI unreachable, no wheels, wheels that disagree, more
than one mcp line in a wheel (environment-split; a human judges those),
anything unparseable. Nothing here exits 0 on "could not tell".

WHEN TO DELETE IT. In the commit that raises the floor, together with
.github/workflows/semgrep-mcp-watch.yml and its test. Until then a red run,
and GitHub's failure email, is the reminder.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from email.parser import HeaderParser
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

PREFIX = "semgrep-mcp-watch:"
# The four advisories against mcp 1.29.0 (GHSA-5h93-6whr-6q8j, -84m7-p3x7-pcfv,
# -rwrf-2pqf-9j8j, -w4fh-qvv9-3v23; OSV, read 2026-11-01): each is fixed in
# 1.30.0 on the 1.x line and in 2.2.0 on the 2.x line, and 2.0.0 and 2.1.0 carry
# all four again. A version clears them only outside both ranges, so a semgrep
# that admits nothing but mcp 2.0-2.1 is still blocked.
AFFECTED = ((None, Version("1.30.0")), (Version("2.0.0"), Version("2.2.0")))
AFFECTED_TEXT = "<1.30.0 or >=2.0.0,<2.2.0"
ROOT = Path(__file__).resolve().parents[2]
PYPI = "https://pypi.org"
SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"


class CouldNotTell(Exception):
    """A reason the verdict is unknown. Always exit 2, never 0."""


def _get(url: str, accept: str, attempts: int) -> bytes:
    scheme = urllib.parse.urlsplit(url).scheme
    if scheme not in ("https", "http"):
        raise CouldNotTell(f"refusing to read {url}: scheme {scheme!r} is not http(s)")
    last: Exception | None = None
    for attempt in range(max(attempts, 1)):
        if attempt:
            time.sleep(5 * attempt)
        # S310 justification (both lines): the scheme check above means `file:`
        # and custom schemes never reach urlopen. The URLs come from --pypi
        # (https://pypi.org unless a test points it elsewhere) and from the
        # `url` of PyPI's own index entries, so neither is a literal.
        request = urllib.request.Request(  # noqa: S310
            url, headers={"Accept": accept, "User-Agent": "aramid-semgrep-mcp-watch"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                return response.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
    raise CouldNotTell(f"could not read {url}: {last}")


def fetch_snapshot(pypi: str, attempts: int) -> dict:
    """What PyPI says today, in the shape `--snapshot` takes."""
    info = json.loads(_get(f"{pypi}/pypi/semgrep/json", "application/json", attempts))
    version = info["info"]["version"]

    simple = json.loads(_get(f"{pypi}/simple/semgrep/", SIMPLE_JSON, attempts))
    wheels: dict[str, list[str]] = {}
    for entry in simple.get("files", []):
        name = entry.get("filename", "")
        if not (name.startswith(f"semgrep-{version}-") and name.endswith(".whl")):
            continue
        if entry.get("yanked"):
            continue
        if not (entry.get("core-metadata") or entry.get("data-dist-info-metadata")):
            raise CouldNotTell(f"{name} publishes no separate metadata file")
        metadata = _get(entry["url"] + ".metadata", "*/*", attempts).decode("utf-8")
        wheels[name] = HeaderParser().parsestr(metadata).get_all("Requires-Dist") or []

    mcp = json.loads(_get(f"{pypi}/pypi/mcp/json", "application/json", attempts))
    mcp_versions = [
        release for release, files in mcp.get("releases", {}).items()
        if files and not all(f.get("yanked") for f in files)]
    return {"semgrep_version": version, "wheels": wheels, "mcp_versions": mcp_versions}


def semgrep_requirement(pyproject: Path) -> Requirement:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    for line in data.get("project", {}).get("dependencies", []):
        requirement = Requirement(line)
        if canonicalize_name(requirement.name) == "semgrep":
            return requirement
    raise CouldNotTell(f"{pyproject} declares no semgrep dependency")


def _clears_advisories(version: Version) -> bool:
    return not any((low is None or version >= low) and version < high
                   for low, high in AFFECTED)


def _mcp_line(wheel: str, requires: list[str]) -> Requirement | None:
    """The wheel's mcp requirement for a plain install; None when it has none
    outside an optional extra."""
    found = []
    for line in requires:
        try:
            requirement = Requirement(line)
        except InvalidRequirement as exc:
            raise CouldNotTell(f"{wheel}: unparseable Requires-Dist {line!r}: {exc}") from exc
        if canonicalize_name(requirement.name) != "mcp":
            continue
        if requirement.marker is not None and "extra" in str(requirement.marker):
            continue                # only `pip install semgrep[<extra>]` gets this one
        found.append(requirement)
    if len(found) > 1:
        raise CouldNotTell(f"{wheel} has {len(found)} mcp requirements "
                           f"({'; '.join(map(str, found))}): judge them by hand")
    return found[0] if found else None


def evaluate(snapshot: dict, bounds: Requirement) -> tuple[int, str]:
    """(exit code, message) for a snapshot; CouldNotTell when it cannot say."""
    raw = snapshot.get("semgrep_version")
    wheels = snapshot.get("wheels") or {}
    if not raw or not wheels:
        raise CouldNotTell(f"no wheels found for semgrep {raw or '(no version)'}")
    try:
        version = Version(raw)
    except InvalidVersion as exc:
        raise CouldNotTell(f"semgrep version {raw!r} is not a version: {exc}") from exc

    lines = {wheel: _mcp_line(wheel, requires) for wheel, requires in sorted(wheels.items())}
    if len({str(r) if r else None for r in lines.values()}) > 1:
        detail = "; ".join(f"{wheel}: {r or 'no mcp'}" for wheel, r in lines.items())
        raise CouldNotTell(f"semgrep {version}'s wheels disagree about mcp: {detail}")
    mcp = next(iter(lines.values()))

    raise_to = f"raise the floor in pyproject.toml to semgrep>={version}"
    if not bounds.specifier.contains(version, prereleases=True):
        raise_to += (f", and widen it: semgrep {version} is outside pyproject.toml's "
                     f"`{bounds}`")
    if mcp is None:
        return 1, (f"semgrep {version} no longer depends on mcp (none of its "
                   f"{len(lines)} wheels requires it outside an extra): {raise_to}")

    finals = []
    for release in snapshot.get("mcp_versions") or []:
        try:
            parsed = Version(release)
        except InvalidVersion:
            continue
        if not (parsed.is_prerelease or parsed.is_devrelease):
            finals.append(parsed)
    if not finals:
        raise CouldNotTell("no final mcp releases listed")

    # Release candidates are dropped once, in `finals` above; `prereleases=True`
    # makes this ask only whether the range admits the version. With
    # `prereleases=False` here as well, either guard alone could break unseen.
    allowed = [v for v in finals
               if _clears_advisories(v) and mcp.specifier.contains(v, prereleases=True)]
    if allowed:
        return 1, (f"semgrep {version} allows mcp {max(allowed)} (`{mcp}`, all "
                   f"{len(lines)} wheels), clear of the advisories: {raise_to}")
    return 0, (f"semgrep {version} still requires `{mcp}` (all {len(lines)} wheels): "
               f"every mcp it allows is affected ({AFFECTED_TEXT}); newest mcp "
               f"release: {max(finals)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--snapshot", type=Path,
                        help="read this JSON instead of PyPI (tests)")
    parser.add_argument("--pyproject", type=Path, default=ROOT / "pyproject.toml")
    parser.add_argument("--pypi", default=PYPI, help="index base URL")
    parser.add_argument("--attempts", type=int, default=3,
                        help="tries per PyPI read before giving up")
    args = parser.parse_args(argv)

    try:
        bounds = semgrep_requirement(args.pyproject)
        if args.snapshot:
            snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
        else:
            snapshot = fetch_snapshot(args.pypi.rstrip("/"), args.attempts)
        code, message = evaluate(snapshot, bounds)
    except Exception as exc:  # every failure is "could not tell" -- red, never green
        reason = str(exc) if isinstance(exc, CouldNotTell) else f"{type(exc).__name__}: {exc}"
        print(f"::error::{PREFIX} could not tell: {reason}")
        return 2

    print(f"{'::error::' if code else '::notice::'}{PREFIX} {message}")
    return code


if __name__ == "__main__":
    sys.exit(main())
