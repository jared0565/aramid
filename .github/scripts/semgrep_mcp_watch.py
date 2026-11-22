"""Go red the day a semgrep release lets mcp, opentelemetry-api or wcmatch past its pin.

WHY THIS EXISTS. aramid depends on semgrep, and semgrep pins three packages
that carry advisories: `mcp==1.29.0`, `opentelemetry-api~=1.37.0` and
`wcmatch~=8.3`. Every install of aramid carries all three. aramid imports none
of them (src/aramid/mcp.py is a stdlib-only stdio server, and nothing in
aramid imports opentelemetry or wcmatch), so those ledger rows were overridden
or suppressed as unreachable, with one plan for each (the operator: 2026-10-30
for mcp, 2026-11-16 for opentelemetry-api, 2026-11-21 for wcmatch).
Once a semgrep release admits a fixed version, raise this repo's semgrep floor
to that release, which clears the advisories for every consumer. Until this
script, "has semgrep moved?" was a manual check at the start of each session --
a reminder that lives only in whoever remembers it.

WHAT IT READS. The newest semgrep release on PyPI and the Requires-Dist lines
in EVERY one of its wheels (PEP 658 metadata files). The JSON API's
`requires_dist` comes from a single file, and each wheel carries its own
metadata, so one wheel is not evidence about the others. Then each watched
package's list of final, non-yanked releases, to ask whether the semgrep lines
admit any of them that is clear of the advisories (WATCHED below). A line that
only admits a release candidate does not count: a floor can only move to
something installable. A line gated on an extra (`; extra == "..."`) is not a
dependency of a plain install, so a semgrep whose only line for a package is
one has dropped it as far as aramid is concerned.

SEVERAL LINES CAN HOLD ONE PACKAGE BACK. opentelemetry-sdk and the OTLP
exporter are numbered in lockstep with opentelemetry-api: sdk 1.37.0 requires
`opentelemetry-api==1.37.0`, and the exporter requires `opentelemetry-sdk~=
1.37.0` (read 2026-11-16). semgrep pins all three at `~=1.37.0`, so a release
that moved only its api line would still install api 1.37.x. A fixed version
must be admitted by EVERY semgrep line watched for that package.

WHY A FILE AND NOT AN INLINE STEP. So tests/unit/test_semgrep_mcp_watch.py can
run it against a `--snapshot` of what it would read and pin every outcome
without the network.

EXIT CODES. One line is printed per watched package, and the run exits with
the highest code among them. 0 -- every package still blocked (green, the
normal day). 1 -- act: the newest semgrep admits a fixed version of the package
that line names, or no longer depends on it; raise the floor (and widen
pyproject.toml's semgrep bounds if the release falls outside them). 2 -- could
not tell: PyPI unreachable, no wheels, wheels that disagree, more than one line
for a name in a wheel (environment-split; a human judges those), anything
unparseable. Nothing here exits 0 on "could not tell".

WHEN TO DELETE IT. In the commit that raises the floor past EVERY package in
WATCHED, together with .github/workflows/semgrep-mcp-watch.yml and its test. A commit
that settles one removes that package from WATCHED and its tests. Until then a
red run, and GitHub's failure email, is the reminder.
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
MCP_AFFECTED = ((None, Version("1.30.0")), (Version("2.0.0"), Version("2.2.0")))
# The two advisories against opentelemetry-api 1.37.0 (GHSA-xcq7-p3pf-p88h /
# CVE-2026-114603, fixed in 1.45.1; GHSA-mf5v-w3w3-f6cg / CVE-2026-126360,
# fixed in 1.45.2; OSV, read 2026-11-16): 1.45.1 still carries the second.
OTEL_AFFECTED = ((None, Version("1.45.2")),)
# The advisory against wcmatch (GHSA-53pm-wgxf-c6qf / CVE-2026-132276:
# polynomial-time matching of a name against a multi-star pattern, default
# flags; affected from 0, fixed in 11.2; OSV, read 2026-11-22). semgrep 1.186.0
# requires `wcmatch~=8.3`, which admits nothing past 8.x.
WCMATCH_AFFECTED = ((None, Version("11.2")),)
# package -> (the Requires-Dist names that must ALL admit a fixed version,
#             affected ranges, how the ranges read in a message)
WATCHED = {
    "mcp": (("mcp",), MCP_AFFECTED, "<1.30.0 or >=2.0.0,<2.2.0"),
    "opentelemetry-api": (("opentelemetry-api", "opentelemetry-sdk",
                           "opentelemetry-exporter-otlp-proto-http"),
                          OTEL_AFFECTED, "<1.45.2"),
    "wcmatch": (("wcmatch",), WCMATCH_AFFECTED, "<11.2"),
}
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

    versions: dict[str, list[str]] = {}
    for package in WATCHED:
        data = json.loads(_get(f"{pypi}/pypi/{package}/json", "application/json", attempts))
        versions[package] = [
            release for release, files in data.get("releases", {}).items()
            if files and not all(f.get("yanked") for f in files)]
    return {"semgrep_version": version, "wheels": wheels, "versions": versions}


def semgrep_requirement(pyproject: Path) -> Requirement:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    for line in data.get("project", {}).get("dependencies", []):
        requirement = Requirement(line)
        if canonicalize_name(requirement.name) == "semgrep":
            return requirement
    raise CouldNotTell(f"{pyproject} declares no semgrep dependency")


def _clears(version: Version, affected) -> bool:
    return not any((low is None or version >= low) and version < high
                   for low, high in affected)


def _line(wheel: str, requires: list[str], name: str) -> Requirement | None:
    """The wheel's requirement on `name` for a plain install; None when it has
    none outside an optional extra."""
    found = []
    for line in requires:
        try:
            requirement = Requirement(line)
        except InvalidRequirement as exc:
            raise CouldNotTell(f"{wheel}: unparseable Requires-Dist {line!r}: {exc}") from exc
        if canonicalize_name(requirement.name) != canonicalize_name(name):
            continue
        if requirement.marker is not None and "extra" in str(requirement.marker):
            continue                # only `pip install semgrep[<extra>]` gets this one
        found.append(requirement)
    if len(found) > 1:
        raise CouldNotTell(f"{wheel} has {len(found)} {name} requirements "
                           f"({'; '.join(map(str, found))}): judge them by hand")
    return found[0] if found else None


def _verdict(package: str, snapshot: dict, version: Version, wheels: dict,
             raise_to: str) -> tuple[int, str]:
    """(exit code, message) for one watched package; CouldNotTell when it
    cannot say."""
    names, affected, affected_text = WATCHED[package]
    lines = {wheel: tuple(_line(wheel, requires, name) for name in names)
             for wheel, requires in sorted(wheels.items())}
    if len({tuple(str(r) if r else None for r in found) for found in lines.values()}) > 1:
        detail = "; ".join(
            f"{wheel}: {', '.join(str(r) for r in found if r) or f'no {package}'}"
            for wheel, found in lines.items())
        raise CouldNotTell(f"semgrep {version}'s wheels disagree about {package}: {detail}")
    present = [r for r in next(iter(lines.values())) if r is not None]

    if not present:
        return 1, (f"semgrep {version} no longer depends on {package} (none of its "
                   f"{len(lines)} wheels requires it outside an extra): {raise_to}")

    finals = []
    for release in (snapshot.get("versions") or {}).get(package) or []:
        try:
            parsed = Version(release)
        except InvalidVersion:
            continue
        if not (parsed.is_prerelease or parsed.is_devrelease):
            finals.append(parsed)
    if not finals:
        raise CouldNotTell(f"no final {package} releases listed")

    # Release candidates are dropped once, in `finals` above; `prereleases=True`
    # makes this ask only whether the range admits the version. With
    # `prereleases=False` here as well, either guard alone could break unseen.
    allowed = [v for v in finals if _clears(v, affected)
               and all(r.specifier.contains(v, prereleases=True) for r in present)]
    shown = "`, `".join(map(str, present))
    if allowed:
        return 1, (f"semgrep {version} allows {package} {max(allowed)} (`{shown}`, all "
                   f"{len(lines)} wheels), clear of the advisories: {raise_to}")
    return 0, (f"semgrep {version} still requires `{shown}` (all {len(lines)} wheels): "
               f"every {package} it allows is affected ({affected_text}); newest "
               f"{package} release: {max(finals)}")


def evaluate(snapshot: dict, bounds: Requirement) -> list[tuple[int, str]]:
    """One (exit code, message) per watched package. A package that cannot
    tell does not hide another's verdict; a snapshot that names no release or
    no wheels raises CouldNotTell for all of them."""
    raw = snapshot.get("semgrep_version")
    wheels = snapshot.get("wheels") or {}
    if not raw or not wheels:
        raise CouldNotTell(f"no wheels found for semgrep {raw or '(no version)'}")
    try:
        version = Version(raw)
    except InvalidVersion as exc:
        raise CouldNotTell(f"semgrep version {raw!r} is not a version: {exc}") from exc

    raise_to = f"raise the floor in pyproject.toml to semgrep>={version}"
    if not bounds.specifier.contains(version, prereleases=True):
        raise_to += (f", and widen it: semgrep {version} is outside pyproject.toml's "
                     f"`{bounds}`")
    verdicts = []
    for package in WATCHED:
        try:
            verdicts.append(_verdict(package, snapshot, version, wheels, raise_to))
        except CouldNotTell as exc:
            verdicts.append((2, f"could not tell for {package}: {exc}"))
    return verdicts


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
        verdicts = evaluate(snapshot, bounds)
    except Exception as exc:  # every failure is "could not tell" -- red, never green
        reason = str(exc) if isinstance(exc, CouldNotTell) else f"{type(exc).__name__}: {exc}"
        print(f"::error::{PREFIX} could not tell: {reason}")
        return 2

    for code, message in verdicts:
        print(f"{'::error::' if code else '::notice::'}{PREFIX} {message}")
    return max(code for code, _ in verdicts)


if __name__ == "__main__":
    sys.exit(main())
