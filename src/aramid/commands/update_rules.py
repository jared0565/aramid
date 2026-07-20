"""update_rules -- refresh the vendored, offline semgrep ruleset that
`aramid.runners.semgrep.VENDORED_RULES_PATH` points at.

OFFLINE BY DESIGN -- this command performs no network fetch. The OWASP
ruleset is vendored into the package at build time; refreshing it is a
re-vendor + rebuild step (pull a pinned semgrep-rules ref into the package
tree, rebuild the wheel), NOT a runtime fetch. There is no live fetch to
implement: semgrep's `p/owasp-top-ten` is a registry pack resolved at scan
time, not a tag-addressable artifact this command could pin and download
reproducibly offline. The command stays informational: it reports the pinned
source and target path and whether a ruleset is currently installed, so an
operator knows exactly what to re-vendor and where it goes.
`aramid.runners.semgrep` already tolerates an absent ruleset file at scan
time -- semgrep itself reports a "config not found" fatal error, which
`aramid.runners.semgrep.run` turns into CRASHED (never a silent clean pass;
see that module's own tests).

DEVIATION from Task 7.4's brief text ("into `data/rules/semgrep/`"): the
real, already-implemented `semgrep.VENDORED_RULES_PATH` constant points at
`<aramid package>/rules/owasp.yml`, not `data/rules/semgrep/` -- the brief
text is stale relative to the actual runner. This module targets the path
constant the runner ACTUALLY reads (imported directly, not a second,
independently hardcoded path that could drift from it).

Pinned source (to be fetched by a future, network-enabled implementation):
the semgrep registry's OWASP Top Ten pack (`p/owasp-top-ten`,
https://semgrep.dev/p/owasp-top-ten), curated down to the injection/
deserialization/crypto/command-injection rule classes already referenced by
`aramid.data.block_rules.toml`'s `[semgrep] block` fnmatch patterns. A real
fetch should pin a specific pack release tag (never `latest`) so
`--config <vendored path>` scans stay byte-for-byte reproducible offline.
"""
import sys

from aramid.runners.semgrep import VENDORED_RULES_PATH

PINNED_SOURCE = "https://semgrep.dev/p/owasp-top-ten (pin a specific release tag, not 'latest')"


def cmd_update_rules(root=None) -> int:
    print("aramid: update-rules: the OWASP ruleset is vendored at build time "
          "(offline by design). To refresh, re-vendor from a pinned "
          "semgrep-rules ref and rebuild the package.")
    print(f"aramid: update-rules: pinned source: {PINNED_SOURCE}")
    print(f"aramid: update-rules: target path:   {VENDORED_RULES_PATH}")
    if VENDORED_RULES_PATH.exists():
        print("aramid: update-rules: a vendored ruleset is currently installed.")
    else:
        print("aramid: update-rules: WARNING -- no vendored ruleset is installed yet; "
              "semgrep scans will crash/degrade (never silently pass) until this is "
              "populated.", file=sys.stderr)
    return 0
