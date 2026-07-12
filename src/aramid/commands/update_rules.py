"""update_rules -- refresh the vendored, offline semgrep ruleset that
`aramid.runners.semgrep.VENDORED_RULES_PATH` points at.

STUB, network-fetch not performed (brief Task 7.4 explicitly permits this
when no network is available in this environment -- `aramid.commands
.doctor._fix_gitleaks` establishes the same precedent for a network-
touching repair path that is documented but never exercised by the test
suite). This command documents the pinned source and target path and
reports whether a ruleset is currently installed, so an operator (or a
later, network-enabled implementation of this same command) knows exactly
what to fetch and where it goes. `aramid.runners.semgrep` already tolerates
an absent ruleset file at scan time -- semgrep itself reports a
"config not found" fatal error, which `aramid.runners.semgrep.run` turns
into CRASHED (never a silent clean pass; see that module's own tests). See
also that module's docstring: "The actual rule YAML is populated by a
later task."

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
    print("aramid: update-rules: STUB -- no network fetch performed in this environment.")
    print(f"aramid: update-rules: pinned source: {PINNED_SOURCE}")
    print(f"aramid: update-rules: target path:   {VENDORED_RULES_PATH}")
    if VENDORED_RULES_PATH.exists():
        print("aramid: update-rules: a vendored ruleset is currently installed.")
    else:
        print("aramid: update-rules: WARNING -- no vendored ruleset is installed yet; "
              "semgrep scans will crash/degrade (never silently pass) until this is "
              "populated.", file=sys.stderr)
    return 0
