# Security policy

aramid is a security gate. A defect that lets a finding through, leaks what it
scanned, or executes something it should not is a vulnerability in aramid
itself. This document says how to report one, what counts, and which versions
receive fixes.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting,
which is visible only to the maintainers:

https://github.com/jared0565/aramid/security/advisories/new

Include the aramid version (`aramid --version`), the platform, the smallest
reproduction you have, and the impact as you understand it. If the report is
about a secret aramid failed to catch, describe its shape (the pattern, the
file type, the rule you expected to fire) and do not paste a live credential
into the report.

If you cannot use the form, open a public issue titled "security contact
requested" with no details, and a maintainer will reply with a private channel.

What the maintainers commit to:

| Step | Target |
| --- | --- |
| Acknowledge the report | within 7 days |
| Initial assessment (confirmed, not a vulnerability, or need more information) | within 14 days |
| A fixed release on PyPI, or a written reason none is coming | within 90 days of confirmation |

Disclosure is coordinated: we ask reporters to hold details until a fixed
release is on PyPI, and we credit reporters in `CHANGELOG.md` unless they ask
otherwise. A confirmed vulnerability is published as a GitHub security advisory
with a CVE requested through GitHub when the impact warrants one.

## Supported versions

Only the **latest release on PyPI** receives fixes. aramid is pre-1.0 and
releases are frequent; a security fix ships as a new release, never as a
backport to an older one.

| Version | Supported |
| --- | --- |
| The latest release on PyPI | yes |
| Any earlier release | no, upgrade |

`pip install --upgrade aramid` is the remediation for every advisory unless the
advisory says otherwise.

## What is in scope

A report is a vulnerability in aramid when aramid's own guarantee fails:

- **Gate bypass.** `aramid check` exits 0, or a hook lets a commit or push
  through, while a BLOCK-tier finding is present and none of the documented
  suppression paths (`aramid override`, `.aramid-suppressions.toml`, a
  ledger status transition) was used.
- **Silent downgrade from the scanned repository.** Content of the repository
  being gated (configuration, rules files, file names, analyzer output) can
  change a verdict, disable a runner, or alter the ledger in a way that
  `aramid doctor` and `aramid status` do not surface.
- **Code execution.** Command injection or arbitrary code execution through
  `aramid.toml`, repository content, analyzer output, hook templates, or the
  agent surfaces (`agent-hook`, the MCP server).
- **Leakage.** A scanned secret reaching the ledger, `.aramid/logs`, `--json`
  output, the agent-hook context, or a CI log beyond what `redact` promises.
- **Tamper blindness.** A modified git hook, `.claude/settings.json` entry,
  `.mcp.json` entry, or managed instruction block that `aramid doctor` grades
  `ok`.
- **Unaudited mutation.** The MCP server or any agent surface performing a
  suppression or ledger write without the reason and audit trail the CLI
  requires.
- **Supply chain.** A release whose PyPI bytes differ from the GitHub Release
  bytes, or a workflow change that lets an unpinned action run in CI.

## What is out of scope

These are documented behaviour, not defects. Open a regular issue if the
documentation is unclear.

- `git commit --no-verify` or `git push --no-verify` on a repository that has
  not run `aramid arm --agent`. Local hooks are a convenience; the enforcement
  boundary is `aramid check --all --strict` in CI, as the README states. The
  agent-side rejector exists for AI agents, not as a substitute for CI.
- Findings that an upstream analyzer (gitleaks, semgrep, ruff, pip-audit,
  eslint, mypy) misses or misreports. Report those upstream. The rules aramid
  vendors are in scope.
- Judgement calls of the LLM reviewer. It is advisory until armed, its
  verdicts are refutable by design, and a wrong review is a quality issue, not
  a security one.
- Denial of service against your own machine through a pathological
  repository; the gate has budgets and self-kills, and exceeding them degrades
  the run rather than passing it.

## Verifying a release

The same bytes reach PyPI and the GitHub Release, and you can check:

```bash
pip download aramid==X.Y.Z --no-deps --no-binary :none: -d pypi-dist
gh release download vX.Y.Z --dir gh-dist
sha256sum pypi-dist/* gh-dist/*      # the wheel hashes must match; so must the sdists
```

Releases are built once, gated (`twine check`, packaged-data check, wheel and
sdist smoke tests in clean environments, a green CI matrix on the tagged
commit) and published to TestPyPI and then PyPI from that single artifact via
Trusted Publishing (OIDC). There is no long-lived PyPI token to leak. Every
GitHub Action in this repository is pinned to a full commit SHA, and a test
fails if one is not. See `RELEASING.md` for the full list of gates.

## How aramid guards itself

- Every push runs the test suite and aramid's own gate at both tiers, in
  strict mode, on a seven-leg matrix (Windows, Ubuntu, macOS; Python 3.11 to
  3.14).
- Secret scanning and push protection are enabled on the repository.
- Findings against aramid's own code live in its ledger; open ones carry a
  written reason or block the push. `aramid ledger filter --status open`
  shows them.
