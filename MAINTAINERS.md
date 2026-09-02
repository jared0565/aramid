# Maintainers

## Current

| Role | Who |
| --- | --- |
| Maintainer, release manager, PyPI owner | FBMac ([@jared0565](https://github.com/jared0565)) |

aramid currently has **one maintainer**. This file exists so that fact is a
documented risk with a documented remedy rather than something a reader has to
infer from `git shortlog`.

## What a successor needs

Everything required to keep releasing aramid, in the order it is needed. There
are no long-lived secrets anywhere in this list: publishing uses Trusted
Publishing (OIDC), so there is no API token to hand over or rotate.

1. **Admin on the GitHub repository** `jared0565/aramid`. This carries the
   Actions environments, the required reviewer, secret scanning, push
   protection, private vulnerability reporting, and Dependabot.
2. **Owner role on the PyPI project** `aramid`
   (https://pypi.org/project/aramid/). The trusted publisher is configured on
   the PyPI side as: owner `jared0565`, repository `aramid`, workflow
   `release.yml`, environment `pypi`. Change the repository owner and this
   binding must be re-created; `release.yml` documents the exact page.
3. **The same on TestPyPI**, a separate account with a separate pending
   publisher, environment `testpypi`. The release workflow publishes there
   first as a rehearsal and will not reach PyPI if it fails.
4. **Membership of the `pypi` environment's required reviewers.** The
   irreversible publish job halts until a reviewer approves it. If the only
   reviewer is unreachable, no release can complete; a second maintainer
   should be added here on day one.
5. **Read access to the release evidence.** `RELEASING.md` is the procedure;
   `CHANGELOG.md` is the record; `docs/superpowers/specs/` and
   `docs/superpowers/plans/` hold the design decisions that are not derivable
   from the code.

## Adding a second maintainer

In this order, so the new maintainer can complete a release unassisted:

1. GitHub: add as a collaborator with **Admin**.
2. PyPI and TestPyPI: add as a collaborator with the **Owner** role on
   `aramid`.
3. GitHub: add to the required reviewers of the `pypi` environment
   (Settings, Environments, `pypi`).
4. Have them cut the next patch release end to end, following `RELEASING.md`,
   while the existing maintainer only watches.

Once there are two maintainers, enable a branch ruleset on `main` that
requires the seven `ci (...)` status checks and a pull request; with one
maintainer that ruleset would only block the person who has to fix CI.

## Communication

Security reports: `SECURITY.md` (private vulnerability reporting). Everything
else: GitHub issues on this repository.
