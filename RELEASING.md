# Releasing aramid

aramid is published to [PyPI](https://pypi.org/project/aramid/) — `pip install
aramid` — and the same wheel and sdist are attached to a [GitHub Release].

**The same bytes reach both, and that is now a measured property rather than an
intention.** `publish-pypi` downloads the `gated-dist` artifact the integrity
gates inspected instead of rebuilding from the tag; after 0.2.0 the sha256 of
each file was identical on pypi.org, test.pypi.org and the GitHub Release. The
job used to `checkout` + `build` again, which meant the four gates below vouched
for bytes nobody published — and the two public channels could carry different
code under one version. Do not reintroduce a build step in a publish job.

## The single source of truth

`src/aramid/__init__.py`'s `__version__`. `pyproject.toml` declares
`dynamic = ["version"]` and reads that attribute, so there is nothing else to
keep in step. The release workflow refuses to publish a tag that disagrees
with it.

Versions are **PEP 440**, not semver — that is what Python packaging uses.
`0.1.0-rc1` and `0.1.0rc1` are the same version, and setuptools writes the
normalised form into the wheel. Either spelling is fine in `__version__`.

## Steps

1. **Bump `__version__`** in `src/aramid/__init__.py`.

2. **Re-run `pip install -e .`** — do not skip this, see below.

3. **Update `CHANGELOG.md`**: move the `Unreleased` items under a new version
   heading with today's date, and refresh the link definitions at the bottom.

4. **Commit and push to `main`. Wait for CI to be green.** The tag should point
   at a commit CI has already vetted, not one that is about to be.

5. **Tag and push the tag:**

   ```bash
   git tag -a vX.Y.Z       # must be exactly "v" + __version__
   git push origin vX.Y.Z
   ```

6. The `release` workflow takes it from there.

## Why step 2 is not optional

An editable install records its metadata **at install time**. Bump
`__version__` without reinstalling and the installed metadata still reports the
old version, so `tests/unit/test_version.py::test_installed_metadata_matches_
dunder_version` fails — by design, because that mismatch is real in your
environment.

That test then blocks the push, and the symptom is unhelpful:

```
$ git push origin vX.Y.Z
(+6 baseline findings)
44 findings open in ledger
error: failed to push some refs to '...'
```

`tests` is a BLOCK-tier runner, so a failing suite fails the pre-push gate,
and the gate's human-readable output does not name what blocked. If you see
that, run `python -m aramid check --gate pre-push --json` and look for a
finding whose tool is your test command's `argv[0]` (`python`, for this repo's
configured `[tests].command`). Found during the first end-to-end rehearsal of
this process, which is exactly what rehearsals are for.

## What the release workflow guarantees

Every check runs **before** the release is created, because a published
artifact cannot be recalled, only superseded:

| Gate | Catches |
| --- | --- |
| Tag matches `__version__` | Publishing `aramid-0.2.0.whl` under a tag called `v0.3.0` |
| Packaged data files present | A wheel missing the vendored OWASP ruleset, which makes semgrep crash on every pre-push in every consumer repo |
| Clean-venv smoke test | A wheel that installs but does not work: it installs into a fresh virtualenv, leaves the source tree so an accidental import of it fails, runs the console script, and asserts the ruleset resolves from inside `site-packages` |
| `twine check` | A package page that renders wrong — or, as was true right up until the 0.2.0 metadata work, one with **no description at all** |
| Clean-venv **sdist** smoke test | An sdist that publishes fine and fails on install. The wheel and the sdist are built by different code paths, and any consumer whose platform or policy forces a source build gets this artifact |

## Undoing a release

```bash
gh release delete vX.Y.Z --yes --cleanup-tag
git push --delete origin vX.Y.Z   # if --cleanup-tag did not remove it
git tag -d vX.Y.Z
```

Deleting is safe for the **GitHub Release** half, and it stays safe for as long
as the run sits paused at `publish-pypi` — which, with the required reviewer, is
until someone approves it. It is not safe afterwards: a PyPI version can be
yanked but never re-uploaded, and the first upload claims the public name
permanently. That is why publishing is a separate job, gated on its own
environment.

A publisher misconfiguration fails at `publish-testpypi` instead, which is the
cheap failure: nothing is published, the name stays unclaimed, and
`skip-existing: true` on that job means a retry after fixing it runs clean.

## Publishing to PyPI

`publish-pypi` runs after every gate above passes, using **Trusted Publishing**
(OIDC) — there is no API token and no repository secret to leak or rotate.

### One-time setup — two of them, on the maintainer's accounts

These cannot be done from this repository; they are account-level settings.
Configuring one does **not** configure the other.

1. **pypi.org** → <https://pypi.org/manage/account/publishing/> → *Add a new
   pending publisher* (GitHub tab)

   This is the **account-level** publishing page. *Your projects → Publishing*
   is the path for a project that already exists, and there is nothing there to
   attach to before the first upload.

   | field | value |
   | --- | --- |
   | PyPI project name | `aramid` |
   | Owner | `jared0565` |
   | Repository | `aramid` |
   | Workflow name | `release.yml` |
   | Environment | `pypi` |

   "Pending" is the right kind: it authorises a project that does not exist
   yet, which is the case until the first upload.

2. **test.pypi.org** — <https://test.pypi.org/manage/account/publishing/>, the
   same form on a **separate account with a separate login**. This one is **not
   optional**: `publish-pypi` declares `needs: [release, publish-testpypi]`, so
   without it every release stops before PyPI.

   | field | value |
   | --- | --- |
   | PyPI project name | `aramid` |
   | Owner | `jared0565` |
   | Repository | `aramid` |
   | Workflow name | `release.yml` |
   | Environment | `testpypi` |

   It was optional until 0.2.0, and offered a rehearsal no job performed. It is
   now a gate, because the publish path cannot safely run for the first time
   against a destination that claims the name permanently and forbids
   re-uploading any version. The rehearsal exercises the three things nothing
   else can: the `gated-dist` upload/download round-trip, the OIDC exchange,
   and the rendered package page — go and look at
   <https://test.pypi.org/project/aramid/> before the real name is claimed.

   Note the environments differ (`testpypi` vs `pypi`); a publisher registered
   against the wrong one silently fails to authorise.

**The field that actually goes wrong is `Environment name`.** PyPI labels it
*(optional)* and renders `pypi` as greyed placeholder text, so it reads as
already filled in. It is not — type it. Both publish jobs declare an
`environment:`, and PyPI checks that claim on every upload, so a blank here
produces an authorization failure at publish time with nothing pointing at the
cause. Second-most-likely: **Workflow name** wants the filename `release.yml`,
not the workflow's display name (`release`).

### The `pypi` environment has a required reviewer

Configured 2026-08-09, reviewer `jared0565`. This is live behaviour, not a
suggestion: after the tag, `release` and `publish-testpypi` run unattended, then
the run **halts** at `publish-pypi` until it is approved in the Actions UI
(*Review deployments* → tick `pypi` → *Approve and deploy*). That pause is the
point — it is when you go and look at the TestPyPI page.

Two things learned configuring it:

- The GitHub environments (`pypi`, `testpypi`) must **exist** before a reviewer
  can be attached. A workflow referencing one creates it implicitly at run time,
  which is too late.
- The API happily accepts a `required_reviewers` rule with an **empty** reviewer
  list, and it reads back as `protection_rules=1` — a gate that looks configured
  and enforces nothing. Verify the reviewer *list*, not the rule count.

To remove it: `gh api -X DELETE
repos/jared0565/aramid/environments/pypi/deployment_protection_rules/62182509`

### What actually shipped first

**0.2.0**, on 2026-08-09 — the first version on PyPI. `0.1.0` exists as a
GitHub Release only, describing a much older tree; reusing that number would
have made the Release notes and the PyPI artifact describe different code.

The whole path ran end to end and was verified against the live indexes rather
than the workflow's own report: wheel `284,898 B` and sdist `252,736 B`, with
matching sha256 on pypi.org, test.pypi.org and the GitHub Release, and a
clean-venv `pip install aramid` importing `0.2.0` from `site-packages`.

Bumping `__version__` and cutting the tag is a "is this ready to ship?"
judgement and is deliberately not automated.

[GitHub Release]: https://github.com/jared0565/aramid/releases
