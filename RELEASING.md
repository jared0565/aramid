# Releasing aramid

aramid is published as a wheel attached to a [GitHub Release]. There is no PyPI
package, so `pip install aramid` does not work; consumers install the release
artifact or a git ref (see the README's Install section).

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
   git tag v0.1.0          # must be exactly "v" + __version__
   git push origin v0.1.0
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
$ git push origin v0.1.0
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
| Tag matches `__version__` | Publishing `aramid-0.1.0.whl` under a tag called `v0.2.0` |
| Packaged data files present | A wheel missing the vendored OWASP ruleset, which makes semgrep crash on every pre-push in every consumer repo |
| Clean-venv smoke test | A wheel that installs but does not work: it installs into a fresh virtualenv, leaves the source tree so an accidental import of it fails, runs the console script, and asserts the ruleset resolves from inside `site-packages` |
| `twine check` | A package page that renders wrong — or, as was true until 0.1.0, one with **no description at all** |
| Clean-venv **sdist** smoke test | An sdist that publishes fine and fails on install. The wheel and the sdist are built by different code paths, and any consumer whose platform or policy forces a source build gets this artifact |

## Undoing a release

```bash
gh release delete v0.1.0 --yes --cleanup-tag
git push --delete origin v0.1.0   # if --cleanup-tag did not remove it
git tag -d v0.1.0
```

Deleting is safe for the **GitHub Release** half. It is not safe once
`publish-pypi` has run: a PyPI version can be yanked but never re-uploaded, and
the first upload claims the public name permanently. That is why publishing is
a separate job, gated on its own environment.

## Publishing to PyPI

`publish-pypi` runs after every gate above passes, using **Trusted Publishing**
(OIDC) — there is no API token and no repository secret to leak or rotate.

### One-time setup — two of them, on the maintainer's accounts

These cannot be done from this repository; they are account-level settings.
Configuring one does **not** configure the other.

1. **pypi.org** → *Your projects* → *Publishing* → add a **pending publisher**

   | field | value |
   | --- | --- |
   | PyPI project name | `aramid` |
   | Owner | `jared0565` |
   | Repository | `aramid` |
   | Workflow name | `release.yml` |
   | Environment | `pypi` |

   "Pending" is the right kind: it authorises a project that does not exist
   yet, which is the case until the first upload.

2. **test.pypi.org** — the same form, on a **separate account**. This one is
   **not optional**: `publish-pypi` declares `needs: [release,
   publish-testpypi]`, so without it every release stops before PyPI.

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

Optionally add a required reviewer to the `pypi` GitHub environment; the job is
already gated on it, so no workflow change is needed.

### Which version publishes first

`v0.1.0` is already tagged and has a GitHub Release, so re-pushing that tag
will not re-run the workflow and `gh release create` would fail on the existing
release. PyPI itself is empty (`aramid` is unclaimed), so `0.1.0` is *available*
there — but the clean path is to cut the next version rather than delete and
recreate a published GitHub Release.

Bumping `__version__` and cutting the tag is a "is this ready to ship?"
judgement and is deliberately not automated.

[GitHub Release]: https://github.com/jared0565/aramid/releases
