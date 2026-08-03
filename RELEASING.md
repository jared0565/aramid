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

## Undoing a release

```bash
gh release delete v0.1.0 --yes --cleanup-tag
git push --delete origin v0.1.0   # if --cleanup-tag did not remove it
git tag -d v0.1.0
```

Deleting is safe here precisely because the artifacts are GitHub Releases. If
aramid is ever published to PyPI this stops being true — a PyPI version can be
yanked but never re-uploaded, which is why that step is a separate decision.

[GitHub Release]: https://github.com/jared0565/aramid/releases
