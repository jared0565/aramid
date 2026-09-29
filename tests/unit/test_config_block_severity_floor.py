"""A repo's own aramid.toml cannot loosen the dependency BLOCK threshold the
layers beneath it set (FN-20).

The block_rules floor restored every LIST entry a repo's aramid.toml dropped
and skipped every other value -- and `[deps].block_severity` is the one
scalar in block_rules.toml. The packaged `critical` is the top of the order,
so a repo could not weaken the shipped threshold; but an operator who
tightened it in ~/.aramid/config.toml (to `high`, say) was undone by a repo
committing `critical`, and high-severity CVEs stopped blocking that repo's
pushes. The floor's own docstring names the repo layer as the adversary.

The comparison is on the MAPPED severity, not the string: `policy` maps an
unknown value to MEDIUM, so a repo writing nonsense over an operator's `low`
loosens it exactly as a real word would.
"""
import pytest

from aramid import config


def _deps(tmp_path, monkeypatch, *, operator: str | None, repo: str | None) -> dict:
    """The merged `block_rules.deps` under an operator layer and a repo layer,
    each given as raw TOML (None: the layer is absent)."""
    user = tmp_path / "home" / "config.toml"
    user.parent.mkdir()
    if operator is not None:
        user.write_text(operator, encoding="utf-8")
    monkeypatch.setattr(config, "_user_config_path", lambda: user)
    root = tmp_path / "repo"
    root.mkdir()
    if repo is not None:
        (root / "aramid.toml").write_text(repo, encoding="utf-8")
    return config.load_config(root).block_rules["deps"]


def _table(severity: str | None) -> str | None:
    return None if severity is None else f'[block_rules.deps]\nblock_severity = "{severity}"\n'


def _load(tmp_path, monkeypatch, *, operator: str | None, repo: str | None):
    return _deps(tmp_path, monkeypatch, operator=_table(operator),
                 repo=_table(repo))["block_severity"]


@pytest.mark.parametrize("operator, repo", [
    ("high", "critical"),      # the repo raises it back to the packaged value
    ("low", "high"),
    ("low", "nonsense"),       # maps to MEDIUM: looser than LOW
    ("medium", "CRITICAL"),    # case is not a way round it
])
def test_a_repo_cannot_raise_the_threshold_the_operator_set(tmp_path, monkeypatch, capsys,
                                                             operator, repo):
    assert _load(tmp_path, monkeypatch, operator=operator, repo=repo) == operator
    err = capsys.readouterr().err
    assert (f"aramid: config: aramid.toml raised block_rules.deps.block_severity from "
            f"{operator!r} to {repo!r} -- kept {operator!r}") in err


@pytest.mark.parametrize("operator, repo", [
    (None, "high"),            # stricter than the packaged critical
    ("high", "high"),          # the same
    ("high", "low"),           # stricter than the operator's
])
def test_a_repo_may_lower_it_or_leave_it(tmp_path, monkeypatch, capsys, operator, repo):
    assert _load(tmp_path, monkeypatch, operator=operator, repo=repo) == repo
    assert "block_severity" not in capsys.readouterr().err


def test_the_packaged_threshold_holds_against_a_repo_that_sets_nonsense(tmp_path, monkeypatch,
                                                                        capsys):
    """`critical` is the top: nonsense maps to MEDIUM, which is STRICTER, so it
    stands -- the floor only ever refuses a loosening."""
    assert _load(tmp_path, monkeypatch, operator=None, repo="nonsense") == "nonsense"
    assert "block_severity" not in capsys.readouterr().err


def test_the_operator_layer_itself_is_not_floored(tmp_path, monkeypatch, capsys):
    """Only the repo layer is the adversary: the operator may loosen their
    own machine's threshold (to the packaged value, or past it)."""
    assert _load(tmp_path, monkeypatch, operator="critical", repo=None) == "critical"
    assert "block_severity" not in capsys.readouterr().err


@pytest.mark.parametrize("operator", ["high", None])
def test_a_repo_that_replaces_the_deps_table_keeps_the_threshold(tmp_path, monkeypatch, capsys,
                                                                 operator):
    """`[block_rules] deps = 0` puts a scalar where the table was: the list
    floor fills in an empty table, the key is gone, and policy reads its
    `critical` fallback -- the loosest. The first FN-20 fix compared only a
    key present in BOTH layers; the mutation sweep of it found this. Held
    whatever the floor is, the packaged `critical` included."""
    kept = operator or "critical"
    deps = _deps(tmp_path, monkeypatch, operator=_table(operator), repo="[block_rules]\ndeps = 0\n")
    assert deps["block_severity"] == kept
    assert (f"aramid: config: aramid.toml replaced block_rules.deps, dropping block_severity "
            f"-- kept {kept!r}") in capsys.readouterr().err


def test_an_operator_deps_that_is_not_a_table_has_nothing_to_floor(tmp_path, monkeypatch, capsys):
    """The floor holds the repo to what the layers beneath SET. An operator
    who wrote `deps = 0` set no threshold, so the repo's table stands (and
    `critical` is the top: nothing looser exists to refuse)."""
    deps = _deps(tmp_path, monkeypatch, operator="[block_rules]\ndeps = 0\n",
                 repo=_table("critical"))
    assert deps == {"block_severity": "critical"}
    assert "block_severity" not in capsys.readouterr().err
