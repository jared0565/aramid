
from aramid import leftovers, registry
from aramid.fingerprint import normalize_path


def _seam(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "repos.toml")


def test_register_load_roundtrip(tmp_path, monkeypatch):
    _seam(tmp_path, monkeypatch)
    registry.register(tmp_path / "repoA", "2026-07-13T00:00:00+00:00")
    got = registry.load_registry()
    assert len(got) == 1
    assert normalize_path(got[0]["path"]) == normalize_path(str((tmp_path / "repoA").resolve()))
    assert got[0]["registered_at"] == "2026-07-13T00:00:00+00:00"


def test_load_keeps_only_entries_that_are_tables_with_a_path(tmp_path, monkeypatch):
    _seam(tmp_path, monkeypatch)
    (tmp_path / "repos.toml").write_text(
        'repos = [{path = "C:/a"}, {registered_at = "t"}, {path = ""}, "C:/b"]\n',
        encoding="utf-8")
    assert registry.load_registry() == [{"path": "C:/a"}]


def test_register_is_idempotent(tmp_path, monkeypatch):
    _seam(tmp_path, monkeypatch)
    registry.register(tmp_path / "repoA", "2026-07-13T00:00:00+00:00")
    registry.register(tmp_path / "repoA", "2026-07-14T00:00:00+00:00")
    assert len(registry.load_registry()) == 1


def test_deregister_removes_only_target(tmp_path, monkeypatch):
    _seam(tmp_path, monkeypatch)
    registry.register(tmp_path / "a", "t")
    registry.register(tmp_path / "b", "t")
    registry.deregister(tmp_path / "a")
    got = registry.load_registry()
    assert len(got) == 1 and got[0]["path"].endswith("b")


def test_load_missing_and_corrupt_files(tmp_path, monkeypatch):
    _seam(tmp_path, monkeypatch)
    assert registry.load_registry() == []
    (tmp_path / "repos.toml").write_text("not [ valid toml", encoding="utf-8")
    assert registry.load_registry() == []


# --- a consumer's checkout is never a fleet member ---------------------------

def test_register_refuses_a_checkout_inside_a_consumer_shell(tmp_path, monkeypatch):
    """A consumer's worktree lives at `<temp>/aramid-<kind>-<random>/wt`
    (`leftovers.PREFIXES`). On 2026-09-18 two `aramid-fuzz-*/wt` paths were
    registered by an `aramid init` the consumed repo's own tooling ran in
    there; the drain waited on them (`no rows: wt, wt`) with no row ever
    coming. The location alone is the tell: nothing aramid checks out under
    its own prefix is a repo the fleet should wait on."""
    _seam(tmp_path, monkeypatch)
    wt = leftovers.temp_root() / "aramid-fuzz-3cvlqu0b" / "wt"   # conftest isolates temp_root
    wt.mkdir(parents=True)

    refused = registry.register(wt, "t")

    assert refused == "inside a consumer worktree (aramid-fuzz-3cvlqu0b)"
    assert registry.load_registry() == []


def test_register_refuses_under_the_consumer_marker_wherever_the_path_is(tmp_path, monkeypatch):
    """The other tell: every consumer subprocess carries the marker
    (`worktree_import_env`), so an `aramid init` run by the consumed repo's
    tooling on ANY path -- the checkout, a temp dir of its own -- is refused."""
    _seam(tmp_path, monkeypatch)
    monkeypatch.setenv("ARAMID_CONSUMER_WORKTREE", str(tmp_path / "elsewhere"))

    refused = registry.register(tmp_path / "repoA", "t")

    assert refused == "ARAMID_CONSUMER_WORKTREE is set (a consumer subprocess)"
    assert registry.load_registry() == []


def test_a_temp_path_outside_a_shell_and_a_shell_name_outside_temp_both_register(tmp_path, monkeypatch):
    """The boundary: only the two together -- under the temp root AND below
    an `aramid-<kind>-*` directory -- make a consumer shell. A repo an
    operator keeps under the temp dir, or one whose own directory happens
    to carry the prefix elsewhere, is theirs to register."""
    _seam(tmp_path, monkeypatch)
    under_temp = leftovers.temp_root() / "pytest-of-someone" / "repo"
    named_like_a_shell = tmp_path / "aramid-fuzz-abc" / "wt"       # tmp_path is not temp_root here

    assert registry.register(under_temp, "t") is None
    assert registry.register(named_like_a_shell, "t") is None
    assert len(registry.load_registry()) == 2
