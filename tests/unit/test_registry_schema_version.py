"""~/.aramid/repos.toml carries its shape version (1.0 blocker API-4). A
registry written by a newer aramid reads as empty with one line saying why
-- the unreadable-registry path, where the drain stops before judging
anything -- and is never overwritten: every aramid on the machine shares
this one file."""
import tomllib

import pytest

from aramid import registry


def _seam(tmp_path, monkeypatch):
    p = tmp_path / "repos.toml"
    monkeypatch.setattr(registry, "registry_path", lambda: p)
    return p


def _newer(p, version="2"):
    p.write_text(f'schema_version = {version}\n\n[[repos]]\npath = "C:/x"\n'
                 f'registered_at = "t"\n', encoding="utf-8")
    return p.read_text(encoding="utf-8")


def test_the_registry_is_written_with_its_schema_version_first(tmp_path, monkeypatch):
    p = _seam(tmp_path, monkeypatch)
    assert registry.register(tmp_path / "a", "t") is None

    data = tomllib.loads(p.read_text(encoding="utf-8"))
    assert list(data) == ["schema_version", "repos"]
    assert data["schema_version"] == registry.REGISTRY_SCHEMA_VERSION == 1


def test_an_unversioned_registry_still_reads(tmp_path, monkeypatch):
    """Every repos.toml written before 0.19.0 has no version key."""
    p = _seam(tmp_path, monkeypatch)
    p.write_text('[[repos]]\npath = "C:/x"\nregistered_at = "t"\n', encoding="utf-8")
    assert registry.load_registry() == [{"path": "C:/x", "registered_at": "t"}]


@pytest.mark.parametrize("version", ["2", '"1"'])
def test_a_registry_from_a_newer_aramid_reads_as_empty_and_says_why(
        tmp_path, monkeypatch, capsys, version):
    """A version this aramid cannot read -- higher, or not an integer at
    all -- is not guessed at."""
    p = _seam(tmp_path, monkeypatch)
    _newer(p, version)
    shown = "2" if version == "2" else "'1'"

    assert registry.load_registry() == []
    assert capsys.readouterr().err == (
        f"aramid: registry: {p} was written by a newer aramid (registry schema "
        f"{shown}; this one reads up to 1) -- upgrade aramid to use it; treating "
        f"as empty\n")


def test_a_newer_registry_is_never_overwritten(tmp_path, monkeypatch, capsys):
    p = _seam(tmp_path, monkeypatch)
    before = _newer(p)

    assert registry.register(tmp_path / "a", "t") == (
        f"{p} was written by a newer aramid (registry schema 2; this one reads up "
        f"to 1) -- upgrade aramid to use it")
    with pytest.raises(registry.RegistryTooNew):
        registry.deregister(tmp_path / "a")
    assert registry.remove("C:/x") == 0, "nothing it can read, so nothing removed"

    assert p.read_text(encoding="utf-8") == before


def test_an_unreadable_registry_is_never_overwritten(tmp_path, monkeypatch):
    """One `aramid init` anywhere used to replace a corrupt or half-written
    repos.toml with a one-repo fleet -- no error, no backup -- and the
    readiness verdict then graded that repo alone (the 10Z drain's review of
    bad0ce1, 2026-09-25). Only a person can say what the file held."""
    p = _seam(tmp_path, monkeypatch)
    p.write_text("not [ valid toml", encoding="utf-8")

    refused = registry.register(tmp_path / "a", "t")
    assert refused is not None and refused.startswith(f"{p} is unreadable (")
    assert refused.endswith(") -- left untouched; fix it by hand, or delete it to "
                            "start the fleet over")
    with pytest.raises(registry.RegistryUnusable) as raised:
        registry.deregister(tmp_path / "a")
    assert str(raised.value) == refused
    assert registry.remove("C:/x") == 0, "nothing it can read, so nothing removed"

    assert p.read_text(encoding="utf-8") == "not [ valid toml"
