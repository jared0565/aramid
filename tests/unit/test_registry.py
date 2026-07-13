from pathlib import Path

from aramid import registry
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
