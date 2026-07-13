"""Shared fixtures for the integration test suite.

`registry.register`/`registry.deregister` write to `registry.registry_path()`
(default `Path.home() / ".aramid" / "repos.toml"`) -- since `cmd_init` now
calls `registry.register` and `cmd_uninstall` now calls `registry.deregister`
(Task 9), every test in this package that exercises either would otherwise
touch the real home directory on whatever machine runs the suite. This
mirrors the exact concern `config._user_config_path`'s docstring already
flags ("monkeypatch this rather than touching a real ~/.aramid/config.toml
on the machine running the test suite"), except registry is a *write*, not
just a read, so leaving it unpatched would actually create/append files
outside the test sandbox.

Autouse-patch the seam to a per-test tmp_path location so that never
happens. A later `monkeypatch.setattr(registry, "registry_path", ...)`
inside an individual test body simply overrides this one (monkeypatch
applies in call order), so tests that need to assert against a specific
registry file location remain free to do so.
"""
import pytest

from aramid import registry


@pytest.fixture(autouse=True)
def _isolated_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "registry_path", lambda: tmp_path / "repos.toml")
