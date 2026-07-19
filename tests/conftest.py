"""Suite-wide fixtures.

`autolearn.load_state`/`save_state` default to `autolearn.state_path()`
(`Path.home() / ".aramid" / "autolearn_state.json"`). The llm-review
consumer READS it on every consume() and the drain WRITES it at rollup
time, so without isolation the suite would read/write real machine state
(the same concern tests/integration/conftest.py documents for the
registry). Autouse-patch the seam to a per-test tmp_path; individual tests
that seed state simply call autolearn.save_state(...) and hit the same
patched location.
"""
import pytest

from aramid import autolearn


@pytest.fixture(autouse=True)
def _isolated_autolearn_state(tmp_path, monkeypatch):
    monkeypatch.setattr(autolearn, "state_path",
                        lambda: tmp_path / "autolearn_state.json")
