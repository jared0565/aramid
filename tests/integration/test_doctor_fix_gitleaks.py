"""Offline coverage for doctor._fix_gitleaks download/checksum/extract path,
which is network-touching and never exercised elsewhere (all other doctor
tests monkeypatch the prober). We feed a synthetic archive through a
monkeypatched urlopen + injected checksum -- no network, runs everywhere."""
import hashlib
import io
import tarfile
import zipfile

import pytest

from aramid.commands import doctor


class _FakeResp:
    def __init__(self, data):
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._data


def _archive_for(platform_key, exe_name, payload=b"#!/fake gitleaks\n"):
    """Build the archive shape _fix_gitleaks expects for this platform:
    a zip (windows keys) or tar.gz (others) whose single member is exe_name."""
    buf = io.BytesIO()
    if "windows" in platform_key:
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(exe_name, payload)
    else:
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo(name=exe_name)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


@pytest.fixture
def _wired(tmp_path, monkeypatch):
    key = doctor._gitleaks_platform_key()
    if key is None:
        pytest.skip("no gitleaks platform key for this OS/arch")
    exe = doctor._exe_name("gitleaks")
    data = _archive_for(key, exe)
    monkeypatch.setattr(doctor, "_tools_dir", lambda: tmp_path / "tools")
    monkeypatch.setattr(doctor.urllib.request, "urlopen",
                        lambda url, timeout=60: _FakeResp(data))
    return key, exe, data, tmp_path


def test_fix_gitleaks_extracts_on_matching_checksum(_wired, monkeypatch):
    key, exe, data, tmp_path = _wired
    monkeypatch.setitem(doctor.GITLEAKS_SHA256, key, hashlib.sha256(data).hexdigest())
    assert doctor._fix_gitleaks() is True
    assert (tmp_path / "tools" / exe).exists()


def test_fix_gitleaks_rejects_on_bad_checksum(_wired, monkeypatch):
    key, exe, data, tmp_path = _wired
    monkeypatch.setitem(doctor.GITLEAKS_SHA256, key, "00" * 32)  # wrong sha
    assert doctor._fix_gitleaks() is False
    assert not (tmp_path / "tools" / exe).exists()
