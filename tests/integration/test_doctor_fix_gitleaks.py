"""Offline coverage for doctor._fix_gitleaks download/checksum/extract path,
which is network-touching and never exercised elsewhere (all other doctor
tests monkeypatch the prober). We feed a synthetic archive through a
monkeypatched urlopen + injected checksum -- no network, runs everywhere."""
import hashlib
import io
import tarfile
import zipfile
from pathlib import Path

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


# --fix now REPLACES aramid's own gitleaks when it is off the pin (FN-5), so a
# write that fails partway (a full disk, the binary in use on Windows) must
# leave the working copy it found, never half a new one.

def _working_copy(tmp_path, exe):
    dest = tmp_path / "tools" / exe
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"the working gitleaks")
    return dest


def test_a_write_that_fails_partway_leaves_the_gitleaks_it_was_replacing(
        _wired, monkeypatch, capsys):
    key, exe, data, tmp_path = _wired
    monkeypatch.setitem(doctor.GITLEAKS_SHA256, key, hashlib.sha256(data).hexdigest())
    dest = _working_copy(tmp_path, exe)
    real = Path.write_bytes

    def dies_partway(self, payload):
        real(self, payload[: len(payload) // 2])
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "write_bytes", dies_partway)

    assert doctor._fix_gitleaks() is False
    assert dest.read_bytes() == b"the working gitleaks"
    assert sorted(p.name for p in dest.parent.iterdir()) == [exe]
    assert "aramid: doctor --fix: could not install gitleaks:" in capsys.readouterr().err


def test_a_replace_the_os_refuses_leaves_the_gitleaks_it_was_replacing(
        _wired, monkeypatch, capsys):
    key, exe, data, tmp_path = _wired
    monkeypatch.setitem(doctor.GITLEAKS_SHA256, key, hashlib.sha256(data).hexdigest())
    dest = _working_copy(tmp_path, exe)

    def in_use(src, dst):
        raise PermissionError(13, "The process cannot access the file", str(dst))

    monkeypatch.setattr(doctor.os, "replace", in_use)

    assert doctor._fix_gitleaks() is False
    assert dest.read_bytes() == b"the working gitleaks"
    assert sorted(p.name for p in dest.parent.iterdir()) == [exe]
    assert "aramid: doctor --fix: could not install gitleaks:" in capsys.readouterr().err


def test_a_good_download_replaces_the_copy_that_was_there(_wired, monkeypatch):
    key, exe, data, tmp_path = _wired
    monkeypatch.setitem(doctor.GITLEAKS_SHA256, key, hashlib.sha256(data).hexdigest())
    dest = _working_copy(tmp_path, exe)

    assert doctor._fix_gitleaks() is True
    assert dest.read_bytes() == b"#!/fake gitleaks\n"
    assert sorted(p.name for p in dest.parent.iterdir()) == [exe]
