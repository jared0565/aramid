"""`doctor --fix` fetching gitleaks: retry, then the GitHub API asset endpoint
(interop round 335 item 1; operator decision 2026-11-23).

On 2026-11-08 GitHub's `releases/download/...` path answered 504, 502 and
read timeouts for about three hours while the REST API asset endpoint served
the same file. One attempt at one URL left gitleaks MISSING and graphite's CI
security job failed seven times. A fake network only: the release URL, the
release JSON and the asset endpoint are answered by URL."""
import hashlib
import io
import json
import zipfile

import pytest

from aramid.commands import doctor

RELEASE = doctor.GITLEAKS_RELEASE_URL
API = (f"https://api.github.com/repos/gitleaks/gitleaks/releases/tags/"
       f"v{doctor.GITLEAKS_VERSION}")
ASSET_ID = 300123


class _Resp:
    def __init__(self, data):
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._data


def _archive(exe):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(exe, b"#!/fake gitleaks\n")
    return buf.getvalue()


class _Net:
    """Answers by URL. `release_fails` failures on the release URL first;
    the API side answers `release_json` and then the asset bytes."""

    def __init__(self, data, asset, *, release_fails=0, api_fails=False, release_json=None,
                 asset_id=ASSET_ID):
        self.data, self.asset, self.asset_id = data, asset, asset_id
        self.release_fails, self.api_fails = release_fails, api_fails
        self.release_json = release_json if release_json is not None else {
            "assets": [{"name": "other.zip", "id": 7}, {"name": asset, "id": asset_id}]}
        self.calls = []

    def __call__(self, req, timeout=60):
        url = req if isinstance(req, str) else req.full_url
        accept = None if isinstance(req, str) else req.get_header("Accept")
        self.calls.append((url, accept))
        if url.startswith("https://github.com/"):
            if self.release_fails:
                self.release_fails -= 1
                raise OSError("HTTP Error 504: Gateway Time-out")
            return _Resp(self.data)
        if self.api_fails:
            raise OSError("HTTP Error 502: Bad Gateway")
        if url == API:
            body = self.release_json
            return _Resp(body if isinstance(body, bytes) else json.dumps(body).encode())
        if url == f"https://api.github.com/repos/gitleaks/gitleaks/releases/assets/{self.asset_id}":
            return _Resp(self.data)
        raise AssertionError(f"unexpected url {url}")


@pytest.fixture
def wired(tmp_path, monkeypatch):
    # The platform is pinned, never read: the fake archive is the windows
    # zip, and a skip on every other OS left the fetch unexecuted on CI's
    # coverage leg (5 latent mutants in doctor.py, CI 45192611672).
    key = "windows_x64"
    monkeypatch.setattr(doctor, "_gitleaks_platform_key", lambda: key)
    exe = doctor._exe_name("gitleaks")
    data = _archive(exe)
    asset = f"gitleaks_{doctor.GITLEAKS_VERSION}_{key}.zip"
    monkeypatch.setattr(doctor, "_tools_dir", lambda: tmp_path / "tools")
    monkeypatch.setitem(doctor.GITLEAKS_SHA256, key, hashlib.sha256(data).hexdigest())
    slept = []
    monkeypatch.setattr(doctor, "_sleep", slept.append, raising=False)

    def net(**kw):
        n = _Net(data, asset, **kw)
        monkeypatch.setattr(doctor.urllib.request, "urlopen", n)
        return n
    return net, slept, tmp_path / "tools" / exe, asset


def test_a_release_url_that_fails_twice_is_tried_a_third_time(wired):
    net, slept, dest, asset = wired
    n = net(release_fails=2)

    assert doctor._fix_gitleaks() is True

    assert dest.is_file()
    assert [u for u, _a in n.calls] == [RELEASE.format(asset=asset)] * 3
    assert slept == [2.0, 8.0]


def test_after_three_failures_the_api_asset_endpoint_serves_it(wired):
    net, slept, dest, asset = wired
    n = net(release_fails=3)

    assert doctor._fix_gitleaks() is True

    assert dest.is_file()
    assert n.calls[3:] == [
        (API, "application/vnd.github+json"),
        (f"https://api.github.com/repos/gitleaks/gitleaks/releases/assets/{ASSET_ID}",
         "application/octet-stream")]
    assert slept == [2.0, 8.0]


def test_the_checksum_holds_whichever_route_served_the_bytes(wired, monkeypatch, capsys):
    net, _slept, dest, _asset = wired
    net(release_fails=3)
    key = doctor._gitleaks_platform_key()
    monkeypatch.setitem(doctor.GITLEAKS_SHA256, key, "00" * 32)

    assert doctor._fix_gitleaks() is False

    assert not dest.exists()
    assert "failed its sha256 check" in capsys.readouterr().err


def test_when_every_route_fails_the_error_names_each(wired, capsys):
    net, _slept, dest, asset = wired
    net(release_fails=3, api_fails=True)

    assert doctor._fix_gitleaks() is False

    assert not dest.exists()
    assert capsys.readouterr().err == (
        f"aramid: doctor --fix: could not download gitleaks: "
        f"{RELEASE.format(asset=asset)} failed 3 times (last: HTTP Error 504: Gateway "
        f"Time-out); the GitHub API asset endpoint failed (HTTP Error 502: Bad Gateway)\n")


@pytest.mark.parametrize("release_json, said", [
    ({"assets": [{"name": "other.zip", "id": 1}]}, "the release lists no {asset}"),
    ({"assets": [{"name": "{asset}", "id": "https://elsewhere.example/x"}]},
     "the release gives {asset} no numeric id"),
    ({"assets": [{"name": "{asset}", "id": 0}]}, "the release gives {asset} no numeric id"),
    ({"message": "Not Found"}, "the release lists no {asset}"),
    (b"<html>502 Bad Gateway</html>", "its release JSON could not be read"),
], ids=["not-listed", "id-not-a-number", "id-zero", "no-assets", "not-json"])
def test_an_api_answer_it_cannot_use_is_named_and_fetches_nothing_else(wired, capsys,
                                                                     release_json, said):
    net, _slept, dest, asset = wired
    if isinstance(release_json, dict) and release_json.get("assets"):
        for a in release_json["assets"]:
            a["name"] = a["name"].format(asset=asset)
    n = net(release_fails=3, release_json=release_json)

    assert doctor._fix_gitleaks() is False

    assert not dest.exists()
    assert [u for u, _a in n.calls][3:] == [API]
    assert capsys.readouterr().err.endswith(
        f"; the GitHub API asset endpoint failed ({said.format(asset=asset)})\n")


def test_the_lowest_asset_id_is_fetched(wired):
    net, _slept, dest, _asset = wired
    n = net(release_fails=3, asset_id=1)

    assert doctor._fix_gitleaks() is True

    assert dest.is_file()
    assert n.calls[-1] == ("https://api.github.com/repos/gitleaks/gitleaks/releases/assets/1",
                           "application/octet-stream")
