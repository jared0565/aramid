"""scripts/promote_live.py -- "already live" must mean a PROMOTED wheel, not
merely a matching version.

Found by the llm-review consumer (ledger be79fea8, promote_live.py:105):
`main` returned 0 on version equality alone. The likeliest reason anyone runs
this script is to repair an accidental `pip install -e .` right after a
release -- exactly when the checkout's `__version__` equals the version being
promoted -- and in that case it printed "already live ... Nothing to do." and
left every consumer on the working tree. The post-install check (version AND
path outside the checkout) already knew better; the pre-check did not ask.

The probe now also reports whether the installed distribution is editable
(`direct_url.json`'s `dir_info.editable`, the same key `aramid doctor` reads),
which catches the case the path check cannot: an editable install of some
OTHER clone of aramid, which resolves outside this checkout.

The script is loaded from its path on purpose -- it is not a package module,
by design (see its docstring on why it is not `aramid promote`).
"""
import hashlib
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "promote_live.py"


@pytest.fixture(scope="module")
def pl():
    spec = importlib.util.spec_from_file_location("promote_live", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _cp(rc: int, stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr="")


def _outside(tmp_path) -> str:
    return str(tmp_path / "site-packages" / "aramid" / "__init__.py")


def _inside() -> str:
    return str(REPO / "src" / "aramid" / "__init__.py")


# --- the probe ---------------------------------------------------------------

def test_live_reports_version_path_and_editability(pl, monkeypatch):
    monkeypatch.setattr(pl, "_run", lambda argv, **kw: _cp(
        0, '["0.5.0", "/sp/aramid/__init__.py", false]\n'))
    assert pl._live() == ("0.5.0", "/sp/aramid/__init__.py", False)


def test_live_distrusts_a_failed_probe_even_when_it_printed_something(pl, monkeypatch):
    """rc != 0 means the answer is unknown, whatever reached stdout."""
    monkeypatch.setattr(pl, "_run", lambda argv, **kw: _cp(
        1, '["0.5.0", "/sp/aramid/__init__.py", false]\n'))
    assert pl._live() == (None, None, None)


def test_the_real_probe_answers_in_shape(pl):
    """Unmocked: a clean interpreter with PYTHONPATH stripped. CI installs the
    checkout editable, so there `inside` is True and the editable flag must
    be read from a real direct_url.json; a two-aramid machine runs a promoted
    wheel and exercises the False side. Both shapes are asserted, but only
    the CI leg proves the True detection -- named so nobody reads a local
    green as covering it."""
    version, path, editable = pl._live()
    assert isinstance(version, str) and isinstance(path, str), (version, path)
    assert isinstance(editable, bool)
    inside = REPO in Path(path).resolve().parents
    if inside:
        assert editable is True, "resolving inside the checkout is only possible editable"


# --- the pre-check -----------------------------------------------------------

def _main(pl, monkeypatch, argv, lives, digest=None, run=None):
    monkeypatch.setattr(sys, "argv", ["promote_live.py", *argv])
    it = iter(lives)
    monkeypatch.setattr(pl, "_live", lambda: next(it))
    calls = []

    def _digest(tag, asset):
        calls.append((tag, asset))
        return digest
    monkeypatch.setattr(pl, "_release_digest", _digest)
    if run is not None:
        monkeypatch.setattr(pl, "_run", run)
    return pl.main(), calls


def test_matching_version_from_a_promoted_wheel_is_already_live(
        pl, monkeypatch, tmp_path, capsys):
    rc, calls = _main(pl, monkeypatch, ["0.5.0"],
                      [("0.5.0", _outside(tmp_path), False)])
    assert rc == 0
    assert "already live" in capsys.readouterr().out
    assert calls == [], "nothing to promote; the release is never consulted"


def test_matching_version_resolving_inside_the_checkout_is_NOT_already_live(
        pl, monkeypatch, capsys):
    """The repro: an editable install of this checkout at the released
    version. `_release_digest` returns None so the run ends in a refusal --
    which is the proof it went PAST the early return."""
    rc, calls = _main(pl, monkeypatch, ["0.5.0"], [("0.5.0", _inside(), True)])
    out = capsys.readouterr()
    assert "already live" not in out.out
    assert calls, "must go on to promote the released wheel"
    assert rc != 0


def test_matching_version_from_an_editable_install_elsewhere_is_NOT_already_live(
        pl, monkeypatch, tmp_path, capsys):
    """Path outside this checkout, but the distribution says editable: some
    other clone. The path check alone would have called this promoted."""
    rc, calls = _main(pl, monkeypatch, ["0.5.0"],
                      [("0.5.0", _outside(tmp_path), True)])
    assert "already live" not in capsys.readouterr().out
    assert calls


# --- the post-check ----------------------------------------------------------

def test_post_install_fails_if_what_is_live_is_still_editable(
        pl, monkeypatch, tmp_path, capsys):
    """Download, digest and pip all succeed, and the probe afterwards reports
    the right version at a path outside the checkout -- but editable. The
    version+path check that existed before would have printed OK."""
    wheel_bytes = b"not really a wheel"
    digest = hashlib.sha256(wheel_bytes).hexdigest()

    def _run(argv, **kw):
        if "download" in argv:
            out = Path(argv[argv.index("--dir") + 1])
            (out / pl.WHEEL_ASSET.format(version="0.5.0")).write_bytes(wheel_bytes)
        return _cp(0)

    rc, _ = _main(pl, monkeypatch, ["0.5.0", "--confirm"],
                  [("0.4.1", _outside(tmp_path), False),
                   ("0.5.0", _outside(tmp_path), True)],
                  digest=digest, run=_run)
    out = capsys.readouterr()
    assert rc == 3
    assert "FAILED" in out.err and "editable" in out.err, out.err
    assert "Consumers now run" not in out.out

# --- what the operator reads --------------------------------------------------

def test_help_leads_with_the_scripts_purpose(pl, monkeypatch, capsys):
    """The argparse description is the docstring's FIRST line; the second is
    blank. A `--help` that opens with an empty description is the mutant."""
    monkeypatch.setattr(sys, "argv", ["promote_live.py", "--help"])
    with pytest.raises(SystemExit) as exc:
        pl.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "Promote a released aramid to the LIVE tool" in out


def test_a_failed_probe_is_reported_as_not_installed(pl, monkeypatch, capsys):
    """`None or 'not installed'` / `None or '-'`: the two lines an operator
    reads first. Under `and` they would print `None`."""
    rc, calls = _main(pl, monkeypatch, ["0.5.0"], [(None, None, None)])
    out = capsys.readouterr().out
    assert "live now : not installed" in out
    assert "           -" in out
    assert calls, "an unknown live state must still go on to promote"


def test_a_known_live_version_is_printed_not_a_placeholder(
        pl, monkeypatch, tmp_path, capsys):
    """The other direction of the same `or`: with a real version, `and` would
    print the placeholder instead of the version."""
    rc, _ = _main(pl, monkeypatch, ["0.5.0"], [("0.4.1", _outside(tmp_path), False)])
    out = capsys.readouterr().out
    assert "live now : 0.4.1" in out
    assert _outside(tmp_path) in out
