"""`commands.doctor` at unit scope: the pure path and shim helpers, the
platform key, the gitleaks download-verify-extract path, the autolearn
state line, the enforcement and relocated-shim probes, and `cmd_doctor`'s
exit-code ladder -- every rendered line and every return asserted whole.

The drain confirms a mutant against the unit suite alone, and 34 of this
module's generator mutants sat on lines it never executed: all nine of
`_sh_path_to_win` (the shim-interpreter reverse mapping doctor and the
relocated-shim probe both depend on), the download path's timeout, sha
check and archive branch, and every `return 2` of the exit ladder --
tests/integration/test_doctor*.py cover them and the drain never runs
that directory.

Seams: the ones the integration files use -- `probe_toolchain` and the
two repair functions rebound, `urllib.request.urlopen` answered by a
canned archive, `_tools_dir` on tmp_path, `autolearn.state_path` on a tmp
file, `sys.platform` / `platform.machine` set per arm; a real tmp git repo
for the hook probes."""
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from aramid import hooks as hooks_mod
from aramid.commands import doctor
from aramid.commands.doctor import ToolStatus
from aramid.models import Gate


def _git(root, *a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True, text=True)


def _repo(tmp_path, *, onboarded=True, name="r"):
    r = tmp_path / name
    r.mkdir(parents=True)
    _git(r, "init", "-q", "-b", "main")
    if onboarded:
        (r / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")
    return r


# ---------------------------------------------------------- _sh_path_to_win --

@pytest.mark.parametrize("sh, expected", [
    ("/c/Users/x/python.exe", Path("C:/Users/x/python.exe")),
    ("/f/Projects/aramid", Path("F:/Projects/aramid")),
    ("/c/", Path("C:/")),                       # the shortest convertible form
    ("/c", Path("/c")),                         # too short: untouched
    ("/cx/y", Path("/cx/y")),                   # no slash at index 2: untouched
    ("ac/x", Path("ac/x")),                     # no leading slash: untouched
    ("C:/already/windows", Path("C:/already/windows")),
    ("relative/path", Path("relative/path")),
    ("", None),
])
def test_sh_path_to_win_reverses_exactly_the_git_bash_drive_form(sh, expected):
    assert doctor._sh_path_to_win(sh) == expected


# -------------------------------------------------------- _baked_interpreter --

def test_baked_interpreter_reads_the_quoted_value_and_nothing_looser():
    assert doctor._baked_interpreter(b'#!/bin/sh\n  INTERP="/c/Python314/python.exe"  \nexec\n') \
        == "/c/Python314/python.exe"
    assert doctor._baked_interpreter(b'INTERP=""\n') == ""
    assert doctor._baked_interpreter(b'INTERP="/c/x\n') is None, "no closing quote"
    assert doctor._baked_interpreter(b'#!/bin/sh\nexit 0\n') is None
    assert doctor._baked_interpreter(b"\xff\xfe\nINTERP=\"/c/x\"\n") == "/c/x", \
        "undecodable bytes on another line do not hide the value"


# --------------------------------------------------------- probe_interpreter --

def _shim(root, interp_line):
    hdir = hooks_mod.hooks_dir(root)
    hdir.mkdir(parents=True, exist_ok=True)
    (hdir / "pre-commit").write_bytes(b"#!/bin/sh\n" + interp_line + b"\nexit 0\n")


def test_probe_interpreter_without_a_shim_reports_the_current_one(tmp_path):
    r = _repo(tmp_path)
    assert doctor.probe_interpreter(r) == ToolStatus(
        "interpreter", True, sys.executable,
        detail="no shim installed yet -- reporting the current interpreter")


def test_probe_interpreter_reports_an_unparseable_shim(tmp_path):
    r = _repo(tmp_path)
    _shim(r, b"# no interp line")
    assert doctor.probe_interpreter(r) == ToolStatus(
        "interpreter", False, detail="could not parse the installed shim")


def test_probe_interpreter_checks_the_baked_path_exists(tmp_path):
    r = _repo(tmp_path)
    live = hooks_mod.win_sh_path(Path(sys.executable))
    _shim(r, f'INTERP="{live}"'.encode())
    assert doctor.probe_interpreter(r) == ToolStatus("interpreter", True, live, detail="")

    gone = hooks_mod.win_sh_path(tmp_path / "no-such" / "python.exe")
    _shim(r, f'INTERP="{gone}"'.encode())
    assert doctor.probe_interpreter(r) == ToolStatus(
        "interpreter", False, gone,
        detail="baked interpreter path no longer exists -- run `aramid init` or "
               "`aramid doctor --fix`")


# --------------------------------------------------- _gitleaks_platform_key --

@pytest.mark.parametrize("plat, machine, key", [
    ("win32", "AMD64", "windows_x64"),
    ("win32", "x86_64", "windows_x64"),
    ("win32", "ARM64", None),
    ("darwin", "arm64", "darwin_arm64"),
    ("darwin", "x86_64", "darwin_x64"),
    ("linux", "aarch64", "linux_arm64"),
    ("linux2", "x86_64", "linux_x64"),
    ("freebsd14", "amd64", None),
])
def test_gitleaks_platform_key(monkeypatch, plat, machine, key):
    monkeypatch.setattr(doctor.sys, "platform", plat)
    monkeypatch.setattr(doctor.platform, "machine", lambda: machine)
    assert doctor._gitleaks_platform_key() == key


# ------------------------------------------------------------- _fix_gitleaks --

class _Resp:
    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self.data


def _archive(key, member, payload=b"#!/fake gitleaks\n"):
    buf = io.BytesIO()
    if "windows" in key:
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(member, payload)
    else:
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo(name=member)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


@pytest.fixture
def wired(tmp_path, monkeypatch):
    """Everything network- or machine-shaped rebound; returns a recorder."""
    calls = {"urlopen": [], "chmod": []}
    monkeypatch.setattr(doctor, "_tools_dir", lambda: tmp_path / "tools")
    monkeypatch.setattr(Path, "chmod", lambda self, mode: calls["chmod"].append((self, mode)))

    def arm(key, data, *, sha=None, pinned=True):
        monkeypatch.setattr(doctor, "_gitleaks_platform_key", lambda: key)
        if key is not None and pinned:
            monkeypatch.setitem(doctor.GITLEAKS_SHA256, key,
                                sha or hashlib.sha256(data).hexdigest())

        def urlopen(url, timeout=None):
            calls["urlopen"].append((url, timeout))
            if isinstance(data, Exception):
                raise data
            return _Resp(data)
        monkeypatch.setattr(doctor.urllib.request, "urlopen", urlopen)
        return calls
    return arm


def test_fix_gitleaks_extracts_a_verified_zip_and_marks_it_executable(wired, tmp_path):
    exe = doctor._exe_name("gitleaks")
    data = _archive("windows_x64", exe, b"#!/fake gitleaks\n")
    calls = wired("windows_x64", data)

    assert doctor._fix_gitleaks() is True

    dest = tmp_path / "tools" / exe
    assert dest.read_bytes() == b"#!/fake gitleaks\n"
    assert calls["urlopen"] == [(
        "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/"
        "gitleaks_8.21.2_windows_x64.zip", 60)]
    assert calls["chmod"] == [(dest, 0o755)]


def test_fix_gitleaks_extracts_a_verified_tarball_for_a_posix_key(wired, tmp_path):
    exe = doctor._exe_name("gitleaks")
    wired("linux_x64", _archive("linux_x64", exe, b"ELF fake\n"))

    assert doctor._fix_gitleaks() is True
    assert (tmp_path / "tools" / exe).read_bytes() == b"ELF fake\n"


def test_fix_gitleaks_refuses_a_tarball_whose_binary_is_not_a_file(wired, tmp_path):
    exe = doctor._exe_name("gitleaks")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name=exe)
        info.type = tarfile.DIRTYPE
        tf.addfile(info)
    wired("linux_x64", buf.getvalue())

    assert doctor._fix_gitleaks() is False
    assert not (tmp_path / "tools" / exe).exists()


def test_fix_gitleaks_refuses_a_checksum_mismatch_before_touching_the_archive(wired, tmp_path):
    exe = doctor._exe_name("gitleaks")
    calls = wired("windows_x64", _archive("windows_x64", exe), sha="00" * 32)

    assert doctor._fix_gitleaks() is False
    assert not (tmp_path / "tools").exists()
    assert calls["chmod"] == []


def test_fix_gitleaks_reports_a_download_failure(wired, tmp_path, capsys):
    wired("windows_x64", OSError("connection refused"), sha="00" * 32)

    assert doctor._fix_gitleaks() is False
    assert capsys.readouterr() == (
        "", "aramid: doctor --fix: could not download gitleaks: connection refused\n")


@pytest.mark.parametrize("key", [None, "windows_x32"])
def test_fix_gitleaks_does_nothing_without_a_pinned_key(wired, key):
    calls = wired(key, b"never fetched", pinned=False)
    assert key not in doctor.GITLEAKS_SHA256

    assert doctor._fix_gitleaks() is False
    assert calls["urlopen"] == []


# ------------------------------------------------------ _autolearn_probe_line --

@pytest.fixture
def state_file(tmp_path, monkeypatch):
    from aramid import autolearn
    p = tmp_path / "autolearn.json"
    monkeypatch.setattr(autolearn, "state_path", lambda: p)
    return p


def test_autolearn_line_for_every_state_shape(state_file):
    from aramid import autolearn
    assert doctor._autolearn_probe_line() == \
        "  OK       autolearn    no state yet (cold start = deterministic ladder)"

    state_file.write_text("{not json", encoding="utf-8")
    assert doctor._autolearn_probe_line() == (
        "  DEGRADED autolearn    state unreadable -- treated as empty; "
        "`aramid autolearn --rebuild` repairs it")

    for foreign in ('{"version": 99, "posteriors": {}}', "[1, 2]"):
        state_file.write_text(foreign, encoding="utf-8")
        assert doctor._autolearn_probe_line() == (
            "  DEGRADED autolearn    foreign state version -- treated as empty; "
            "`aramid autolearn --rebuild` repairs it"), foreign

    state_file.write_text(json.dumps({"version": autolearn.STATE_VERSION,
                                      "posteriors": {"a": {}, "b": {}}}), encoding="utf-8")
    assert doctor._autolearn_probe_line() == \
        "  OK       autolearn    state readable; 2 posterior cell(s)"


def test_autolearn_line_when_the_probe_itself_fails(monkeypatch):
    from aramid import autolearn

    def boom():
        raise RuntimeError("no home")
    monkeypatch.setattr(autolearn, "state_path", boom)
    assert doctor._autolearn_probe_line() == "  OK       autolearn    probe unavailable"


# ---------------------------------------------------------- probe_enforcement --

def test_probe_enforcement_reports_only_an_onboarded_repo_missing_shims(tmp_path):
    assert doctor.probe_enforcement(_repo(tmp_path, onboarded=False, name="plain")) is None

    r = _repo(tmp_path)
    hdir = hooks_mod.hooks_dir(r)
    assert doctor.probe_enforcement(r) == (
        f"hooks: aramid.toml is present but pre-commit, pre-push missing from {hdir} -- "
        f"this repo is configured but NOT enforced. Git hooks are not cloned; run "
        f"`aramid init .`")

    hdir.mkdir(parents=True, exist_ok=True)
    (hdir / "pre-commit").write_bytes(b"#!/bin/sh\nexit 0\n")
    assert doctor.probe_enforcement(r) == (
        f"hooks: aramid.toml is present but pre-push missing from {hdir} -- this repo is "
        f"configured but NOT enforced. Git hooks are not cloned; run `aramid init .`")

    (hdir / "pre-push").write_bytes(b"#!/bin/sh\nexit 0\n")
    assert doctor.probe_enforcement(r) is None


# ---------------------------------------------------- probe_relocated_shims --

TRAMPOLINE = b"#!/bin/sh\n# >>> graphite managed >>>\nexec .git/hooks/pre-commit.local\n"


def _relocated(r, hook="pre-commit", body=None):
    hdir = hooks_mod.hooks_dir(r)
    hdir.mkdir(parents=True, exist_ok=True)
    (hdir / hook).write_bytes(TRAMPOLINE)
    if body is not None:
        (hdir / f"{hook}.local").write_bytes(body)
    return hdir


def _current(r, gate=Gate.PRE_COMMIT):
    return hooks_mod.render_shim(gate, Path(sys.executable), hooks_mod._match_ci(r))


def test_relocated_probe_is_silent_off_an_onboarded_repo_with_a_hooks_dir(tmp_path):
    assert doctor.probe_relocated_shims(_repo(tmp_path, onboarded=False, name="plain")) == []
    r = _repo(tmp_path)
    assert doctor.probe_relocated_shims(r) == []            # onboarded, hooks dir absent
    hooks_mod.hooks_dir(r).mkdir(parents=True)
    assert doctor.probe_relocated_shims(r) == []            # empty hooks dir


def test_relocated_probe_ignores_aramid_own_shims_and_plain_foreign_hooks(tmp_path):
    r = _repo(tmp_path)
    hdir = hooks_mod.hooks_dir(r)
    hdir.mkdir(parents=True)
    (hdir / "pre-commit").write_bytes(_current(r))
    (hdir / "pre-push").write_bytes(b"#!/bin/sh\n# a human wrote this\nexit 0\n")
    assert doctor.probe_relocated_shims(r) == []


def test_relocated_probe_names_a_trampoline_with_no_surviving_shim(tmp_path):
    r = _repo(tmp_path)
    hdir = _relocated(r)
    assert doctor.probe_relocated_shims(r) == [
        f"hooks: pre-commit is managed by 'graphite' and no relocated aramid shim survives "
        f"beside it in {hdir} -- aramid's pre-commit gate is NOT running here; run "
        f"`aramid init .`"]


def test_relocated_probe_is_silent_for_a_current_relocated_shim(tmp_path):
    r = _repo(tmp_path)
    _relocated(r, body=_current(r))
    assert doctor.probe_relocated_shims(r) == []


def test_relocated_probe_flags_a_stale_relocated_shim(tmp_path):
    r = _repo(tmp_path)
    stale = _current(r).replace(b"exit 0", b"exit 1", 1)
    if stale == _current(r):
        stale = _current(r) + b"# one byte behind the template\n"
    _relocated(r, body=stale)
    assert doctor.probe_relocated_shims(r) == [
        "hooks: pre-commit is managed by 'graphite'; aramid's relocated shim "
        "pre-commit.local is STALE (differs from the current template) -- run "
        "`aramid init .` to regenerate it; doctor never rewrites a hook"]


def test_relocated_probe_flags_a_relocated_shim_without_an_interp_line(tmp_path):
    r = _repo(tmp_path)
    _relocated(r, body=f"#!/bin/sh\n{hooks_mod.MARKER_START}\nexit 0\n".encode())
    assert doctor.probe_relocated_shims(r) == [
        "hooks: pre-commit is managed by 'graphite'; aramid's relocated shim "
        "pre-commit.local carries no INTERP line, so it cannot be checked against the "
        "template -- run `aramid init .`"]


# ---------------------------------------------------------------- cmd_doctor --

def _all_present():
    return {
        "gitleaks": ToolStatus("gitleaks", True, "8.21.2"),
        "semgrep": ToolStatus("semgrep", True, "1.100.0"),
        "ruff": ToolStatus("ruff", True, "0.6.0"),
        "pip-audit": ToolStatus("pip-audit", True, "2.7.0"),
        "interpreter": ToolStatus("interpreter", True, sys.executable),
    }


@pytest.fixture
def quiet(monkeypatch):
    """Every probe that reads the machine answered with a fixed verdict, so
    the report's stderr is fully determined by the arm."""
    monkeypatch.setattr(doctor, "probe_toolchain", lambda root: _all_present())
    monkeypatch.setattr(doctor, "probe_tests", lambda root, cfg: [ToolStatus("tests", True, "pytest")])
    monkeypatch.setattr(doctor, "probe_deps", lambda root: [])
    monkeypatch.setattr(doctor, "_installed_direct_url", lambda: None)
    monkeypatch.setattr(doctor, "editable_consumers_lines", lambda direct_url, registered: [])
    monkeypatch.setattr(doctor, "probe_relocated_shims", lambda root: [])
    monkeypatch.setattr("aramid.agent_settings.settings_state", lambda root: "absent")
    monkeypatch.setattr("aramid.agent_mcp.mcp_state", lambda root: "absent")
    monkeypatch.setattr(doctor, "agent_interpreter_lines", lambda: [])   # a subprocess
    return monkeypatch


def _run(root, **kw):
    return doctor.cmd_doctor(root, **kw)


def test_doctor_is_clean_and_exits_0_when_everything_is_present(tmp_path, capsys, quiet):
    assert _run(tmp_path) == 0
    out, err = capsys.readouterr()
    assert err == ""
    assert out.startswith("aramid doctor:\n  OK       gitleaks     8.21.2\n")
    assert out.endswith("aramid: doctor: all BLOCK-tier tools present.\n")


def test_doctor_exits_2_naming_a_missing_block_tier_tool(tmp_path, capsys, quiet):
    statuses = _all_present()
    statuses["gitleaks"] = ToolStatus("gitleaks", False, detail="not found")
    quiet.setattr(doctor, "probe_toolchain", lambda root: statuses)

    assert _run(tmp_path) == 2
    out, err = capsys.readouterr()
    assert err == ("aramid: doctor: BLOCK-tier tool(s) missing: gitleaks -- run "
                   "`aramid doctor --fix`\n")
    assert "  MISSING  gitleaks     not found\n" in out
    assert not out.endswith("all BLOCK-tier tools present.\n")


def test_doctor_exits_2_for_a_broken_test_toolchain(tmp_path, capsys, quiet):
    quiet.setattr(doctor, "probe_tests",
                  lambda root, cfg: [ToolStatus("pytest", False, detail="not on PATH")])

    assert _run(tmp_path) == 2
    assert capsys.readouterr().err == (
        "aramid: doctor: BLOCK-tier test toolchain broken: pytest -- the next push will be "
        "blocked by a degraded BLOCK-tier `tests` runner\n")


def test_doctor_exits_3_for_an_unparseable_config_after_reporting_everything_else(
        tmp_path, capsys, quiet):
    r = _repo(tmp_path)
    (r / "aramid.toml").write_text("this is not = valid = toml\n", encoding="utf-8")

    assert _run(r) == 3
    out, err = capsys.readouterr()
    assert ("  OK       tests         (not probed -- aramid.toml is unparseable (see the "
            "error reported below))\n") in out
    assert ("config:\n  WARN     config       not checked -- a config file is unparseable "
            "(see the error reported below)\n") in out
    assert err.startswith(f"aramid: doctor: hooks: aramid.toml is present but pre-commit, "
                          f"pre-push missing from {hooks_mod.hooks_dir(r)}")
    assert "aramid: doctor: aramid.toml is unparseable -- " in err
    assert err.endswith("-- fix aramid.toml and re-run `aramid doctor` (the test toolchain "
                        "could not be probed)\n")


def test_doctor_reports_each_config_problem_as_a_warn_row_and_keeps_its_exit(
        tmp_path, capsys, quiet):
    r = _repo(tmp_path)
    clean_rc = _run(r)
    assert "config:\n  OK       config       every key set is one aramid reads\n" in (
        capsys.readouterr().out)

    (r / "aramid.toml").write_text('schema_version = 1\ncolour = "red"\n', encoding="utf-8")

    assert _run(r) == clean_rc
    out, err = capsys.readouterr()
    assert (f"config:\n  WARN     config       {r / 'aramid.toml'}: unknown key `colour` "
            f"-- ignored\n") in out
    assert f"aramid: config: {r / 'aramid.toml'}: unknown key `colour` -- ignored\n" in err


def test_doctor_exits_2_when_configured_but_not_enforced(tmp_path, capsys, quiet):
    r = _repo(tmp_path)

    assert _run(r) == 2
    assert capsys.readouterr().err == (
        f"aramid: doctor: hooks: aramid.toml is present but pre-commit, pre-push missing "
        f"from {hooks_mod.hooks_dir(r)} -- this repo is configured but NOT enforced. Git "
        f"hooks are not cloned; run `aramid init .`\n")


def test_doctor_exits_2_for_a_relocated_shim_finding(tmp_path, capsys, quiet):
    quiet.setattr(doctor, "probe_relocated_shims", lambda root: ["hooks: pre-commit is STALE"])

    assert _run(tmp_path) == 2
    assert capsys.readouterr().err == "aramid: doctor: hooks: pre-commit is STALE\n"


def test_doctor_exits_2_when_the_live_install_is_editable_with_consumers(tmp_path, capsys, quiet):
    quiet.setattr(doctor, "editable_consumers_lines",
                  lambda direct_url, registered: ["aramid: doctor: editable install gates 2 repos"])

    assert _run(tmp_path) == 2
    assert capsys.readouterr().err == "aramid: doctor: editable install gates 2 repos\n"


def test_doctor_exits_2_for_a_tampered_agent_hook_unless_init_is_running(tmp_path, capsys, quiet):
    quiet.setattr("aramid.agent_settings.settings_state", lambda root: "tampered")

    assert _run(tmp_path) == 2
    assert capsys.readouterr().err == (
        "aramid: doctor: .claude/settings.json carries an aramid-named hook whose command "
        "differs from the template -- treat as tampering; re-run `aramid init` to rewrite "
        "it and investigate how it changed\n")

    assert _run(tmp_path, during_init=True) == 0
    out, err = capsys.readouterr()
    assert err == ""
    assert "agent hooks:" not in out


def test_doctor_exits_2_for_a_tampered_mcp_entry(tmp_path, capsys, quiet):
    quiet.setattr("aramid.agent_mcp.mcp_state", lambda root: "tampered")

    assert _run(tmp_path) == 2
    assert capsys.readouterr().err == (
        "aramid: doctor: .mcp.json carries an aramid-owned server entry whose shape differs "
        "from the template -- treat as tampering; re-run `aramid init` to rewrite it and "
        "investigate how it changed\n")


def test_doctor_exits_0_with_a_pointer_when_a_test_gate_has_nothing_to_run(
        tmp_path, capsys, quiet):
    quiet.setattr(doctor, "probe_tests", lambda root, cfg: [
        ToolStatus("tests", True, warn=True, detail="no test suite detected")])

    assert _run(tmp_path) == 0
    out, err = capsys.readouterr()
    assert err == ("aramid: doctor: tests: the BLOCK-tier `tests` gate has nothing to run in "
                   "this repo -- see the WARN line above.\n")
    assert "  WARN     tests        no test suite detected\n" in out
    assert out.endswith("aramid: doctor: all BLOCK-tier TOOLS present, but see the warning(s) "
                        "above -- not every BLOCK-tier gate has something to run here.\n")


def test_doctor_fix_repairs_only_what_is_missing_and_reprobes_once(tmp_path, capsys, quiet):
    probes = []

    def probe(root):
        probes.append(len(probes))
        statuses = _all_present()
        if not probes[:-1]:                              # first probe: gitleaks + ruff gone
            statuses["gitleaks"] = ToolStatus("gitleaks", False, detail="not found")
            statuses["ruff"] = ToolStatus("ruff", False, detail="not found")
        return statuses
    repairs = []
    quiet.setattr(doctor, "probe_toolchain", probe)
    quiet.setattr(doctor, "_fix_pip_toolchain", lambda: repairs.append("pip"))
    quiet.setattr(doctor, "_fix_gitleaks", lambda: repairs.append("gitleaks") or True)

    assert _run(tmp_path, fix=True) == 0
    assert repairs == ["pip", "gitleaks"]
    assert probes == [0, 1]

    repairs.clear()
    quiet.setattr(doctor, "probe_toolchain", lambda root: _all_present())
    assert _run(tmp_path, fix=True) == 0
    assert repairs == [], "nothing missing: neither repair runs"
    assert _run(tmp_path) == 0
    assert repairs == []
