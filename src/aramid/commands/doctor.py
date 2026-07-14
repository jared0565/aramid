"""doctor -- probe the tool toolchain and the git hook shim's baked
interpreter; `--fix` installs the owned pip toolchain into the CURRENT
interpreter and downloads a pinned gitleaks release binary into
`~/.aramid/tools/` (sha256-verified before ever being trusted/executed).

BLOCK-tier gate (spec §3/§8): `doctor` -- and later `init`, refusing to arm
hooks -- treat gitleaks and semgrep as tools that MUST be present; WARN-tier
tools (ruff, pip-audit here; eslint/tsc/mypy at the runner layer) degrade
gracefully at runtime and are reported but never fail doctor's own exit
code.

Probing quirk this module exists to get right: aramid's "owned" pip tools
(ruff, semgrep, pip-audit) are dependencies of the aramid package itself,
installed into the CURRENT interpreter -- but pip's console-script
directory for that interpreter is not guaranteed to be on PATH, and isn't
even always the same directory `sysconfig`'s default scheme reports
(observed on this exact host: aramid is installed into the PER-USER site,
so its console scripts live under the "user" sysconfig scheme's Scripts
dir, e.g. ".../AppData/Roaming/Python/Python3XX/Scripts" -- both absent
from PATH and different from the default-scheme Scripts dir). `probe_tool`
therefore checks PATH, the default-scheme scripts dir, AND the per-user
scheme's scripts dir. Separately, semgrep's `semgrep.exe` wrapper shells
out to a sibling `pysemgrep.exe` by bare name -- if the wrapper's own
directory isn't on PATH, semgrep's `--version` fails even when the file
exists two inches away; the probe subprocess call works around this by
prepending the resolved executable's own directory to the child's PATH.
"""
import hashlib
import io
import os
import platform
import shutil
import subprocess
import sys
import sysconfig
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

# BLOCK-tier tools per spec §3/§8 -- doctor's own pass/fail gate. `init`
# (Task 6.2) refuses to arm hooks until both are present; this module only
# owns the probe-and-report/repair behavior, not that refusal.
BLOCK_TIER = ("gitleaks", "semgrep")

# Tools aramid owns as pip dependencies of itself (see pyproject.toml
# `[project.dependencies]`) -- `--fix` pip-installs these into the CURRENT
# interpreter, never a different one. gitleaks is a standalone Go binary,
# not pip-installable, handled separately below.
OWNED_PIP_TOOLCHAIN = ("ruff", "semgrep", "pip-audit")

ALL_TOOLS = ("gitleaks", "semgrep", "ruff", "pip-audit")

# Pinned gitleaks release. Real values sourced from the project's published
# `gitleaks_<ver>_checksums.txt` (github.com/gitleaks/gitleaks release
# v8.21.2 assets), not placeholders -- verified via sha256 before a
# downloaded binary is ever trusted/extracted/executed. `_fix_gitleaks` is
# intentionally never exercised by the test suite (no network in tests).
GITLEAKS_VERSION = "8.21.2"
# NOTE: no "windows_x32" entry -- `_gitleaks_platform_key` below can never
# return that key (32-bit Windows falls to the `None` branch), so a pinned
# checksum for it would be unreachable dead weight. Dropped rather than
# wired up: 32-bit Windows is not a supported target.
GITLEAKS_SHA256 = {
    "windows_x64": "f238c85e5f47e18fac779ce71ee11091cf70a0a8fb4415f165efba2800eef133",
    "linux_x64": "5bc41815076e6ed6ef8fbecc9d9b75bcae31f39029ceb55da08086315316e3ba",
    "linux_arm64": "654c935542c89f565aabe7bf7c6c500830f116c114f0aeb509d2460c1ac2e6da",
    "darwin_x64": "5b42c6e4b1fd693eaeb2b5b7faa5f17a1434299d4deb2de63d4b2efd7c753128",
    "darwin_arm64": "cad3de5dc9a4d5447d967a70a4d49499c557f04db028274cc324f9ff983f6502",
}
GITLEAKS_RELEASE_URL = (
    f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/{{asset}}"
)


@dataclass
class ToolStatus:
    name: str
    present: bool
    version: str = ""
    detail: str = ""


def _tools_dir() -> Path:
    """Seam for tests -- monkeypatch this rather than touching the real
    ~/.aramid/tools on the machine running the test suite."""
    return Path.home() / ".aramid" / "tools"


def _exe_name(name: str) -> str:
    return f"{name}.exe" if sys.platform == "win32" else name


def _scripts_dirs() -> list[Path]:
    """Every plausible location pip may have installed this interpreter's
    console scripts to: the default sysconfig scheme, plus the per-user
    scheme (an editable/`--user` install -- aramid's own on this host --
    lands console scripts under the user scheme, which the default scheme
    alone does not report)."""
    dirs = [Path(sysconfig.get_path("scripts"))]
    user_scheme = "nt_user" if os.name == "nt" else "posix_user"
    try:
        user_dir = Path(sysconfig.get_path("scripts", user_scheme))
        if user_dir not in dirs:
            dirs.append(user_dir)
    except (KeyError, ValueError):
        pass
    return dirs


def _locate_owned_tool(name: str) -> Path | None:
    exe = shutil.which(name)
    if exe:
        return Path(exe)
    for scripts_dir in _scripts_dirs():
        candidate = scripts_dir / _exe_name(name)
        if candidate.exists():
            return candidate
    return None


def _locate_gitleaks() -> Path | None:
    exe = shutil.which("gitleaks")
    if exe:
        return Path(exe)
    candidate = _tools_dir() / _exe_name("gitleaks")
    return candidate if candidate.exists() else None


def probe_tool(name: str) -> ToolStatus:
    """Probe one tool via `<exe> --version`. Never raises -- a missing
    binary, a timeout, or a non-zero/garbled --version all collapse to
    "missing" (doctor's job is to report honestly, not to guess)."""
    exe = _locate_gitleaks() if name == "gitleaks" else _locate_owned_tool(name)
    if exe is None:
        return ToolStatus(name, False, detail="not found on PATH or in aramid's managed locations")

    # Prepend the resolved exe's own directory to PATH: pip's console-script
    # dir is frequently absent from PATH, and semgrep's wrapper shells out to
    # a sibling executable by bare name -- both need this to succeed.
    env = {**os.environ, "PATH": str(exe.parent) + os.pathsep + os.environ.get("PATH", "")}
    try:
        # noqa justification (S603): `exe` is not attacker-controlled -- it
        # is the Path this function itself just resolved via
        # `_locate_gitleaks`/`_locate_owned_tool` (shutil.which or a fixed,
        # known scripts dir), and `name` comes from the hardcoded ALL_TOOLS
        # tuple above, never external input. Probing "<tool> --version" is
        # doctor's whole job.
        cp = subprocess.run([str(exe), "--version"], capture_output=True, text=True,  # noqa: S603
                             timeout=15, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ToolStatus(name, False, detail=str(exc))

    output = (cp.stdout or cp.stderr).strip()
    version = output.splitlines()[0] if output else ""
    if cp.returncode != 0:
        return ToolStatus(name, False, version, detail=f"--version exited {cp.returncode}")
    return ToolStatus(name, True, version)


def _sh_path_to_win(interp_sh: str) -> Path | None:
    """Reverse of `hooks.win_sh_path`: `/c/x/y` -> `C:/x/y`."""
    if len(interp_sh) >= 3 and interp_sh[0] == "/" and interp_sh[2] == "/":
        return Path(f"{interp_sh[1].upper()}:{interp_sh[2:]}")
    return Path(interp_sh) if interp_sh else None


def probe_interpreter(root: Path) -> ToolStatus:
    """Probe the interpreter baked into the installed pre-commit shim, if
    any -- parses the `INTERP="..."` line `render_shim` writes. Falls back
    to reporting the interpreter doctor itself is running under when no
    shim is installed yet (nothing recorded to check)."""
    from aramid.hooks import hooks_dir

    shim = hooks_dir(root) / "pre-commit"
    if not shim.exists():
        return ToolStatus("interpreter", True, sys.executable,
                           detail="no shim installed yet -- reporting the current interpreter")

    text = shim.read_bytes().decode("utf-8", errors="replace")
    interp_sh = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('INTERP="') and line.endswith('"'):
            interp_sh = line[len('INTERP="'):-1]
            break

    if interp_sh is None:
        return ToolStatus("interpreter", False, detail="could not parse the installed shim")

    win_path = _sh_path_to_win(interp_sh)
    exists = win_path is not None and win_path.exists()
    detail = "" if exists else "baked interpreter path no longer exists -- run `aramid init` or `aramid doctor --fix`"
    return ToolStatus("interpreter", exists, interp_sh, detail=detail)


def probe_toolchain(root: Path) -> dict[str, ToolStatus]:
    """Probe every owned tool plus the recorded shim interpreter. This is
    the seam tests monkeypatch (`doctor.probe_toolchain`) to simulate a
    missing tool without touching the real machine's PATH/Scripts dir."""
    statuses = {name: probe_tool(name) for name in ALL_TOOLS}
    statuses["interpreter"] = probe_interpreter(root)
    return statuses


def _report_line(status: ToolStatus) -> str:
    if status.present:
        detail = f" ({status.detail})" if status.detail else ""
        return f"  OK       {status.name:<12} {status.version}{detail}".rstrip()
    return f"  MISSING  {status.name:<12} {status.detail}".rstrip()


def _fix_pip_toolchain() -> None:
    """`pip install` the owned pip toolchain into the CURRENT interpreter
    (never a different one -- doctor repairs the interpreter it is itself
    running under)."""
    # noqa justification (S603): `sys.executable` is this process's own
    # interpreter path and OWNED_PIP_TOOLCHAIN is the hardcoded tuple
    # ("ruff", "semgrep", "pip-audit") declared above -- no external input
    # reaches this argv. `pip install`-ing aramid's own owned toolchain is
    # exactly what `doctor --fix` is for.
    subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", *OWNED_PIP_TOOLCHAIN],  # noqa: S603
                   check=False)


def _gitleaks_platform_key() -> str | None:
    machine = platform.machine().lower()
    if sys.platform == "win32":
        return "windows_x64" if machine in ("amd64", "x86_64") else None
    if sys.platform == "darwin":
        return "darwin_arm64" if machine in ("arm64", "aarch64") else "darwin_x64"
    if sys.platform.startswith("linux"):
        return "linux_arm64" if machine in ("arm64", "aarch64") else "linux_x64"
    return None


def _fix_gitleaks() -> bool:
    """Download the pinned gitleaks release for this platform into
    `~/.aramid/tools/`, verifying sha256 BEFORE ever extracting/trusting it.
    Network-touching by design -- never exercised by the test suite (the
    pinned Task 6.3 test is monkeypatch-only)."""
    key = _gitleaks_platform_key()
    if key is None or key not in GITLEAKS_SHA256:
        return False

    ext = "zip" if "windows" in key else "tar.gz"
    asset = f"gitleaks_{GITLEAKS_VERSION}_{key}.{ext}"
    url = GITLEAKS_RELEASE_URL.format(asset=asset)

    try:
        # noqa justification (S310): `url` is built a few lines above from
        # GITLEAKS_RELEASE_URL (a hardcoded "https://github.com/..." format
        # string), GITLEAKS_VERSION (a pinned constant), and `key`/`asset`
        # derived from `_gitleaks_platform_key()`'s small fixed set of
        # platform strings -- never from user/CLI/network input, so the
        # scheme is always https:// by construction, and the downloaded
        # bytes are sha256-verified against GITLEAKS_SHA256 below before
        # ever being trusted/extracted/executed.
        with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310
            data = resp.read()
    except OSError as exc:
        # covers urllib.error.URLError/HTTPError (both OSError subclasses)
        # plus raw socket errors -- a network failure during `doctor --fix`
        # should report cleanly, not crash with a raw traceback.
        print(f"aramid: doctor --fix: could not download gitleaks: {exc}", file=sys.stderr)
        return False

    if hashlib.sha256(data).hexdigest() != GITLEAKS_SHA256[key]:
        return False

    tools_dir = _tools_dir()
    tools_dir.mkdir(parents=True, exist_ok=True)
    exe_name = _exe_name("gitleaks")
    dest = tools_dir / exe_name

    if ext == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            dest.write_bytes(zf.read(exe_name))
    else:
        import tarfile
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            member = tf.extractfile(exe_name)
            if member is None:
                return False
            dest.write_bytes(member.read())

    dest.chmod(0o755)
    return True


def probe_providers() -> list[str]:
    """Zero-LLM-call provider probe (spec section 7): which/env/spend reads
    only. Informational -- provider absence never changes doctor's exit code
    (LLM review degrades gracefully; BLOCK-tier tools do not)."""
    from datetime import datetime, timezone
    from aramid.providers import spend as spend_mod
    lines = []
    for name, exe in (("claude-cli", "claude"), ("codex-cli", "codex")):
        found = shutil.which(exe)
        lines.append(f"  OK       {name:<12} {found}" if found
                     else f"  MISSING  {name:<12} not found on PATH")
    if not os.environ.get("OPENROUTER_API_KEY"):
        lines.append("  MISSING  openrouter   no OPENROUTER_API_KEY in environment")
    else:
        # Self-enforcing fail-safe: the "never crashes" contract for doctor
        # must not depend solely on spend.py's internal guarantees. month is
        # already None on an unreadable log (fail-closed money path), but any
        # unexpected error here degrades to an informational line rather than
        # propagating out of cmd_doctor (which has no outer try/except).
        try:
            month = spend_mod.month_spend_usd(
                "openrouter", datetime.now(timezone.utc).isoformat())
            detail = ("spend log unreadable -- calls refused" if month is None
                      else f"this month ${month:.2f}")
            lines.append(f"  OK       openrouter   key set; {detail}")
        except Exception:
            lines.append("  OK       openrouter   key set; openrouter probe unavailable")
    if not os.environ.get("OLLAMA_API_KEY"):
        lines.append("  MISSING  ollama-cloud no OLLAMA_API_KEY in environment")
    else:
        lines.append("  OK       ollama-cloud key set")
    return lines


def cmd_doctor(root: Path, fix: bool = False) -> int:
    """Probe the toolchain (and shim interpreter); when `fix`, repair
    what's missing/owned and re-probe. Returns 0 if both BLOCK-tier tools
    (gitleaks, semgrep) are present, else 2 -- WARN-tier tool absence
    (ruff, pip-audit) is reported but never changes the exit code."""
    statuses = probe_toolchain(root)

    if fix:
        if any(not statuses[name].present for name in OWNED_PIP_TOOLCHAIN):
            _fix_pip_toolchain()
        if not statuses["gitleaks"].present:
            _fix_gitleaks()
        statuses = probe_toolchain(root)

    print("aramid doctor:")
    for name in ALL_TOOLS:
        print(_report_line(statuses[name]))
    print(_report_line(statuses["interpreter"]))

    print("llm providers:")
    for line in probe_providers():
        print(line)

    missing_block = [name for name in BLOCK_TIER if not statuses[name].present]
    if missing_block:
        print(f"aramid: doctor: BLOCK-tier tool(s) missing: {', '.join(missing_block)} "
              f"-- run `aramid doctor --fix`", file=sys.stderr)
        return 2

    print("aramid: doctor: all BLOCK-tier tools present.")
    return 0
