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
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

from aramid import toolpath
from aramid.runners import clippy as clippy_runner
from aramid.runners import deps as deps_runner

# T-2: `doctor` also probes the repo's TEST toolchain (`probe_tests` below).
# `tests` is BLOCK-tier in the gate (pipeline.BLOCK_TIER_KEYS), but neither
# BLOCK_TIER nor ALL_TOOLS above has ever covered it -- so doctor could print
# "all BLOCK-tier tools present" and exit 0 on a repo whose test tool is
# absent, and the very next push would be blocked by a degraded BLOCK-tier
# `tests` runner doctor never warned about. Deliberately kept OUT of
# BLOCK_TIER/ALL_TOOLS (see probe_tests' own docstring): those two tuples
# drive the unconditional probe loop and `--fix`, and test tools are
# repo-dependent, not aramid-owned -- `--fix` must never try to install them.
# probe_tests' own MISSING verdicts fold into cmd_doctor's exit code via a
# separate `missing_tests` list, parallel to `missing_block` but never
# merged with it.

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
# downloaded binary is ever trusted/extracted/executed. `_fix_gitleaks`'s
# download/checksum/extract path is covered offline via a synthetic archive +
# injected checksum (tests/integration/test_doctor_fix_gitleaks.py); the real
# network fetch itself is never exercised in tests.
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
    # Third state, deliberately not a `present` flip. "Nothing to probe" is
    # neither present nor missing: flipping `present` would fold it into
    # `missing_tests` and fail doctor with "test toolchain broken", inventing
    # a failure the gate would never produce. Report, do not block -- same
    # rule as probe_deps' cargo-audit.
    warn: bool = False


def _tools_dir() -> Path:
    """Download DESTINATION for `_fix_gitleaks`. Delegates to `toolpath` so
    there is one definition; kept as a named function because the fix tests
    monkeypatch it to avoid writing to the real ~/.aramid/tools."""
    return toolpath.tools_dir()


def _exe_name(name: str) -> str:
    return toolpath.exe_name(name)


def _scripts_dirs() -> list[Path]:
    return toolpath.scripts_dirs()


# Both locators now delegate to the SAME resolver the runners use. They used
# to duplicate its search order, and the duplicate drifted: doctor looked in
# ~/.aramid/tools while `run_subprocess` used bare `shutil.which`, so
# `doctor --fix` could install gitleaks, report "OK", and leave the gate
# skipping it as MISSING. One resolver is what makes doctor's verdict true.
def _locate_owned_tool(name: str) -> Path | None:
    return toolpath.resolve(name)


def _locate_gitleaks() -> Path | None:
    return toolpath.resolve("gitleaks")


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
        # S603 justification: `exe` is not attacker-controlled -- it
        # is the Path this function itself just resolved via
        # `_locate_gitleaks`/`_locate_owned_tool` (shutil.which or a fixed,
        # known scripts dir), and `name` comes from the hardcoded ALL_TOOLS
        # tuple above, never external input. Probing "<tool> --version" is
        # doctor's whole job.
        cp = subprocess.run([str(exe), "--version"], capture_output=True, text=True,  # noqa: S603
                             encoding="utf-8", errors="replace",
                             timeout=15, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ToolStatus(name, False, detail=str(exc))

    output = (cp.stdout or cp.stderr).strip()
    version = output.splitlines()[0] if output else ""
    if cp.returncode != 0:
        return ToolStatus(name, False, version, detail=f"--version exited {cp.returncode}")
    return ToolStatus(name, True, version)


def _version_of(exe: Path) -> str:
    """`<exe> --version`, first line, or "" if it will not answer. Same
    PATH-prepend as probe_tool for the same reason (semgrep's wrapper shells
    out to a sibling by bare name). Never raises: this feeds an advisory
    notice, and a notice must not be able to fail a doctor run."""
    env = {**os.environ, "PATH": str(exe.parent) + os.pathsep + os.environ.get("PATH", "")}
    try:
        cp = subprocess.run([str(exe), "--version"], capture_output=True, text=True,  # noqa: S603
                             encoding="utf-8", errors="replace", timeout=15, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    out = (cp.stdout or cp.stderr).strip()
    return out.splitlines()[0] if out else ""


def divergence_lines() -> list[str]:
    """Report every declared dependency whose resolved copy is not the one pip
    installed beside aramid. Empty -- and therefore silent -- in the ordinary
    case, including the common one where a user installed the analyzers
    themselves and has no venv copy at all; a notice on every run is a notice
    nobody reads.

    Both ABSOLUTE PATHS and both versions are printed. Naming only the tool
    would leave the reader unable to tell which analyzer produced a finding
    set, which is the entire question this answers.

    Advisory, never a failure: PATH-first is intended behaviour
    (`toolpath.divergence`), and an operator pinning their own toolchain is
    doing something legitimate. What they should not have to do is guess that
    it happened."""
    lines = []
    for d in toolpath.divergences():
        raw_rv, raw_dv = _version_of(d.resolved), _version_of(d.dependency_copy)
        # Two different FILES of the same VERSION cannot report differently,
        # so saying so trains the reader to skip this block. Found by looking
        # at the real output, not by a test: on a machine with both a
        # user-scheme and a venv pip-audit 2.10.1 the first version of this
        # printed DRIFT for it. UNKNOWN is not agreement -- if either copy
        # will not answer `--version`, report, because the silent case would
        # be the one where the unreadable binary is the broken one.
        if raw_rv and raw_dv and raw_rv == raw_dv:
            continue
        rv = raw_rv or "version unknown"
        dv = raw_dv or "version unknown"
        lines.append(f"  DRIFT    {d.tool:<12} running {rv}")
        lines.append(f"                        {d.resolved}")
        lines.append(f"           aramid's own dependency is {dv}")
        lines.append(f"                        {d.dependency_copy}")
    if lines:
        lines.append("  findings are only comparable across machines when these agree; "
                     "PATH wins by design (see toolpath.divergence)")
    return lines


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


def probe_deps(root: Path) -> list[ToolStatus]:
    """Probe the repo's dependency-audit toolchain for stacks whose audit
    tool is NOT in `ALL_TOOLS`. Today that means cargo-audit.

    Why this exists (graphite, round 14, 2026-07-31): `ALL_TOOLS` covers
    gitleaks/semgrep/ruff/pip-audit, so on a Cargo workspace cargo-audit
    could be selected by the gate, MISSING at run time, and doctor still
    print a clean bill of health -- the only supply-chain gate on that repo
    absent while the health command says all is well. Structurally the same
    "control that looks like coverage and is not" failure as the flat
    cargo-audit severity constant.

    Two deliberate boundaries, both mirroring `probe_tests`:
      - Kept OUT of `ALL_TOOLS`/`BLOCK_TIER`: those drive the unconditional
        probe loop and `--fix`, and cargo-audit is a cargo subcommand plugin
        (`cargo install cargo-audit`), not an aramid-owned pip dependency --
        `--fix` must never try to install it.
      - Conditional on the lockfile that SELECTS the tool, so a Python or JS
        repo never sees a spurious "cargo-audit missing".
    Unlike `probe_tests`, these statuses must NOT feed doctor's exit code:
    `deps` is not in `pipeline.BLOCK_TIER_KEYS`, so a missing cargo-audit
    can never fail a gate, and doctor inventing a failure the gate would
    never produce is its own kind of lie. Report, do not block.
    """
    statuses: list[ToolStatus] = []
    if (root / "Cargo.lock").exists():
        resolved = toolpath.resolve(deps_runner.NAME_CARGO_AUDIT)
        statuses.append(
            ToolStatus(deps_runner.NAME_CARGO_AUDIT, True, detail=str(resolved))
            if resolved is not None else
            ToolStatus(
                deps_runner.NAME_CARGO_AUDIT, False,
                detail="not installed -- Rust dependency advisories are NOT being "
                       "checked on this repo; `cargo install cargo-audit` to enable "
                       "(non-blocking: deps is not a BLOCK-tier gate)"))
    # clippy keys off Cargo.toml, not Cargo.lock: the runner analyses the
    # crate, which exists whether or not a lockfile has been generated.
    if (root / "Cargo.toml").exists():
        resolved = toolpath.resolve(clippy_runner.CLIPPY_BIN)
        statuses.append(
            ToolStatus(clippy_runner.NAME, True, detail=str(resolved))
            if resolved is not None else
            ToolStatus(
                clippy_runner.NAME, False,
                detail="not installed -- Rust lint is NOT being checked on this "
                       "repo; `rustup component add clippy` to enable "
                       "(non-blocking: clippy is not a BLOCK-tier gate)"))
    return statuses


def _tests_section(cfg) -> dict:
    """`cfg.tests` if it is actually a dict -- a hand-edited aramid.toml
    could set `tests` to any TOML type (e.g. a bare string or number), and
    that must degrade to "no section" rather than blow up the `.get()`
    calls below. Mirrors aramid.pipeline.run_gate's own `tests_cfg =
    cfg.tests if isinstance(cfg.tests, dict) else {}` guard at the
    RunContext construction site -- same rule, so doctor and the real gate
    can never disagree about what counts as "no [tests] section"."""
    return cfg.tests if isinstance(cfg.tests, dict) else {}


def _tests_enabled(cfg) -> bool:
    return bool(_tests_section(cfg).get("enabled", True))


def _effective_test_command(cfg):
    """The SAME precedence aramid.pipeline.run_gate resolves onto
    RunContext.test_command: `[tests].command` wins over the legacy
    top-level `test_command` (schema v1's key, shipped documented but with
    no read site anywhere until now -- see pipeline.py's own comment at
    that call site). Falsy (None/""/[]) means "not configured" either
    way -- matching `runners.tests.run()`'s own `if command:` check, so a
    RunContext built from this same Config would make the identical
    branch decision doctor just reported."""
    return _tests_section(cfg).get("command", cfg.test_command)


def _configured_argv0(command) -> tuple[str | None, str | None]:
    """Parse a configured `[tests].command` down to just its argv[0] -- the
    only thing doctor may look at (see `probe_tests`' docstring for why it
    must never reach `probe_tool` here). Reuses `runners.tests._argv` -- the
    exact parsing rule `run_custom` applies to this same config value at
    gate time -- rather than a second, independent implementation that
    could quietly drift from it (the same one-true-resolver argument
    `toolpath.py`'s own docstring makes about tool-path resolution).

    `_argv` itself has no try/except: it is only ever called one step away
    from a subprocess boundary, inside a gate runner. doctor has no such
    boundary, and its own contract (`probe_tool`'s docstring) is that it
    never raises -- so this wraps the call and turns any TOML value
    `_argv` cannot parse (an int, a float, a bool, a table/dict -- anything
    that is not a list/tuple/str) into a plain reported reason instead of
    a propagating exception. Also rejects an argv that parses but is empty,
    or whose first element is itself an empty string (`shlex.split('"" -q')`
    -> `['', '-q']`) -- `Path("")` / `toolpath.resolve("")` would otherwise
    resolve to the cwd rather than visibly failing.

    Returns (argv0, None) on success, or (None, reason) -- reason is always
    a human-readable string, never an exception -- when `command` doesn't
    yield a usable argv[0]."""
    from aramid.runners.tests import _argv
    try:
        argv = _argv(command)
    except (TypeError, ValueError, AttributeError) as exc:
        return None, f"[tests].command is set but not a valid command ({exc})"
    if not argv or not argv[0]:
        return None, "[tests].command is set but parses to an empty command"
    return argv[0], None


def probe_tests(root: Path, cfg) -> list[ToolStatus]:
    """Probe the repo's TEST toolchain -- the BLOCK-tier `tests` runner
    (pipeline.BLOCK_TIER_KEYS) that BLOCK_TIER/ALL_TOOLS above have never
    covered (see this module's docstring). Mirrors `runners.tests.run()`'s
    own dispatch order exactly -- `[tests].enabled`, then a configured
    command, then detection -- so what doctor reports is always what the
    gate would actually try to do:

      0. `[tests].enabled = false`: `pipeline._is_applicable` removes the
         tests runner from selection entirely -- a runner that is never
         selected cannot surface as MISSING/degraded, so a missing tool
         behind a disabled gate is not a broken toolchain. Reported, never
         counted as broken -- the same "legitimate state" logic as case 3
         below, just gated on config instead of detection.
      1. `[tests].command` (or the legacy top-level `test_command`) is
         set: the configured command short-circuits detection entirely,
         so pytest/npm are irrelevant. SECURITY: this value is EXTERNAL
         INPUT -- `aramid.toml` ships with a cloned repo -- so it is never
         passed to `probe_tool`, which executes `<name> --version` under a
         S603 justification that assumes `name` is always a hardcoded
         literal, never external input. `toolpath.resolve` is pure lookup
         and executes nothing, so it -- and only it -- is used here.
         Resolving argv[0] proves the binary exists, NOT that the suite
         runs or that its selector matches anything -- the wording below
         says so.
      2. No command, but `detect_tests` finds pytest and/or npm: probe
         each with the existing hardcoded-name `probe_tool` path, exactly
         as the four ALL_TOOLS tools are probed -- "pytest"/"npm" here are
         hardcoded string literals in this function, never external input,
         so `probe_tool`'s S603 justification holds for these calls too.
      3. Neither: no test suite exists in this repo. A legitimate,
         non-broken state -- reported as present=True so it can never
         contribute a MISSING/exit-2 verdict; a repo with no tests must
         not be told its toolchain is broken.

    Returns one ToolStatus per probed tool (0, 1, or 2 entries depending on
    the case) -- never raises, matching `probe_tool`'s own contract: a
    malformed `[tests].command` degrades to a report via
    `_configured_argv0` above, same as a missing/garbled tool degrades to
    "missing"."""
    if not _tests_enabled(cfg):
        return [ToolStatus(
            "tests", True,
            detail="[tests].enabled = false -- the BLOCK-tier test gate is "
                   "disabled for this repo; toolchain not probed")]

    command = _effective_test_command(cfg)
    if command:
        argv0, reason = _configured_argv0(command)
        if reason is not None:
            return [ToolStatus("tests", False, detail=reason)]
        located = toolpath.resolve(argv0)
        if located is None:
            return [ToolStatus(
                "tests", False,
                detail=(f"[tests].command is configured (argv[0] '{argv0}') "
                        f"but '{argv0}' was not found on PATH or in "
                        f"aramid's managed locations"))]
        return [ToolStatus(
            "tests", True, str(located),
            detail=(f"custom [tests].command configured -- argv[0] "
                    f"'{argv0}' resolves; this does not verify the suite "
                    f"runs or that its selector matches anything"))]

    from aramid.detectors import detect_tests
    kinds = detect_tests(root)
    if not kinds:
        return [ToolStatus(
            "tests", True, warn=True,
            detail="no test suite detected -- the BLOCK-tier test gate will "
                   "run NOTHING, so a green gate will not mean your tests "
                   "passed. aramid recognizes only pytest (test_*.py, "
                   "*_test.py, conftest.py) and an npm `test` script; cargo "
                   "and go suites are not detected. Set [tests].command to "
                   "point aramid at your suite, or [tests].enabled = false "
                   "to declare this repo has none")]

    out = []
    if "pytest" in kinds:
        s = probe_tool("pytest")
        out.append(ToolStatus("tests-pytest", s.present, s.version, s.detail))
    if "npm" in kinds:
        s = probe_tool("npm")
        out.append(ToolStatus("tests-npm", s.present, s.version, s.detail))
    # Same rule as the two above: probed because detect_tests found the
    # SUITE, so a missing binary is a BLOCK-tier gate that cannot run --
    # exactly what this probe exists to catch before the next push does.
    if "cargo" in kinds:
        s = probe_tool("cargo")
        out.append(ToolStatus("tests-cargo", s.present, s.version, s.detail))
    if "go" in kinds:
        s = probe_tool("go")
        out.append(ToolStatus("tests-go", s.present, s.version, s.detail))
    return out


def _report_line(status: ToolStatus) -> str:
    if status.warn:
        return f"  WARN     {status.name:<12} {status.detail}".rstrip()
    if status.present:
        detail = f" ({status.detail})" if status.detail else ""
        return f"  OK       {status.name:<12} {status.version}{detail}".rstrip()
    return f"  MISSING  {status.name:<12} {status.detail}".rstrip()


def _fix_pip_toolchain() -> None:
    """`pip install` the owned pip toolchain into the CURRENT interpreter
    (never a different one -- doctor repairs the interpreter it is itself
    running under)."""
    # S603 justification: `sys.executable` is this process's own
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
        # S310 justification: `url` is built a few lines above from
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


def _autolearn_probe_line() -> str:
    """State-file health (autolearn spec section 12). Informational only --
    an unreadable state is treated as empty by the engine (cold start)."""
    import json as _json

    from aramid import autolearn
    try:
        p = autolearn.state_path()
        if not p.exists():
            return "  OK       autolearn    no state yet (cold start = deterministic ladder)"
        try:
            data = _json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return ("  DEGRADED autolearn    state unreadable -- treated as empty; "
                    "`aramid autolearn --rebuild` repairs it")
        if not isinstance(data, dict) or data.get("version") != autolearn.STATE_VERSION:
            return ("  DEGRADED autolearn    foreign state version -- treated as empty; "
                    "`aramid autolearn --rebuild` repairs it")
        return (f"  OK       autolearn    state readable; "
                f"{len(data.get('posteriors', {}))} posterior cell(s)")
    except Exception:
        return "  OK       autolearn    probe unavailable"


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


def probe_enforcement(root: Path) -> str | None:
    """Detect "configured but NOT enforced": `aramid.toml` present (so the
    repo IS onboarded) while the gate shims are absent (so nothing fires).

    This is the fresh-clone hole. `.git/hooks` is not version-controlled, so
    cloning an onboarded repo -- or checking it out on another machine --
    yields the committed config with no shims. The repo looks onboarded and
    the gate silently never runs.

    Returns a message, or None when there is nothing to report. No
    `aramid.toml` means deliberately not onboarded, which is NOT a finding:
    nagging every un-onboarded repo is how a real warning gets ignored.

    Deliberately separate from `probe_interpreter`, which reports "no shim
    installed yet" as a benign fallback note. Same underlying observation,
    opposite severity -- that line is fine pre-`init` and alarming after it,
    and only this function knows which case it is."""
    try:
        if not (root / "aramid.toml").exists():
            return None
        from aramid.hooks import GATES, hooks_dir
        hdir = hooks_dir(root)
        missing = [g.value for g in GATES if not (hdir / g.value).exists()]
        if not missing:
            return None
        return (f"hooks: aramid.toml is present but {', '.join(missing)} "
                f"missing from {hdir} -- this repo is configured but NOT "
                f"enforced. Git hooks are not cloned; run `aramid init .`")
    except Exception:
        return None                     # fail open: never break doctor


def cmd_doctor(root: Path, fix: bool = False) -> int:
    """Probe the toolchain (and shim interpreter); when `fix`, repair
    what's missing/owned and re-probe. Returns 0 if both BLOCK-tier tools
    (gitleaks, semgrep) are present, else 2 -- WARN-tier tool absence
    (ruff, pip-audit) is reported but never changes the exit code.

    Also returns 2 for "configured but NOT enforced" (see
    `probe_enforcement`). That widens 2 from "a BLOCK-tier tool is missing"
    to "the gate is not fully operational", which covers both: in each case
    the repo is not actually being gated, and reporting 0 would be a false
    green light.

    T-2: also returns 2 when the repo's TEST toolchain is broken (see
    `probe_tests`) -- a detected-or-configured test suite whose tool cannot
    be resolved, exactly the state that leaves the BLOCK-tier `tests`
    runner degraded at the next push. Kept as its own `missing_tests` list,
    parallel to `missing_block` but never merged into BLOCK_TIER itself
    (test tools are repo-dependent, not aramid-owned -- see this module's
    docstring). A repo with no test suite, or with `[tests].enabled =
    false`, is a legitimate state and never contributes here.

    [review] Also returns 3 -- the "engine or config error" tier used
    throughout this codebase (cli.py's argparse-failure remap;
    cmd_status's identical `except Exception: ... return 3` around this
    SAME load_config call) -- when aramid.toml cannot be parsed at all.
    Deliberately its own code, never folded into the 2 above: a broken
    config and a missing BLOCK-tier tool are different problems with
    different remedies (fix the TOML vs. install the tool), and conflating
    them would send an operator chasing the wrong one. Unlike cmd_status,
    doctor does NOT abort on this -- every other probe here (ALL_TOOLS,
    interpreter, llm providers, autolearn) is independent of aramid.toml's
    content and still runs and prints; only the test-toolchain probe
    (which needs `[tests].command`/`.enabled` from that same file) is
    skipped, replaced by a status saying so. A diagnostic tool that dies on
    the one input it should diagnose is worse than one that never had the
    feature -- matching this module's existing probe_enforcement/
    probe_providers fail-open convention."""
    statuses = probe_toolchain(root)

    if fix:
        if any(not statuses[name].present for name in OWNED_PIP_TOOLCHAIN):
            _fix_pip_toolchain()
        if not statuses["gitleaks"].present:
            _fix_gitleaks()
        statuses = probe_toolchain(root)

    from aramid import config as config_mod
    cfg = None
    config_error: str | None = None
    try:
        cfg = config_mod.load_config(root)
    except Exception as exc:
        # fail open: never break doctor -- aramid.toml is EXTERNAL input
        # (ships with a cloned repo, hand-editable), and a broken one is
        # precisely when an operator reaches for `doctor`. See
        # probe_enforcement/probe_providers above for the same convention,
        # and cmd_status for the same try/except around this same call.
        config_error = str(exc)

    test_statuses = (probe_tests(root, cfg) if cfg is not None else
                     [ToolStatus("tests", True,
                                 detail="not probed -- aramid.toml is unparseable "
                                        "(see the error reported below)")])

    print("aramid doctor:")
    for name in ALL_TOOLS:
        print(_report_line(statuses[name]))
    for s in test_statuses:
        print(_report_line(s))
    # Reported, never folded into `missing_block`/`missing_tests` below:
    # `deps` is not BLOCK-tier, so a missing cargo-audit cannot fail a gate
    # and must not fail doctor. See `probe_deps`.
    for s in probe_deps(root):
        print(_report_line(s))
    print(_report_line(statuses["interpreter"]))
    for line in divergence_lines():
        print(line)

    print("llm providers:")
    for line in probe_providers():
        print(line)

    print("autolearn:")
    print(_autolearn_probe_line())

    unenforced = probe_enforcement(root)
    if unenforced:
        print(f"aramid: doctor: {unenforced}", file=sys.stderr)

    if config_error is not None:
        print(f"aramid: doctor: aramid.toml is unparseable -- {config_error} "
              f"-- fix aramid.toml and re-run `aramid doctor` (the test "
              f"toolchain could not be probed)", file=sys.stderr)

    missing_block = [name for name in BLOCK_TIER if not statuses[name].present]
    missing_tests = [s.name for s in test_statuses if not s.present]
    if missing_block:
        print(f"aramid: doctor: BLOCK-tier tool(s) missing: {', '.join(missing_block)} "
              f"-- run `aramid doctor --fix`", file=sys.stderr)
    if missing_tests:
        print(f"aramid: doctor: BLOCK-tier test toolchain broken: "
              f"{', '.join(missing_tests)} -- the next push will be blocked "
              f"by a degraded BLOCK-tier `tests` runner", file=sys.stderr)
    if missing_block or missing_tests:
        return 2

    if config_error is not None:
        return 3

    if unenforced:
        return 2                        # tools fine, but nothing is gating

    warn_tests = [s for s in test_statuses if s.warn]
    for s in warn_tests:
        # A POINTER, not the detail again -- the WARN row above already
        # carries the full text, and printing the paragraph twice is how a
        # loud channel teaches people to skim past it. Same shape as the
        # missing_block line: short here, detail in the table.
        print(f"aramid: doctor: {s.name}: the BLOCK-tier `{s.name}` gate has "
              f"nothing to run in this repo -- see the WARN line above.",
              file=sys.stderr)
    if warn_tests:
        # Never the bare sentence: on a Rust or Go repo it was the last thing
        # printed, and it reads as coverage the run does not have.
        print("aramid: doctor: all BLOCK-tier TOOLS present, but see the "
              "warning(s) above -- not every BLOCK-tier gate has something "
              "to run here.")
        return 0
    print("aramid: doctor: all BLOCK-tier tools present.")
    return 0
