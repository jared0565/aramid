"""PLAT-1: prove an INSTALLED aramid works, not the editable checkout.

Every other CI step runs against `pip install -e .[dev]`, so the package,
its vendored semgrep ruleset and its semgrep binary all come from the source
tree or the job's base environment. A green run there proves nothing about
the wheel or the sdist a user installs.

    installed_smoke.py wheel <aramid-*.whl>
        A clean venv, the wheel installed WITH its dependencies, then a real
        `check --gate pre-push --all --strict --json` against a throwaway git
        repo holding one line the vendored OWASP ruleset flags.
    installed_smoke.py sdist <aramid-*.tar.gz>
        A clean venv, the sdist installed with `--no-deps` -- the same arm as
        the release job's sdist smoke, and the only one that reproduces the
        0.17.10 failure (an sdist whose runner chain imports a dependency).

Every assertion is on WHERE a thing resolved or on a JSON field, never on
the exit code: a fresh fixture ledger, the pre-push ratchet, the fresh-ledger
downgrade and `--strict` each move the exit for reasons unrelated to this.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

FIXTURE_FILE = "app.py"
FIXTURE_SOURCE = (
    "import hashlib\n"
    "\n"
    "\n"
    "def digest(data: bytes) -> str:\n"
    "    return hashlib.md5(data).hexdigest()\n"
)
# The gate's BLOCK-tier `tests` slot needs a test runner the wheel does not
# ship. Off, explicitly, and asserted below as off -- not left to degrade.
FIXTURE_CONFIG = "[tests]\nenabled = false\n"
WEAK_HASH_RULE = "python-weak-hash-md5-sha1"

# Import exactly what the release job's smoke imports: this chain is held
# dependency-free (tests/unit/test_release_smoke_imports.py), so it runs under
# `--no-deps` too.
PROBE = ("import pathlib, aramid; from aramid.runners import semgrep; "
         "print(pathlib.Path(aramid.__file__).resolve()); "
         "print(pathlib.Path(semgrep.VENDORED_RULES_PATH).resolve())")


class SmokeFailed(Exception):
    """A check failed. Never `assert`: `python -O` strips those, and a smoke
    that cannot fail proves nothing."""


def require(ok, message: str) -> None:
    if not ok:
        raise SmokeFailed(message)


def bin_dir(venv: Path) -> Path:
    return venv / ("Scripts" if os.name == "nt" else "bin")


def python_in(venv: Path) -> Path:
    return bin_dir(venv) / ("python.exe" if os.name == "nt" else "python")


def inside(path, root: Path) -> bool:
    try:
        Path(path).resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def run(argv, **kw) -> subprocess.CompletedProcess:
    print("+", " ".join(str(a) for a in argv), flush=True)
    return subprocess.run([str(a) for a in argv], **kw)  # noqa: S603 - argv is built in this file


def make_venv(where: Path) -> Path:
    run([sys.executable, "-m", "venv", where], check=True)
    return where


def probe(venv: Path, python: Path, cwd: Path) -> None:
    """The package and its ruleset resolve inside `venv`. `-P` and a cwd
    outside the checkout, so neither the source tree nor the cwd can stand
    in for the installed copy."""
    out = run([python, "-P", "-c", PROBE], cwd=cwd, check=True,
              capture_output=True, text=True).stdout.split("\n")
    package, rules = out[0].strip(), out[1].strip()
    print(f"aramid imported from {package}\nruleset resolved at {rules}")
    require(inside(package, venv), f"aramid was imported from outside the venv: {package}")
    require(inside(rules, venv), f"the ruleset resolved outside the venv: {rules}")
    require(Path(rules).is_file(), f"the ruleset is missing from the install: {rules}")


def fixture(where: Path) -> Path:
    where.mkdir()
    empty = where.parent / "empty-template"
    empty.mkdir(exist_ok=True)
    # An empty template and no hooksPath: a global init.templateDir or
    # core.hooksPath must not install or run anyone's hooks in here.
    run(["git", "init", "-q", f"--template={empty}", where], check=True)
    (where / FIXTURE_FILE).write_text(FIXTURE_SOURCE, encoding="utf-8")
    (where / "aramid.toml").write_text(FIXTURE_CONFIG, encoding="utf-8")
    git = ["git", "-C", where, "-c", f"core.hooksPath={empty}",
           "-c", "user.name=smoke", "-c", "user.email=smoke@example.invalid"]
    run([*git, "add", "-A"], check=True)
    run([*git, "commit", "-q", "-m", "fixture"], check=True)
    return where


def gate_env(venv: Path, home: Path, venv_first: bool = True) -> dict:
    """The venv's scripts FIRST on PATH: `toolpath.resolve` asks
    `shutil.which` before anything else, so whichever semgrep PATH names
    first is the one the gate runs. HOME points at a scratch directory so the
    run writes nothing into the machine's ~/.aramid; gitleaks, which aramid
    does not install, is carried over from wherever it already resolves."""
    env = dict(os.environ)
    path = env.get("PATH", "")
    gitleaks = shutil.which("gitleaks")
    if gitleaks is None:
        downloaded = Path.home() / ".aramid" / "tools" / (
            "gitleaks.exe" if os.name == "nt" else "gitleaks")
        gitleaks = str(downloaded) if downloaded.is_file() else None
    require(gitleaks, "gitleaks is not on PATH and not in ~/.aramid/tools")
    path = os.pathsep.join([str(Path(gitleaks).parent), path])
    if venv_first:
        path = os.pathsep.join([str(bin_dir(venv)), path])
    env["PATH"] = path
    env["HOME"] = env["USERPROFILE"] = str(home)
    return env


def gate(venv: Path, repo: Path, env: dict) -> dict:
    cp = run([python_in(venv), "-P", "-m", "aramid", "check", "--gate", "pre-push",
              "--all", "--strict", "--json"], cwd=repo, env=env,
             capture_output=True, text=True)
    print(f"exit {cp.returncode} (not asserted)")
    if cp.stderr.strip():
        print(cp.stderr.strip())
    return json.loads(cp.stdout)


def check_gate(report: dict, venv: Path) -> None:
    ran = report["tools_ran"]
    semgrep = report["tools"].get("semgrep", {})
    print(f"tools_ran={ran} degraded={report['degraded']} semgrep={semgrep}")
    require("semgrep" in ran, f"semgrep did not run: tools_ran={ran}")
    require("semgrep" not in report["degraded"],
            f"semgrep degraded: {report['degraded_reasons'].get('semgrep')}")
    require(inside(semgrep.get("path", ""), venv),
            f"the gate ran a semgrep from outside the venv: {semgrep}")
    require("tests" not in ran and "tests" not in report["degraded"],
            "the fixture's [tests] slot was meant to be off")
    hits = [f for f in report["findings"]
            if f["tool"] == "semgrep" and f["file"] == FIXTURE_FILE
            and WEAK_HASH_RULE in f["rule"]]
    require(hits, "the installed ruleset did not flag the fixture's md5 line: "
                  f"{[(f['tool'], f['rule'], f['file']) for f in report['findings']]}")
    print(f"semgrep flagged {FIXTURE_FILE}:{hits[0]['line']} with {hits[0]['rule']}")


def main(argv: list[str]) -> int:
    # Every refusal before the first side effect: an unmatched `dist/*.whl`
    # arrives as the literal pattern, and a venv to install nothing into is
    # minutes spent to learn it.
    require(len(argv) == 2, f"usage: installed_smoke.py wheel|sdist <artifact>, not {argv!r}")
    mode, artifact = argv[0], Path(argv[1]).resolve()
    require(mode in ("wheel", "sdist"), f"mode must be wheel or sdist, not {mode!r}")
    require(artifact.is_file(), f"no such artifact: {artifact}")
    work = Path(tempfile.mkdtemp(prefix=f"aramid-{mode}-smoke-"))
    venv = make_venv(work / "venv")
    python = python_in(venv)
    install = [python, "-m", "pip", "install", "--quiet"]
    if mode == "sdist":
        install.append("--no-deps")
    run([*install, artifact], check=True)
    probe(venv, python, cwd=work)
    if mode == "wheel":
        home = work / "home"
        home.mkdir()
        check_gate(gate(venv, fixture(work / "repo"), gate_env(venv, home)), venv)
    print(f"PLAT-1 {mode} smoke: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
