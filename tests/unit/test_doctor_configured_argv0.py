"""`_configured_argv0` rejects an argv whose FIRST element is empty -- the
`shlex.split('"" -q')` -> `['', '-q']` case its docstring names, where
`Path("")` would otherwise resolve to the cwd and doctor would report a
present tool for an empty command. Pinned at unit scope because the drain
confirms with `pytest -q tests/unit` (item 7dea7f37, 2026-09-04)."""
import sys
from pathlib import Path

from aramid import config
from aramid.commands import doctor


def test_an_empty_first_element_is_rejected_even_when_the_second_is_not():
    argv0, reason = doctor._configured_argv0('"" -q')
    assert argv0 is None
    assert "empty command" in reason


def test_a_single_element_command_is_accepted():
    # There is no argv[1] here: the check must look at argv[0] only.
    assert doctor._configured_argv0("pytest") == ("pytest", None)


def test_a_usable_command_passes_through_its_argv0():
    assert doctor._configured_argv0(["python", "-m", "pytest"]) == ("python", None)


# --- a bare name that used to find a file of the repo root (FN-46) --------

_RUNTESTS = "aramid-fn46-runtests"


def _probe(root, command):
    (root / "aramid.toml").write_text(f"[tests]\ncommand = {command}\n", encoding="utf-8")
    return doctor.probe_tests(root, config.load_config(root))


def test_a_bare_name_that_is_a_file_of_the_repo_root_is_told_how_to_name_it(
        tmp_path, monkeypatch):
    """`runtests` used to find the repo's own `runtests.cmd` (Windows looks
    in the current directory) or `runtests` (a bare name was handed through
    as a path). A bare name is looked for on PATH only now, and doctor says
    what to write instead."""
    file = f"{_RUNTESTS}.cmd" if sys.platform == "win32" else _RUNTESTS
    (tmp_path / file).write_text("", encoding="utf-8")
    (tmp_path / file).chmod(0o755)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NoDefaultCurrentDirectoryInExePath", raising=False)

    [status] = _probe(tmp_path, f'["{_RUNTESTS}", "-q"]')

    assert (status.name, status.present, status.warn) == ("tests", False, False)
    assert status.detail == (
        f"[tests].command is configured (argv[0] '{_RUNTESTS}') but '{_RUNTESTS}' was not "
        f"found on PATH or in aramid's managed locations. The repo root holds `{file}`: a "
        f"bare name is looked for on PATH only, so name the file by its path "
        f"(`./{_RUNTESTS}`)")

    # And written that way it is found: the hint is one that works.
    [status] = _probe(tmp_path, f'["./{_RUNTESTS}", "-q"]')
    assert (status.present, Path(status.version).name) == (True, file)


def test_a_bare_name_that_is_nowhere_gets_no_hint(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    [status] = _probe(tmp_path, '["aramid-fn46-nowhere"]')

    assert (status.present, status.detail) == (
        False,
        "[tests].command is configured (argv[0] 'aramid-fn46-nowhere') but "
        "'aramid-fn46-nowhere' was not found on PATH or in aramid's managed locations")


def test_only_a_bare_name_is_looked_for_in_the_repo_root(tmp_path):
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "run").write_text("", encoding="utf-8")
    (tmp_path / "run").write_text("", encoding="utf-8")
    assert doctor._in_the_repo_root(tmp_path, "run") == "run"
    assert doctor._in_the_repo_root(tmp_path, "tools/run") is None
    assert doctor._in_the_repo_root(tmp_path, "nothing") is None
