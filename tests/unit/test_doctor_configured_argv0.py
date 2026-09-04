"""`_configured_argv0` rejects an argv whose FIRST element is empty -- the
`shlex.split('"" -q')` -> `['', '-q']` case its docstring names, where
`Path("")` would otherwise resolve to the cwd and doctor would report a
present tool for an empty command. Pinned at unit scope because the drain
confirms with `pytest -q tests/unit` (item 7dea7f37, 2026-09-04)."""
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
