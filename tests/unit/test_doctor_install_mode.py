"""unit: doctor reports when aramid ITSELF is installed editable.

The separation this guards: other repos on this machine run the promoted
wheel from site-packages, while this repo's working tree is edited freely.
`pip install -e .` here collapses that in one command -- every consumer
silently starts running uncommitted edits, with nothing in their output
saying so. It is not hypothetical: a downstream repo was running an editable
install of this tree for days, and the fix was for THEM to pin a wheel.

Keyed on the installed distribution's `direct_url.json` rather than on
`aramid.__file__`, deliberately. `__file__` reports whichever copy the
current process imported -- and this repo's own test suite imports the tree
on purpose (`pyproject.toml`'s `pythonpath = ["src"]`), so a `__file__` check
would fire on every legitimate local run and be trained away. What matters is
what OTHER processes resolve, which is the installed distribution.
"""
import json

from aramid.commands.doctor import install_mode_lines


def test_an_editable_install_is_reported():
    direct_url = json.dumps({
        "url": "file:///F:/Projects/aramid",
        "dir_info": {"editable": True},
    })

    lines = install_mode_lines(direct_url)

    assert lines, "an editable install of aramid itself must be reported"
    text = "\n".join(lines).lower()
    assert "editable" in text
    assert "f:/projects/aramid" in text, "the reader has to be told WHICH tree"


def test_a_wheel_install_is_silent():
    """The promoted state. Reporting it would train the reader to skip the
    block, which is how the editable case gets missed when it appears."""
    direct_url = json.dumps({
        "url": "file:///C:/tmp/aramid-0.3.0-py3-none-any.whl",
        "archive_info": {"hash": "sha256=0495ff59"},
    })

    assert install_mode_lines(direct_url) == []


def test_an_index_install_is_silent():
    """No `direct_url.json` at all is what `pip install aramid` from PyPI
    leaves behind -- the most normal state there is."""
    assert install_mode_lines(None) == []


def test_a_non_editable_local_install_is_silent():
    """`pip install .` copies the tree into site-packages. It is a local
    install but NOT live-linked, so edits do not reach consumers and there is
    nothing to warn about -- `editable` is the discriminating key, not the
    presence of `dir_info`."""
    direct_url = json.dumps({
        "url": "file:///F:/Projects/aramid",
        "dir_info": {},
    })

    assert install_mode_lines(direct_url) == []


def test_malformed_direct_url_does_not_raise():
    """doctor's whole job is reporting honestly; it must not crash because a
    packaging file is odd. Silence here is safe -- the editable case has a
    positive marker, so failing to parse can only under-report."""
    assert install_mode_lines("{not json") == []
    assert install_mode_lines("") == []
