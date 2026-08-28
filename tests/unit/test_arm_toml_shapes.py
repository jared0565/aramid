"""`aramid arm` must see every header and key spelling TOML allows -- and when
it cannot, it must REFUSE rather than write a file the loader cannot parse.

Found by the llm-review consumer on the 0.5.0 arm fix (ledger c543ff6e,
arm.py:69) and confirmed by reproduction on 2026-08-28, wider than reported:
the section regexes anchored a bare `[table]` at column 0, so an indented
header, a header with a trailing comment, whitespace inside the brackets, or
an indented key were all invisible. `_arm_sectioned_key` then appended a
second `[table]` (or a second key), `tomllib` refused the result with "Cannot
declare ('shadow',) twice" / "Cannot overwrite a value", and `arm` had already
printed its success line and returned 0. The next gate crashed in
`load_config` -- loud, but the operator was told the gate was armed, and the
file they had to repair by hand was one aramid corrupted.

Two layers, because the second is what the first can never be: (1) the
regexes accept what TOML accepts; (2) before writing, the rewritten text is
parsed with the loader's own parser and the key must read `true` where the
loader reads it. Any spelling the regexes still miss -- a dotted-key table, a
quoted header -- now ends in a refusal that names the key and leaves the file
byte-for-byte unchanged, instead of a success line over a broken config.
"""
import tomllib

import pytest

from aramid.commands.arm import cmd_arm

# (cmd_arm kwargs, key, table)
SECTIONED = [
    ({"shadow": True}, "shadow_block_armed", "shadow"),
    ({"llm": True}, "llm_block_armed", "llm"),
    ({"mutation": True}, "mutation_block_armed", "mutation"),
    ({"mutation_score": True}, "score_block_armed", "mutation"),
    ({"red_proof": True}, "red_proof_block_armed", "red_proof"),
]
ROOT = [
    ({"tdd": True}, "tdd_block_armed"),
    ({}, "semgrep_block_armed"),          # the bare `aramid arm`
]

# Legal TOML spellings of "[table] / key = false" that a regex anchored on a
# bare `[table]` at column 0 does not see. Each one corrupted the file.
SHAPES = {
    "indented_header": "  [{t}]\n{k} = false\n",
    "comment_after_header": "[{t}]  # bake started 2026-08-01\n{k} = false\n",
    "indented_key": "[{t}]\n  {k} = false\n",
    "space_inside_brackets": "[ {t} ]\n{k} = false\n",
}


def _arm(tmp_path, text, **kwargs):
    toml = tmp_path / "aramid.toml"
    toml.write_text(text, encoding="utf-8")
    rc = cmd_arm(tmp_path, **kwargs)
    return rc, toml


@pytest.mark.parametrize("shape", list(SHAPES))
@pytest.mark.parametrize("kwargs,key,table", SECTIONED, ids=[c[1] for c in SECTIONED])
def test_every_legal_spelling_of_the_section_is_armed_in_place(
        tmp_path, capsys, kwargs, key, table, shape):
    text = "schema_version = 1\n" + SHAPES[shape].format(t=table, k=key)
    assert tomllib.loads(text)[table][key] is False, "the fixture must be legal TOML"

    rc, toml = _arm(tmp_path, text, **kwargs)

    assert rc == 0
    written = toml.read_text(encoding="utf-8")
    parsed = tomllib.loads(written)          # the old code left this unparseable
    assert parsed[table][key] is True
    assert written.count(f"[{table}]") + written.count(f"[ {table} ]") == 1, (
        "one header, not a duplicate appended at EOF")
    assert capsys.readouterr().err == "", "the key was correctly placed: no NOTE"


def test_a_trailing_comment_on_the_header_survives(tmp_path):
    text = "[shadow]  # bake started 2026-08-01\nshadow_block_armed = false\n"
    rc, toml = _arm(tmp_path, text, shadow=True)
    assert rc == 0
    assert "# bake started 2026-08-01" in toml.read_text(encoding="utf-8")


def test_an_indented_key_keeps_its_indentation(tmp_path):
    text = "[shadow]\n  shadow_block_armed = false\n"
    rc, toml = _arm(tmp_path, text, shadow=True)
    assert rc == 0
    assert "\n  shadow_block_armed = true\n" in toml.read_text(encoding="utf-8")


def test_an_indented_NEXT_header_still_ends_the_section(tmp_path, capsys):
    """The span must stop at `  [llm]`: the old `^\\[` overran it, found the
    twin inside [llm], rewrote THAT, and left [shadow] without the key."""
    text = "[shadow]\nenabled = true\n  [llm]\nshadow_block_armed = false\n"
    rc, toml = _arm(tmp_path, text, shadow=True)
    assert rc == 0
    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["shadow"]["shadow_block_armed"] is True
    assert parsed["llm"]["shadow_block_armed"] is False, "the twin is left untouched"
    err = capsys.readouterr().err
    assert "shadow_block_armed" in err and "line 4" in err, err


@pytest.mark.parametrize("kwargs,key", ROOT, ids=[c[1] for c in ROOT])
def test_a_root_key_is_inserted_before_an_indented_header_not_after_it(
        tmp_path, kwargs, key):
    """With no root key present and `  [llm]` unseen, the old code appended at
    EOF -- inside [llm], where the loader never reads a root key."""
    text = "schema_version = 1\n  [llm]\nenabled = true\n"
    rc, toml = _arm(tmp_path, text, **kwargs)
    assert rc == 0
    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed[key] is True
    assert key not in parsed["llm"]


def test_a_spelling_the_regexes_cannot_see_is_REFUSED_not_corrupted(tmp_path, capsys):
    """A dotted key defines the table without a header. The regexes miss it;
    appending `[shadow]` would be a second declaration. The rewrite must be
    parsed before it is written, and refused."""
    text = "schema_version = 1\nshadow.shadow_block_armed = false\n"
    rc, toml = _arm(tmp_path, text, shadow=True)

    assert rc == 3
    assert toml.read_text(encoding="utf-8") == text, "byte-for-byte unchanged"
    out = capsys.readouterr()
    assert "BLOCKS" not in out.out, "no success line over a refused write"
    assert "shadow_block_armed" in out.err and "unchanged" in out.err, out.err


def test_a_file_that_does_not_parse_is_REFUSED_before_any_rewrite(tmp_path, capsys):
    text = "[shadow\nshadow_block_armed = false\n"
    rc, toml = _arm(tmp_path, text, shadow=True)

    assert rc == 3
    assert toml.read_text(encoding="utf-8") == text
    out = capsys.readouterr()
    assert "BLOCKS" not in out.out
    assert "does not parse" in out.err, out.err


def test_a_misplaced_key_on_line_1_is_still_named(tmp_path, capsys):
    """The twin at offset 0 with no section anywhere: `_misplaced_lines`'s
    empty span must exclude nothing. (Pins the `(0, 0)` sentinel -- a survived
    mutant turned it into `(0, 1)`, which silently exempted line 1.)"""
    rc, toml = _arm(tmp_path, "shadow_block_armed = false\n", shadow=True)
    assert rc == 0
    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed["shadow"]["shadow_block_armed"] is True
    assert parsed["shadow_block_armed"] is False
    err = capsys.readouterr().err
    assert "shadow_block_armed" in err and "line 1" in err, err
