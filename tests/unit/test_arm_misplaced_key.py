"""`aramid arm` must arm the key THE LOADER READS, not a same-named key that
happens to sit somewhere else in the file.

Found by the llm-review consumer on the commit that added `arm --shadow`, and
confirmed by reproduction on 2026-08-27 before anything was tagged: with a
stray `shadow_block_armed = false` at the TOP LEVEL of aramid.toml -- an easy
mistake, because `semgrep_block_armed` and `tdd_block_armed` genuinely live
there -- `arm --shadow` rewrote that line, printed "now BLOCKS at every gate",
and returned 0, while `[shadow].shadow_block_armed` (the only key
`policy.classify` reads) stayed unset. A security gate the operator had just
been told was armed was not.

The mechanism was shared. Every sectioned rewrite (`llm`, `mutation`,
`mutation-score`, `red-proof`, `shadow`) searched the WHOLE file for its key,
and the two root rewrites (`semgrep`, `tdd`) did the same in the other
direction -- a same-named key inside some [table] would have been rewritten
while the loader reads the top level. `_arm_autolearn_text` alone scoped its
substitution to its section's span, because `armed` is a generic name; the
docstrings of the others said scoping was unnecessary because their key names
were globally unique. Uniqueness across sections was never the risk.
PLACEMENT is: the rewrite must be scoped to where the loader reads.

Three placements per key, because they fail differently: the twin alone (the
repro -- old code rewrote it and wrote nothing the loader reads), a section
present without the key (old code rewrote the twin and never inserted), and
both present (old code rewrote BOTH, which armed the gate by accident and hid
the problem). In every case the twin must be left untouched -- it is the
operator's text, not aramid's to delete -- and named on stderr.
"""
import tomllib

import pytest

from aramid import config as config_mod
from aramid.commands.arm import cmd_arm

# (cmd_arm kwargs, key, section header, table name)
SECTIONED = [
    ({"shadow": True}, "shadow_block_armed", "[shadow]", "shadow"),
    ({"llm": True}, "llm_block_armed", "[llm]", "llm"),
    ({"mutation": True}, "mutation_block_armed", "[mutation]", "mutation"),
    ({"mutation_score": True}, "score_block_armed", "[mutation]", "mutation"),
    ({"red_proof": True}, "red_proof_block_armed", "[red_proof]", "red_proof"),
]
# root keys: (cmd_arm kwargs, key)
ROOT = [
    ({"tdd": True}, "tdd_block_armed"),
    ({}, "semgrep_block_armed"),          # the bare `aramid arm`
]
PLACEMENTS = ["twin_only", "section_without_key", "both"]


def _sectioned_toml(key: str, header: str, placement: str) -> str:
    """The misplaced twin is always line 2, so the NOTE can be asserted."""
    text = f"schema_version = 1\n{key} = false\n"
    if placement == "section_without_key":
        text += f"\n{header}\nenabled = true\n"
    elif placement == "both":
        text += f"\n{header}\nenabled = true\n{key} = false\n"
    return text


def _root_toml(key: str, placement: str) -> str:
    """The misplaced twin sits inside [llm]; with `both`, the real root key
    is line 2 and the twin is line 5."""
    text = "schema_version = 1\n"
    if placement == "both":
        text += f"{key} = false\n"
    text += f"\n[llm]\n{key} = false\n"
    return text


@pytest.mark.parametrize("placement", PLACEMENTS)
@pytest.mark.parametrize("kwargs,key,header,table", SECTIONED,
                         ids=[c[1] for c in SECTIONED])
def test_sectioned_key_is_armed_where_the_loader_reads_it(
        tmp_path, capsys, kwargs, key, header, table, placement):
    toml = tmp_path / "aramid.toml"
    toml.write_text(_sectioned_toml(key, header, placement), encoding="utf-8")

    assert cmd_arm(tmp_path, **kwargs) == 0

    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))   # also: no dup-key corruption
    assert parsed[table][key] is True, f"the key under {header} is what the loader reads"
    assert parsed[key] is False, "the misplaced top-level twin must be left untouched"
    err = capsys.readouterr().err
    assert key in err and "line 2" in err, f"stderr must name the misplaced twin:\n{err}"


@pytest.mark.parametrize("placement", PLACEMENTS)
@pytest.mark.parametrize("kwargs,key", ROOT, ids=[c[1] for c in ROOT])
def test_root_key_is_armed_at_the_root_not_inside_a_table(
        tmp_path, capsys, kwargs, key, placement):
    if placement == "section_without_key":
        pytest.skip("a root key has no section to be absent from; covered by twin_only")
    toml = tmp_path / "aramid.toml"
    toml.write_text(_root_toml(key, placement), encoding="utf-8")

    assert cmd_arm(tmp_path, **kwargs) == 0

    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))
    assert parsed[key] is True, "the top-level key is what the loader reads"
    assert parsed["llm"][key] is False, "the twin inside [llm] must be left untouched"
    err = capsys.readouterr().err
    twin_line = "line 5" if placement == "both" else "line 4"
    assert key in err and twin_line in err, f"stderr must name the misplaced twin:\n{err}"


def test_the_repro_that_held_the_0_5_0_tag(tmp_path, capsys):
    """Exactly the finding, asserted through the loader the gate uses rather
    than through tomllib: the old code returned 0, printed the BLOCKS line,
    and left `cfg.shadow.get("shadow_block_armed")` as None."""
    toml = tmp_path / "aramid.toml"
    toml.write_text("schema_version = 1\nshadow_block_armed = false\n\n"
                    "[shadow]\nenabled = true\n", encoding="utf-8")

    assert cmd_arm(tmp_path, shadow=True) == 0

    cfg = config_mod.load_config(tmp_path)
    assert cfg.shadow.get("shadow_block_armed") is True, (
        "arm --shadow reported success while the loader still reads nothing armed")
    out = capsys.readouterr()
    assert "BLOCKS at every gate" in out.out          # the success line is still earned
    assert "shadow_block_armed" in out.err and "outside [shadow]" in out.err


def test_a_correctly_placed_key_produces_no_note(tmp_path, capsys):
    """The NOTE is for misplaced twins only. A clean file must arm silently
    on stderr, or the warning trains people to ignore it."""
    toml = tmp_path / "aramid.toml"
    toml.write_text("[shadow]\nshadow_block_armed = false\n", encoding="utf-8")

    assert cmd_arm(tmp_path, shadow=True) == 0

    assert capsys.readouterr().err == ""
    assert tomllib.loads(toml.read_text(encoding="utf-8"))["shadow"]["shadow_block_armed"] is True
