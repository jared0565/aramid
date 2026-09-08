"""Unit-scope pins for the mutation consumer's config prologue.

The 2026-09-06 14:00Z drain (item d3b12f06) reported survivors on the first
lines of `consume` -- `mcfg = getattr(cfg, "mutation", None) or {}` and the
`enabled` check -- which only the integration suite drives. The drain
confirms against `[mutation].test_command` (`pytest -q tests/unit`), so a
rule covered only there reads as a survivor; see
test_mutation_consumer_argv.py for the same shape on the argv helpers.
"""
from types import SimpleNamespace

from aramid import config as config_mod
from aramid.consumers import mutation as mut_consumer
from aramid.consumers.base import DrainContext


def test_a_disabled_mutation_section_is_honoured_before_anything_runs(tmp_path):
    # `or {}` -> `and {}` would read a POPULATED section as empty and run on
    # every default, `enabled` first; `if not enabled` -> `if enabled` would
    # run exactly when told not to. Either way the consumer gets past this
    # line with a root that is not a repository and no ledger, and blows up
    # instead of returning the disabled result.
    root = tmp_path / "not-a-repo"      # tmp_path itself holds the isolation fixture's dirs
    root.mkdir()
    cfg = SimpleNamespace(mutation={"enabled": False, "max_mutants": 1})
    ctx = DrainContext(root=root, cfg=cfg, ledger=None, clock=lambda: "t")
    item = SimpleNamespace(id="q", base=None, head="deadbeef")

    res = mut_consumer.consume(item, ctx)

    assert (res.state, res.note) == ("ok", "disabled")
    assert list(root.iterdir()) == [], "a disabled consumer touched the root"


# --- the knobs have ONE source of defaults: src/aramid/data/defaults.toml ---
#
# `consume` read every knob as `mcfg.get(<knob>, <literal>)`, duplicating the
# packaged default in a literal that production could never reach (every
# production config comes through `load_config`, which merges defaults.toml
# first). Each literal surfaced as an `int-bound` survivor whenever the
# function was edited -- d0340435 (20), f6befacb (600), d49f5a07 (120), all
# suppressed as DEAD FALLBACK with "retire by removing the literal fallbacks".
# Retired: the knobs come from one reader that falls back to the packaged
# table itself, so there is no literal left to mutate.

KNOBS = ("max_mutants", "wall_budget_s", "mutant_timeout_s", "confirm_cap",
         "retest_cap", "retest_open_survivors")


def test_a_missing_knob_reads_the_packaged_default_not_a_literal():
    packaged = config_mod._read_data_toml("defaults.toml")["mutation"]
    got = mut_consumer._knobs({})
    assert {k: got[k] for k in KNOBS} == {k: packaged[k] for k in KNOBS}


def test_a_configured_knob_wins_over_the_packaged_default():
    got = mut_consumer._knobs({"max_mutants": 7, "wall_budget_s": 1800, "retest_open_survivors": False})
    assert (got["max_mutants"], got["wall_budget_s"], got["retest_open_survivors"]) == (7, 1800.0, False)
    assert got["confirm_cap"] == config_mod._read_data_toml("defaults.toml")["mutation"]["confirm_cap"]


def test_knob_values_are_typed_like_the_prologue_expects():
    got = mut_consumer._knobs({"max_mutants": "5", "wall_budget_s": "90", "mutant_timeout_s": 30})
    assert got["max_mutants"] == 5 and isinstance(got["max_mutants"], int)
    assert got["wall_budget_s"] == 90.0 and isinstance(got["wall_budget_s"], float)
    assert got["mutant_timeout_s"] == 30.0 and isinstance(got["mutant_timeout_s"], float)
    assert isinstance(got["confirm_cap"], int) and isinstance(got["retest_cap"], int)


def test_the_baseline_budget_derives_from_the_mutant_timeout_when_unset():
    """`baseline_timeout_s` has no packaged default: it is four mutant
    timeouts unless the repo sets it (this repo does, 900)."""
    assert mut_consumer._knobs({"mutant_timeout_s": 50})["baseline_timeout_s"] == 200.0
    assert mut_consumer._knobs({"baseline_timeout_s": 900})["baseline_timeout_s"] == 900.0
