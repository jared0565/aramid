"""Unit-scope pins for the mutation consumer's config prologue.

The 2026-09-06 14:00Z drain (item d3b12f06) reported survivors on the first
lines of `consume` -- `mcfg = getattr(cfg, "mutation", None) or {}` and the
`enabled` check -- which only the integration suite drives. The drain
confirms against `[mutation].test_command` (`pytest -q tests/unit`), so a
rule covered only there reads as a survivor; see
test_mutation_consumer_argv.py for the same shape on the argv helpers.
"""
from types import SimpleNamespace

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
