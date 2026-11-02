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


# --- the three range decisions the prologue makes, pinned ----------------
#
# The 2026-09-08 18:00Z drain reported three survivors on lines only the
# integration suite drives, once the six knob literals stopped absorbing the
# budget ahead of them: the source-file filter (`and` -> `or` admitted every
# changed file), the re-test enable (`and` -> `or` re-tested with the knob
# off, or with no test changed), and the claimed partition (`c[1]` -> `c[2]`
# handed a LINE NUMBER to the stem rule, so nothing was ever claimed). Each
# is a pure function of the range now.

def test_only_changed_python_sources_are_mutated():
    changed = {"src/b.py": {2}, "tests/unit/test_a.py": {1}, "docs/x.md": {1},
               "src/a.py": {1}, "src/a_test.py": {1}, "src/test_b.py": {1}}
    assert mut_consumer._source_files(changed) == ["src/a.py", "src/b.py"]


def test_re_tests_run_only_when_enabled_and_a_test_changed():
    with_test = {"src/a.py": {1}, "tests/unit/test_a.py": {1}}
    no_test = {"src/a.py": {1}}
    assert mut_consumer._retest_wanted({"retest_open_survivors": True}, with_test) is True
    assert mut_consumer._retest_wanted({"retest_open_survivors": True}, no_test) is False
    assert mut_consumer._retest_wanted({"retest_open_survivors": False}, with_test) is False


def test_a_survivor_is_claimed_by_its_module_path_not_its_line():
    """(fid, rel, line, op): the stem rule is asked about `rel`. Asked about
    the line number instead (`c[2]`) it maps nothing, and the claimed pass
    -- the reason a test-only push is worth a worktree -- never runs."""
    survivors = [("a" * 64, "src/pkg/widget.py", 7, "cmp-flip"),
                 ("b" * 64, "src/pkg/other.py", 7, "cmp-flip")]
    changed = {"tests/unit/test_widget.py": {1}}
    assert mut_consumer._claimed(survivors, changed) == [survivors[0]]
    assert mut_consumer._claimed(survivors, {"src/pkg/widget.py": {3}}) == []


# --- the idle check and the three give-ups, pinned at the boundary ---------
#
# The 2026-09-08 22:00Z drain reported two more `consume` survivors the unit
# suite never reached: the idle check (`and` -> `or` returned "no python
# files in range" whenever EITHER side was empty, so a range with sources
# but no re-tests was never mutated) and the timeout give-up (`>=` -> `>`
# gave up one attempt late). Both are pure functions now; the give-ups are
# pinned on both sides of every threshold with the documented THREE
# strikes seeded literally, so a moved constant is a red test too.

def test_nothing_to_run_only_when_both_sources_and_re_tests_are_empty():
    cand = ("a" * 64, "src/pkg/x.py", 3, "cmp-flip")
    assert mut_consumer._nothing_to_run([], []) is True
    assert mut_consumer._nothing_to_run(["src/pkg/x.py"], []) is False
    assert mut_consumer._nothing_to_run([], [cand]) is False
    assert mut_consumer._nothing_to_run(["src/pkg/x.py"], [cand]) is False


def _ledger_with_notes(tmp_path, notes):
    """A real ledger holding one CONSUMER_RUN_FINISHED per (item_id, note)."""
    from aramid.ledger import Event, EventType, Ledger
    led = Ledger(tmp_path / "ledger.db")
    for i, (item_id, note) in enumerate(notes):
        led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"run{i}",
                         f"2026-09-08T00:00:{i:02d}Z", None,
                         {"consumer": mut_consumer.NAME, "item_id": item_id, "note": note}))
    return led


def _item(head="h" * 40, item_id="item-1"):
    return SimpleNamespace(id=item_id, head=head)


def test_timeout_give_up_fires_at_exactly_the_threshold_across_items(tmp_path):
    prefix = mut_consumer.timeout_note_prefix(480.0, "pytest -q")
    n = 3  # the documented three strikes, not the constant
    below = _ledger_with_notes(tmp_path / "b", [(f"i{k}", prefix + " x") for k in range(n - 1)])
    at = _ledger_with_notes(tmp_path / "a", [(f"i{k}", prefix + " x") for k in range(n)])
    assert mut_consumer._give_up_note(below, _item(), "pytest -q", 480.0, "python") is None
    note = mut_consumer._give_up_note(at, _item(), "pytest -q", 480.0, "python")
    assert note is not None and note.startswith("mutation giving up: pytest -q does not fit")
    assert f"{n} attempts" in note and "baseline_timeout_s" in note


def test_missing_command_give_up_fires_at_exactly_the_threshold(tmp_path):
    prefix = mut_consumer.missing_note_prefix("python")
    n = 3
    below = _ledger_with_notes(tmp_path / "b", [(f"i{k}", prefix + " x") for k in range(n - 1)])
    at = _ledger_with_notes(tmp_path / "a", [(f"i{k}", prefix + " x") for k in range(n)])
    assert mut_consumer._give_up_note(below, _item(), "pytest -q", 480.0, "python") is None
    note = mut_consumer._give_up_note(at, _item(), "pytest -q", 480.0, "python")
    assert note == ("mutation giving up: python not found after "
                    f"{n} attempts -- fix [mutation].test_command or [tests].command")


# --- the repo-scoped give-ups count only since the last GREEN baseline -----
#
# graphite, 2026-10-17..29: three 1500s baseline timeouts twelve days apart,
# 22 runs between them whose baselines finished green, and a
# permanent stand-down saying the suite "does not fit". A run that carries
# `baseline_s` is one whose baseline FINISHED GREEN -- `consume` records it on
# that path only -- which disproves "does not fit", so it resets the count.
# Nothing else may: the never-latch fix (a give-up returns ok, so the next
# drain is a fresh item at a new head) has to keep latching across both.

_GRAPHITE_SUITE = "-P scripts/mutation_tests.py"
_GRAPHITE_ARGS = (_GRAPHITE_SUITE, 1500.0, "python")
_TIMEOUT = {"state": "degraded",
            "note": mut_consumer.timeout_note_prefix(1500.0, _GRAPHITE_SUITE)
            + " (last seen @ 893dd08717be)"}
_GREEN = {"state": "ok", "note": "1 confirmed survivor(s) of 10 mutant(s) tested",
          "baseline_s": 1388.0}
_GRAPHITE_GIVE_UP = ("mutation giving up: -P scripts/mutation_tests.py does not fit the 1500s "
                     "baseline budget after 3 attempts -- raise [mutation].baseline_timeout_s, "
                     "or point [mutation].test_command at a narrower suite")


def _ledger_with_runs(tmp_path, runs):
    """A real ledger holding one CONSUMER_RUN_FINISHED per payload, oldest
    first, each on its own queue item; `consumer` defaults to this one."""
    from aramid.ledger import Event, EventType, Ledger
    led = Ledger(tmp_path / "ledger.db")
    for i, payload in enumerate(runs):
        led.append(Event(EventType.CONSUMER_RUN_FINISHED, f"run{i}",
                         f"2026-10-29T00:00:{i:02d}Z", None,
                         {"consumer": mut_consumer.NAME, "item_id": f"i{i}", **payload}))
    return led


def test_timeout_give_up_counts_only_timeouts_since_the_last_green_baseline(tmp_path):
    spread = _ledger_with_runs(tmp_path / "s", [_TIMEOUT, _GREEN, _GREEN, _TIMEOUT,
                                                _GREEN, _TIMEOUT])
    two_since = _ledger_with_runs(tmp_path / "t", [_TIMEOUT, _TIMEOUT, _GREEN,
                                                   _TIMEOUT, _TIMEOUT])
    three_since = _ledger_with_runs(tmp_path / "a", [_TIMEOUT, _GREEN, _TIMEOUT,
                                                     _TIMEOUT, _TIMEOUT])
    assert mut_consumer._give_up_note(spread, _item(), *_GRAPHITE_ARGS) is None, \
        "graphite's shape: three timeouts, never three without a green baseline between"
    assert mut_consumer._give_up_note(two_since, _item(), *_GRAPHITE_ARGS) is None
    assert mut_consumer._give_up_note(three_since, _item(), *_GRAPHITE_ARGS) == _GRAPHITE_GIVE_UP


def test_a_green_baseline_resets_the_count_by_its_key_not_its_value(tmp_path):
    instant = dict(_GREEN, baseline_s=0.0)
    led = _ledger_with_runs(tmp_path, [_TIMEOUT, _TIMEOUT, instant, _TIMEOUT])
    assert mut_consumer._give_up_note(led, _item(), *_GRAPHITE_ARGS) is None


def test_runs_that_never_finished_a_green_baseline_do_not_reset_the_count(tmp_path):
    """The never-latch guard. Between three timeouts on three items: a give-up
    (ok, so its item drained), an idle item, a RED baseline (it finished, but
    a suite that stops at its first failure proves nothing about the whole
    suite's time), and a green baseline recorded by ANOTHER consumer."""
    give_up = {"state": "ok", "note": _GRAPHITE_GIVE_UP}
    idle = {"state": "ok", "note": "no python files in range"}
    red = {"state": "degraded",
           "note": mut_consumer.failing_note_prefix("f" * 40) + " -- rc 1: boom"}
    elsewhere = dict(_GREEN, consumer="js_mutation")
    led = _ledger_with_runs(tmp_path, [_TIMEOUT, give_up, idle, _TIMEOUT, red, elsewhere,
                                       _TIMEOUT])
    assert mut_consumer._give_up_note(led, _item(), *_GRAPHITE_ARGS) == _GRAPHITE_GIVE_UP


def test_missing_command_give_up_counts_only_since_the_last_green_baseline(tmp_path):
    missing = {"state": "degraded",
               "note": mut_consumer.missing_note_prefix("python") + " (resolved from x)"}
    reset = _ledger_with_runs(tmp_path / "r", [missing, missing, _GREEN, missing])
    latched = _ledger_with_runs(tmp_path / "l", [missing, _GREEN, missing, missing, missing])
    assert mut_consumer._give_up_note(reset, _item(), "pytest -q", 480.0, "python") is None
    assert mut_consumer._give_up_note(latched, _item(), "pytest -q", 480.0, "python") == (
        "mutation giving up: python not found after 3 attempts -- fix "
        "[mutation].test_command or [tests].command")


def test_failing_baseline_give_up_is_scoped_to_this_item_and_head(tmp_path):
    head = "c" * 40
    prefix = mut_consumer.failing_note_prefix(head)
    n = 3
    below = _ledger_with_notes(tmp_path / "b", [("item-1", prefix + " x")] * (n - 1))
    other_item = _ledger_with_notes(tmp_path / "o", [("item-9", prefix + " x")] * n)
    at = _ledger_with_notes(tmp_path / "a", [("item-1", prefix + " x")] * n)
    args = ("pytest -q", 480.0, "python")
    assert mut_consumer._give_up_note(below, _item(head), *args) is None
    assert mut_consumer._give_up_note(other_item, _item(head), *args) is None
    assert mut_consumer._give_up_note(at, _item(head), *args) == \
        "mutation giving up: baseline persistently failing"


def test_stalled_baseline_give_up_is_scoped_to_this_item_and_head(tmp_path):
    head = "c" * 40
    note = mut_consumer.stalled_note(301.0, head)
    assert note.startswith(mut_consumer.stalled_note_prefix(head)), "one helper, both ends"
    n = 3
    below = _ledger_with_notes(tmp_path / "b", [("item-1", note)] * (n - 1))
    other_item = _ledger_with_notes(tmp_path / "o", [("item-9", note)] * n)
    other_head = _ledger_with_notes(
        tmp_path / "h", [("item-1", mut_consumer.stalled_note(301.0, "d" * 40))] * n)
    at = _ledger_with_notes(tmp_path / "a", [("item-1", note)] * n)
    args = ("pytest -q", 480.0, "python")
    assert mut_consumer._give_up_note(below, _item(head), *args) is None
    assert mut_consumer._give_up_note(other_item, _item(head), *args) is None
    assert mut_consumer._give_up_note(other_head, _item(head), *args) is None
    assert mut_consumer._give_up_note(at, _item(head), *args) == (
        "mutation giving up: baseline persistently stalls (last seen @ cccccccccccc) -- fix"
        " the hang, or raise [timeouts].stall_s if the suite legitimately idles that long")
