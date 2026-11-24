"""`aramid fleet` says when its snapshot was computed (interop round 347
item 2; operator decision 2026-11-24, "time + init re-judges"). bytesTTS read
a 15:00Z snapshot at ~16:10Z, missing a repo registered at 16:07Z, and the
text output printed no time at all -- only `--json` had `computed_at`. It
printed one only once the snapshot was over 12 hours old."""
from aramid import fleet

AT = "2026-11-16T15:00:10+00:00"


def _verdict(computed_at=AT):
    return {"schema_version": fleet.SCHEMA_VERSION, "computed_at": computed_at,
            "verdict": "insufficient", "reasons": [], "fleet": {}, "repos": {}}


def _lines(verdict, now):
    return fleet.render_report(verdict, fleet.load_policy(), now=now).splitlines()


def test_the_second_line_says_when_and_how_long_ago(tmp_path):
    lines = _lines(_verdict(), "2026-11-16T16:10:30+00:00")

    assert lines[0].startswith("fleet health -- 1.0 readiness (policy: ")
    assert lines[1] == f"snapshot computed {AT} (1h ago)"
    assert lines[2] == ""


def test_a_fresh_snapshot_reads_in_minutes(tmp_path):
    assert _lines(_verdict(), "2026-11-16T15:03:10+00:00")[1] == (
        f"snapshot computed {AT} (3m ago)")


def test_without_a_clock_it_says_when_only(tmp_path):
    assert _lines(_verdict(), None)[1] == f"snapshot computed {AT}"


def test_an_unreadable_time_is_said_to_be_unknown(tmp_path):
    assert _lines(_verdict("yesterday"), "2026-11-16T16:10:30+00:00")[1] == (
        "snapshot computed: unknown")
    assert _lines(_verdict(None), "2026-11-16T16:10:30+00:00")[1] == (
        "snapshot computed: unknown")


def test_no_verdict_has_no_snapshot_line(tmp_path):
    lines = _lines(None, "2026-11-16T16:10:30+00:00")

    assert not any(ln.startswith("snapshot computed") for ln in lines)
