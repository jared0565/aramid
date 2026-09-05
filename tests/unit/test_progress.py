"""`aramid.progress.StderrReporter` -- the sink the gate hands its runners.

On a terminal (git relays a hook's stderr to the one the push was typed in)
each report overwrites the previous line in place. In a log file it writes
one line at most every `min_interval_s`, buffering the newest text between
writes so `flush()` can land the last state -- a 100% line must never be
throttled away.
"""
import io

from aramid.progress import StderrReporter


class _Tty(io.StringIO):
    def isatty(self):
        return True


def test_on_a_terminal_each_report_overwrites_the_previous_line():
    out = _Tty()
    rep = StderrReporter(stream=out, clock=lambda: 0.0)
    rep("aramid: tests 69/151 (45%) 7s elapsed")
    rep("aramid: tests 138/151 (91%) 13s elapsed")
    rep.flush()
    assert out.getvalue() == (
        "\raramid: tests 69/151 (45%) 7s elapsed"
        "\raramid: tests 138/151 (91%) 13s elapsed"
        "\n")


def test_on_a_terminal_a_shorter_line_blanks_the_tail_of_the_longer_one():
    out = _Tty()
    rep = StderrReporter(stream=out, clock=lambda: 0.0)
    long = "aramid: tests collecting and something long"
    short = "aramid: tests 1/2"
    rep(long)
    rep(short)
    # Padding covers what the longer line left behind; nothing more.
    assert out.getvalue() == "\r" + long + "\r" + short + " " * (len(long) - len(short))


def test_in_a_log_the_first_report_is_written_at_once():
    out = io.StringIO()
    rep = StderrReporter(stream=out, clock=lambda: 100.0, min_interval_s=30)
    rep("aramid: tests collecting")
    assert out.getvalue() == "aramid: tests collecting\n"


def test_in_a_log_reports_inside_the_interval_are_held_and_the_newest_lands_later():
    out = io.StringIO()
    now = [100.0]
    rep = StderrReporter(stream=out, clock=lambda: now[0], min_interval_s=30)
    rep("aramid: tests collecting")
    now[0] = 110.0
    rep("aramid: tests 69/151 (45%) 10s elapsed")     # held
    now[0] = 120.0
    rep("aramid: tests 138/151 (91%) 20s elapsed")    # replaces the held one
    assert out.getvalue() == "aramid: tests collecting\n"
    now[0] = 131.0
    rep("aramid: tests 150/151 (99%) 31s elapsed")    # interval elapsed: written
    assert out.getvalue() == ("aramid: tests collecting\n"
                              "aramid: tests 150/151 (99%) 31s elapsed\n")


def test_in_a_log_flush_lands_a_held_report_and_nothing_when_nothing_is_held():
    out = io.StringIO()
    now = [100.0]
    rep = StderrReporter(stream=out, clock=lambda: now[0], min_interval_s=30)
    rep("aramid: tests collecting")
    now[0] = 105.0
    rep("aramid: tests 151/151 (100%) 5s elapsed")    # held
    rep.flush()
    assert out.getvalue() == ("aramid: tests collecting\n"
                              "aramid: tests 151/151 (100%) 5s elapsed\n")
    rep.flush()
    assert out.getvalue().count("\n") == 2


class _Broken(io.StringIO):
    attempts = 0

    def write(self, s):
        self.attempts += 1
        raise OSError("stderr is gone")


def test_a_broken_stream_never_raises_and_is_not_retried():
    stream = _Broken()
    rep = StderrReporter(stream=stream, clock=lambda: 0.0)
    rep("aramid: tests collecting")
    rep("aramid: tests 1/2 (50%) 3s elapsed")
    rep.flush()
    assert stream.attempts == 1


def test_in_a_log_a_report_exactly_at_the_interval_is_written():
    # `>=`, not `>`: the 30 s cadence means "every 30 s", not "every 30 s
    # and a bit". The mutation drain probes exactly this boundary.
    out = io.StringIO()
    now = [100.0]
    rep = StderrReporter(stream=out, clock=lambda: now[0], min_interval_s=30)
    rep("aramid: tests collecting")
    now[0] = 130.0
    rep("aramid: tests 69/151 (45%) 30s elapsed")
    assert out.getvalue() == ("aramid: tests collecting\n"
                              "aramid: tests 69/151 (45%) 30s elapsed\n")


def test_on_a_terminal_a_longer_line_after_a_shorter_one_gets_no_padding():
    out = _Tty()
    rep = StderrReporter(stream=out, clock=lambda: 0.0)
    rep("aramid: tests 1/2")
    rep("aramid: tests 2/2 (100%) 9s elapsed")
    assert out.getvalue() == "\raramid: tests 1/2\raramid: tests 2/2 (100%) 9s elapsed"
