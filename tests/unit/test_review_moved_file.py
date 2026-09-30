"""FN-22: moving a file resolved its LLM findings.

`auto_resolve_llm` resolves an open LLM finding whose evidence quote is no
longer in its file at HEAD. A path absent at HEAD read as "", so a `git mv`
resolved every finding on the file -- an armed confirmed critical included --
until a drain re-reviewed the new path. Now a path absent at HEAD is searched
for across every tracked file at HEAD first: the quote found anywhere keeps
the finding open (the code moved), found nowhere resolves it as before (the
code is gone). Real git repos throughout; nothing about git is faked except
the one timeout."""
import subprocess
from datetime import datetime, timezone

import pytest

from aramid import gitutil, review
from aramid.ledger import Ledger
from aramid.models import Finding, Gate, Severity, Source, Verdict

NOW = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc).isoformat()
FID = "e" * 64
QUOTE = "        return db.get(order_id)"
ORDERS = "class Orders:\n    def get(self, order_id):\n        return db.get(order_id)\n"


def _git(root, *a):
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a],
                   cwd=root, check=True, capture_output=True, text=True)


def _write(r, files):
    for rel, body in files.items():
        p = r / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")


def _commit(r, msg):
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", msg)


def _repo(tmp_path, files):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _write(r, {"README.md": "orders service\n", **files})
    _commit(r, "base")
    return r


def _move(r, src, dst, body=None):
    (r / dst).parent.mkdir(parents=True, exist_ok=True)
    _git(r, "mv", src, dst)
    if body is not None:
        (r / dst).write_text(body, encoding="utf-8")
    _commit(r, "move")


def _finding(evidence=QUOTE, file="src/orders.py"):
    return Finding(id=FID, tool="llm-review", rule="llm/a01", severity_raw="critical",
                   severity=Severity.CRITICAL, verdict=Verdict.WARN, file=file, line=3,
                   message="IDOR: no ownership check (fix: verify owner)",
                   evidence=evidence, gate=Gate.ALL, source=Source.LLM, confirmed=True)


def _resolve(r, finding=None):
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.record_run("r0", NOW, "drain", set(), set(), [finding or _finding()])
        resolved = review.auto_resolve_llm(r, led, "r1", NOW)
        status = led.open_findings()[FID]["status"]
    finally:
        led.close()
    return resolved, status


def test_a_moved_file_keeps_its_llm_finding(tmp_path):
    r = _repo(tmp_path, {"src/orders.py": ORDERS})
    _move(r, "src/orders.py", "src/api/orders.py")

    assert _resolve(r) == ([], "open")


def test_a_deleted_file_still_resolves_its_llm_finding(tmp_path):
    r = _repo(tmp_path, {"src/orders.py": ORDERS})
    _git(r, "rm", "-q", "src/orders.py")
    _commit(r, "delete")

    assert _resolve(r) == ([FID], "fixed")


def test_a_moved_file_whose_quoted_line_was_fixed_resolves(tmp_path):
    r = _repo(tmp_path, {"src/orders.py": ORDERS})
    _move(r, "src/orders.py", "src/api/orders.py",
          ORDERS.replace("db.get(order_id)", "db.get_owned(order_id, user)"))

    assert _resolve(r) == ([FID], "fixed")


def test_a_moved_file_whose_quote_lost_its_indentation_keeps(tmp_path):
    # the quote is searched for by its line's text, not its indentation
    r = _repo(tmp_path, {"src/orders.py": ORDERS})
    _move(r, "src/orders.py", "src/orders_fn.py",
          "def get(order_id):\n    return db.get(order_id)\n")

    assert _resolve(r) == ([], "open")


TWO_LINES = "    if order_id:\n        return db.get(order_id)"


def test_the_whole_quote_decides_not_the_line_it_is_searched_by(tmp_path):
    guarded = "def get(order_id):\n    if order_id:\n        return db.get(order_id)\n"
    r = _repo(tmp_path, {"src/orders.py": guarded})
    # the longest line survives the move, the guard above it does not
    _move(r, "src/orders.py", "src/api/orders.py",
          "def get(order_id):\n    return db.get(order_id)\n")

    assert _resolve(r, _finding(TWO_LINES)) == ([FID], "fixed")


def test_every_candidate_is_read_until_one_carries_the_whole_quote(tmp_path):
    guarded = "def get(order_id):\n    if order_id:\n        return db.get(order_id)\n"
    r = _repo(tmp_path, {"src/orders.py": guarded,
                         "src/a_cache.py": "def get(order_id):\n    return db.get(order_id)\n"})
    # a_cache.py matches the searched line and sorts first; only b_orders.py
    # carries the whole quote
    _move(r, "src/orders.py", "src/b_orders.py")

    assert _resolve(r, _finding(TWO_LINES)) == ([], "open")


def test_the_quote_is_searched_by_its_longest_line(tmp_path):
    # the short line is respaced in the move, so only the long one is found
    # as written; the whole quote still matches once whitespace is stripped
    quote = "    x = 1\n    return db.get(order_id)"
    r = _repo(tmp_path, {"src/orders.py":
                         "def get(order_id):\n    x = 1\n    return db.get(order_id)\n"})
    _move(r, "src/orders.py", "src/api/orders.py",
          "def get(order_id):\n    x=1\n    return db.get(order_id)\n")

    assert _resolve(r, _finding(quote)) == ([], "open")


def test_a_file_still_at_head_is_judged_by_its_own_content(tmp_path):
    # the quote moved to ANOTHER file while its own file stayed: resolved,
    # exactly as before FN-22 -- only an absent path is searched for
    r = _repo(tmp_path, {"src/orders.py": ORDERS})
    _write(r, {"src/orders.py": "class Orders:\n    pass\n",
               "src/api/orders.py": ORDERS})
    _commit(r, "split")

    assert _resolve(r) == ([FID], "fixed")


def test_a_git_timeout_in_the_search_resolves_nothing(tmp_path, monkeypatch):
    r = _repo(tmp_path, {"src/orders.py": ORDERS})
    _move(r, "src/orders.py", "src/api/orders.py")
    real = gitutil._run

    def run(root, *args):
        if args[:1] == ("grep",):
            raise gitutil.GitTimeout("git grep timed out after 600 s and was killed")
        return real(root, *args)
    monkeypatch.setattr(gitutil, "_run", run)
    led = Ledger(r / ".aramid" / "ledger.db")
    try:
        led.record_run("r0", NOW, "drain", set(), set(), [_finding()])
        with pytest.raises(gitutil.GitTimeout):
            review.auto_resolve_llm(r, led, "r1", NOW)
        status = led.open_findings()[FID]["status"]
    finally:
        led.close()
    assert status == "open"
