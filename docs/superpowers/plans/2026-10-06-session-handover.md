# Session Handover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The resumable state stays in the gitignored `.superpowers/sdd/progress.md`.

**Goal:** Every repo aramid runs in can carry a restart or crash handover from one agent session to the next without the operator: an agent writes it with `aramid handover write`, and a fresh session sees it first in the SessionStart hook and in `aramid status` (including the `aramid_status` MCP tool). It resumes the work and marks the handover consumed with `aramid handover done`.

**Architecture:** A small module `aramid/handover.py` owns one never-committed file, `.aramid/handover.json`, plus its archive `.aramid/handovers/`. Three thin surfaces sit on top of it: the CLI (`commands/handover_cmd.py`), MCP tools in `mcp_tools.py`, and the two delivery points that already exist in every armed repo (`agent_hook._session_context` and `status.cmd_status`). The instruction reaches consumers through `ARAMID.md.tmpl` and the managed agent block on their next `aramid init`.

**Tech Stack:** Python stdlib (`json`, `os.replace`, `datetime`), argparse, pytest.

**Spec:** `docs/superpowers/specs/2026-10-06-aramid-stall-watchdog-and-handover-design.md` (Part B).

## Global Constraints

1. The handover file lives under `.aramid/`, which `aramid init` gitignores in every consumer (`init.GITIGNORE_ENTRIES`). Never write it anywhere tracked.
2. Writes are atomic: write a temp file in `.aramid/`, then `os.replace`. A reader never sees half a file.
3. Never delete a handover. `done` and `--replace` archive to `.aramid/handovers/<stamp>.json`.
4. The SessionStart lines, verbatim. First: `aramid: PENDING HANDOVER written <age> ago at <head12> -- resume it WITHOUT asking the operator, then run 'aramid handover done':`. Then each body line as `aramid: | <line>`, capped at 8000 body characters. Past the cap: `aramid: | ... (truncated; 'aramid handover show' prints all of it)`.
5. The status line, verbatim: `  handover: PENDING, written <age> ago -- 'aramid handover show'`, placed right after `aramid status:`.
6. Age format: `<n>s`, `<n>m`, `<n>h`, or `<n>d`, using the largest unit that is ≥ 1. A future or unparseable timestamp reads `unknown`.
7. Every commit: CHANGELOG `[Unreleased]`; `python -P -m aramid check --staged`; `python -P -m aramid ledger filter --status open`; `git commit -F <file>` (Write tool); trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; never `--no-verify`; never `pip install -e .`. New test files: `pytest --co -q tests` before staging.
8. This repo's own `ARAMID.md`, `CLAUDE.md` and `AGENTS.md` are regenerated through aramid's own code with `PYTHONPATH=src`: `_write_aramid_md` per `tests/unit/test_aramid_md_template_sync.py::REGEN_CMD`, and `agent_files.write_agent_blocks(Path('.'))`. Never edit them by hand.

## Review Focus

1. **A corrupt or hand-edited `handover.json`** (invalid JSON, missing `body`). `show` and the hook must not crash: the hook prints nothing extra and still prints the posture block, and `show` says the file is unreadable and names it. Test: Task 1 `test_a_corrupt_file_reads_as_unreadable_not_a_crash`, Task 3 `test_session_start_survives_a_corrupt_handover`.
2. **A body with no trailing newline, CRLF line endings, or an 8000+ character body.** The hook output must keep one line per body line, with no stray `\r`, and truncate exactly at the cap. Test: Task 3 `test_session_start_truncates_a_long_body_at_the_cap`.
3. **`write` when one is already pending.** It must refuse without `--replace` and leave the pending one byte-identical. Test: Task 1 `test_write_refuses_over_a_pending_one`.
4. **Not a git repo, or no HEAD yet.** `head` is null, and the hook prints `at (no commit)`. Test: Task 1 `test_head_is_none_outside_a_commit`.
5. **Two `done` calls in a row.** The second reports none pending and exits 0. Test: Task 2 `test_done_twice_is_idempotent`.

---

### Task 1: `aramid/handover.py` -- the file, its archive, and its age

**Files:**
- Create: `src/aramid/handover.py`
- Test: `tests/unit/test_handover_store.py`

**Interfaces:**
- Produces:
  - `Pending = dataclass(written_at: str, head: str | None, author: str | None, body: str)`
  - `handover.read(root: Path) -> Pending | None`: raises `handover.Unreadable(path)` on corrupt content.
  - `handover.write(root: Path, body: str, *, author: str | None = None, replace: bool = False, now: datetime | None = None) -> Path`: raises `handover.AlreadyPending` or `handover.EmptyBody`.
  - `handover.done(root: Path) -> Path | None`: the archive path, or None when nothing is pending.
  - `handover.age(written_at: str, now: datetime) -> str`
  - `handover.PATH = Path(".aramid") / "handover.json"`, `handover.ARCHIVE = Path(".aramid") / "handovers"`.

- [ ] **Step 1: Write the failing tests**

```python
"""The handover store: one never-committed file per repo, archived (never
deleted) when consumed."""
import json
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from aramid import handover

NOW = datetime(2026, 10, 6, 8, 0, 0, tzinfo=timezone.utc)


def _git(tmp_path):
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q",
                    "--allow-empty", "-m", "x", "--no-verify"], cwd=tmp_path, check=True)
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=tmp_path, check=True,
                          capture_output=True, text=True).stdout.strip()


def test_write_then_read_round_trips(tmp_path):
    sha = _git(tmp_path)
    path = handover.write(tmp_path, "resume step 3\n", author="claude", now=NOW)
    assert path == tmp_path / ".aramid" / "handover.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "schema": 1, "written_at": "2026-10-06T08:00:00+00:00", "head": sha,
        "author": "claude", "body": "resume step 3\n"}
    assert handover.read(tmp_path) == handover.Pending(
        "2026-10-06T08:00:00+00:00", sha, "claude", "resume step 3\n")


def test_read_with_nothing_pending_is_none(tmp_path):
    assert handover.read(tmp_path) is None


def test_write_refuses_an_empty_body(tmp_path):
    with pytest.raises(handover.EmptyBody):
        handover.write(tmp_path, "  \n\t", now=NOW)
    assert not (tmp_path / ".aramid" / "handover.json").exists()


def test_write_refuses_over_a_pending_one(tmp_path):
    handover.write(tmp_path, "first", now=NOW)
    before = (tmp_path / ".aramid" / "handover.json").read_bytes()
    with pytest.raises(handover.AlreadyPending):
        handover.write(tmp_path, "second", now=NOW)
    assert (tmp_path / ".aramid" / "handover.json").read_bytes() == before


def test_replace_archives_the_old_one_first(tmp_path):
    handover.write(tmp_path, "first", now=NOW)
    handover.write(tmp_path, "second", replace=True, now=NOW + timedelta(minutes=5))
    assert handover.read(tmp_path).body == "second"
    archived = sorted((tmp_path / ".aramid" / "handovers").iterdir())
    assert [json.loads(p.read_text(encoding="utf-8"))["body"] for p in archived] == ["first"]


def test_done_archives_and_returns_the_path(tmp_path):
    handover.write(tmp_path, "x", now=NOW)
    archived = handover.done(tmp_path)
    assert archived == tmp_path / ".aramid" / "handovers" / "2026-10-06T08-00-00+00-00.json"
    assert json.loads(archived.read_text(encoding="utf-8"))["body"] == "x"
    assert handover.read(tmp_path) is None


def test_done_with_nothing_pending_is_none(tmp_path):
    assert handover.done(tmp_path) is None


def test_two_archives_with_the_same_stamp_do_not_overwrite(tmp_path):
    handover.write(tmp_path, "a", now=NOW)
    first = handover.done(tmp_path)
    handover.write(tmp_path, "b", now=NOW)
    second = handover.done(tmp_path)
    assert first != second
    assert {json.loads(p.read_text(encoding="utf-8"))["body"]
            for p in (first, second)} == {"a", "b"}


def test_a_corrupt_file_reads_as_unreadable_not_a_crash(tmp_path):
    (tmp_path / ".aramid").mkdir()
    (tmp_path / ".aramid" / "handover.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(handover.Unreadable) as exc:
        handover.read(tmp_path)
    assert exc.value.path == tmp_path / ".aramid" / "handover.json"


def test_a_file_without_a_body_is_unreadable(tmp_path):
    (tmp_path / ".aramid").mkdir()
    (tmp_path / ".aramid" / "handover.json").write_text('{"schema": 1}', encoding="utf-8")
    with pytest.raises(handover.Unreadable):
        handover.read(tmp_path)


def test_head_is_none_outside_a_commit(tmp_path):
    handover.write(tmp_path, "x", now=NOW)              # not a git repo at all
    assert handover.read(tmp_path).head is None


@pytest.mark.parametrize("delta,expected", [
    (timedelta(seconds=42), "42s"), (timedelta(minutes=5, seconds=59), "5m"),
    (timedelta(hours=3, minutes=1), "3h"), (timedelta(days=2, hours=23), "2d"),
    (timedelta(seconds=0), "0s"),
])
def test_age_uses_the_largest_whole_unit(delta, expected):
    assert handover.age((NOW - delta).isoformat(), NOW) == expected


def test_age_of_a_future_or_garbage_stamp_is_unknown():
    assert handover.age((NOW + timedelta(hours=1)).isoformat(), NOW) == "unknown"
    assert handover.age("yesterday", NOW) == "unknown"
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python -P -m pytest tests/unit/test_handover_store.py -q`
Expected: collection error, `cannot import name 'handover'`.

- [ ] **Step 3: Implement `src/aramid/handover.py`**

```python
"""Restart / crash recovery that does not need the operator (0.20.4).

One file per repo, `.aramid/handover.json`, NEVER committed: `aramid init`
gitignores `.aramid/` everywhere. An agent writes it before a restart or a
long pause; a fresh session finds it first in the SessionStart hook and in
`aramid status`, resumes the work without asking anyone, then runs
`aramid handover done`, which ARCHIVES it under `.aramid/handovers/` --
never deleted, so what was handed over stays auditable.

Operator, 2026-10-06: "this must be true to all repo where Aramid is
running" -- per-agent memory exists in one repo for one agent; aramid is
already in every armed repo, so it carries the state.
"""
import json
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PATH = Path(".aramid") / "handover.json"
ARCHIVE = Path(".aramid") / "handovers"
SCHEMA = 1


@dataclass(frozen=True)
class Pending:
    written_at: str
    head: str | None
    author: str | None
    body: str


class EmptyBody(ValueError):
    pass


class AlreadyPending(RuntimeError):
    pass


class Unreadable(RuntimeError):
    def __init__(self, path: Path):
        super().__init__(f"{path} is not a readable handover")
        self.path = path


def _head(root: Path) -> str | None:
    try:
        done = subprocess.run(["git", "rev-parse", "--verify", "-q", "HEAD"],  # noqa: S603,S607
                              cwd=root, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    sha = done.stdout.strip()
    return sha if done.returncode == 0 and sha else None


def read(root: Path) -> Pending | None:
    path = Path(root) / PATH
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        body = data["body"]
        if not isinstance(body, str):
            raise TypeError("body")
        return Pending(str(data.get("written_at") or ""), data.get("head"),
                       data.get("author"), body)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise Unreadable(path) from exc


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _archive(root: Path) -> Path:
    src = Path(root) / PATH
    try:
        stamp = json.loads(src.read_text(encoding="utf-8")).get("written_at") or "unknown"
    except (OSError, ValueError, AttributeError):
        stamp = "unreadable"
    safe = "".join(c if c.isalnum() or c in "+-" else "-" for c in str(stamp))
    dest_dir = Path(root) / ARCHIVE
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{safe}.json"
    n = 1
    while dest.exists():
        n += 1
        dest = dest_dir / f"{safe}-{n}.json"
    os.replace(src, dest)
    return dest


def write(root: Path, body: str, *, author: str | None = None, replace: bool = False,
          now: datetime | None = None) -> Path:
    if not body.strip():
        raise EmptyBody("a handover needs a body")
    path = Path(root) / PATH
    if path.exists():
        if not replace:
            raise AlreadyPending(str(path))
        _archive(root)
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    _atomic_write(path, {"schema": SCHEMA, "written_at": stamp, "head": _head(Path(root)),
                         "author": author, "body": body})
    return path


def done(root: Path) -> Path | None:
    if not (Path(root) / PATH).exists():
        return None
    return _archive(root)


def age(written_at: str, now: datetime) -> str:
    try:
        then = datetime.fromisoformat(written_at)
    except (TypeError, ValueError):
        return "unknown"
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    secs = (now - then).total_seconds()
    if secs < 0:
        return "unknown"
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            return f"{int(secs // size)}{unit}"
    return f"{int(secs)}s"
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -P -m pytest tests/unit/test_handover_store.py -q`
Expected: all pass. Note on `test_done_archives_and_returns_the_path`: `2026-10-06T08:00:00+00:00` maps to `2026-10-06T08-00-00+00-00`, because `:` becomes `-` and `+` is kept.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/handover.py tests/unit/test_handover_store.py CHANGELOG.md
git commit -F <msg file>   # feat(handover): a per-repo, never-committed session handover store
```

---

### Task 2: `aramid handover write | show | done`

**Files:**
- Create: `src/aramid/commands/handover_cmd.py`
- Modify: `src/aramid/cli.py` (subparser beside `notices`, around line 101; dispatch beside `notices`, around line 336)
- Test: `tests/unit/test_handover_cmd.py`

**Interfaces:**
- Consumes: `handover.read/write/done/age` (Task 1).
- Produces: `cmd_handover(action: str, root: Path, *, file: str | None = None, author: str | None = None, replace: bool = False, now: datetime | None = None, stdin=None) -> int`, and `render_pending(p: Pending, now: datetime) -> str` (the `show` text, reused by Task 3).

- [ ] **Step 1: Write the failing tests**

```python
"""`aramid handover` -- the CLI over the store."""
import io
from datetime import datetime, timezone

from aramid import handover
from aramid.commands import handover_cmd

NOW = datetime(2026, 10, 6, 10, 0, 0, tzinfo=timezone.utc)
THEN = datetime(2026, 10, 6, 8, 0, 0, tzinfo=timezone.utc)


def test_show_with_nothing_pending(tmp_path, capsys):
    assert handover_cmd.cmd_handover("show", tmp_path, now=NOW) == 0
    assert capsys.readouterr().out == "no pending handover\n"


def test_write_from_stdin_then_show(tmp_path, capsys):
    rc = handover_cmd.cmd_handover("write", tmp_path, author="claude",
                                   stdin=io.StringIO("step 3 next\n"), now=THEN)
    assert rc == 0
    assert capsys.readouterr().out == f"aramid: handover written: {tmp_path / '.aramid' / 'handover.json'}\n"
    assert handover_cmd.cmd_handover("show", tmp_path, now=NOW) == 0
    assert capsys.readouterr().out == (
        "pending handover (written 2h ago, at (no commit), by claude):\n"
        "step 3 next\n")


def test_write_from_a_file(tmp_path, capsys):
    src = tmp_path / "h.md"
    src.write_text("from a file\n", encoding="utf-8")
    assert handover_cmd.cmd_handover("write", tmp_path, file=str(src), now=THEN) == 0
    assert handover.read(tmp_path).body == "from a file\n"


def test_write_refuses_empty_with_rc_2(tmp_path, capsys):
    assert handover_cmd.cmd_handover("write", tmp_path, stdin=io.StringIO("\n"), now=THEN) == 2
    assert capsys.readouterr().err == "aramid: handover: refusing an empty handover\n"


def test_write_over_a_pending_one_needs_replace(tmp_path, capsys):
    handover_cmd.cmd_handover("write", tmp_path, stdin=io.StringIO("a"), now=THEN)
    capsys.readouterr()
    assert handover_cmd.cmd_handover("write", tmp_path, stdin=io.StringIO("b"), now=THEN) == 2
    assert capsys.readouterr().err == (
        "aramid: handover: one is already pending -- read it with `aramid handover show`;"
        " pass --replace to archive it and write this one\n")
    assert handover_cmd.cmd_handover("write", tmp_path, stdin=io.StringIO("b"),
                                     replace=True, now=THEN) == 0
    assert handover.read(tmp_path).body == "b"


def test_done_archives_and_says_where(tmp_path, capsys):
    handover_cmd.cmd_handover("write", tmp_path, stdin=io.StringIO("a"), now=THEN)
    capsys.readouterr()
    assert handover_cmd.cmd_handover("done", tmp_path, now=NOW) == 0
    out = capsys.readouterr().out
    assert out == ("aramid: handover consumed; archived to "
                   f"{tmp_path / '.aramid' / 'handovers' / '2026-10-06T08-00-00+00-00.json'}\n")


def test_done_twice_is_idempotent(tmp_path, capsys):
    handover_cmd.cmd_handover("write", tmp_path, stdin=io.StringIO("a"), now=THEN)
    handover_cmd.cmd_handover("done", tmp_path, now=NOW)
    capsys.readouterr()
    assert handover_cmd.cmd_handover("done", tmp_path, now=NOW) == 0
    assert capsys.readouterr().out == "no pending handover\n"


def test_show_of_a_corrupt_file_names_it_and_returns_3(tmp_path, capsys):
    (tmp_path / ".aramid").mkdir()
    (tmp_path / ".aramid" / "handover.json").write_text("{", encoding="utf-8")
    assert handover_cmd.cmd_handover("show", tmp_path, now=NOW) == 3
    assert capsys.readouterr().err == (
        f"aramid: handover: {tmp_path / '.aramid' / 'handover.json'} is not a readable"
        " handover -- read it by hand, then `aramid handover done` archives it\n")


def test_cli_wires_the_subcommand(tmp_path, monkeypatch, capsys):
    from aramid import cli
    monkeypatch.chdir(tmp_path)
    assert cli.main(["handover", "show"]) == 0
    assert capsys.readouterr().out == "no pending handover\n"
```

(`cli.main(argv)` parses `argv` and uses `Path.cwd()` as `root`, as in `tests/integration/test_cli_dispatch.py`.)

- [ ] **Step 2: Run them to verify they fail**

Run: `python -P -m pytest tests/unit/test_handover_cmd.py -q`
Expected: FAIL. No module `aramid.commands.handover_cmd`.

- [ ] **Step 3: Implement**

`src/aramid/commands/handover_cmd.py`:

```python
"""`aramid handover write | show | done` -- see aramid/handover.py."""
import sys
from datetime import datetime, timezone
from pathlib import Path

from aramid import handover


def render_pending(p: handover.Pending, now: datetime) -> str:
    head = p.head[:12] if p.head else "(no commit)"
    by = f", by {p.author}" if p.author else ""
    body = p.body if p.body.endswith("\n") else p.body + "\n"
    return f"pending handover (written {handover.age(p.written_at, now)} ago, at {head}{by}):\n{body}"


def cmd_handover(action: str, root, *, file: str | None = None, author: str | None = None,
                 replace: bool = False, now: datetime | None = None, stdin=None) -> int:
    root = Path(root)
    now = now or datetime.now(timezone.utc)
    if action == "write":
        if file and file != "-":
            body = Path(file).read_text(encoding="utf-8")
        else:
            body = (stdin or sys.stdin).read()
        try:
            path = handover.write(root, body, author=author, replace=replace, now=now)
        except handover.EmptyBody:
            print("aramid: handover: refusing an empty handover", file=sys.stderr)
            return 2
        except handover.AlreadyPending:
            print("aramid: handover: one is already pending -- read it with"
                  " `aramid handover show`; pass --replace to archive it and write this one",
                  file=sys.stderr)
            return 2
        print(f"aramid: handover written: {path}")
        return 0
    try:
        pending = handover.read(root)
    except handover.Unreadable as exc:
        print(f"aramid: handover: {exc.path} is not a readable handover -- read it by hand,"
              f" then `aramid handover done` archives it", file=sys.stderr)
        if action != "done":
            return 3
        pending = True
    if action == "show":
        if pending:
            print(render_pending(pending, now), end="")
        else:
            print("no pending handover")
        return 0
    if action == "done":
        archived = handover.done(root)
        print(f"aramid: handover consumed; archived to {archived}" if archived
              else "no pending handover")
        return 0
    print(f"aramid: handover: unknown action {action!r}", file=sys.stderr)
    return 2
```

`cli.py`, the subparser:

```python
    p_handover = sub.add_parser("handover",
                                help="session handover for restarts: write (stdin or --file),"
                                     " show, done (archives it)")
    handover_sub = p_handover.add_subparsers(dest="handover_command")
    p_hw = handover_sub.add_parser("write")
    p_hw.add_argument("--file", default=None, help="read the body from FILE ('-' = stdin)")
    p_hw.add_argument("--author", default=None)
    p_hw.add_argument("--replace", action="store_true",
                      help="archive a pending handover and write this one")
    handover_sub.add_parser("show")
    handover_sub.add_parser("done")
```

The dispatch:

```python
    if args.command == "handover":
        from aramid.commands.handover_cmd import cmd_handover
        return cmd_handover(args.handover_command or "show", root,
                            file=getattr(args, "file", None),
                            author=getattr(args, "author", None),
                            replace=getattr(args, "replace", False))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -P -m pytest tests/unit/test_handover_cmd.py tests/integration/test_cli_dispatch.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/handover_cmd.py src/aramid/cli.py tests/unit/test_handover_cmd.py CHANGELOG.md
git commit -F <msg file>   # feat(cli): aramid handover write | show | done
```

---

### Task 3: Delivery -- SessionStart hook, `aramid status`, MCP tools

**Files:**
- Modify: `src/aramid/commands/agent_hook.py` (`_session_context`, around line 138); `src/aramid/commands/status.py` (`cmd_status`, around line 417); `src/aramid/mcp_tools.py` (`TOOLS`, around line 162)
- Modify test: `tests/unit/test_mcp_tools.py::test_tool_names_are_exactly_the_spec_seven` (rename to `..._spec_ten`, add the three names)
- Test: `tests/unit/test_handover_delivery.py`

**Interfaces:**
- Consumes: `handover.read`, `handover.age`, `handover_cmd.render_pending`, `handover_cmd.cmd_handover` (Tasks 1 and 2).
- Produces: `agent_hook._handover_lines(repo: Path, now: datetime) -> list[str]` and `status._handover_line(root: Path, now: datetime) -> str | None`.

- [ ] **Step 1: Write the failing tests**

```python
"""A pending handover is the FIRST thing a fresh session sees."""
from datetime import datetime, timezone

from aramid import handover
from aramid.commands import agent_hook as ah
from aramid.commands import status

NOW = datetime(2026, 10, 6, 10, 0, 0, tzinfo=timezone.utc)
THEN = datetime(2026, 10, 6, 8, 0, 0, tzinfo=timezone.utc)


def test_no_handover_no_lines(tmp_path):
    assert ah._handover_lines(tmp_path, NOW) == []
    assert status._handover_line(tmp_path, NOW) is None


def test_session_start_lines_lead_with_the_instruction(tmp_path):
    handover.write(tmp_path, "step 3 next\r\nthen push\n", now=THEN)
    assert ah._handover_lines(tmp_path, NOW) == [
        "aramid: PENDING HANDOVER written 2h ago at (no commit) -- resume it WITHOUT"
        " asking the operator, then run 'aramid handover done':",
        "aramid: | step 3 next",
        "aramid: | then push",
    ]


def test_session_start_truncates_a_long_body_at_the_cap(tmp_path):
    body = "\n".join("x" * 99 for _ in range(100))     # 9999 characters
    handover.write(tmp_path, body, now=THEN)
    lines = ah._handover_lines(tmp_path, NOW)
    shown = "\n".join(l.removeprefix("aramid: | ") for l in lines[1:-1])
    assert len(shown) <= 8000
    assert lines[-1] == "aramid: | ... (truncated; 'aramid handover show' prints all of it)"


def test_session_start_survives_a_corrupt_handover(tmp_path):
    (tmp_path / ".aramid").mkdir()
    (tmp_path / ".aramid" / "handover.json").write_text("{", encoding="utf-8")
    assert ah._handover_lines(tmp_path, NOW) == [
        "aramid: PENDING HANDOVER file is unreadable: "
        f"{tmp_path / '.aramid' / 'handover.json'} -- read it by hand, then"
        " 'aramid handover done'"]


def test_status_line(tmp_path):
    handover.write(tmp_path, "x", now=THEN)
    assert status._handover_line(tmp_path, NOW) == (
        "  handover: PENDING, written 2h ago -- 'aramid handover show'")


def test_mcp_tools_exist_and_round_trip(tmp_path, monkeypatch):
    import subprocess
    from aramid import mcp_tools
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    (tmp_path / "aramid.toml").write_text("schema_version = 1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    out = mcp_tools.TOOLS["aramid_handover_write"]["handler"](None, {"body": "resume X"})
    assert out["isError"] is False
    out = mcp_tools.TOOLS["aramid_handover_show"]["handler"](None, {})
    assert "resume X" in out["content"][0]["text"]
    out = mcp_tools.TOOLS["aramid_handover_done"]["handler"](None, {})
    assert out["isError"] is False
    assert handover.read(tmp_path) is None
```

Also pin the integration: in `tests/unit/test_agent_hook_dispatch.py`, add a test that with a pending handover `_session_context(r)` STARTS with the PENDING line and still ends with the `aramid: commands:` line, so the posture block is intact after it.

- [ ] **Step 2: Run them to verify they fail**

Run: `python -P -m pytest tests/unit/test_handover_delivery.py -q`
Expected: FAIL. `agent_hook` has no `_handover_lines`.

- [ ] **Step 3: Implement**

`agent_hook.py`:

```python
_HANDOVER_CAP = 8000


def _handover_lines(repo: Path, now) -> list[str]:
    """A pending handover, FIRST in the SessionStart block (0.20.4): the
    session that finds it resumes it without asking the operator. A corrupt
    file is reported in one line and never breaks the posture block."""
    from aramid import handover
    try:
        p = handover.read(repo)
    except handover.Unreadable as exc:
        return [f"aramid: PENDING HANDOVER file is unreadable: {exc.path} -- read it"
                f" by hand, then 'aramid handover done'"]
    if p is None:
        return []
    head = p.head[:12] if p.head else "(no commit)"
    lines = [f"aramid: PENDING HANDOVER written {handover.age(p.written_at, now)} ago at"
             f" {head} -- resume it WITHOUT asking the operator, then run"
             f" 'aramid handover done':"]
    body = p.body.replace("\r\n", "\n").replace("\r", "\n")
    truncated = len(body) > _HANDOVER_CAP
    lines.extend("aramid: | " + l for l in body[:_HANDOVER_CAP].rstrip("\n").split("\n"))
    if truncated:
        lines.append("aramid: | ... (truncated; 'aramid handover show' prints all of it)")
    return lines
```

In `_session_context`, build `lines` as today, then prefix it with
`_handover_lines(repo, datetime.now(timezone.utc)) + ` before joining. The
`datetime` import already exists further down that function, so hoist it to
module scope.

`status.py`:

```python
def _handover_line(root: Path, now) -> str | None:
    from aramid import handover
    try:
        p = handover.read(root)
    except handover.Unreadable as exc:
        return f"  handover: UNREADABLE {exc.path} -- read it by hand, then 'aramid handover done'"
    if p is None:
        return None
    return f"  handover: PENDING, written {handover.age(p.written_at, now)} ago -- 'aramid handover show'"
```

In `cmd_status`, right after `"aramid status:",`, insert the line when it is not None.

`mcp_tools.py`, with handlers next to the others:

```python
@_onboarded
def _handover_show(repo, args):
    from aramid.commands.handover_cmd import cmd_handover
    return _run(cmd_handover, "show", repo)


@_onboarded
def _handover_write(repo, args):
    import io
    from aramid.commands.handover_cmd import cmd_handover
    body = args.get("body")
    if not isinstance(body, str) or not body.strip():
        raise _InvalidParams("`body` is required and must be non-empty")
    return _run(cmd_handover, "write", repo, author=args.get("author"),
                replace=bool(args.get("replace", False)), stdin=io.StringIO(body))


@_onboarded
def _handover_done(repo, args):
    from aramid.commands.handover_cmd import cmd_handover
    return _run(cmd_handover, "done", repo)
```

The three `TOOLS` entries:

```python
    "aramid_handover_show": {
        "description": "The pending session handover for this repo, if any"
                       " -- resume it without asking the operator.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": _handover_show,
    },
    "aramid_handover_write": {
        "description": "Record where you are before a restart or long pause;"
                       " the next session resumes from it. Refuses over a"
                       " pending one unless replace is true.",
        "inputSchema": {
            "type": "object",
            "properties": {"body": {"type": "string", "minLength": 1},
                           "author": {"type": "string"},
                           "replace": {"type": "boolean"}},
            "required": ["body"],
        },
        "handler": _handover_write,
    },
    "aramid_handover_done": {
        "description": "Mark the pending handover consumed (archived, never deleted).",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": _handover_done,
    },
```

- [ ] **Step 4: Run the tests and every pin on these surfaces**

Run: `python -P -m pytest tests/unit/test_handover_delivery.py tests/unit/test_agent_hook_dispatch.py tests/unit/test_mcp_tools.py tests/unit/test_agent_mcp.py tests/unit/test_mcp_protocol.py tests/unit/test_status_lines.py tests/integration/test_agent_hook*.py -q`
Expected: all pass after the tool-count pin is updated to ten.

- [ ] **Step 5: Commit**

```bash
git add src/aramid/commands/agent_hook.py src/aramid/commands/status.py src/aramid/mcp_tools.py tests/unit/test_handover_delivery.py tests/unit/test_mcp_tools.py tests/unit/test_agent_hook_dispatch.py CHANGELOG.md
git commit -F <msg file>   # feat(handover): SessionStart, status and MCP surface a pending handover first
```

---

### Task 4: Tell every agent -- template, managed block, this repo's copies

**Files:**
- Modify: `src/aramid/data/ARAMID.md.tmpl` (agent section); `src/aramid/agent_files.py` (`_BLOCK`)
- Modify tests: `tests/unit/test_agent_files.py::test_block_full_text_is_pinned`
- Regenerate (aramid code, `PYTHONPATH=src`): `ARAMID.md`, `CLAUDE.md`, `AGENTS.md`

- [ ] **Step 1: Update the pin first (red)**

In `test_block_full_text_is_pinned`, add after the tool-only bullet and before `<!-- aramid:end -->`:

```
- Before a restart or a long pause, record where you are with
  `aramid handover write`; a fresh session that finds one pending resumes
  it without asking the operator, then runs `aramid handover done`.
```

Run: `python -P -m pytest tests/unit/test_agent_files.py::test_block_full_text_is_pinned -q`. Expected: FAIL.

- [ ] **Step 2: Change `_BLOCK` to match, and add the same bullet to `ARAMID.md.tmpl`** in its agent-instructions list (read the template for the list's current shape and register).
- [ ] **Step 3: Regenerate this repo's copies**

```bash
PYTHONPATH=src python -P -c "from pathlib import Path; from aramid.commands.init import _write_aramid_md; from aramid.detectors import detect_stacks, detect_package_manager; r=Path('.'); _write_aramid_md(r, detect_stacks(r, r), detect_package_manager(r))"
PYTHONPATH=src python -P -c "from pathlib import Path; from aramid import agent_files; print(agent_files.write_agent_blocks(Path('.')))"
git diff --stat ARAMID.md CLAUDE.md AGENTS.md
```

Expected: only the new bullet changes in each file. Check with `git diff`; never accept a wider diff without reading it.

- [ ] **Step 4: Run** `python -P -m pytest tests/unit/test_agent_files.py tests/unit/test_aramid_md_template_sync.py tests/unit/test_tool_only_rule.py tests/integration/test_init.py -q`. Expected: pass.
- [ ] **Step 5: CHANGELOG `[Unreleased]`**, `### Added`: `aramid handover`, the delivery surfaces, and the line "consumers pick up the instruction on their next `aramid init`". Then commit.
- [ ] **Step 6: Full unit suite** with the rc read directly (`> log 2>&1; echo $? > rc`), then push per the watchdog plan's Global Constraint 9.
