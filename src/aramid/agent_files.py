"""agent_files -- the managed instruction block aramid owns inside a
consumer's agent instruction files (CLAUDE.md, AGENTS.md).

Spec: docs/superpowers/specs/2026-08-31-aramid-agent-enforcement-design.md §3.

The block is regenerated wholesale on every `init`, like ARAMID.md -- but
unlike ARAMID.md these files are SHARED with the operator and other tools,
so every write is fence-scoped: content outside the markers is never
touched, and a file whose fence is damaged (a begin marker with no end
marker) is never written at all. A splice that cannot see where the fence
ends would eat whatever follows it, so refusing is the only safe write.

Only durable instructions belong in the block -- no counts, dates, or
posture. Live state is the session-start agent hook's job (spec §5); a
tracked file must not be able to go stale against the ledger.
"""
from pathlib import Path

AGENT_FILES = ("CLAUDE.md", "AGENTS.md")

_BEGIN_PREFIX = "<!-- aramid:begin"
_END_MARKER = "<!-- aramid:end -->"

_BLOCK = """\
<!-- aramid:begin -- managed by `aramid init`; hand-edits inside the fence are overwritten -->
## Aramid (security & quality gate)

This repo is gated by aramid. Read `ARAMID.md` before your first commit.

- Before committing: run `aramid check --staged`. Read findings with
  `aramid ledger filter --status open`.
- NEVER pass `--no-verify` (or `-n`) to `git commit`, or `--no-verify` to
  `git push` -- it disables secret scanning along with everything else.
- To suppress a WARN finding, use `aramid override <id> --reason "..."`
  (ledger-logged); never edit findings away by hand.
<!-- aramid:end -->
"""


def render_block() -> str:
    return _BLOCK


def _find_fence(lines: list[str]) -> tuple[int | None, int | None]:
    """Indexes of the begin and end marker lines, either possibly None."""
    begin = end = None
    for i, line in enumerate(lines):
        if begin is None and line.lstrip().startswith(_BEGIN_PREFIX):
            begin = i
        elif begin is not None and line.strip() == _END_MARKER:
            end = i
            break
    return begin, end


def write_agent_blocks(root: Path) -> list[tuple[str, str]]:
    """Write/refresh the managed block in each of AGENT_FILES.

    Returns [(filename, action)]; action is one of "created" (file was
    absent), "appended" (file had no fence), "replaced" (fence refreshed),
    "unchanged" (fence already current), "damaged" (begin marker without an
    end marker -- file left untouched, caller must report it).
    """
    actions: list[tuple[str, str]] = []
    for name in AGENT_FILES:
        path = root / name
        if not path.is_file():
            path.write_text(_BLOCK, encoding="utf-8")
            actions.append((name, "created"))
            continue
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        begin, end = _find_fence(lines)
        if begin is not None and end is None:
            actions.append((name, "damaged"))
            continue
        if begin is None:
            sep = ("" if text.endswith("\n\n")
                   else "\n" if text.endswith("\n") else "\n\n")
            path.write_text(text + sep + _BLOCK, encoding="utf-8")
            actions.append((name, "appended"))
            continue
        new = "".join(lines[:begin]) + _BLOCK + "".join(lines[end + 1:])
        if new == text:
            actions.append((name, "unchanged"))
        else:
            path.write_text(new, encoding="utf-8")
            actions.append((name, "replaced"))
    return actions


def remove_agent_blocks(root: Path) -> list[tuple[str, str]]:
    """Reverse of write_agent_blocks, for `aramid uninstall`.

    Returns [(filename, action)]; "removed" strips the fence, "deleted"
    unlinks a file that held nothing but the block, "absent" means no file
    or no fence, "damaged" means an unterminated fence -- untouched, same
    refusal as the writer and for the same reason.
    """
    actions: list[tuple[str, str]] = []
    for name in AGENT_FILES:
        path = root / name
        if not path.is_file():
            actions.append((name, "absent"))
            continue
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        begin, end = _find_fence(lines)
        if begin is None:
            actions.append((name, "absent"))
            continue
        if end is None:
            actions.append((name, "damaged"))
            continue
        rest = "".join(lines[:begin]) + "".join(lines[end + 1:])
        if rest.strip():
            path.write_text(rest, encoding="utf-8")
            actions.append((name, "removed"))
        else:
            path.unlink()
            actions.append((name, "deleted"))
    return actions


def agent_block_states(root: Path) -> list[tuple[str, str]]:
    """Read-only state per agent file, for `aramid doctor`.

    States: "ok" (fence matches the current template), "stale" (fence
    present but differs), "absent" (no file or no fence), "damaged"
    (unterminated fence). Doctor reports; it never rewrites.
    """
    block_lines = _BLOCK.splitlines(keepends=True)
    states: list[tuple[str, str]] = []
    for name in AGENT_FILES:
        path = root / name
        if not path.is_file():
            states.append((name, "absent"))
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        except OSError:
            states.append((name, "absent"))
            continue
        begin, end = _find_fence(lines)
        if begin is None:
            states.append((name, "absent"))
        elif end is None:
            states.append((name, "damaged"))
        elif lines[begin:end + 1] == block_lines:
            states.append((name, "ok"))
        else:
            states.append((name, "stale"))
    return states
