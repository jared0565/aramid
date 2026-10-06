# aramid 0.20.4 -- stall watchdog and session handover (design)

Date: 2026-10-06. Status: DESIGN, decided by the agent under the operator's
2026-10-06 rules (below); the operator may redirect, nobody waits for them.

Two operator requirements from 2026-10-06, one release:

1. **"Aramid as a tool must be able to recognize this kind of events."** A
   pip-audit run sat idle for 97 minutes while its caller waited for it to
   finish. aramid's own launcher would have cut it at the runner's wall-clock
   budget and reported `timeout after 180 s`. That line says nothing about
   whether the child was working slowly or doing nothing at all.
2. **"This must be true to all repo where Aramid is running."** Restart and
   crash recovery must not depend on the operator carrying a prompt across the
   restart, nor on per-repo agent memory that only Claude has. aramid is
   already present in every armed repo, so aramid carries the handover.

Part A (the watchdog) and Part B (the handover) share no code. Each has its
own plan:
`docs/superpowers/plans/2026-10-06-stall-watchdog.md` and
`docs/superpowers/plans/2026-10-06-session-handover.md`.

---

## Part A -- the stall watchdog

### A.1 What was measured (2026-10-06, Windows 11, CPython 3.14)

- **The hang's likely mechanism, demonstrated (not observed as the 02:30Z
  cause).** pip-audit 2.10.1's `pip_audit/_subprocess.py::run` opens the
  child with `Popen(bufsize=0, stdout=PIPE, stderr=PIPE)`. It then calls
  `process.stdout.read()` with no size, which on a raw `FileIO` reads to EOF,
  and it never drains stderr in the meantime. A child that writes more than
  the Windows default pipe buffer to stderr therefore blocks on that write.
  pip-audit's own `run()` returned in 0.4 s at 1000 and 4000 bytes of child
  stderr, and HUNG at 4200, 8000, 16000, 70000 and 200000 bytes, so the
  threshold is 4096. Both processes then sit at exactly zero CPU, and pip's
  keep-alive socket stays ESTABLISHED. That is the signature the 02:30Z
  stall showed. No pip timeout can break it, which fits `PIP_DEFAULT_TIMEOUT=60`
  not helping. Linux pipe buffers are 64 KB, so this is mostly a Windows
  hazard.
- **The stall is not deterministic.** The same project-mode audit ran clean
  in 37 s at 08:12Z, and the push gate's own audit at 08:19Z finished in
  under a minute.
- **A process-tree sampler distinguishes the cases**
  (`stallwatch_proto.py`, session scratchpad; ctypes Toolhelp32 +
  `GetProcessTimes`). It sampled every 5 s with a 20 s window:

  | arm | verdict |
  |---|---|
  | pip-audit `run()` deadlock (200 KB stderr) | stalled at 25 s, tree of 2, CPU delta exactly 0 |
  | busy loop | never idle; hit the 30 s hard cap |
  | sleeps 3 s, prints a line each time | exited rc 0, never idle |
  | `time.sleep(40)` | **stalled at 25 s**, the false-stall shape (see A.4) |
  | busy GRANDCHILD under an idle child | never idle (descendant CPU counted) |
  | real pip-audit CLI, unreachable extra index (retry/backoff) | never stalled in 240 s. Idle gaps reached 25 s between 15.6 ms CPU ticks |

  pip-audit's spinner wrote nothing to a non-TTY pipe in its idle windows, so
  the no-output signal holds for it. Windows charges CPU in 15.6 ms ticks, so
  "no CPU" here means not a single tick charged in the window.

### A.2 Behaviour

`runners/base.py::run_subprocess` is the single launcher for every runner
and consumer (21 call sites in `src/`; `graphite query "callers
run_subprocess"`). Its wait becomes a loop that wakes every `SAMPLE_S`
(15 s) until the child exits, the wall-clock budget expires, or the child
is judged stalled. At each wake it records:

- the child's **process tree**: a map of `pid -> (creation time, CPU
  time)` covering the child and every descendant;
- the **bytes read so far** from stdout and stderr. Both pipes are always
  drained by daemon reader threads; the `_tapped_communicate` shape becomes
  the only path.

A wake counts as **activity** when the tree's membership changed, any
member's CPU time advanced, or either byte count advanced. If there has
been no activity for `stall_s` seconds, the child is **stalled**: the
launcher kills the tree (`_kill_tree`), waits for the kill under the
existing post-kill cap, and returns:

```python
RunnerResult(tool, ToolState.TIMEOUT, stderr=<reason>, duration_s=<elapsed>,
             stalled_s=<idle seconds>)
```

The reason text is:
`aramid: <tool> stalled: no CPU in any of its <n> processes and no output for <idle> s; killed after <elapsed> s. A child blocked on a full pipe or on a read with no timeout looks like this; a slow one does not.`

**Why TIMEOUT and not a new `ToolState`.** About a dozen sites branch on
`state is ToolState.TIMEOUT`. They include the mutation and js_mutation
consumers ("a TIMEOUT IS NOT A FAILURE": a killed run must not read as a
killed mutant), fuzz, `pipeline._BAD_STATES`, `runners/tests.py` and
`runners/_util.py`. A new enum member would fall into their default
branches, and in mutation that default means "mutant killed". A stall is a
timeout that was recognised early. Its control flow must be identical, and
only its report differs.

### A.3 Measuring the tree (no new dependency)

`aramid/proctree.py`, standard library only, because `runners/base.py`
must import nothing outside it (sdist `--no-deps` smoke). One function:

```python
def sample(root_pid: int) -> dict[int, tuple[int, int]] | None
```

It returns `{pid: (creation_ticks, cpu_ticks)}` for the root and every
descendant, or `None` if the tree cannot be measured. **`None` means "not
measured", and the watchdog treats it as activity.** A watchdog that cannot
see must behave exactly as today's wall-clock timeout, never as a stall.

- **Windows**: `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` gives
  (pid, ppid). `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` plus
  `GetProcessTimes` give creation and kernel+user time. This is measured
  above.
- **Linux**: `/proc/<pid>/stat`. Parse after the LAST `)` (the comm field
  can contain spaces and parentheses). Fields are ppid (4), utime (14),
  stime (15), starttime (22). Enumerate `/proc/[0-9]*`.
- **macOS and others**: `ps -A -o pid=,ppid=,time=`, bounded at 5 s. If it
  fails, returns non-zero or produces unparseable output, the result is
  `None`. Creation time is not available here, so it is recorded as 0.
- **PID reuse**: a candidate child created before its parent is not a
  descendant and is skipped (Windows and Linux). Wherever this guard is
  wrong or absent, the error shows up as a membership change, and that is
  activity. Every measurement error leans toward "active", never toward a
  false stall.

### A.4 The window, and the false-stall risk

A legitimately quiet child reads as stalled: `time.sleep(40)` did so at
20 s in A.1. So does a test waiting on a container or service outside the
tree. The defaults are chosen against that:

- `stall_s` default **300**. That is 12x the longest legitimate idle gap
  measured (pip backoff, 25 s). It still turns the 4800 s budget on this
  repo's test gate into a 5-minute detection.
- `stall_s = 0` disables the watchdog: today's behaviour, wall clock only.
- Configured as `[timeouts] stall_s` (aramid.toml or `~/.aramid/config.toml`).
  It is read once per command and set as module state with
  `runners.base.set_stall_window(seconds)`, the same pattern as the drain's
  `closed()` registry. The launchers are reached from inside consumers that
  hold no config, so module state is how the setting reaches them.
- When `stall_s >= timeout_s`, the watchdog cannot fire before the budget
  does. It still runs; it simply never decides first.

### A.5 Reporting

- `pipeline._degraded_reasons`: a TIMEOUT with `stalled_s` reads
  `stalled: no CPU or output for <idle> s (killed after <elapsed> s)`
  instead of `timeout after <n> s`. The console's degraded list, the run
  row's `degraded` map and `GateResult.degraded_reasons` all take it from
  there.
- `GateResult.stalled: tuple[str, ...]`, sorted tool names. It is built
  where `degraded_reasons` is built, from `RunnerResult.stalled_s`, never by
  parsing the reason string.
- `health.Health.stalled_tools` and the fleet row's
  `evidence.stalled_tools`. The `no_self_inflicted_block` red description
  then reads `pip-audit (stalled)` rather than a bare `pip-audit`.
- `aramid status`, on the last-run line: `..., stalled: pip-audit`, only when
  the latest run had one.

### A.6 Out of scope

- Fixing pip-audit. The deadlock is upstream (`_subprocess.run`). Reporting
  it is an outward-facing act and the operator's call. The watchdog makes
  aramid robust to it either way.
- The gate-level budget (`_run_selected` abandoning a runner at the gate's
  budget) is unchanged.
- `gitutil._run` and `providers.base.run_provider_subprocess` keep their own
  launchers and timeouts. They are short-budget and out of this release.

---

## Part B -- the session handover

### B.1 Shape

- **One file per repo, never committed**: `.aramid/handover.json`. `aramid
  init` writes `.aramid/` into every consumer's `.gitignore`
  (`GITIGNORE_ENTRIES`), so it is untracked by construction. The file holds:
  ```json
  {"schema": 1, "written_at": "<UTC ISO>", "head": "<git sha or null>",
   "author": "<free text or null>", "body": "<markdown>"}
  ```
- **Consumed, not deleted**: `done` moves it to
  `.aramid/handovers/<written_at, filesystem-safe>.json`. The archive is the
  audit trail. Nothing prunes it in this release.
- Written atomically: write a temp file in `.aramid/`, then `os.replace`.

### B.2 Commands (`aramid handover ...`) and MCP tools

| command | effect | exit |
|---|---|---|
| `write [--file F]` (stdin when no `--file` or `-`) | refuses an empty or whitespace-only body (rc 2); refuses when one is already pending unless `--replace`, which archives the old one first | 0 / 2 |
| `show` | prints `pending handover (written <age> ago, at <head12>[, by <author>]):` then the body. With none pending, prints `no pending handover` | 0 |
| `done` | archives the pending one and prints where it went. With none, prints `no pending handover` (idempotent) | 0 |

MCP: `aramid_handover_show`, `aramid_handover_write` (`body`, optional
`author`, `replace`) and `aramid_handover_done`, in `mcp_tools.py` and
behind `@_onboarded`, like the existing seven tools.

### B.3 Delivery: a fresh session finds it without the operator

- **SessionStart hook** (`commands/agent_hook._session_context`). When a
  handover is pending, the FIRST lines are:
  `aramid: PENDING HANDOVER written <age> ago at <head12> -- resume it WITHOUT asking the operator, then run 'aramid handover done':`
  followed by the body, each line prefixed `aramid: | `, capped at 8000
  characters. Past the cap: `aramid: | ... (truncated; 'aramid handover show' prints all of it)`.
- **`aramid status`**: right after `aramid status:`, the line
  `  handover: PENDING, written <age> ago -- 'aramid handover show'`. This
  also reaches non-Claude agents through the `aramid_status` MCP tool.
- **Docs**: the `ARAMID.md` template and the managed agent block
  (`agent_files._BLOCK`, CLAUDE.md and AGENTS.md) gain one bullet:
  `- Before a restart or a long pause, record where you are with
  `aramid handover write`; a fresh session that finds one pending resumes
  it without asking the operator, then runs `aramid handover done`.`
  Consumers get it on their next `aramid init`. This repo's block is
  refreshed by running `init` as a tool, never by hand.

### B.4 Threat model and provenance

- **What a planted handover could do.** The hook delivers the body to a fresh
  agent framed as "resume WITHOUT asking the operator". A file an attacker
  placed in `.aramid/handover.json` is therefore a prompt injection with the
  operator's own authority attached. Gitignoring `.aramid/` does not stop
  that: `git add -f`, a zip or tarball download, a copied folder, and a
  case-variant or submodule `.aramid` all deliver a file.
- **Why a git check cannot cover it.** A git check (`ls-files`) sees only
  what arrived through git. A zip, a copy, or a directory with no `.git` at
  all carries a file with no index entry, and every git-based variant tried
  leaked (case-variant paths, a gitlink `.aramid`, `GIT_LITERAL_PATHSPECS`,
  a "dubious ownership" refusal read as "not tracked"). The only check that
  covers every route authenticates the file's ORIGIN.
- **Provenance.** `write` signs the file; `read` delivers it only when the
  signature verifies, with no git subprocess and no network. The key is 32
  bytes from `secrets.token_bytes`, created on the first `write` at `~/.aramid/handover.key`
  (written complete to a temp file, fsynced, then published with `os.link`,
  which never replaces; where hard links are unavailable it falls back to
  `O_EXCL` creation), or at `$ARAMID_HANDOVER_KEY_FILE`
  when set (an env var, so spawned test processes see the same path). `read`
  never creates it. The file gains `"v": 1`, `"root"` (the repo's
  `os.path.normcase(os.path.realpath(root))`) and `"mac"`, an HMAC-SHA256 over
  the canonical JSON (sorted keys, compact, ASCII) of `v`, `root`,
  `written_at`, `head`, `author` and `body`. A handover copied into another
  repo on the same machine fails on `root`; an edited field fails the MAC; a
  missing or corrupt key (not exactly 32 bytes, never regenerated silently)
  means nothing can be verified.
- **The MAC covers exactly the delivered fields.** `v`, `root`, `written_at`,
  `head`, `author` and `body` are authenticated; any other field in the file
  is ignored and never delivered. The MAC is checked over the STORED fields
  first, with the stored root as part of the input, and only then is the
  stored root compared with this repo's, so nothing read from the file is
  echoed before it is authenticated. `v` must be the integer 1 (not `true`,
  not `1.0`).
- **An unverified file is visible, never an instruction.** `read` raises
  `Unreadable(path, reason, pending, kind, stored_root)`. `kind` is one of a
  fixed set of eleven (`corrupt`, `too_large`, `symlink`, `not_regular`,
  `unsigned`, `no_key`, `key_corrupt`, `key_unreadable`, `mismatch`,
  `other_repo`, `io_error`; an `OSError` such as a sharing violation is
  `io_error`, not corruption).
  Consumers print FIXED text per kind, never the free-form `reason`; the one
  variable they may print is `stored_root`, set only for `other_repo` after
  the MAC verified it, and only through `Unreadable.display_root` (or
  `handover.printable`), which escapes every control or line-breaking
  character and backslashes (a signed POSIX path can legally contain a
  newline, and a literal backslash-n must not look like an escaped one). `pending` carries the parsed body when only
  provenance failed, so `show` can print it under a NOT VERIFIED header for a
  human; the hook never prints the body. A file over 1 MiB, or one that is not
  a regular file, is refused before it is parsed (on POSIX the open uses
  `O_NOFOLLOW|O_NONBLOCK` and re-checks type and size on the fd), so a planted
  FIFO or huge file cannot stall session start. Every field the MAC covers is
  type-checked BEFORE it is hashed, so a deeply nested JSON file, or a field
  of the wrong type (except `v`/`mac`, which read as `unsigned`), reads as
  `corrupt` and nothing nested reaches the MAC;
  `done` or `--replace` still archives any such file.
- **Trade-off.** The root is part of the signature, so renaming or moving
  the repo turns its pending handover into "written for another repo" until
  it is done or replaced. `done` and `--replace` archive an unverified file
  like any other and never delete it.
- **Out of reach.** The MAC proves "aramid on this machine wrote it", not
  "the operator meant it": a prompt-injected agent with shell access can run
  `aramid handover write`, and an archived handover moved back into place
  verifies. Anyone who can read `~/.aramid/handover.key` or run code as the
  operator can sign a handover too; all of these fall under the operator's own
  account. This defends against a repository's contents, not against that.

### B.5 Out of scope

Expiry, multiple concurrent handovers, ledger events, and graphite. graphite
holds code-graph state only. Whether it should mirror this is an improvement
suggestion for its channel, not something to build there.
