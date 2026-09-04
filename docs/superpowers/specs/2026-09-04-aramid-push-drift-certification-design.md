# aramid: pre-push certification names what it certified, and fails when it moves

**Date:** 2026-09-04
**Status:** accepted (interop round 176 from graphite-agent; reproduced first-hand, see section 2)
**Scope:** `aramid check --gate pre-push`, the managed pre-push shim, the run row, the reporter

## 1. The finding

Over smart HTTP, `git push` runs the pre-push hook in the parent process
FIRST, with the ref list it resolved before the hook; THEN `git-remote-http`
spawns `git send-pack --stdin`, which is handed the refspec by NAME
(`refs/heads/main:refs/heads/main`) and resolves it itself, at hook EXIT.
The parent prints and updates tracking from ITS resolution. So a commit made
on the branch while the hook runs ships, ungated, while `git push` prints
the pre-hook range. Native transports (`file://`, `ssh://`, `git://`) pack
the parent's object ids and are not affected.

graphite-agent saw it in production (round 176): its push 5's gate certified
`e451980..12a1d68`; a commit made nine minutes into the 18-minute gate,
`673c804`, is what GitHub's branch activity shows arriving, with no gate run
and no CI run of its own on `12a1d68`.

## 2. Reproduced here

Measured 2026-09-04 on this machine, git 2.53.0.windows.1, two arms
(`scratchpad/httpexp/exp.py`, `server.py`: `git http-backend` behind a
50-line CGI shim). Hook = `sleep 6`, recording `git rev-parse main` at start
and end; an empty commit 2.5 s in.

    file:// remote -> remote tip = PRE-hook tip; git printed the pre-hook range   <- control
    smart HTTP     -> remote tip = the IN-HOOK commit; git printed the pre-hook range

Both arms printed all three shas, so a non-execution cannot read as a pass.

## 3. Why it is aramid's defect and not only git's

The gate's own contract is "what reached the remote passed the gate". Today
`aramid check --gate pre-push`:

- never reads the hook's stdin -- the `<local ref> <local sha> <remote ref>
  <remote sha>` lines git hands every pre-push hook -- so it does not even
  know which refs it is certifying;
- resolves its range as `@{u}..HEAD` at START (`gitutil.resolve_range`) and
  never looks again;
- records on the run row `tools` / `selected` / `expected` only, so the
  ledger cannot answer "which commits did this pre-push run cover".

On this repo the gate takes ~33 minutes over an HTTPS remote. The window is
a working session, and nothing local says it happened.

## 4. Design

### 4.1 The shim marks itself as the caller

`hooks.render_shim` prefixes both interpreter arms with `ARAMID_HOOK=<gate>`:

    ARAMID_HOOK=pre-push "$INTERP" -P -m aramid check --gate pre-push --all --strict

The gate reads stdin ONLY under that marker. By hand and in CI the process
may have an empty non-tty stdin (CI does), and reading it there would turn
the CI pre-push-tier run into "nothing to push" (section 4.4). The marker is
the only signal that git is on the other end of the pipe.

`aramid init` regenerates the shim (it is machine-local and gitignored).
Until a consumer re-runs `init`, its shim has no marker and the gate uses the
HEAD fallback of 4.3 -- which still catches a moved branch for the ordinary
`git push origin <current branch>`.

### 4.2 What is certified: `pushrefs`

New module `src/aramid/pushrefs.py`:

- `PushRef(local_ref, local_sha, remote_ref, remote_sha)` -- one stdin line.
- `parse_push_lines(text) -> list[PushRef]`: four whitespace-separated
  fields per non-empty line; a malformed line is skipped (fail-open, never
  raises inside a gate); a deletion (`local_ref == "(delete)"` or an all-zero
  local sha) is dropped -- nothing ships, nothing to certify.
- `read_hook_stdin() -> str | None`: the whole of stdin when `ARAMID_HOOK`
  is set and stdin is not a tty, else `None`. Never blocks: git closes the
  pipe after writing the lines.
- `Certification(refs: tuple[PushRef, ...], head_at_start: str | None,
  hook: bool)` and `certify(root, refs, hook)`: resolves `HEAD` once, at
  start.
- `drift(root, cert) -> list[Moved]`, `Moved(ref, before, after)`: each
  certified local ref is re-resolved; a ref whose sha differs from the one
  git handed the hook is moved. With no refs (by hand, no marker), `HEAD`
  at start vs `HEAD` now, under the name `HEAD`.
- `render(moved) -> str`: one line per ref, the shape the finding asked
  for, 7-character shas:

      main moved during the gate: 12a1d68 -> 673c804; re-run the push

  `main` is the local ref with `refs/heads/` stripped.

### 4.3 The gate fails on drift

`cmd_check` (pre-push only): certify BEFORE `pipeline.run_gate`; `run_gate`
computes `drift` at its END -- after every runner has returned, before
`record_run` -- and carries it on `GateResult.refs_moved`. `cmd_check` turns
a non-empty `refs_moved` into exit 1 AFTER the fresh-ledger downgrade (a
moved branch is not a legacy finding to grandfather) and prints
`aramid: pre-push: <render(moved)>` to stderr. Fail, not warn: the
certification is void and git will not say so. `--strict` is irrelevant
(1 stays 1).

The pre-commit gate is untouched: HEAD does not move under a commit hook.

### 4.4 Nothing to push means nothing to certify

Under the marker, an empty ref list (git's "Everything up-to-date", or a
push that only deletes) returns 0 without running the tools, prints
`aramid: pre-push: nothing to push -- git handed the hook an empty ref list;
gate not run` to stderr, and writes NO run row and NO fleet row: a row with
no tools would read as a skip and start a skip streak (fleet criterion
`no_skip_streak`) for a push that shipped nothing. graphite's push 6 spent
10.9 minutes on exactly this.

Without the marker, an empty stdin means nothing: the gate runs as it does
today.

### 4.5 The run row says what was certified

`ledger.record_run` gains `certified`, `refs_moved`, `head_at_exit`:

- `RUN_STARTED` payload: `refs: [{local_ref, local_sha, remote_ref,
  remote_sha}]`, `head_at_start`, `hook: bool` -- written only when a
  certification was supplied, so older rows keep the key absent (the
  `expected` convention).
- `RUN_FINISHED` payload: `head_at_exit`, `refs_moved: [{ref, before,
  after}]` (empty list when nothing moved) -- same rule.

`reporter.render_json` gains `refs_moved`. The console report is unchanged;
the stderr line is the operator's signal, as with every other gate message.

### 4.6 Not done, on purpose

- The tree-level tools are not skipped on an empty range: they see the
  tree, and the range-level ones (tdd, red-proof) already handle an empty
  range.
- No attempt to make the push atomic (re-resolving in the hook and pushing
  the certified sha ourselves): the hook is not positioned to push, and a
  second push after the failure is the honest shape.
- No change to `@{u}..HEAD` range resolution: with drift failing the gate,
  the range the tools saw is the range that ships.

## 5. Testing

- Unit (`tests/unit/test_pushrefs.py`): parse (normal, deletion dropped,
  malformed skipped, empty); `read_hook_stdin` (marker + pipe -> text; no
  marker -> None; tty -> None); certify + drift on a scratch git repo (a
  commit after certify -> moved with both shas; none -> empty; no refs ->
  HEAD fallback named `HEAD`); `render` wording pinned literally.
- Shim (`tests/unit/test_hooks_template.py`): both interpreter arms of the
  pre-push shim carry `ARAMID_HOOK=pre-push`; pre-commit's carry
  `ARAMID_HOOK=pre-commit`.
- Integration (`tests/integration/test_check_push_drift.py`), real scratch
  repos, a fake runner that COMMITS mid-gate as the seam: exit 1 + the
  stderr line + `refs` / `head_at_start` on `RUN_STARTED` + `refs_moved` /
  `head_at_exit` on `RUN_FINISHED`; no commit -> exit unchanged,
  `refs_moved: []`; empty stdin under the marker -> exit 0, no run row, the
  fake runner never ran; stdin lines WITHOUT the marker -> ignored, HEAD
  fallback still fails the moved branch; a fresh ledger's downgrade does not
  mask the drift.

## 6. Rollout

Ships in the next release. Every consumer gets the HEAD fallback the moment
the release is promoted (the gate is the wheel); the stdin certification and
the empty-push skip arrive when it re-runs `aramid init`, which regenerates
the shim. The release announcement says both.

Operational rule until then, and after: nothing is committed on a branch
while its push is inside the hook.
