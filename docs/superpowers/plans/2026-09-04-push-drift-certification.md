# Push Drift Certification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The pre-push gate names the refs git handed it, fails when any of them moved while it ran, records both on the run row, and skips a push that ships nothing.

**Architecture:** A new `pushrefs` module owns the git pre-push stdin contract (parse, certify at start, re-resolve at exit, render). The managed shim exports `ARAMID_HOOK=<gate>` so the gate knows git is on the other end of stdin. `cmd_check` certifies before `run_gate`; `run_gate` measures drift after the last runner and hands it to `record_run` (`RUN_STARTED.refs/head_at_start/hook`, `RUN_FINISHED.refs_moved/head_at_exit`) and to `GateResult.refs_moved`; `cmd_check` turns drift into exit 1 after the fresh-ledger downgrade.

**Tech Stack:** Python stdlib, git; pytest with scratch repos (the `_repo` / `_no_user_config` / fake-runner pattern of `tests/integration/test_check.py`).

**Spec:** `docs/superpowers/specs/2026-09-04-aramid-push-drift-certification-design.md`

## Global Constraints

1. Nothing in the gate path may raise: `pushrefs` functions return empty results on any git failure (fail-open in the wrong direction is not acceptable for drift, so `drift` reports a ref it could not re-resolve as MOVED with `after = None`, which fails the gate).
2. Stdin is read only under `ARAMID_HOOK` and only when not a tty; never block.
3. Payload keys are written only when a certification was supplied (absent on older rows, like `expected`).
4. Tests: `python -m pytest <path> -q -p no:cacheprovider`; never `pip install -e .`.
5. Every commit: `python -P -m aramid check --staged` then `python -P -m aramid ledger filter --status open`; commit via `git commit -F`, trailers `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` + `Claude-Session: https://claude.ai/code/session_01Swr1yPAqMtUnH36YVhune9`. Never `--no-verify`.
6. Heredoc bodies mangle backslashes: Write/Edit tools for any source with one.

---

### Task 1: `pushrefs` -- parse, certify, drift, render

**Files:** Create `src/aramid/pushrefs.py`; Test `tests/unit/test_pushrefs.py`.

**Interfaces (produces):**
```python
@dataclass(frozen=True)
class PushRef: local_ref: str; local_sha: str; remote_ref: str; remote_sha: str
@dataclass(frozen=True)
class Certification: refs: tuple[PushRef, ...]; head_at_start: str | None; hook: bool
@dataclass(frozen=True)
class Moved: ref: str; before: str; after: str | None
HOOK_ENV = "ARAMID_HOOK"
def parse_push_lines(text: str) -> list[PushRef]
def read_hook_stdin() -> str | None
def certify(root: Path, refs, hook: bool) -> Certification
def drift(root: Path, cert: Certification) -> list[Moved]
def render(moved) -> str
def short_ref(ref: str) -> str          # refs/heads/main -> main
def payload_refs(cert) -> list[dict]; def payload_moved(moved) -> list[dict]
```

- [ ] Step 1: write `tests/unit/test_pushrefs.py` (parse: normal / deletion dropped / malformed skipped / empty; `read_hook_stdin`: marker+pipe -> text, no marker -> None, tty -> None; certify+drift on a scratch repo: commit after certify -> `[Moved("refs/heads/main", a, b)]`, none -> `[]`, no refs -> `[Moved("HEAD", a, b)]`; render pinned: `main moved during the gate: 12a1d68 -> 673c804; re-run the push`).
- [ ] Step 2: run, expect `ModuleNotFoundError: aramid.pushrefs`.
- [ ] Step 3: implement `src/aramid/pushrefs.py` per the spec 4.2 (`gitutil._run(root, "rev-parse", ref)` for resolution; `sys.stdin.isatty()` guarded with try/except -> treat as tty).
- [ ] Step 4: green. Gate, commit `feat(pushrefs): the git pre-push stdin contract -- parse, certify at start, re-resolve at exit`.

### Task 2: the shim marks itself

**Files:** Modify `src/aramid/hooks.py` (`render_shim`, both interpreter arms); Test `tests/unit/test_hooks_template.py`.

- [ ] Step 1: test: `render_shim(Gate.PRE_PUSH, interp, match_ci=True)` bytes contain `ARAMID_HOOK=pre-push "` before the `-m aramid check --gate pre-push --all --strict` line AND `ARAMID_HOOK=pre-push py -3 -P -m aramid check`; pre-commit's contain `ARAMID_HOOK=pre-commit`.
- [ ] Step 2: red. Step 3: prefix both arms: `f'    ARAMID_HOOK={hook} "$INTERP" -P -m aramid check {...}'` and `f"    ARAMID_HOOK={hook} py -3 -P -m aramid check {...}"`. Step 4: green, plus `tests/unit/test_hooks.py tests/unit/test_hook_shim_shadowing.py tests/unit/test_cmd_hooks.py`. Gate, commit `feat(hooks): the managed shim tells the gate that git is on stdin (ARAMID_HOOK=<gate>)`.

### Task 3: the gate certifies, fails on drift, records both, skips an empty push

**Files:** Modify `src/aramid/commands/check.py` (`cmd_check`), `src/aramid/pipeline.py` (`run_gate` kwarg `certified`, drift before `record_run`, `GateResult.refs_moved`), `src/aramid/ledger.py` (`record_run` kwargs `certified`, `refs_moved`, `head_at_exit`), `src/aramid/reporter.py` (`render_json` key `refs_moved`); Test `tests/integration/test_check_push_drift.py`.

Seam for the tests: a fake runner registered in `pipeline.RUNNERS` whose `run` commits on the scratch repo (the gate is between certify and drift while runners run).

- [ ] Step 1: tests:
  - `test_a_commit_during_the_gate_fails_it_and_is_recorded`: marker set (`monkeypatch.setenv("ARAMID_HOOK", "pre-push")`), stdin = `io.StringIO(f"refs/heads/main {sha} refs/heads/main {'0'*40}\n")`, fake runner commits -> `rc == 1`; stderr contains `main moved during the gate: {sha[:7]} -> {new[:7]}; re-run the push`; ledger `RUN_STARTED.refs[0].local_sha == sha`, `head_at_start == sha`, `hook is True`; `RUN_FINISHED.refs_moved == [{"ref": "refs/heads/main", "before": sha, "after": new}]`, `head_at_exit == new`.
  - `test_no_movement_keeps_the_verdict_and_records_empty_drift`: same setup, runner does not commit -> rc 0, `refs_moved == []`, `head_at_exit == sha`.
  - `test_empty_ref_list_under_the_marker_skips_the_gate`: stdin `""` -> rc 0, stderr has `nothing to push`, no `RUN_STARTED` event, fake runner never called.
  - `test_without_the_marker_stdin_is_ignored_and_head_still_certified`: env unset, stdin has a line, runner commits -> rc 1, message names `HEAD`, `RUN_STARTED.refs == []`, `hook is False`.
  - `test_fresh_ledger_downgrade_does_not_mask_drift`: no baseline in the ledger (first pre-push run), runner commits -> rc 1.
  - `test_json_report_carries_refs_moved`: `as_json=True`, runner commits -> parsed stdout JSON `refs_moved[0]["ref"] == "refs/heads/main"`.
- [ ] Step 2: red (`TypeError: run_gate() got an unexpected keyword` / missing keys).
- [ ] Step 3: implement:
  - `cmd_check`: after `fresh = ...`: if `gate is Gate.PRE_PUSH`: `text = pushrefs.read_hook_stdin()`; `hook = text is not None`; `refs = pushrefs.parse_push_lines(text or "")`; if `hook and not refs`: print the nothing-to-push line to stderr, `return 0` (inside the try, before invalidation); `cert = pushrefs.certify(root, refs, hook)`; else `cert = None`. Pass `certified=cert` to `run_gate`. After the fresh-ledger block: `if result.refs_moved: print("aramid: pre-push: " + pushrefs.render(result.refs_moved), file=sys.stderr); exit_code = 1`.
  - `run_gate(..., certified=None)`: before `record_run`: `moved = pushrefs.drift(root, certified) if certified is not None else []`; `head_at_exit = gitutil head (rev-parse HEAD) if certified else None`; `record_run(..., certified=certified, refs_moved=moved, head_at_exit=head_at_exit)`; `GateResult(..., refs_moved=tuple(moved))`.
  - `GateResult`: `refs_moved: tuple = ()`.
  - `ledger.record_run`: `if certified is not None: payload["refs"] = pushrefs.payload_refs(certified); payload["head_at_start"] = certified.head_at_start; payload["hook"] = certified.hook`; `if refs_moved is not None: finished["refs_moved"] = pushrefs.payload_moved(refs_moved)`; `if head_at_exit is not None: finished["head_at_exit"] = head_at_exit`.
  - `reporter.render_json`: `"refs_moved": [dataclasses.asdict(m) for m in getattr(result, "refs_moved", ())]`.
- [ ] Step 4: green; then `tests/integration/test_check.py tests/integration/test_gates_end_to_end.py tests/integration/test_check_fleet.py tests/unit/test_reporter*.py tests/unit/test_ledger*.py`. Gate, commit `feat(gate): pre-push certifies the refs git handed it and fails when one moved during the gate (round 176)`.

### Task 4: docs

- [ ] `docs/user-guide.md`: a short section under the pre-push gate: what is certified, the failure line, the nothing-to-push skip, re-run `aramid init` to get the marker, the operational rule.
- [ ] `CHANGELOG.md` Unreleased: Added (certification + skip) / Fixed (a commit during the gate shipped ungated over HTTPS). Gate, commit `docs: push drift certification`.
