# Aramid Release-Hardening Bundle — Design

Date: 2026-07-20
Status: approved (user), pre-plan
Base: main @ 607172a (766 tests green)
Branch: feat/release-hardening

## 1. Purpose

Three independent release-correctness items, closed in one branch, chosen from
the 2026-07-20 verified backlog survey (each re-checked against main@607172a):

1. **gitleaks `protect`→`git` argv drift** in the sole BLOCK-tier secrets gate,
   plus the real-binary and offline tests that were never written for it.
2. **First-release baseline-reset** — no CLI path to rebuild the ratchet
   baseline after a fingerprint-affecting upgrade, and no user-facing doc for
   the churn behavior.
3. **Self-dogfood honesty** — aramid's own repo doesn't carry its config and the
   README overstates what is wired/committed.

Non-goals: the other verified-backlog items (compact() landmine, override/gate
predicate extraction, deps force_refresh, triage content_signal, update-rules
stub, pnpm/yarn live capture), and roadmap features 2c-1b / 2c-3. No gate-path
behavior change except the one intended, behavior-equivalent gitleaks argv swap.

## 2. Item 1 — gitleaks argv drift + tests

### Problem
`runners/gitleaks.py:53-56` builds the staged-mode argv as
`["gitleaks", "protect", "--staged", "--report-format", "json",
"--report-path", <p>]`. The history path (`:48-52`) already uses the newer
`gitleaks git --log-opts <rng> …`. `protect` was deprecated in gitleaks 8.19
and hidden from `--help`; it still functions on the pinned **8.21.2**
(`doctor.py:59`) — gitleaks's own 8.21.2 pre-commit hook still calls
`gitleaks protect --staged`, confirming deprecated-but-functional. The hole is
conditional but real: when `GITLEAKS_VERSION` is later bumped to a release that
*removes* `protect`, `gitleaks protect --staged` returns exit 126 (unknown
flag/command) → aramid's runner maps a non-`{0,1}` exit to CRASHED → and at
pre-commit CRASHED fails **open** ({2,3}→0), so staged secrets pass silently.

### Fix
Change the staged-mode argv to `["gitleaks", "git", "--staged", …]`. Verified
against gitleaks v8.21.2 source (`cmd/git.go`): the `git` subcommand registers
`Flags().Bool("staged", …, "scan staged commits (good for pre-commit)")`, and
`--report-format`/`--report-path` are root flags already used on `git` by the
history path. `--staged` scans the staged diff — behaviorally identical to
`protect --staged` on 8.21.2. Both argv paths now use the non-deprecated `git`
command. Update the two comments that reference `protect --staged`
(`gitleaks.py:47` and `:88`) to say `git --staged`.

### Tests
- **Unit** (`tests/unit/test_runner_gitleaks.py`): assert `_build_argv` staged
  mode (`ctx.rng is None`) yields `["gitleaks", "git", "--staged", …]` and no
  longer contains `"protect"`; history mode (`ctx.rng is not None`) unchanged.
- **Live, skip-if-absent** (`tests/integration/`): mirror the
  `_find_semgrep` / `_find_tool` skip-if-absent pattern
  (`test_gates_end_to_end.py`) with a new gitleaks discovery. Build a temp git
  repo, seed a detectable secret, and run gitleaks through the runner in BOTH
  modes (staged: stage the secret, `ctx.rng=None`; history: commit it,
  `ctx.rng="<range>"`). Assert: a finding is produced (BLOCK-tier), a clean
  tree yields none, and the real binary's exit stays within the `{0,1}` set the
  runner treats as OK. Skips cleanly where gitleaks is absent.
- **Offline `_fix_gitleaks`** (`tests/integration/test_doctor.py` or a new
  file): monkeypatch `urllib.request.urlopen` to return a synthetic archive
  (zip on Windows key, tar.gz otherwise) whose member is `_exe_name("gitleaks")`
  and inject its real sha256 into `GITLEAKS_SHA256` for the current platform
  key. Assert (a) a matching checksum extracts the binary to the tools dir and
  returns True, and (b) a deliberately-wrong `GITLEAKS_SHA256` entry rejects
  (returns False, nothing extracted). No network, runs everywhere.

### CI
Add a step to `.github/workflows/aramid.yml` that installs the pinned gitleaks
8.21.2 on the CI runner before the test job, so the skip-if-absent live test
**executes** rather than skips — the drift protection is only real if the
binary actually runs in CI. Exact install mechanism (action vs. scripted
download) is a plan detail, matched to the workflow's runner OS.

## 3. Item 2 — `aramid rebaseline` command + churn doc + semgrep nit

### Command
New `src/aramid/commands/rebaseline.py` exposing
`cmd_rebaseline(root: Path, *, yes: bool = False) -> int`:
- Without `--yes`: print what will be discarded (current baseline size + the
  warning that ratchet grandfathering is dropped), do NOT write, return 3.
  Non-interactive-safe — no prompt that would hang CI/hooks.
- With `--yes`: mirror `init.py:271-273` — `run_gate(root, Gate.ALL, "all",
  cfg, ledger)`, then `ledger.write_baseline(result.run_id, _now(),
  {f.id for f in result.findings})`. Because `baseline_ids()` is latest-wins
  (`ledger.py:96-101`), the fresh `BASELINE_SNAPSHOT` supersedes the old one.
  Print old→new counts, return 0.

`cli.py`: add a `rebaseline` subparser (`path` nargs="?" default=".",
`--yes` store_true) and a dispatch branch calling `cmd_rebaseline(root,
yes=args.yes)`.

### Migration doc
New README subsection "Upgrading / re-baselining": the fingerprint is
`sha256(tool + rule + norm_path + sha256(norm_line) + occurrence_index)`, and
semgrep rule-id normalization / path handling feed it, so a future aramid
upgrade that changes those re-fingerprints grandfathered findings and the
ratchet re-escalates them as new BLOCKs. Remedy: run `aramid rebaseline --yes`
after such an upgrade to re-snapshot the current findings as the accepted
baseline. State plainly that this discards prior grandfathering.

### semgrep nit
`runners/semgrep.py:_canonical_rule_id` (`:67-70`) uses the LEFTMOST
`check_id.find(prefix)`. Switch to `rfind` so a repo checkout path that itself
contains the literal `owasp-top-ten.` / `aramid-regression.` can't truncate the
id early. Add a test: a check_id whose path prefix contains the literal still
recovers the exact canonical id. Behavior identical for all normal paths.

## 4. Item 3 — self-dogfood config + honest docs

- **Commit** a minimal `aramid.toml` at repo root: `schema_version = 1` plus
  only settings equal to defaults, so aramid's own CI gate result
  (`aramid check --all --strict --json`) is byte-for-byte unchanged. This is the
  durable dogfood artifact a maintainer's `aramid init .` would otherwise write.
- **README fixes**:
  - Frame hooks/drain as a per-clone local action (`aramid init .`,
    `aramid schedule install`) — `.git/hooks` is not version-controlled, so the
    repo cannot "carry" them; only `aramid.toml` and a compiled pack are
    committable.
  - Correct the `.aramid-rules/regression.yml` reference (`README:80`): it is
    *produced* by `aramid pack compile` from resolved findings, not
    pre-committed; the repo has none yet.
  - Add a short "dogfood this repo locally" maintainer block with the exact
    commands.
- No test (docs + defaults-equal config). Guarded by the full-suite + ruff gate
  and CI's own `check --all` on the new `aramid.toml`.

## 5. Testing & gates

- TDD per item: failing test → red proof → minimal impl → green → commit.
- Full suite green (766 base + new). Ruff parity with the baseline measured at
  branch creation (record the exact count; every task must match it).
- Whole-branch adversarial review (sonnet subagent).
- CI green on the merge commit, now **including** the executing live gitleaks
  test.

## 6. Invariants (review-checked)

1. **Gate path unchanged except the intended gitleaks argv**, which is
   behavior-equivalent on the pinned 8.21.2 (staged diff scan, same JSON
   report). No change to `pipeline.py`, `policy.py`, other runners, or hooks.
2. **No BLOCK-path change**: `rebaseline` only writes a `BASELINE_SNAPSHOT`
   event; it never resolves/overrides/blocks a finding.
3. **Ledger event shapes unchanged**: `rebaseline` reuses the existing
   `write_baseline`/`run_gate` path; no new event type.
4. **`aramid.toml` neutrality**: the committed config must leave aramid's own
   gate result identical (defaults-equal), verified by CI `check --all`.
5. **semgrep `rfind` change is a strict robustness improvement**: identical
   output for every path that does not embed the literal prefix.
