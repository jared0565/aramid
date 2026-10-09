# Inline markers that silence a BLOCK rule become visible (FN-38) — design

Status: DRAFT, 2026-10-09. Shape chosen by the operator ("go with your
recommendations"): make the markers VISIBLE, do not refuse them. Not built.

## 1. The problem (measured 2026-10-09, plan FN-38)

aramid runs each tool with the repo's own suppressions in force. A committed
marker can therefore remove a BLOCK finding with no `.aramid-suppressions.toml`
entry, no reason recorded, and no row in the ledger:

| Tool | Marker | Measured |
|---|---|---|
| ruff | `# noqa: S105` on the line | yes |
| ruff | a `per-file-ignores` entry for the file | yes |
| gitleaks | `# gitleaks:allow` on the line | yes, on all three scan paths |
| semgrep | a bare `# nosemgrep` on the line | yes |

A top-level ruff `lint.ignore` does NOT silence a rule, because aramid's
`--extend-select S` overrides it. This was measured for S105, S106 and S608.

These markers hold at every gate and in CI. That bypasses the floor that
`block_rules` keeps against repo config.

aramid's agent surfaces exist to stop an agent from bypassing the gate
(`--no-verify` is refused). Appending `# noqa: S105` is the same move, made
inside the diff.

## 2. What changes

For each BLOCK producer, aramid learns which BLOCK-tier hits the repo's own
markers hid in this run. It reports each one as a finding:

- tool `aramid`, rule `inline-suppressed-block`, tier WARN;
- the finding names the underlying tool, rule, file and line, and the kind
  of marker;
- its fingerprint is (underlying tool, rule, file, line content), so it
  survives line moves the way other findings do.

It never blocks on its own, at any gate. It is exempt from the
no-new-warnings ratchet; see section 4 for why. A team accepts a marker by
committing a `.aramid-suppressions.toml` entry with a reason for the new
finding's id. That gives the marker the same review and stale detection as
any other suppression. `aramid status` gets a count line.

The finding does not change what the underlying tool reports. The marker
still silences the tool's own BLOCK, so nothing that passes today starts
failing.

## 3. How each tool's hidden hits are found

| Tool | Mechanism | Extra cost | Verified 2026-10-09 (scratch repos from FN-38's probe) |
|---|---|---|---|
| ruff | A second run with `--isolated --ignore-noqa --select <curated BLOCK set>`, over the files the first run examined. A hit is hidden when the second run has it and the first does not, matched by (rule, file, line). | about 0.35 s whole-tree here | yes, on ruff 0.16.10: S105 comes back under both `# noqa` and `per-file-ignores`, and the bare control is unchanged |
| gitleaks | A second run with `--ignore-gitleaks-allow`, on the same scan path (staged / range / dir). A hit is hidden when the second run has it and the first does not, matched by (rule, file, line, commit). `.gitleaksignore` and a repo `.gitleaks.toml` allowlist are further channels; see section 5, question 2. | 1-4 s here | yes: a `gitleaks:allow` line gives 0 findings by default and 1 with the flag, on 8.21.2 and on 8.28.0 |
| semgrep | One run, not two. `--disable-nosem` makes semgrep report the results it would have hidden, marked `extra.is_ignored: true`. The runner keeps those out of the normal findings and turns them into this rule. | none | yes, on semgrep 1.178.0: 0 results by default, 1 with the flag, marked `is_ignored: true` |

`--isolated` also ignores the repo's ruff `exclude`. The second run is
therefore given only the files the first run reports as examined
(`--show-files`), so a file the repo excludes is never reported as
"hidden".

Only hits whose rule is BLOCK-tier in the RESOLVED `block_rules` (the
machine floor plus additions) count. A WARN-tier rule silenced inline is the
repo's own business.

**Scope: these three producers only.** A repo can add BLOCK rules for any
runner through `block_rules`, and eslint (`// eslint-disable...`) and clippy
(`#[allow(...)]`) have inline markers of their own. They are out of scope
for this design, which covers the producers with a curated BLOCK set by
default. Each needs its own detection mechanism. They are filed as a
follow-up on FN-38 in the plan, not silently covered.

## 4. Deployment: the first run after upgrading

Every consumer that already carries markers sees them all at once on the
first run under the new version. This repo would see 25 ruff findings
(13 S106, 10 S105, 2 S107), almost all under `per-file-ignores` for
`tests/**`.

If these findings were ordinary WARNs, the pre-push ratchet would escalate
each new one to BLOCK. The first push after upgrading would then be refused
for markers nobody added in it.

That is the failure the memory *a precondition may not cover its own
deployment* names. Hence:

- the rule is ratchet-exempt, alongside `DEPS_SHAPE_DRIFT_RULE` and `tdd`;
- it ships WARN-only. Arming it to BLOCK
  (`inline_suppression_block_armed`) is a later, separate decision.

Arming makes sense once a team has written its entries. Until then, a new
marker in a push shows as a new WARN in the push's report, which review
sees.

## 5. Open questions for the operator

1. **`per-file-ignores` for test trees.** Most of this repo's 25 hits are
   fake credentials in test fixtures, under `tests/**`. Options:
   - (a) report them like any other hit; one `.aramid-suppressions.toml`
     entry per finding; noisy, but honest;
   - (b) accept a path-scoped entry: `tool`/`rule`/`path` glob with a reason,
     no id. This is new syntax for the suppressions file;
   - (c) skip test paths entirely.

   Proposed: (a) for 1.0, because the entries already exist for gitleaks
   test fixtures. Revisit (b) if consumers object.
2. **gitleaks' file-level channels** (`.gitleaksignore`, a repo
   `.gitleaks.toml` allowlist). Proposed: out of scope here. They are files
   in the repo root a reviewer sees, unlike a marker at the end of a line.
   File them as a follow-up if wanted.
3. **Arming.** Proposed: keep it WARN-only for 1.0 and decide arming after
   the fleet has run it for one bake period.

## 6. Tests (to write first)

- For each tool, a bare control (the tool's own BLOCK fires, and no
  `inline-suppressed-block`) and a marked arm (no tool BLOCK, exactly one
  `inline-suppressed-block` naming the tool, rule and line).
- The rule is WARN at both gates and never escalated by the ratchet. Test
  this through `_escalates` and through a real pre-push on a ledger that has
  a baseline.
- A `.aramid-suppressions.toml` entry for the new id sets it aside, and goes
  stale when the line changes.
- A WARN-tier rule silenced inline produces nothing.
- A degraded second pass (ruff or gitleaks) is reported degraded for that
  part. It does not degrade the tool's own result, which is unchanged.

## 7. Docs

- user guide section 12: replace FN-32's limitation item with the new
  behaviour;
- section 5: suppressing a marker;
- KB: the runner notes and the rule;
- the ARAMID.md template's "does not override the target repo's ignores"
  sentence: true for `per-file-ignores` and `noqa` at the tool level, and now
  reported;
- CHANGELOG `Added`.
