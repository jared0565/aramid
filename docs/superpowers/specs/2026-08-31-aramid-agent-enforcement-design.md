# Aramid — Agent Enforcement Layer (universally non-optional for agent coders)

**Date:** 2026-08-31
**Baseline:** `main` @ `eaf2291` (release: v0.7.2), level with `origin/main`, CI green, 3 open ledger findings (all suppressed, 0 blocking).
**Status:** design approved by the user in two section groups (2026-08-31); ready for writing-plans.
**Scope decisions made by the user:** all **four** surfaces in one epic, MCP included (option 2 of 3);
managed blocks go to **CLAUDE.md + AGENTS.md** (option 1 of 3); the MCP server exposes the **full
loop including override/mark-*** (option 2 of 3); deployment is **approach B — universal presence,
staged teeth** (init writes every surface everywhere; the blocking rejector bakes advisory-first and
arms per-repo via `aramid arm --agent`).

---

## 1. Context & motivation

aramid's enforcement today is mechanical on the **git path** (fail-closed pre-push shims, a
machine-wide hook template seeding new clones, CI `--strict`) and **discretionary on the agent
path**: an agent coder meets aramid only if it happens to read `ARAMID.md`, or when a push
bounces. `aramid init` writes no agent instruction files, no harness hooks, no MCP entry — a
first-hand check of `commands/init.py` confirms no reference to CLAUDE.md or AGENTS.md anywhere.

The failure mode this produces: an agent's first contact with aramid is a blocked push it has to
reverse-engineer, and the cheapest wrong reaction — `git commit --no-verify` / `git push
--no-verify` — silently disables gitleaks along with everything else. Nothing in the agent's
context warns it, and nothing rejects it.

graphite solved the same problem on this machine with four surfaces, all verified in this repo's
own working tree: managed instruction sections written by its init, a `SessionStart` hook injecting
live context, a `PreToolUse` hook that can reject tool calls, and an MCP server in `.mcp.json`.
This spec gives aramid the equivalent four, with aramid's own bake-then-arm posture instead of
graphite's strict-from-day-one.

**Relationship to the existing gate:** the git-hook gate and CI `--strict` remain the enforcement
backstop. The agent layer is defense-in-depth and early feedback — with one exception: an **armed**
`pre-tool-use` rejector is genuinely load-bearing against `--no-verify`, because `--no-verify` is
precisely the bypass the git-hook layer cannot see.

## 2. Approaches considered

- **A — strict from day one (graphite-style).** Every surface blocking immediately. Rejected: a
  blocking hook's day-one false-positive tax lands on consumers already onboarded, who receive the
  new surface on their next routine `init` with no bake. (graphite's strict grep-rejection is a
  documented recurring nuisance on this machine.)
- **B — universal presence, staged teeth. CHOSEN.** `init` writes all four surfaces
  unconditionally; the rejector ships advisory and blocks only after `aramid arm --agent`. This is
  the house pattern — semgrep, llm, autolearn, tdd, mutation, mutation-score, red-proof, and shadow
  all arm exactly this way (`arm.py`).
- **C — opt-in flag (`init --agents`).** Rejected: contradicts the goal; "universally not
  optional" cannot be opt-in.

## 3. Surface 1 — managed instruction blocks (CLAUDE.md + AGENTS.md)

A marker-fenced block, identical content in both files:

```markdown
<!-- aramid:begin — managed by `aramid init`; hand-edits inside the fence are overwritten -->
## Aramid (security & quality gate)

This repo is gated by aramid. Read `ARAMID.md` before your first commit.
- Before committing: `aramid check --staged`. Findings: `aramid ledger filter --status open`.
- NEVER pass `--no-verify` (or `-n`) to `git commit`, or `--no-verify` to `git push` — it
  disables secret scanning along with everything else. Armed repos reject the call outright.
- To suppress a WARN finding, use `aramid override <id> --reason "..."` (ledger-logged); never
  edit findings away by hand.
<!-- aramid:end -->
```

**Write semantics** (new `_write_agent_blocks(root)` in `commands/init.py`, beside
`_write_aramid_md`):

- File absent → created containing only the block.
- Markers present → the fenced region is replaced in place with the current template.
- File present without markers → block appended after a blank line.
- Content outside the fence is never touched; regeneration runs on every `init`, like ARAMID.md.
- Both files are tracked, so teammates' agents inherit the block on pull.

**Static/live division:** the blocks carry only durable instructions. No counts, dates, or posture
— live state is the session-start hook's job (§5), so a tracked file can never go stale against
the ledger.

## 4. Config-merge plumbing (`.claude/settings.json`, `.mcp.json`) — carries surfaces 2–4

Two new merge writers in `commands/init.py`, both following the discipline aramid's git-hook
installer already uses for foreign hooks (chain, never clobber) and graphite's init uses for
`.mcp.json` (rewrite own entry unconditionally, preserve foreign ones byte-for-byte):

**`_merge_claude_settings(root)`** adds to `.claude/settings.json`:

```json
{
  "hooks": {
    "SessionStart": [{ "hooks": [{ "type": "command",
        "command": "python -P -m aramid agent-hook session-start" }] }],
    "PreToolUse": [{ "matcher": "Bash|PowerShell", "hooks": [{ "type": "command",
        "command": "python -P -m aramid agent-hook pre-tool-use" }] }]
  }
}
```

- Ownership test: a hook entry whose command contains `-m aramid agent-hook` is aramid's; it is
  rewritten to the current template on every init (generator fixes reach every consumer on their
  next init — the artifact lesson applied from day one). Everything else is preserved exactly.
- Matcher is `Bash|PowerShell` only. aramid has no business intercepting Grep/Glob.
- The file may already belong to another tool (in aramid's own repo it is graphite's): the merge
  must leave foreign hooks intact, and dogfooding init on this repo is the live acceptance test.
- An existing file that fails to parse as JSON, or whose `hooks` value has an unexpected shape, is
  **never written**: init prints a notice naming the file and moves on. A merge that cannot read
  what it merges into must not guess.

**`_merge_mcp_json(root)`** merges into `.mcp.json`:

```json
{ "mcpServers": { "aramid": { "command": "python", "args": ["-P", "-m", "aramid.mcp"] } } }
```

Same ownership/preservation/unparseable rules, keyed on the `aramid` server name.

Every generated command carries `-P` (the `python -m` cwd-shadowing doctrine; `arm --shadow`
already exists for the repo-root hijack class). Both files use plain `python`, matching the
graphite entries beside them; `doctor` (§8) verifies that PATH's `python` actually imports aramid
and flags a mismatch.

## 5. Surface 2 — `aramid agent-hook session-start`

New subcommand family in `commands/agent_hook.py`, dispatching on `{session-start, pre-tool-use}`,
speaking Claude Code's hook protocol (JSON on stdin; response via stdout JSON / exit code).

`session-start` injects live posture as additional context, derived the way `status` derives it
(reuse `commands/status.py` internals behind a compact renderer):

- open findings with blocking count, per-tool skip streaks, degraded markers;
- gate posture: which arms are baking vs armed (semgrep, llm, ..., agent);
- one pointer line to ARAMID.md and the managed block's commands.

Constraints:

- Reads only local ledger + config. No scans, no network, no subprocesses. Budget < 2 s.
- Outside an onboarded repo (no `aramid.toml`), or on ANY internal error: exit 0, no output.
  **Fail-open, stated as policy:** a context hook must never break session start; the git-hook
  layer beneath it still enforces.

## 6. Surface 3 — `aramid agent-hook pre-tool-use`

Fires on every Bash/PowerShell tool call. Parses the command string from the hook JSON and scans
for git bypass invocations. Everything else is allowed silently.

**What matches** (token-level, never substring):

- `git commit` carrying `--no-verify` or `-n` (on commit, `-n` IS `--no-verify`);
- `git push` carrying `--no-verify` (`-n` on push is `--dry-run` — harmless, must NOT match);
- `git -c core.hooksPath=...` (any spelling: `-c key=value` as one or two tokens) wrapping a
  `commit` or `push` — the other bypass door.

**Parsing rules:** tokenize shell-style; find every `git` invocation in the string (compound
commands — `&&`, `;`, `|` — are scanned in full, not just the head); identify the subcommand as
the first non-option token after `git`'s own `-c/-C/--git-dir/--work-tree` options. Quoted strings
that merely contain the flag text (a filename, a commit message) never match, because matching is
on parsed tokens. Best-effort by design: a bypass the parser misses is caught by nothing today, so
false negatives only fail back to the status quo; false positives are the expensive direction and
the rules above are written to make them structurally hard.

**Behavior by posture** (`agent_block_armed` in `aramid.toml`, default false):

- **Baking** (default): allow, and surface a warning through the protocol's advisory channel —
  "this repo's gate treats bypass as ledger-visible; the armed version of this hook rejects this
  call." The exact protocol field for a non-blocking PreToolUse warning is pinned at plan time
  against the installed harness version (candidates: `permissionDecision: "allow"` with a reason
  the harness surfaces, or stdout transcript output); if no advisory channel renders, baking mode
  degrades to allow-and-log and the teaching stays with the instruction block.
- **Armed:** deny via `hookSpecificOutput.permissionDecision: "deny"` with a reason naming the fix
  path (run the command without `--no-verify`, or `aramid override <id> --reason "..."` the
  specific finding); fallback exit 2 + stderr where JSON denial is unsupported.
- **Internal error, unparseable stdin, non-matching command:** allow, exit 0. Fail-open as policy:
  only a positive match while armed ever blocks. The failure direction is deliberate — this layer
  is defense-in-depth above a gate that still runs; a hook crash must not take unrelated tool
  calls down with it.

**Latency:** the hook runs on every Bash/PowerShell call. Top-level imports in `agent_hook.py` are
stdlib-only; aramid's heavy modules load lazily inside the matched branch. Target < 500 ms on the
non-matching path (the overwhelming majority).

**Scope property worth stating:** this binds agents, not humans. An operator typing in a real
terminal is untouched — the right boundary for an agent-awareness layer.

## 7. Surface 4 — the MCP server (`aramid.mcp`)

`src/aramid/mcp.py`, runnable as `python -P -m aramid.mcp`, stdio transport. Full loop per the
user's scope decision:

| Tool | Maps to | Notes |
|---|---|---|
| `aramid_check` | `check` internals | args: gate (pre-commit/pre-push/all), staged, strict |
| `aramid_status` | `status` internals | the same posture the session-start hook renders |
| `aramid_ledger_filter` | `ledger filter` | status/tool filters; returns suppression notes |
| `aramid_resolvers` | `resolvers` | yield report |
| `aramid_override` | `override` | **reason required, non-empty**; ledger-logged as CLI |
| `aramid_mark_not_a_secret` | `ledger mark-not-a-secret` | reason required |
| `aramid_mark_rotated` | `ledger mark-rotated` | reason required |

- Tools call the same internal functions the CLI commands use — no subprocess self-reinvocation
  (no `-m` chain to protect, one code path to test).
- Suppression via MCP carries identical authority and identical audit trail to the CLI; the
  transport changes, the ledger event does not.
- **Implementation:** a minimal in-house stdio server (initialize / tools-list / tools-call per
  the current MCP revision) rather than a new SDK dependency — consistent with aramid's offline,
  dependency-light discipline and the graphite precedent. Conformance is validated in tests
  against a real client handshake (§10). If protocol conformance proves fiddly at implementation
  time, adopting the official SDK is an allowed plan-level reversal; the tool surface above is
  the contract, not the plumbing.
- The server operates on the repo at its cwd and refuses (JSON-RPC error, not crash) outside an
  onboarded repo.

## 8. Lifecycle — arm, uninstall, doctor, status, config

- **`aramid arm --agent`** joins the existing mutually-exclusive arm family in `arm.py`: flips
  `agent_block_armed = true` via the same comment-preserving edit machinery; refuses without
  `aramid.toml`.
- **Config:** `agent_block_armed` (default false) added to `config.py` beside
  `semgrep_block_armed`, read with the same `merged.get(..., False)` pattern so pre-existing
  configs need no migration. Whether `CURRENT_SCHEMA_VERSION` must bump for an additive key is
  checked at plan time against config.py's mismatch rule; the default assumption is no bump.
- **Fresh `init` stub** gains `agent_block_armed = false` next to `semgrep_block_armed = false`.
- **`aramid uninstall`** removes: both managed blocks (fence-scoped; a file left empty by removal
  is deleted), aramid's own entries from `.claude/settings.json` hook arrays and `.mcp.json`
  (foreign content preserved; files left structurally empty are deleted). Ledger kept, as today.
- **`aramid doctor`** reports, never rewrites:
  - per instruction file: block present / stale (differs from current template) / absent;
  - `.claude/settings.json` and `.mcp.json`: aramid entry present / stale / absent / **tampered**
    — an aramid-named entry whose command differs from the template. Tampered is a security
    signal (the `.mcp.json` hijack is the most serious surface in the graphite postmortem) and
    exits 2, like "configured but NOT enforced". Absent/stale surfaces are advisory (exit
    unchanged) — they are not BLOCK-tier tools;
  - PATH `python` resolves to an interpreter that imports aramid (else the generated commands
    dangle) — advisory with a named remedy.
- **`aramid status`** gains one line, e.g.
  `agent surfaces: blocks 2/2 · hooks ok · mcp ok | baking` (armed shows `| armed`).

## 9. Security analysis

- **Threat: repo-planted shadow hijacks the generated commands.** All generated commands carry
  `-P`; `arm --shadow` already covers the `python -m aramid` repo-root hijack class; `doctor`'s
  tampered check covers edits to the entries themselves. The MCP entry gets the same three
  protections and is the highest-value target.
- **Threat: hostile hook stdin.** The pre-tool-use hook parses attacker-adjacent text (commands
  influenced by repo content). Parsing is defensive: token-exact matching, no regex over raw
  strings, no eval, unparseable input → allow. The worst outcome of hostile input is a false
  *allow*, which is the status quo.
- **Fail direction, named per surface** (an `except` branch is a policy decision): session-start
  fail-open (context only); pre-tool-use fail-open except positive-match-while-armed (backstopped
  by the git gate and CI `--strict`); merges fail-closed on unreadable JSON (report, don't
  write); MCP errors are JSON-RPC errors, never silent successes.
- **Suppression over MCP** grants no authority the CLI lacks; reasons are mandatory and
  ledger-logged. The audit trail is transport-independent.

## 10. Testing

- **Rejector red-first:** prove an armed repo denies `git commit --no-verify` and
  `git push --no-verify` (assert the deny JSON, not a substring), prove baking allows with the
  advisory, prove `git push -n` (dry-run) and a commit message *containing* the literal string
  `--no-verify` are allowed. Compound-command arms (`x && git commit -n`).
- **Merge semantics, perturb by ADDING:** start from a settings.json/mcp.json holding a foreign
  hook/server, run init, assert the foreign entry survives byte-for-byte and aramid's entry
  matches the template; repeat with a stale aramid entry (rewritten) and an unparseable file
  (untouched + notice rendered).
- **Block writer:** all three file states (absent / fenced / unfenced), idempotence (second init
  is a no-op diff), outside-the-fence preservation.
- **Machine isolation:** every test runs in a tmp repo via the suite's existing isolation
  fixtures; no test touches the developer's real `~/.claude`, this repo's own settings.json, or
  the machine registry (aramid's suite has been burned by machine state twice — the fixture is
  load-bearing, not hygiene).
- **Rendered strings:** session-start context and the advisory/deny messages asserted as full
  rendered lines, not substrings.
- **MCP conformance smoke:** spawn the server, complete a real initialize handshake, list tools,
  call `aramid_status` and one suppression tool end-to-end against a scratch ledger.
- **Dogfood acceptance:** `aramid init .` on this repo must leave graphite's settings.json hooks
  and `.mcp.json` entry intact with only aramid's additions in the diff.

## 11. Sub-project decomposition (implementation order)

1. **Instruction blocks** — `_write_agent_blocks`, uninstall removal, doctor block checks.
   Zero runtime risk; ships alone.
2. **session-start + settings merge** — `agent_hook.py` skeleton, `_merge_claude_settings`,
   doctor settings checks, status line.
3. **pre-tool-use rejector + `arm --agent`** — parser, posture, config key, red-first suite.
4. **MCP server + `.mcp.json`** — `mcp.py`, `_merge_mcp_json`, doctor mcp checks, conformance
   tests.

Each sub-project gets its own implementation plan and lands CI-green independently, in this order
(the order is by value-per-risk and was approved with the design).

## 12. Explicitly out of scope

- Other harness files (GEMINI.md, `.cursorrules`, per-editor task files) — the AGENTS.md
  convention is the cross-agent umbrella.
- Stop hooks / per-turn gate runs — the gate is far too slow for a per-turn surface.
- Rejecting direct edits to `.git/hooks` — `doctor` already validates shim integrity; enforcement
  there is a different mechanism.
- Machine-wide (template-level) arming of the agent rejector — arming stays per-repo.
- Any network behavior in any new surface; everything here is offline like the gate itself.
- graphite's repo or any other consumer's working tree: consumers pick these surfaces up by
  re-running `aramid init` themselves, announced over the shared channel, not by aramid editing
  foreign repos.
