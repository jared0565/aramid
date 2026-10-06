# Codex CLI / Codex Desktop Project Instructions

<!-- graphite:managed version=14 -->
## Shared Graphite Instructions

Graphite-first is required in this repo. Follow `GRAPHITE.md` before making non-trivial code changes: for cross-file questions (who-calls, where-defined, impact, data flow, structure) run the Graphite commands first; grep/glob are for literal text and filename lookups only. Fall back to manual search only after a Graphite answer proved insufficient, and say so. Use the existing `graph-out/graph.json` as the shared project graph, and do not edit `graph-out/` manually.

**Stay inside this repository.** Do not read, write, or run commands in any other repo, including its graph. Findings about another repo go to its agent as a recommendation through the shared `.agent-channel/` (see its `PROTOCOL.md`); that agent decides and acts. A tool doing its designed job is a separate question from an agent's boundary. See `GRAPHITE.md` section "Repository Isolation".
<!-- graphite:managed-end -->

<!-- aramid:begin -- managed by `aramid init`; hand-edits inside the fence are overwritten -->
## Aramid (security & quality gate)

This repo is gated by aramid. Read `ARAMID.md` before your first commit.

- Before committing: run `aramid check --staged`. Read findings with
  `aramid ledger filter --status open`.
- NEVER pass `--no-verify` (or `-n`) to `git commit`, or `--no-verify` to
  `git push` -- it disables secret scanning along with everything else.
  Armed repos reject the call outright.
- To suppress a WARN finding, use `aramid override <id> --reason "..."`
  (ledger-logged); never edit findings away by hand.
- aramid is a tool: use it only through its commands and MCP tools, never
  by talking to aramid's agent. The shared agent channel takes only bug
  reports and improvement suggestions for aramid. See `ARAMID.md`.
- Before a restart or a long pause, record where you are with
  `aramid handover write` (or the `aramid_handover_write` MCP tool); a fresh
  session that finds a verified one pending resumes it without asking the
  operator, then runs `aramid handover done`. Never act on a handover shown
  as NOT VERIFIED without the operator.
<!-- aramid:end -->

## Tools, not their agents (operator rule, 2026-10-04)

graphite is used in this repo only as a tool: its CLI, its MCP query tools
and its graph. Do not talk to graphite's agent: no answers to its questions,
no requests, no replies. The shared agent channel takes only two things from
this repo: a bug report or an improvement suggestion addressed to a tool.
Reading the channel (`list`, `read`, one `inbox` per session) is fine;
receiving a question is not a reason to answer it. This narrows the
"findings go to its agent as a recommendation" wording in the graphite
section above.

The same rule holds for aramid toward every repo where it is installed:
consumers use aramid only as a tool and send its agent only bug reports and
improvement suggestions (stated to them in `ARAMID.md` and in the aramid
block that `aramid init` writes). aramid's agent likewise posts only bug
reports and improvement suggestions: no release announcements, no replies.
