---
name: codex-auto-review
description: Inspect and manage the Antigravity Codex Auto Review plugin (PreToolUse approval guardian and Stop auto code review hooks). Trigger when viewing audit logs, tuning models/modes/severity thresholds, or toggling either hook.
---

# Codex Auto Review Plugin Operations

This plugin provides two independently configurable lifecycle hooks powered by your local OpenAI Codex CLI (`codex-auto-review`):

1. **`codex-guardian-approval` (`PreToolUse`)**: Evaluates potentially risky tool calls (shell commands, writes outside workspace or to sensitive files, and mutating MCP calls) while fast-allowing safe read-only commands and normal in-workspace code writes. Fails safe (`decision: "ask"`) if Codex is unavailable or times out.
2. **`codex-stop-code-review` (`Stop`)**: Collects a secret-redacted Git diff at the end of mutating turns (prioritizing uncommitted changes, and falling back to local commits created during the current turn when the working tree is clean) and runs a single-turn structured code review. Blocking findings (`p0`/`p1` by default) are injected back via `decision: "continue"` so the agent fixes them automatically (bounded by `diffHash`/`lastReviewedCommit` deduplication and `maxAutoFixRounds`).

## Key Paths

- Runtime configuration (hot-reloaded, no restart needed): `<plugin_root>/config.json`
- Hook registrations & independent enable flags: `<plugin_root>/hooks.json`
- Redacted audit logs: `$PLUGIN_DATA/audit.jsonl` (typically `~/.gemini/antigravity/plugin_data/codex-auto-review/audit.jsonl`, falling back to `<plugin_root>/logs/audit.jsonl`)

## Common Adjustments in `config.json`

- Toggle hooks individually: `guardian.enabled` / `codeReview.enabled`
- Change Guardian strictness: `guardian.mode` (`"high_autonomy"` | `"standard"` | `"strict"`)
- Whitelist read-only MCP tools for fast-allow: `guardian.readOnlyMcpTools` (e.g. `["my-mcp:read_file", "my-mcp:list_dir"]`)
- Change models or reasoning effort: `guardian.model` / `codeReview.model` (default `"codex-auto-review"`) and `reasoningEffort` (`"low"` | `"medium"` | `"high"`)
- Change Stop review scope & blocking threshold: `codeReview.reviewCommittedInTurn` (default `true`, falls back to commits created in the current turn when the working tree is clean), `codeReview.minBlockingSeverity` (`"p0"` | `"p1"` | `"p2"`), and `codeReview.maxAutoFixRounds` (default `2`)
