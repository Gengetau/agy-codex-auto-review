<div align="center">
  <img src="./assets/logo.svg" width="88" height="88" alt="Codex Auto Review Logo" />
  <h1>AGY Codex Auto Review</h1>
  <p>Bring local OpenAI Codex <code>codex-auto-review</code> into Google Antigravity lifecycle hooks: <strong>PreToolUse Approval Guardian + Stop Auto Code Review</strong></p>
  <p>
    <a href="./README.md">简体中文</a> · <strong>English</strong>
  </p>
</div>

---

## Why This Plugin?

Long autonomous coding sessions in Antigravity often force an awkward trade-off:
1. **Approval fatigue vs. safety**: Clicking approve on every shell command or MCP call breaks flow, while blindly auto-approving everything risks credential exfiltration, destructive commands, or unauthorized force pushes.
2. **Same-model blind spots**: A model reviewing its own fresh code can miss subtle auth bypasses, off-by-one boundaries, or contract regressions until manual review or production failures.

**AGY Codex Auto Review** bridges your locally authenticated OpenAI Codex CLI and its dedicated hidden **`codex-auto-review`** model (which does not count toward standard ChatGPT 5-hour/weekly plan limits when signed in with a ChatGPT account) into two native Antigravity hooks — with zero extra API keys, zero npm dependencies, and zero background daemons.

---

## Key Features

### 1. `PreToolUse` Approval Guardian
- **Zero latency on read-only tools**: Matcher targets mutating/exec tools only (`run_command`, file write/edit/delete, `call_mcp_tool` / `mcp_*`). Built-in read-only tools (`read_file`, `search_web`, etc.) never spawn the hook (`0ms`).
- **Fast local pre-filter (`<15ms`) with adversarial hardening**:
  - Fast-allows strictly single read-only commands (`git status`, `git diff`, `ls`, etc.) and normal in-workspace source edits;
  - Rejects shell chaining/redirection/injection (`&&`, `|`, `>`, `$(...)`, `git -c`, `--output`, sensitive file reads), sibling-directory prefix collisions, and symlink escapes;
  - **Self-protection**: Any attempt to edit this guardian plugin's own files is always routed to review, preventing prompt-injection tampering.
- **Three configurable modes & tiered prompts**: Supports `high_autonomy` (default), `standard`, and `strict`. Uses tiered confirmation mapping: `medium` risk returns `ask` (unlocking "Always allow" options 2 & 3), `high` risk returns `force_ask` (single-use approval), and `critical` returns `deny`.
- **Full conversation-flow authorization awareness**: Reads up to `2 MB` from the transcript tail to reconstruct recent `User ↔ Assistant` turns with **head+tail truncation (up to 4,000 chars)** on the proposal preceding the latest user reply, accurately resolving concise confirmations (`"ok"`, `"yes"`, `"嗯"`, `"继续"`, `"1"`) while keeping untrusted `toolCall.args` strictly isolated.
- **Fail-safe degradation**: If Codex times out, fails, is missing, or outputs invalid JSON, the hook never silently allows — it falls back to `decision: "ask"` for human confirmation.

### 2. `Stop` Automatic Code Review
- **Single-turn structured diff review (Windows-sandbox safe)**: Collects a secret-redacted uncommitted Git diff locally (`git status -uall` expands newly created directories while skipping `.env`, keys, binaries, `node_modules`, and docs-only changes) and sends it to Codex with a strict JSON Schema — avoiding Windows `CreateProcess` sandbox blocks inside `codex exec review`.
- **Automatic fix-and-verify loop**: When concrete **`P0` / `P1`** defects (configurable) are found, the hook outputs `{"decision": "continue", "reason": "..."}`. Antigravity injects those findings as a system message and automatically wakes the working model to fix them and re-run tests.
- **Loop & noise protection**:
  - Skips pure Q&A / non-mutating turns and non-`NO_TOOL_CALL` terminations (errors, cancellations, running background tasks);
  - SHA-256 `diffHash` deduplication + `maxAutoFixRounds` cap (default `2`) + **Fail-open** on Stop errors so a session can never be trapped.

### 3. Redacted Audit Trail & Cross-Platform Discovery
- Every decision is logged with automatic secret redaction to `$PLUGIN_DATA/audit.jsonl` (falling back to `<plugin_root>/logs/audit.jsonl`) with automatic log rotation.
- Automatically discovers the newest local Codex binary across Windows (`WindowsApps` / `LocalAppData`), macOS (`Codex.app` / Homebrew), and Linux (`PATH`).

---

## How It Works

```text
Antigravity Agent Loop
  │
  ├─[PreToolUse]──► pre_tool_guardian.mjs
  │     ├─ Fast path (<15ms): strictly read-only command / normal workspace edit / allowlisted read-only MCP ─► allow
  │     └─ Risky / cross-boundary / sensitive action ─► codex exec -m codex-auto-review (--output-schema)
  │           ├─ allow      ─► auto-approved (120s per-conversation cache)
  │           ├─ force_ask  ─► prompts user with risk rationale
  │           ├─ deny       ─► hard-blocked; rationale returned to working model
  │           └─ error/timeout ─► fail-safe fallback to ask
  │
  └─[Stop]────────► stop_code_review.mjs
        ├─ No code diff / non-Git dir / unchanged diffHash / max rounds reached ─► {} finish turn
        └─ Redacted Git Diff ─► codex exec -m codex-auto-review (--output-schema)
              ├─ pass (no P0/P1)  ─► {} finish turn normally
              └─ fix_required     ─► {"decision":"continue","reason":"..."}
                                     host injects findings as systemMessage for auto-fix
```

---

## Prerequisites

1. **Antigravity** (Desktop App or `agy` CLI)
2. **Node.js >= 20** (zero third-party dependencies)
3. **Local OpenAI Codex installation signed in** (Codex Desktop App or Codex CLI using `~/.codex` auth)
4. **Git** (for collecting uncommitted diffs in the `Stop` hook)

---

## Installation

### Option 1: Install via `agy` CLI (Recommended)

```bash
agy plugin install https://github.com/Gengetau/agy-codex-auto-review
```

### Option 2: Clone directly into the global plugins directory

```bash
git clone https://github.com/Gengetau/agy-codex-auto-review.git ~/.gemini/config/plugins/codex-auto-review
```

Verify installation:

```bash
agy plugin list
agy plugin validate ~/.gemini/config/plugins/codex-auto-review --strict
```

Toggle the plugin anytime:

```bash
agy plugin disable codex-auto-review
agy plugin enable codex-auto-review
```

---

## Configuration (`config.json`)

Edits to `config.json` take effect immediately on the next hook invocation (no restart required):

```json
{
  "codexBin": "",
  "guardian": {
    "enabled": true,
    "mode": "high_autonomy",
    "model": "codex-auto-review",
    "reasoningEffort": "low",
    "serviceTier": "fast",
    "timeoutMs": 28000,
    "fastAllowReadOnlyCommands": true,
    "fastAllowWorkspaceCodeWrites": true,
    "cacheAllowTtlSec": 120,
    "transcriptRecentUserTurns": 6,
    "readOnlyMcpTools": []
  },
  "codeReview": {
    "enabled": true,
    "model": "codex-auto-review",
    "reasoningEffort": "medium",
    "serviceTier": "fast",
    "timeoutMs": 55000,
    "minBlockingSeverity": "p1",
    "maxAutoFixRounds": 2,
    "maxDiffChars": 48000,
    "maxSingleFileChars": 12000,
    "reviewDocsOnly": false
  },
  "auditLog": {
    "enabled": true,
    "maxBytes": 2097152
  }
}
```

| Option | Description |
| :--- | :--- |
| `codexBin` | Optional explicit path to `codex` binary; leave empty for auto-discovery (or override via `CODEX_BIN`) |
| `guardian.mode` | `high_autonomy` (default) / `standard` / `strict` (escalates any non-`low` action to `ask`) |
| `guardian.readOnlyMcpTools` | Allowlist of read-only MCP tools to fast-allow, formatted as `"server:tool"` (e.g. `["my-server:read_file"]`) |
| `codeReview.model` | Defaults to `codex-auto-review`; can be switched to any model in your Codex account (e.g. `gpt-6.2-sol`, `gpt-6.2-astra`) |
| `codeReview.serviceTier` | Set to `""` for standard tier or `"fast"` for priority speed (note: `"fast"` uses higher quota on standard models) |
| `codeReview.minBlockingSeverity` | Minimum finding severity that triggers auto-fix continuation: `p0` / `p1` (default) / `p2` |
| `codeReview.maxAutoFixRounds` | Maximum auto-fix continuation rounds per turn (default `2`) |

---

## Testing

### Offline unit & adversarial tests (no network / Codex auth required)

```bash
node --test tests/run_tests.mjs
```

### Full suite including live local Codex E2E tests

```bash
# macOS / Linux
LIVE_CODEX=1 node --test tests/run_tests.mjs

# Windows PowerShell
$env:LIVE_CODEX="1"; node --test tests/run_tests.mjs
```

---

## License

[MIT License](./LICENSE)
