import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
export const PLUGIN_ROOT = resolve(process.env.PLUGIN_ROOT || resolve(__dirname, '..'));
export const DATA_DIR = resolve(process.env.PLUGIN_DATA || join(PLUGIN_ROOT, 'logs'));
export const LOGS_DIR = process.env.PLUGIN_DATA ? DATA_DIR : join(PLUGIN_ROOT, 'logs');
export const SCHEMAS_DIR = join(PLUGIN_ROOT, 'schemas');

const DEFAULT_CONFIG = {
  codexBin: '',
  guardian: {
    enabled: true,
    mode: 'high_autonomy',
    model: 'codex-auto-review',
    reasoningEffort: 'low',
    serviceTier: 'fast',
    timeoutMs: 28000,
    fastAllowReadOnlyCommands: true,
    fastAllowWorkspaceCodeWrites: true,
    cacheAllowTtlSec: 120,
    transcriptRecentUserTurns: 6,
    transcriptMaxReadBytes: 2097152,
    readOnlyMcpTools: [],
  },
  codeReview: {
    enabled: true,
    model: 'codex-auto-review',
    reasoningEffort: 'medium',
    serviceTier: 'fast',
    timeoutMs: 55000,
    minBlockingSeverity: 'p1',
    maxAutoFixRounds: 2,
    maxDiffChars: 48000,
    maxSingleFileChars: 12000,
    reviewDocsOnly: false,
    reviewCommittedInTurn: true,
  },
  auditLog: {
    enabled: true,
    maxBytes: 2097152,
  },
};

export function loadConfig() {
  const cfgPath = join(PLUGIN_ROOT, 'config.json');
  try {
    if (!existsSync(cfgPath)) return structuredClone(DEFAULT_CONFIG);
    const raw = JSON.parse(readFileSync(cfgPath, 'utf8'));
    return {
      codexBin: typeof raw.codexBin === 'string' ? raw.codexBin : '',
      guardian: { ...DEFAULT_CONFIG.guardian, ...(raw.guardian || {}) },
      codeReview: { ...DEFAULT_CONFIG.codeReview, ...(raw.codeReview || {}) },
      auditLog: { ...DEFAULT_CONFIG.auditLog, ...(raw.auditLog || {}) },
    };
  } catch {
    return structuredClone(DEFAULT_CONFIG);
  }
}

export function readStdin() {
  return new Promise((resolvePromise) => {
    let raw = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      raw += chunk;
    });
    process.stdin.on('end', () => resolvePromise(raw));
    process.stdin.on('error', () => resolvePromise(raw));
  });
}

export function sha256(text) {
  return createHash('sha256').update(String(text || ''), 'utf8').digest('hex');
}

export function redactSecrets(input) {
  if (input == null) return '';
  let s = String(input);
  const rules = [
    [/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]'],
    [/\bsk-proj-[A-Za-z0-9_\-]{16,}/g, '[REDACTED_OPENAI_KEY]'],
    [/\bsk-[A-Za-z0-9_\-]{16,}/g, '[REDACTED_API_KEY]'],
    [/\bgh[pousr]_[A-Za-z0-9_]{20,}/g, '[REDACTED_GITHUB_TOKEN]'],
    [/\bgithub_pat_[A-Za-z0-9_]{20,}/g, '[REDACTED_GITHUB_TOKEN]'],
    [/\bAQ\.[A-Za-z0-9_\-\.]{16,}/g, '[REDACTED_GOOGLE_KEY]'],
    [/\bAIza[0-9A-Za-z_\-]{20,}/g, '[REDACTED_GOOGLE_API_KEY]'],
    [/\b4\/0A[A-Za-z0-9_\-\.]{16,}/g, '[REDACTED_OAUTH_CODE]'],
    [/\bxox[baprs]-[A-Za-z0-9\-]{16,}/g, '[REDACTED_SLACK_TOKEN]'],
    [/(\bBearer\s+)[A-Za-z0-9_\-\.=]{16,}/gi, '$1[REDACTED_BEARER_TOKEN]'],
    [
      /(\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|owner[_-]?token|secret|password|passwd|authorization)\s*[:=]\s*["']?)([^\s"',;`\r\n]{8,})/gi,
      '$1[REDACTED_SECRET]',
    ],
  ];
  for (const [re, rep] of rules) {
    s = s.replace(re, rep);
  }
  return s;
}

/**
 * Keeps both the beginning and the end of long messages so action checklists
 * and final approval questions at the tail are never clipped away.
 */
export function truncateHeadTail(text, maxChars, headRatio = 0.4) {
  const s = String(text || '').trim();
  if (s.length <= maxChars) return s;
  const marker = ' ...[middle truncated]... ';
  const avail = Math.max(40, maxChars - marker.length);
  const headLen = Math.max(20, Math.floor(avail * headRatio));
  const tailLen = Math.max(20, avail - headLen);
  return s.slice(0, headLen).trimEnd() + marker + s.slice(s.length - tailLen).trimStart();
}

export function resolveCodexBinary(config) {
  const explicit = String(process.env.CODEX_BIN || config?.codexBin || '').trim();
  if (explicit) {
    return existsSync(explicit) ? explicit : '';
  }

  const candidates = [];
  const pushIfFile = (p) => {
    try {
      if (existsSync(p)) {
        const st = statSync(p);
        if (st.isFile()) candidates.push({ path: p, mtimeMs: st.mtimeMs });
      }
    } catch {}
  };

  if (process.platform === 'win32') {
    const winAppsDir = join(process.env.ProgramFiles || 'C:\\Program Files', 'WindowsApps');
    try {
      if (existsSync(winAppsDir)) {
        for (const entry of readdirSync(winAppsDir, { withFileTypes: true })) {
          if (entry.isDirectory() && /^OpenAI\.Codex_/i.test(entry.name)) {
            pushIfFile(join(winAppsDir, entry.name, 'app', 'resources', 'codex.exe'));
          }
        }
      }
    } catch {}

    const localAppData = process.env.LOCALAPPDATA || join(homedir(), 'AppData', 'Local');
    const codexBinRoot = join(localAppData, 'OpenAI', 'Codex', 'bin');
    try {
      if (existsSync(codexBinRoot)) {
        for (const entry of readdirSync(codexBinRoot, { withFileTypes: true })) {
          if (entry.isDirectory()) {
            pushIfFile(join(codexBinRoot, entry.name, 'codex.exe'));
          }
        }
      }
    } catch {}

    pushIfFile(join(homedir(), '.codex', 'plugins', '.plugin-appserver', 'codex.exe'));
  } else if (process.platform === 'darwin') {
    pushIfFile('/Applications/Codex.app/Contents/Resources/codex');
    pushIfFile(join(homedir(), 'Applications', 'Codex.app', 'Contents', 'Resources', 'codex'));
    pushIfFile('/opt/homebrew/bin/codex');
    pushIfFile('/usr/local/bin/codex');
    pushIfFile(join(homedir(), '.local', 'bin', 'codex'));
  } else {
    pushIfFile(join(homedir(), '.local', 'bin', 'codex'));
    pushIfFile('/usr/local/bin/codex');
    pushIfFile('/usr/bin/codex');
  }

  if (candidates.length > 0) {
    candidates.sort((a, b) => b.mtimeMs - a.mtimeMs);
    return candidates[0].path;
  }

  const cmd = process.platform === 'win32' ? 'where' : 'which';
  const res = spawnSync(cmd, ['codex'], { encoding: 'utf8', timeout: 3000 });
  if (res.status === 0 && res.stdout) {
    const first = res.stdout.split(/\r?\n/).map((s) => s.trim()).find(Boolean);
    if (first && existsSync(first)) return first;
  }

  return '';
}

export function runCodexStructured({
  codexBin,
  prompt,
  schemaPath,
  model,
  reasoningEffort = 'low',
  serviceTier = 'fast',
  timeoutMs = 28000,
  cwd,
}) {
  if (!codexBin || !existsSync(codexBin)) {
    return { ok: false, error: 'codex_binary_not_found' };
  }
  const outPath = join(tmpdir(), `agy-codex-review-${process.pid}-${randomUUID()}.json`);
  const args = [
    'exec',
    '--ephemeral',
    '--ignore-user-config',
    '--skip-git-repo-check',
    '-s', 'read-only',
    '-m', model,
    '-c', `model_reasoning_effort="${reasoningEffort}"`,
  ];
  if (serviceTier) {
    args.push('-c', `service_tier="${serviceTier}"`);
  }
  args.push('--output-schema', schemaPath, '-o', outPath, '-');

  const t0 = Date.now();
  try {
    const res = spawnSync(codexBin, args, {
      cwd: cwd && existsSync(cwd) ? cwd : undefined,
      input: prompt,
      encoding: 'utf8',
      timeout: timeoutMs,
      windowsHide: true,
      maxBuffer: 4 * 1024 * 1024,
    });
    const elapsedMs = Date.now() - t0;
    if (res.error) {
      return {
        ok: false,
        error: res.error.code === 'ETIMEDOUT' ? 'codex_timeout' : `spawn_error:${res.error.message}`,
        elapsedMs,
      };
    }
    if (res.status !== 0) {
      return {
        ok: false,
        error: `codex_exit_${res.status}`,
        stderr: redactSecrets((res.stderr || '').slice(-400)),
        elapsedMs,
      };
    }
    const rawOut = existsSync(outPath)
      ? readFileSync(outPath, 'utf8').trim()
      : String(res.stdout || '').trim();
    if (!rawOut) {
      return { ok: false, error: 'codex_empty_output', elapsedMs };
    }
    const parsed = JSON.parse(rawOut);
    return { ok: true, data: parsed, elapsedMs };
  } catch (err) {
    return {
      ok: false,
      error: `codex_parse_or_exec_error:${err?.message || String(err)}`,
      elapsedMs: Date.now() - t0,
    };
  } finally {
    try {
      if (existsSync(outPath)) unlinkSync(outPath);
    } catch {}
  }
}

export function cleanUserMessage(raw) {
  return redactSecrets(
    String(raw || '')
      .replace(/<ADDITIONAL_METADATA>[\s\S]*?<\/ADDITIONAL_METADATA>/g, '')
      .replace(/<USER_SETTINGS_CHANGE>[\s\S]*?<\/USER_SETTINGS_CHANGE>/g, '')
      .replace(/<\/?USER_REQUEST>/g, '')
      .replace(/\s+/g, ' ')
      .trim()
  );
}

/**
 * Extracts a structured recent User <-> Assistant conversation window from
 * transcript.jsonl (reading up to 2 MB from the tail so long multi-tool turns
 * never push out the user's authorization or the preceding assistant proposal).
 * Uses head+tail preservation so long proposals keep their final action plan
 * and confirmation question intact.
 */
export function inspectTranscript(transcriptPath, maxUserTurns = 6, maxReadBytes = 2097152) {
  const result = {
    recentUserTurns: [],
    recentDialogue: [],
    precedingAssistantProposal: '',
    currentTurnProgress: '',
    currentTurnMutated: false,
    currentTurnTools: [],
    lastUserCreatedAtMs: null,
  };
  if (!transcriptPath || typeof transcriptPath !== 'string' || !existsSync(transcriptPath)) {
    return result;
  }
  try {
    const st = statSync(transcriptPath);
    const limit = Math.max(256 * 1024, Number(maxReadBytes) || 2097152);
    let raw = '';
    if (st.size <= limit) {
      raw = readFileSync(transcriptPath, 'utf8');
    } else {
      const fullBuf = readFileSync(transcriptPath);
      raw = fullBuf.subarray(fullBuf.length - limit).toString('utf8');
      const nl = raw.indexOf('\n');
      if (nl >= 0) raw = raw.slice(nl + 1);
    }

    const lines = raw.split(/\r?\n/).filter(Boolean);
    const parsedSteps = [];
    const userStepIndices = [];

    for (let i = 0; i < lines.length; i++) {
      let obj;
      try {
        obj = JSON.parse(lines[i]);
      } catch {
        continue;
      }
      const idx = parsedSteps.length;
      parsedSteps.push(obj);
      if (obj.type === 'USER_INPUT' || obj.source === 'USER_EXPLICIT') {
        const txt = cleanUserMessage(typeof obj.content === 'string' ? obj.content : '');
        if (txt) {
          const parsedTs = typeof obj.created_at === 'string' ? Date.parse(obj.created_at) : NaN;
          userStepIndices.push({ idx, txt, createdAtMs: Number.isFinite(parsedTs) ? parsedTs : null });
        }
      }
    }

    const recentUsers = userStepIndices.slice(-Math.max(1, maxUserTurns));
    result.recentUserTurns = recentUsers.map((u) => truncateHeadTail(u.txt, 800, 0.5));

    const lastUserEntry = userStepIndices[userStepIndices.length - 1] || null;
    const lastUserIdx = lastUserEntry ? lastUserEntry.idx : -1;
    result.lastUserCreatedAtMs = lastUserEntry ? lastUserEntry.createdAtMs : null;

    // Build chronological User <-> Assistant dialogue pairs for the recent window.
    // For each user turn, include the final substantive assistant message right before it
    // (especially generous budget for the one right before the latest user message).
    const dialogue = [];
    for (let uPos = 0; uPos < recentUsers.length; uPos++) {
      const u = recentUsers[uPos];
      const prevBoundary = uPos > 0 ? recentUsers[uPos - 1].idx : -1;
      const isLatestUser = uPos === recentUsers.length - 1;

      let prevAsstText = '';
      for (let i = u.idx - 1; i > prevBoundary; i--) {
        const s = parsedSteps[i];
        if (s.type === 'PLANNER_RESPONSE' && typeof s.content === 'string' && s.content.trim()) {
          prevAsstText = redactSecrets(s.content.replace(/\s+/g, ' ').trim());
          break;
        }
      }

      if (prevAsstText) {
        const budget = isLatestUser ? 4000 : 1000;
        const formattedAsst = truncateHeadTail(prevAsstText, budget, isLatestUser ? 0.35 : 0.4);
        dialogue.push({ role: 'assistant', text: formattedAsst, isPrecedingLatestUser: isLatestUser });
        if (isLatestUser) {
          result.precedingAssistantProposal = formattedAsst;
        }
      }

      dialogue.push({
        role: 'user',
        text: truncateHeadTail(u.txt, isLatestUser ? 1200 : 600, 0.5),
        isLatestUser,
      });
    }

    // Also capture the most recent assistant progress summary in the current turn (after lastUserIdx)
    const mutatingRe = /^(run_command|write_file|write_to_file|edit_file|replace_file_content|multi_replace_file_content|delete_file|apply_patch|send_command_input|call_mcp_tool|mcp_.*)$/i;
    const seenTools = new Set();
    let latestCurrentTurnText = '';
    for (let i = Math.max(0, lastUserIdx + 1); i < parsedSteps.length; i++) {
      const step = parsedSteps[i];
      if (step.type === 'PLANNER_RESPONSE' && typeof step.content === 'string' && step.content.trim()) {
        latestCurrentTurnText = redactSecrets(step.content.replace(/\s+/g, ' ').trim());
      }
      const calls = Array.isArray(step.tool_calls) ? step.tool_calls : [];
      for (const tc of calls) {
        const name = String(tc?.name || tc?.tool || '').trim();
        if (!name) continue;
        seenTools.add(name);
        if (mutatingRe.test(name)) {
          result.currentTurnMutated = true;
        }
      }
    }
    if (latestCurrentTurnText) {
      result.currentTurnProgress = truncateHeadTail(latestCurrentTurnText, 800, 0.4);
    }
    result.recentDialogue = dialogue;
    result.currentTurnTools = Array.from(seenTools);
  } catch {}
  return result;
}

export function canonicalPath(p, baseDir) {
  if (!p || typeof p !== 'string') return '';
  let resolved = p.trim();
  if (resolved.startsWith('~/') || resolved.startsWith('~\\')) {
    resolved = join(homedir(), resolved.slice(2));
  }
  resolved = baseDir && !isAbsolute(resolved) ? resolve(baseDir, resolved) : resolve(resolved);

  let cur = resolved;
  const tail = [];
  for (let i = 0; i < 32; i++) {
    if (existsSync(cur)) {
      try {
        const real = realpathSync(cur);
        resolved = tail.length ? join(real, ...tail.reverse()) : real;
      } catch {}
      break;
    }
    const parent = dirname(cur);
    if (parent === cur) break;
    tail.push(cur.slice(parent.length).replace(/^[\\/]+/, ''));
    cur = parent;
  }
  return resolved;
}

export function isPathInside(targetPath, rootDir) {
  if (!targetPath || !rootDir) return false;
  const normTarget = process.platform === 'win32' ? targetPath.toLowerCase() : targetPath;
  const normRoot = process.platform === 'win32' ? rootDir.toLowerCase() : rootDir;
  const rel = relative(normRoot, normTarget);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

export function loadState() {
  const statePath = join(DATA_DIR, 'state.json');
  try {
    if (!existsSync(statePath)) return { allowCache: {}, stopReview: {} };
    const parsed = JSON.parse(readFileSync(statePath, 'utf8'));
    return {
      allowCache: parsed?.allowCache && typeof parsed.allowCache === 'object' ? parsed.allowCache : {},
      stopReview: parsed?.stopReview && typeof parsed.stopReview === 'object' ? parsed.stopReview : {},
    };
  } catch {
    return { allowCache: {}, stopReview: {} };
  }
}

export function saveState(state) {
  try {
    mkdirSync(DATA_DIR, { recursive: true });
    const statePath = join(DATA_DIR, 'state.json');
    const tmpPath = join(DATA_DIR, `state.${process.pid}.${randomUUID().slice(0, 8)}.tmp`);
    const body = JSON.stringify(state, null, 2);
    writeFileSync(tmpPath, body, 'utf8');
    try {
      renameSync(tmpPath, statePath);
    } catch {
      writeFileSync(statePath, body, 'utf8');
      try { unlinkSync(tmpPath); } catch {}
    }
  } catch {}
}

export function appendAudit(config, entry) {
  if (!config?.auditLog?.enabled) return;
  try {
    mkdirSync(LOGS_DIR, { recursive: true });
    const logPath = join(LOGS_DIR, 'audit.jsonl');
    const maxBytes = Number(config.auditLog.maxBytes) || 2097152;
    if (existsSync(logPath) && statSync(logPath).size > maxBytes) {
      try {
        const lines = readFileSync(logPath, 'utf8').split(/\r?\n/).filter(Boolean);
        const kept = lines.slice(-Math.max(100, Math.floor(lines.length / 2))).join('\n') + '\n';
        writeFileSync(logPath, kept, 'utf8');
      } catch {}
    }
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      ...entry,
    });
    appendFileSync(logPath, redactSecrets(line) + '\n', 'utf8');
  } catch {}
}
