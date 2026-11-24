import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  appendAudit,
  canonicalPath,
  cleanUserMessage,
  inspectTranscript,
  loadConfig,
  loadState,
  readStdin,
  redactSecrets,
  resolveCodexBinary,
  runCodexStructured,
  saveState,
  SCHEMAS_DIR,
  sha256,
} from './common.mjs';

const SEVERITY_RANK = { none: 0, p3: 1, p2: 2, p1: 3, p0: 4 };

const SKIP_FILE_RE = /(?:^|\/)(?:node_modules|\.venv|venv|__pycache__|dist|build|\.next|target|\.gradle|\.idea|\.vscode)\/|(?:^|\/)(?:\.env(?:\.[^/]+)?|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|uv\.lock|Cargo\.lock|poetry\.lock|auth\.json|oauth_creds\.json)$|\.(?:png|jpe?g|gif|webp|ico|mp4|mp3|wav|zip|tar|gz|7z|pdf|exe|dll|so|dylib|db|db-wal|db-shm|sqlite|sqlite3|pyc|woff2?|ttf|otf|pem|key|p12|pfx)$/i;
const DOC_ONLY_RE = /\.(?:md|mdx|txt|rst)$/i;

function runGit(cwd, args) {
  return spawnSync('git', args, {
    cwd,
    encoding: 'utf8',
    timeout: 8000,
    windowsHide: true,
    maxBuffer: 4 * 1024 * 1024,
  });
}

export function discoverGitRepos(payload) {
  const candidates = [];
  if (Array.isArray(payload?.workspacePaths)) {
    for (const w of payload.workspacePaths) {
      if (typeof w === 'string' && w.trim()) candidates.push(w.trim());
    }
  }
  if (typeof payload?.cwd === 'string' && payload.cwd.trim()) {
    candidates.push(payload.cwd.trim());
  }

  const seen = new Set();
  const repos = [];
  for (const dir of candidates) {
    if (!existsSync(dir)) continue;
    const res = runGit(dir, ['rev-parse', '--show-toplevel']);
    if (res.status === 0 && res.stdout) {
      const top = canonicalPath(res.stdout.trim());
      const key = process.platform === 'win32' ? top.toLowerCase() : top;
      if (top && !seen.has(key)) {
        seen.add(key);
        repos.push(top);
      }
    }
  }
  return repos;
}

export function collectRepoDiff(repoRoot, config) {
  const maxDiffChars = Number(config?.codeReview?.maxDiffChars) || 48000;
  const maxSingleFileChars = Number(config?.codeReview?.maxSingleFileChars) || 12000;
  const reviewDocsOnly = Boolean(config?.codeReview?.reviewDocsOnly);

  const st = runGit(repoRoot, ['status', '--porcelain=v1', '-z', '-uall']);
  if (st.status !== 0 || !st.stdout) return null;

  const entries = st.stdout.split('\0').filter(Boolean);
  const changedFiles = [];
  const untrackedFiles = [];
  for (let i = 0; i < entries.length; i++) {
    const rec = entries[i];
    if (rec.length < 4) continue;
    const xy = rec.slice(0, 2);
    const file = rec.slice(3).replace(/\\/g, '/');
    if (xy.includes('R') || xy.includes('C')) i++;
    if (!file || SKIP_FILE_RE.test(file)) continue;
    changedFiles.push(file);
    if (xy === '??') untrackedFiles.push(file);
  }

  if (changedFiles.length === 0) return null;
  if (!reviewDocsOnly && changedFiles.every((f) => DOC_ONLY_RE.test(f))) {
    return null;
  }

  const chunks = [];
  let usedChars = 0;
  const pushChunk = (header, body) => {
    if (!body || usedChars >= maxDiffChars) return;
    const cleanBody = redactSecrets(body);
    const remaining = maxDiffChars - usedChars;
    const piece = cleanBody.length > remaining
      ? cleanBody.slice(0, remaining) + '\n... [truncated]'
      : cleanBody;
    const full = `${header}\n${piece}\n`;
    chunks.push(full);
    usedChars += full.length;
  };

  const trackedEligible = changedFiles.filter((f) => !untrackedFiles.includes(f));
  if (trackedEligible.length > 0) {
    const staged = runGit(repoRoot, ['diff', '--cached', '--unified=3', '--', ...trackedEligible]);
    if (staged.status === 0 && staged.stdout.trim()) {
      pushChunk('### Staged Diff', staged.stdout);
    }
    const unstaged = runGit(repoRoot, ['diff', '--unified=3', '--', ...trackedEligible]);
    if (unstaged.status === 0 && unstaged.stdout.trim()) {
      pushChunk('### Unstaged Diff', unstaged.stdout);
    }
  }

  for (const uf of untrackedFiles) {
    if (usedChars >= maxDiffChars) break;
    const abs = join(repoRoot, uf);
    try {
      if (!existsSync(abs)) continue;
      const fst = statSync(abs);
      if (!fst.isFile() || fst.size > 256 * 1024) continue;
      const content = readFileSync(abs, 'utf8');
      if (content.includes('\0')) continue;
      const clipped = content.length > maxSingleFileChars
        ? content.slice(0, maxSingleFileChars) + '\n... [file truncated]'
        : content;
      pushChunk(`### New Untracked File: ${uf}`, clipped);
    } catch {}
  }

  const diffText = chunks.join('\n').trim();
  if (!diffText) return null;

  return {
    repoRoot,
    source: 'working_tree',
    files: changedFiles,
    diffText,
    diffHash: sha256(diffText),
  };
}

export function collectRecentCommitDiff(repoRoot, config, { sinceMs = null, lastReviewedCommit = '' } = {}) {
  const maxDiffChars = Number(config?.codeReview?.maxDiffChars) || 48000;
  const reviewDocsOnly = Boolean(config?.codeReview?.reviewDocsOnly);
  const thresholdSec = Number.isFinite(sinceMs)
    ? Math.floor(sinceMs / 1000) - 2
    : Math.floor((Date.now() - 120_000) / 1000);

  const logRes = runGit(repoRoot, ['log', '--no-merges', '--format=%H\t%ct\t%s', '-n', '10', 'HEAD']);
  if (logRes.status !== 0 || !logRes.stdout || !logRes.stdout.trim()) return null;

  const turnCommits = [];
  for (const line of logRes.stdout.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const parts = line.split('\t');
    const hash = (parts[0] || '').trim();
    const ctSec = Number(parts[1]);
    const subject = parts.slice(2).join('\t').trim();
    if (!hash) continue;
    if (lastReviewedCommit && hash === lastReviewedCommit) break;
    if (!Number.isFinite(ctSec) || ctSec < thresholdSec) break;
    turnCommits.push({ hash, ctSec, subject });
  }
  if (turnCommits.length === 0) return null;

  const newest = turnCommits[0].hash;
  const oldest = turnCommits[turnCommits.length - 1].hash;
  const parentRes = runGit(repoRoot, ['rev-parse', '--verify', `${oldest}^`]);
  const hasParent = parentRes.status === 0 && Boolean(parentRes.stdout && parentRes.stdout.trim());
  const base = hasParent ? parentRes.stdout.trim() : '';

  const namesRes = hasParent
    ? runGit(repoRoot, ['diff', '--name-only', '-z', `${base}..${newest}`])
    : runGit(repoRoot, ['diff-tree', '--no-commit-id', '--name-only', '-r', '--root', '-z', newest]);
  if (namesRes.status !== 0 || !namesRes.stdout) return null;

  const changedFiles = [];
  for (const rawFile of namesRes.stdout.split('\0')) {
    const file = rawFile.replace(/\\/g, '/').trim();
    if (!file || SKIP_FILE_RE.test(file)) continue;
    changedFiles.push(file);
  }
  if (changedFiles.length === 0) return null;
  if (!reviewDocsOnly && changedFiles.every((f) => DOC_ONLY_RE.test(f))) {
    return null;
  }

  const diffRes = hasParent
    ? runGit(repoRoot, ['diff', '--unified=3', `${base}..${newest}`, '--', ...changedFiles])
    : runGit(repoRoot, ['show', '--format=', '--unified=3', newest, '--', ...changedFiles]);
  if (diffRes.status !== 0 || !diffRes.stdout || !diffRes.stdout.trim()) return null;

  const cleanBody = redactSecrets(diffRes.stdout.trim());
  const body = cleanBody.length > maxDiffChars
    ? cleanBody.slice(0, maxDiffChars) + '\n... [truncated]'
    : cleanBody;
  const commitSummary = turnCommits
    .map((c) => `${c.hash.slice(0, 7)} ${c.subject}`.trim())
    .join('; ');
  const diffText = `### Committed Diff (${commitSummary})\n${body}`.trim();
  if (!diffText) return null;

  return {
    repoRoot,
    source: 'recent_commits',
    files: changedFiles,
    commits: turnCommits.map((c) => c.hash.slice(0, 12)),
    headCommit: newest,
    commitSummary,
    diffText,
    diffHash: sha256(diffText),
  };
}

export function buildCodeReviewPrompt(payload, bundle, recentUserTurns) {
  const lastUser = cleanUserMessage(payload?.lastUserInput || '').slice(0, 800);
  const historyBlock = recentUserTurns.length
    ? recentUserTurns.map((t, i) => `  ${i + 1}. ${t}`).join('\n')
    : '  (no prior transcript turns)';
  const diffHeading = bundle.source === 'recent_commits'
    ? `## Recent Commit(s) in This Turn (${bundle.commitSummary || 'HEAD'}) (Secrets Redacted)`
    : '## Uncommitted Changes (Secrets Redacted)';

  return [
    'You are Codex Auto Code Review, acting as an automated senior reviewer at the end of an agent turn.',
    'Do NOT invoke any shell commands or tools. Review ONLY the provided git diff below and output strict JSON matching the schema.',
    '',
    '## Review Bar (High Signal, Zero Noise)',
    '- Focus strictly on real defects:',
    '  * p0: Security vulnerabilities, auth/scope bypasses, credential leaks, data loss/corruption, broken production deployment.',
    '  * p1: Concrete functional bugs, logic/boundary errors (off-by-one, falsy 0 bugs, clock confusion), race conditions, crash paths, broken API contracts, unhandled failure modes.',
    '  * p2: Moderate edge-case gaps or maintainability risks worth noting (non-blocking unless configured).',
    '  * p3: Minor nitpicks (do NOT set fix_required for p2/p3).',
    '- Set verdict="fix_required" ONLY when there is at least one concrete p0 or p1 defect clearly evidenced in the diff.',
    '- Do NOT invent issues about code outside the diff, and do NOT block for style/formatting/comments.',
    '- Write summary, title, and detail concisely (matching the user\'s language).',
    '',
    '## Context',
    `- Repository: ${bundle.repoRoot}`,
    `- Changed Files: ${bundle.files.join(', ')}`,
    `- Latest User Request: ${lastUser || '(empty)'}`,
    '- Recent User Requests:',
    historyBlock,
    '',
    diffHeading,
    bundle.diffText,
  ].join('\n');
}

export async function handleStopHook(payload, config = loadConfig()) {
  if (!config?.codeReview?.enabled) return {};

  const convId = String(payload?.conversationId || 'unknown');
  const termReason = String(payload?.terminationReason || '');
  const fullyIdle = payload?.fullyIdle !== false;
  const continuationActive = Boolean(payload?.continuationActive);

  if (termReason && termReason !== 'NO_TOOL_CALL') {
    appendAudit(config, {
      hook: 'Stop',
      conversationId: convId,
      decision: 'skip_termination_reason',
      terminationReason: termReason,
    });
    return {};
  }
  if (!fullyIdle) {
    appendAudit(config, {
      hook: 'Stop',
      conversationId: convId,
      decision: 'skip_not_idle',
    });
    return {};
  }

  const transcript = inspectTranscript(payload?.transcriptPath, 4);
  if (payload?.transcriptPath && !transcript.currentTurnMutated) {
    appendAudit(config, {
      hook: 'Stop',
      conversationId: convId,
      decision: 'skip_non_mutating',
    });
    return {};
  }

  const repos = discoverGitRepos(payload);
  if (repos.length === 0) {
    appendAudit(config, {
      hook: 'Stop',
      conversationId: convId,
      decision: 'skip_no_git_repo',
    });
    return {};
  }

  const state = loadState();
  const maxRounds = Math.max(1, Number(config.codeReview.maxAutoFixRounds) || 2);
  const minSev = String(config.codeReview.minBlockingSeverity || 'p1').toLowerCase();
  const minRank = SEVERITY_RANK[minSev] ?? SEVERITY_RANK.p1;
  const reviewCommitted = config.codeReview.reviewCommittedInTurn !== false;
  const codexBin = resolveCodexBinary(config);
  const schemaPath = join(SCHEMAS_DIR, 'code_review_schema.json');

  const blockingReports = [];
  let anyBundle = false;

  for (const repoRoot of repos) {
    const stateKey = `${convId}::${repoRoot.toLowerCase()}`;
    const prev = state.stopReview[stateKey] || {
      lastReviewedHash: '',
      lastReviewedCommit: '',
      fixRounds: 0,
      updatedAt: 0,
    };

    let bundle = collectRepoDiff(repoRoot, config);
    if (!bundle && reviewCommitted) {
      bundle = collectRecentCommitDiff(repoRoot, config, {
        sinceMs: transcript.lastUserCreatedAtMs,
        lastReviewedCommit: prev.lastReviewedCommit || '',
      });
    }
    if (!bundle) continue;
    anyBundle = true;

    const currentRounds = continuationActive ? Number(prev.fixRounds || 0) : 0;

    if (prev.lastReviewedHash === bundle.diffHash) {
      appendAudit(config, {
        hook: 'Stop',
        conversationId: convId,
        repo: repoRoot,
        diffSource: bundle.source,
        decision: 'skip_unchanged_diff',
        diffHash: bundle.diffHash.slice(0, 12),
      });
      continue;
    }

    if (currentRounds >= maxRounds) {
      appendAudit(config, {
        hook: 'Stop',
        conversationId: convId,
        repo: repoRoot,
        diffSource: bundle.source,
        decision: 'skip_max_rounds_reached',
        fixRounds: currentRounds,
        diffHash: bundle.diffHash.slice(0, 12),
      });
      state.stopReview[stateKey] = {
        lastReviewedHash: bundle.diffHash,
        lastReviewedCommit: bundle.headCommit || prev.lastReviewedCommit || '',
        fixRounds: currentRounds,
        updatedAt: Date.now(),
      };
      continue;
    }

    const prompt = buildCodeReviewPrompt(payload, bundle, transcript.recentUserTurns);
    const res = runCodexStructured({
      codexBin,
      prompt,
      schemaPath,
      model: config.codeReview.model || 'codex-auto-review',
      reasoningEffort: config.codeReview.reasoningEffort || 'medium',
      serviceTier: config.codeReview.serviceTier || 'fast',
      timeoutMs: Number(config.codeReview.timeoutMs) || 55000,
      cwd: repoRoot,
    });

    if (!res.ok) {
      appendAudit(config, {
        hook: 'Stop',
        conversationId: convId,
        repo: repoRoot,
        diffSource: bundle.source,
        decision: 'fail_open',
        error: res.error,
        elapsedMs: res.elapsedMs,
      });
      continue;
    }

    const review = res.data || {};
    const findings = Array.isArray(review.findings) ? review.findings : [];
    const blockingFindings = findings.filter(
      (f) => (SEVERITY_RANK[String(f?.severity || '').toLowerCase()] ?? 0) >= minRank
    );
    const shouldBlock = review.verdict === 'fix_required' && blockingFindings.length > 0;

    state.stopReview[stateKey] = {
      lastReviewedHash: bundle.diffHash,
      lastReviewedCommit: bundle.headCommit || prev.lastReviewedCommit || '',
      fixRounds: shouldBlock ? currentRounds + 1 : 0,
      updatedAt: Date.now(),
    };

    appendAudit(config, {
      hook: 'Stop',
      conversationId: convId,
      repo: repoRoot,
      diffSource: bundle.source,
      commits: bundle.commits || undefined,
      files: bundle.files.slice(0, 20),
      diffHash: bundle.diffHash.slice(0, 12),
      verdict: review.verdict,
      highestSeverity: review.highest_severity,
      blockingCount: blockingFindings.length,
      fixRound: shouldBlock ? currentRounds + 1 : 0,
      summary: review.summary,
      elapsedMs: res.elapsedMs,
    });

    if (shouldBlock) {
      const lines = blockingFindings.map(
        (f, idx) => `${idx + 1}. [${String(f.severity).toUpperCase()}] ${f.file}: ${f.title} — ${f.detail}`
      );
      const commitHint = bundle.source === 'recent_commits'
        ? '（注：本次审查的是当前回合已提交的本地 commit，请修复后追加提交或按项目规范处理）'
        : '';
      blockingReports.push(
        `仓库 ${repoRoot}（第 ${currentRounds + 1}/${maxRounds} 轮自动审查）${commitHint}：${review.summary}\n${lines.join('\n')}`
      );
    }
  }

  if (!anyBundle) {
    appendAudit(config, {
      hook: 'Stop',
      conversationId: convId,
      repos: repos.slice(0, 5),
      decision: 'skip_no_changes',
    });
  }

  const cutoff = Date.now() - 7 * 24 * 3600 * 1000;
  for (const [k, v] of Object.entries(state.stopReview)) {
    if (!v || (v.updatedAt && v.updatedAt < cutoff)) delete state.stopReview[k];
  }
  saveState(state);

  if (blockingReports.length > 0) {
    return {
      decision: 'continue',
      reason: [
        '[Codex Auto Code Review 发现待修复的高优先级缺陷，请核实源码并修复、重跑相关测试后再收尾汇报]',
        ...blockingReports,
      ].join('\n\n'),
    };
  }

  return {};
}

async function main() {
  try {
    const raw = await readStdin();
    const payload = raw.trim() ? JSON.parse(raw) : {};
    const out = await handleStopHook(payload);
    process.stdout.write(JSON.stringify(out) + '\n');
  } catch {
    process.stdout.write('{}\n');
  }
}

const isDirectRun = process.argv[1] && canonicalPath(process.argv[1]).toLowerCase() === canonicalPath(fileURLToPath(import.meta.url)).toLowerCase();
if (isDirectRun) {
  await main();
}
