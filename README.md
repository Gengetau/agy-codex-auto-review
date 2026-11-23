<div align="center">
  <img src="./assets/logo.svg" width="88" height="88" alt="Codex Auto Review Logo" />
  <h1>AGY Codex Auto Review</h1>
  <p>将本机 OpenAI Codex 官方 <code>codex-auto-review</code> 模型接入 Google Antigravity 生命周期钩子：<strong>PreToolUse 高自治权限守护 + Stop 自动代码审查</strong></p>
  <p>
    <strong>简体中文</strong> · <a href="./README.en.md">English</a>
  </p>
</div>

---

## 为什么做这个插件？

在使用 Antigravity 进行长时间编码或自主任务时，通常会遇到两个痛点：
1. **权限确认过于打扰，但完全放开又不安全**：每条终端命令、跨目录修改或 MCP 操作都弹窗审批会频繁打断心流；可一旦无脑全部自动放行，又可能发生凭据外泄、误删文件或未授权强推主分支。
2. **代码写完缺少独立第二视角复核**：同一个模型刚写完的代码容易有“灯下黑”盲区（如鉴权大小写绕过、边界差一、契约破坏等），等到人工复审或线上报错才发现，返工成本高。

**AGY Codex Auto Review** 利用本机已登录的 OpenAI Codex CLI 及其隐藏专用审查模型 **`codex-auto-review`**（在 ChatGPT 账号登录态下不计入常规 5h / 每周主用量），零额外 API Key、零常驻后台服务，为 Antigravity 接入两道自动化安全与质量防线。

---

## 核心特性

### 1. `PreToolUse` 权限审批守护（Guardian）
- **精准触发，零拖慢只读操作**：仅匹配有副作用的工具（`run_command`、写/改/删文件、`call_mcp_tool` / `mcp_*`）；`read_file`、`search_web` 等纯只读内置工具完全不触发钩子（`0ms`）。
- **分层本地快筛（`<15ms`）+ 强防绕过**：
  - 纯只读单条命令（如 `git status`、`git diff`、`ls`）与工作区内普通代码写入本地秒放；
  - 严防壳注入与绕过（拦截 `&&`/`|`/`>`/`$(...)`/`git -c`/`--output`/敏感文件读取、工作区兄弟目录前缀碰撞、符号链接穿越）；
  - 内置**插件自我保护**：任何尝试修改本插件自身配置或脚本的操作一律强制送审，防止被提示词注入篡改守卫。
- **三档安全策略可热切换**：支持 `high_autonomy`（默认高自治）、`standard`（标准 Guardian）、`strict`（严格模式）。
- **上下文授权感知**：自动读取对话轨迹中最近若干轮用户原话与紧邻确认前的提案摘要，能准确识别你前文已明确批准的操作，减少误拦；同时明确区分“工具参数（不可信）”与“用户指令（授权源）”。
- **Fail-Safe 安全兜底**：审查器超时、断网、登录过期或输出非法 JSON 时，**绝不静默放行**，一律降级返回 `ask` 转人工确认。

### 2. `Stop` 回合结束自动代码审查（Auto Code Review）
- **原生避坑 Windows 沙箱限制**：不依赖容易在 Windows 下触发 Codex 内部沙箱 `CreateProcess` 拦截的交互式子命令，改为宿主侧本地快速采集脱敏未提交 Git diff（支持 `git status -uall` 展开新建子目录，自动跳过 `.env`、密钥、二进制、`node_modules` 与纯文档改动），单轮输出严格 JSON Schema 评审结论。
- **自动回注修复闭环**：仅当发现真实 **`P0` / `P1`**（可配置）缺陷时，向 Antigravity 返回 `{"decision": "continue", "reason": "..."}`，由宿主自动将问题列表作为系统消息注入工作模型，直接驱使其修复并重跑测试。
- **防死循环与防误触发**：
  - 纯问答 / 本回合未改动代码 / 非正常结束（报错、取消、后台任务未完）直接跳过；
  - 内置 `diffHash`（SHA-256）去重与 `maxAutoFixRounds`（默认 `2` 轮）上限，异常时 **Fail-Open** 放行，永不卡死会话。

### 3. 脱敏审计与跨平台
- 所有决策记录自动脱敏密钥/Token 形态后写入 `$PLUGIN_DATA/audit.jsonl`（默认回退至 `<plugin_root>/logs/audit.jsonl`），带大小轮转。
- 自动探测本机最新版 Codex CLI（支持 Windows Store / LocalAppData、macOS `Codex.app` / Homebrew、Linux `PATH`），Codex 更新不失效。

---

## 工作原理

```text
Antigravity Agent Loop
  │
  ├─[工具调用前 PreToolUse]──► pre_tool_guardian.mjs
  │     ├─ 本地快筛(<15ms): 纯只读单命令 / 工作区内普通代码写 / 白名单只读 MCP ─► allow
  │     └─ 高风险/跨界/敏感操作 ─► codex exec -m codex-auto-review (--output-schema)
  │           ├─ allow      ─► 自动放行（免弹窗，同会话 120s 短期缓存）
  │           ├─ force_ask  ─► 弹窗交由人工审批（附风险理由）
  │           ├─ deny       ─► 硬拦截，并将拦截原因返还给工作模型调整方案
  │           └─ 异常/超时  ─► Fail-Safe 降级为 ask
  │
  └─[回合收尾前 Stop]────────► stop_code_review.mjs
        ├─ 非代码改动 / 非 Git 仓库 / diff 未变 / 超最大轮次 ─► {} 直接结束
        └─ 采集脱敏 Git Diff ─► codex exec -m codex-auto-review (--output-schema)
              ├─ pass (无 P0/P1)  ─► {} 正常结束向用户汇报
              └─ fix_required     ─► {"decision":"continue","reason":"..."}
                                     宿主自动注入系统消息，工作模型修复后再审
```

---

## 前置要求

1. **Antigravity**（桌面端或 `agy` CLI）
2. **Node.js >= 20**（零第三方 npm 依赖，纯原生 ESM）
3. **本机已安装并登录 OpenAI Codex**（Codex Desktop App 或 Codex CLI，复用 `~/.codex` 登录态）
4. **Git**（用于 `Stop` 钩子采集仓库变更 diff）

---

## 安装

### 方式一：通过 `agy` CLI 一键安装（推荐）

```bash
agy plugin install https://github.com/Gengetau/agy-codex-auto-review
```

### 方式二：手动克隆到全局插件目录

```bash
git clone https://github.com/Gengetau/agy-codex-auto-review.git ~/.gemini/config/plugins/codex-auto-review
```

安装完成后可运行校验确认生效：

```bash
agy plugin list
agy plugin validate ~/.gemini/config/plugins/codex-auto-review --strict
```

如需临时启停整个插件：

```bash
agy plugin disable codex-auto-review
agy plugin enable codex-auto-review
```

---

## 配置说明（`config.json`）

修改插件根目录的 `config.json` 即时热生效，无需重启 Antigravity：

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

| 配置项 | 说明 |
| :--- | :--- |
| `codexBin` | 手动指定 `codex` 可执行文件路径；留空则自动发现本机最新版本（也可通过环境变量 `CODEX_BIN` 覆盖） |
| `guardian.mode` | `high_autonomy`（默认高自治）/ `standard`（标准 Guardian）/ `strict`（严格，非 low 风险均转人工确认） |
| `guardian.readOnlyMcpTools` | 只读 MCP 工具本地秒放白名单，格式为 `"server:tool"`（如 `["my-server:read_file"]`） |
| `codeReview.model` | 默认 `codex-auto-review`；也可切换为 Codex 账号内任意模型（如 `gpt-6.2-sol`、`gpt-6.2-astra`） |
| `codeReview.serviceTier` | 留空 `""` 使用标准档；`fast` 为加速档（注意：非 `codex-auto-review` 的常规模型使用 `fast` 会额外消耗额度） |
| `codeReview.minBlockingSeverity` | 触发自动打回修复的最低严重级别：`p0` / `p1`（默认）/ `p2` |
| `codeReview.maxAutoFixRounds` | 同一轮次最多自动打回修复次数（默认 `2`），防止死循环 |

> 若希望只启用其中一个钩子，既可以在 `config.json` 里将 `guardian.enabled` 或 `codeReview.enabled` 设为 `false`，也可以直接在 `hooks.json` 中单独关闭对应 hook。

---

## 运行测试

### 纯离线单元与对抗绕过测试（默认，无需网络与 Codex 登录）

```bash
node --test tests/run_tests.mjs
```

### 全套测试（含真实本机 Codex 端到端链路测试）

```bash
# macOS / Linux
LIVE_CODEX=1 node --test tests/run_tests.mjs

# Windows PowerShell
$env:LIVE_CODEX="1"; node --test tests/run_tests.mjs
```

---

## 开源协议

[MIT License](./LICENSE)
