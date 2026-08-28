# pi 扩展安全更新门禁（Safe Update Gate）调研报告

调研日期：2026-08-21 · 调研对象：pi coding agent（`@earendil-works/pi-coding-agent` 0.84.3，本地安装于 `~/.bun/install/global/node_modules/@earendil-works/pi-coding-agent/`，下文简称"本地源码"）

---

## 1. 结论摘要（TL;DR）

1. **不存在现成的完整方案。** pi.dev/packages 市场共 5512 个包，有若干"相邻"安全扩展（安装前审计、已装扩展篡改检测、运行时拦截），但**没有一个**实现"更新前多引擎扫描 → 分级报告 → 选择性更新"的门禁流程。最接近的是 `pi-marketplace`（安装前 audit+确认，但不覆盖 update 流程）和 `@bruschill/pi-plugin-security-audit`（已装扩展指纹+篡改告警，事后检测而非事前拦截）。
2. **`pi update --extensions --safe` 这类 CLI flag 无法由扩展实现**（子命令 dispatch 在扩展加载前完成，且子命令列表硬编码），但 **`/safe-update` chat 命令 + custom tool + `tool_call` 拦截**的组合完全可行，且 pi 已支持按包单独更新（`pi update npm:<pkg>`），扩展 API（`DefaultPackageManager` 导出、`ui.confirm/select`、`pi.exec`）足以落地一个高完成度的方案。
3. pi 自身的更新流程**除 npm 标准 lockfile sha512 外没有任何校验、确认提示或 hook**——供应链风险真实存在（官方 issue #7517 已记录 install 阶段运行 lifecycle scripts 的任意代码执行问题）。
4. 推荐路径：**做一个 pi 扩展**，在 chat 内提供 `/safe-update`：读取已装包清单 → OSV（免费无限制）+ Socket（可选）/VirusTotal（可选，上传 tarball）分级扫描 → 用户逐包确认 → 调用 `pi update npm:<pkg>` 只更新白名单；同时用 `tool_call` hook 拦截 agent 自己跑 `pi update --extensions` 的企图。另可向上游提 issue 请求 pre-update hook / `--safe` flag。

---

## 2. pi 扩展更新机制的事实（本地源码 + 官方文档）

**包来源与安装位置**。三种源：npm / git / 本地路径（`docs/packages.md`，本地源码 "Package Sources" 节）。npm 包安装在 `~/.pi/agent/npm/`（user 级）或 `.pi/npm/`（project 级）；实际安装命令是 `npm install <spec> --prefix <root> --legacy-peer-deps`（本地源码 `dist/core/package-manager.js:1459-1476` `getNpmInstallArgs()`）。本地实例 `~/.pi/agent/npm/package.json` + `package-lock.json` 证实：lockfile 由 npm 维护，条目含 registry 返回的 sha512 integrity——这是**唯一**的完整性机制（防 CDN 篡改），不能防包作者主动发布的恶意新版本。

**版本解析**。`settings.json` 记录的是不带版本的 spec（本地实例：`"npm:pi-web-access"` 等 12 项）。更新时未 pin 的包通过 `npm view <name> version --json` 取 registry 最新版（`dist/core/package-manager.js:1214-1232` `getLatestNpmVersion()`）；带精确版本的 spec（`npm:@foo/bar@1.2.3`）被 update 跳过（`dist/core/package-manager.js:849-858`；`docs/packages.md`："Versioned specs are pinned and skipped by package updates"）。git 包若未 pin ref，会 reconcile 到远端 upstream HEAD（`dist/core/package-manager.js:1535-1547`）。

**校验机制：不存在**。对 `dist/core/package-manager.js` 全文 grep `integrity|shasum|checksum|signature|audit|confirm` —— 零匹配。更新过程无签名校验、无权限提示、无安全门禁。官方文档明确警告："Pi packages run with full system access. Extensions execute arbitrary code... Review source code before installing third-party packages."（`docs/packages.md`，Install and Manage 节）；`docs/security.md` 明确 pi **无内建沙箱**。

**无 hook / 无可拦截点**。`docs/extensions.md` 的完整事件列表（lifecycle/session/agent/tool/model/input）中没有任何 package-update 相关事件。`pi update` 在 CLI 主入口 `dist/main.js:455` 被 dispatch，**早于用户扩展加载**（代码注释："We normally prefer process.exit(0) for package commands so bad extensions cannot keep one-shot commands alive"）；且 update 命令使用 `useSavedProjectTrustOnly: true`（`dist/package-manager-cli.js:805`），连 `project_trust` 扩展事件都不加载。**结论：扩展无法拦截 shell 里直接执行的 `pi update --extensions`。**

**提示横幅来源**。启动时 interactive 模式异步调用 `DefaultPackageManager.checkForAvailableUpdates()`（`dist/modes/interactive/interactive-mode.js:815-821, 891-907`；实现见 `dist/core/package-manager.js:925-977`），有更新则渲染 "Package Updates Available / Run pi update --extensions"（`interactive-mode.js:3522-3528`）。

**按包更新：支持**。`pi update npm:@foo/bar` 与 `pi update --extension <source>` 均只更新单个包（`dist/package-manager-cli.js` `parsePackageCommand()`；`docs/packages.md`）。这是选择性更新的关键支撑。

**上游已知问题**。GitHub `earendil-works/pi`：
- [#7517](https://github.com/earendil-works/pi/issues/7517) "`pi install` runs npm/git lifecycle scripts; default user-scope installs not trust-gated"（安装即任意代码执行，建议默认 `--ignore-scripts`、安装前显示包名/版本/作者、pin 精确版本；被自动关闭）
- [#6845](https://github.com/earendil-works/pi/issues/6845)、[#5785](https://github.com/earendil-works/pi/issues/5785)、[#4929](https://github.com/earendil-works/pi/issues/4929)、[#6028](https://github.com/earendil-works/pi/issues/6028) 围绕 `min-release-age`（npm 冷却期防御）与 pi 更新检查的冲突；本地 CHANGELOG 确认 self-update 显式绕过 release-age gate（`CHANGELOG.md` 引 #4929；managed self-update 用 `npm ci --ignore-scripts --min-release-age=0`，`dist/package-manager-cli.js` `runManagedNpmCi()`）。

---

## 3. 现有 pi 扩展市场盘点

来源：https://pi.dev/packages （显示 "1-50 / 5512"，即市场共 **5512 个包**，按下载量排序）+ npm registry `keywords:pi-package` 检索。市场每页只展示 Top 50（头部为 pi-mcp-adapter、pi-web-access、pi-subagents 等工具类），未发现官方的 security 分类筛选。安全相关候选逐一核查（npm registry 元数据 + README，2026-08-21）：

| 包名 | 一句话用途 | 与"安全更新门禁"的关系 |
|---|---|---|
| [`pi-marketplace`](https://www.npmjs.com/package/pi-marketplace) (0.1.3) | 搜索/详情/**安装前审计**（元数据检查+源码关键词扫描）+ 确认后安装，"never auto-installs" | **gate 的是 install，不覆盖 update**；无外部扫描服务 |
| [`@bruschill/pi-plugin-security-audit`](https://www.npmjs.com/package/@bruschill/pi-plugin-security-audit) (1.0.1) | 已装扩展静态审计 + 指纹 + 篡改告警（wrapper/watchdog/守护三处检测），macOS 专用 | **事后篡改检测**，非更新前拦截；README 自述局限（不读 .node/.wasm，guard 晚一个 session） |
| [`pi-security-scanner`](https://www.npmjs.com/package/pi-security-scanner) (0.1.0) | 运行时 bash/文件拦截 + `/security-scan` 静态扫描已装扩展的危险模式 | 运行时 + 事后扫描 |
| [`@vtstech/pi-security`](https://www.npmjs.com/package/@vtstech/pi-security) (1.3.2) | 命令 blocklist、SSRF 防护、路径校验 | 纯运行时 |
| [`@artale/pi-sentinel`](https://www.npmjs.com/package/@artale/pi-sentinel) (2.6.4) | 审计日志、权限策略、自修改检测 | 运行时/事后 |
| `@gotgenes/pi-permission-system`、`cc-safety-net`、`@trim21/personal-pi-extensions`(bwrap sandbox) | 权限执行/拦截危险命令/沙箱 | 运行时 |

**结论：不存在**"更新前扫描门禁 + 按扫描结果选择性更新"的 pi 包（npm registry 按 `pi-package` × security/audit/update/safe/supply/virus/malware 多组关键词检索后未找到）。相邻空白明确存在。

---

## 4. pi 提供的挂载点评估

**扩展能注册什么**（`docs/extensions.md`）：custom tools（`registerTool`）、slash 命令（`registerCommand`）、快捷键（`registerShortcut`）、CLI flag（`registerFlag`，仅会话内生效）、provider、大量事件 hook、自定义 TUI。扩展以用户全权限运行（无沙箱、无权限模型）。

**扩展不能注册新的 CLI 子命令**：`install/remove/update/list/config` 在 `dist/main.js:455` 与 `dist/package-manager-cli.js` 中硬编码 dispatch，发生在任何用户扩展加载之前。`pi safeupdate --extensions` / `pi update --extensions --safe` **不可行**（除非上游改代码）。`registerFlag` 注册的 flag 也要进入会话流程才有意义，而 `pi update` 根本不进会话。

**可行的替代交互形态**（均有官方示例支撑）：
- `/safe-update` chat 命令：`registerCommand` + `ctx.ui.select/confirm` 交互 + `pi.exec("pi", ["update", "npm:<pkg>"])` 逐包更新（官方示例 `permission-gate.ts`、`github-issue-autocomplete.ts` 证明这套模式成立）。
- 启动时被动检查：`session_start` 事件里读 settings + 调用 `DefaultPackageManager.checkForAvailableUpdates()`——`DefaultPackageManager` 是主包公开导出（本地 `dist/index.d.ts:15`）。
- 运行时防线：`tool_call` 事件可 block bash 调用（`docs/extensions.md` "tool_call ... **Can block**"），可拦截 agent 尝试执行 `pi update --extensions` / `npm install`，强制改走 `/safe-update`。
- UI 能力充分：分级报告可用 `ui.notify/setWidget` + custom TUI（`ctx.ui.custom()`）呈现。

**缺口**：(a) 无法拦截用户在 shell 中直接跑 `pi update`；(b) 无 pre-update 事件，只能在更新前后做检测（指纹对比可参考 `@bruschill/pi-plugin-security-audit` 的做法）；(c) 更新完成后新代码即被加载执行，扫描必须在"下载/安装之前"对 registry 元数据和 tarball 做，而不是装完后。

---

## 5. 外部扫描服务对比表

| 服务 | 扫描对象 | 免费 tier | Rate limit | API 文档 |
|---|---|---|---|---|
| [VirusTotal](https://docs.virustotal.com/) | **文件**（需下载/上传 tarball） | Public API 免费（注册即得 key） | **4 req/min、500 req/天**（官方原文："The Public API is limited to 500 requests per day and a rate of 4 requests per minute"，[public-vs-premium](https://docs.virustotal.com/docs/public-vs-premium-api)） | https://docs.virustotal.com/reference/files |
| [osv.dev](https://osv.dev/) (Google/OpenSSF) | **包名@版本**（静态查库，无需下载） | 完全免费，无需 key | **"Currently there are no limits on the API"**（官方 FAQ 原文，[API 文档](https://google.github.io/osv.dev/api/)） | `POST https://api.osv.dev/v1/query`（package name+ecosystem+version）、`/v1/querybatch` 批量 |
| [Socket](https://socket.dev/) | **包名@版本**（score/issues 静态分析）+ 全量 manifest 扫描 | 需注册 API key；quota 按计划（官方提供 `Get quota` 端点） | 按计划配额（未公开具体免费数值） | https://docs.socket.dev/reference（"Scoring System: Obtain a security score for any package"、"Issue Management: Retrieve issues by package"） |
| `npm audit` / OSV-Scanner | 已安装依赖树 / lockfile | 免费（本地工具） | 本地无限制 | https://docs.npmjs.com/cli/commands/npm-audit 、https://github.com/google/osv-scanner |
| [MetaDefender Cloud](https://metadefender.com/) (OPSWAT) | **文件**（multiscan，20+ AV 引擎）+ hash | 网页免费 30 次上传（官方首页原文："Free limit: 30 file uploads"）；API 需 apikey，精确配额未在公开文档核实到 | 未核实到公开数值（官方文档站需登录） | https://metadefender.opswat.com/ |

**关键事实——哪些能"包名@版本"静态查、哪些必须上传文件**：
- 可静态查（不下载文件）：**OSV**（已知漏洞库）、**Socket**（供应链启发式：install scripts、网络行为、混淆代码等）、npm registry 元数据（发布时间→`min-release-age` 冷却期逻辑，npm ≥11.10.0 原生支持，见 [npm min-release-age](https://www.brandonpugh.com/til/node/package-version-cooldown/)）。
- 必须上传 tarball：**VirusTotal**（`POST /api/v3/files` 标准 key 限 **32MB**，超过需先 `GET /api/v3/files/upload_urls` 取专用 URL，实际上限 650MB、官方建议 >200MB 拆分，[files-upload-url](https://docs.virustotal.com/reference/files-upload-url)）；**MetaDefender** 同理。检测结果结构：VT 返回逐引擎 `last_analysis_results` + 汇总 `last_analysis_stats`（malicious/suspicious/undetected 计数），见 [files reference](https://docs.virustotal.com/reference/files)。
- 对 pi 扩展（npm tarball 一般 <10MB）而言 VT 32MB 上限不是障碍，**4 req/min 才是瓶颈**（12 个包串行更新需 3 分钟配额）；OSV 是天然的零成本第一道闸。

---

## 6. 相邻生态先例

| 先例 | gate 的阶段 | 机制（一句话） |
|---|---|---|
| [Snyk Agent Scan](https://github.com/snyk/agent-scan)（原 Invariant Labs [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan)，仓库已演化并入 Snyk） | **使用前（配置扫描）**+ 运行时 guard hook | 连接 stdio MCP server 抓取 tool descriptions/skills → 本地检查 + 上传分析 API，检测 prompt injection、tool poisoning、tool shadowing、malware payloads，并与已知 MCP server 签名库比对发现 rug pull；README 明确警告"扫描本身会执行配置中的命令"并要求逐 server consent |
| [Claude Code 权限系统](https://code.claude.com/docs/en/permissions) | **运行时（每次工具调用）** | 权限模式（default/acceptEdits/plan/auto/dontAsk/bypassPermissions）+ allow/ask/deny 三类规则（`Bash(npm *)` 等模式匹配，deny 优先）+ PreToolUse hooks 可程序化阻断；官方文档明示 Bash 默认需批准 |
| [Socket Firewall](https://docs.socket.dev/reference/getting-started) | **install 时** | "sits between your package manager and the registry, intercepting installs to check every dependency... and block malware before it hits your system"（官方原文）——与"安全更新门禁"目标最同构的先例 |
| [Socket 浏览器插件](https://docs.socket.dev/docs/socket-security-chrome-extension) | **安装前（浏览 registry 时）** | 在 npm 包页面/搜索结果内嵌安全指标，"protecting you from threats... before you even install them" |
| npm `min-release-age`（≥11.10.0，2026-02） | **install/update 时** | 拒装发布不足 N 天的版本（冷却期），过滤"发布即恶意、数小时内被下架"的抢跑攻击；pnpm/Yarn/Renovate 均已跟进 |
| [JetBrains Marketplace 审核](https://plugins.jetbrains.com/docs/marketplace/jetbrains-marketplace-approval-guidelines.html) | **分发时（含每次更新）** | "we manually review each Plugin and Plugin update one-by-one, before it becomes publicly available"——中心化人工 gate，pi 的去中心化 npm 分发模式没有等价物 |

---

## 7. 可行性方案草图

### 方案 A（推荐）：pi 扩展 `/safe-update` —— chat 内门禁

```
session_start ──► 读 ~/.pi/agent/settings.json (packages) 
              ──► DefaultPackageManager.checkForAvailableUpdates()  [公开导出，dist/index.d.ts:15]
              ──► 有更新 → ui.setWidget 显示 "N updates pending, run /safe-update"

/safe-update 命令流程：
  1. 对每个 待更新包:
     a. OSV  POST /v1/querybatch  {package:{name,ecosystem:"npm"},version}   ← 免费、无限流
     b. Socket GET score/issues（若配置了 API key）                            ← 供应链启发式
     c. npm view <name>@<ver> time.versions[<ver>] → 距今发布时长              ← 冷却期检查
     d. （可选，用户显式开启）npm pack 下载 tarball → VT POST /files（注意 4 req/min）
  2. 渲染分级报告（红/黄/绿）: CVE 数、Socket issue 类型、发布时长、maintainer 变更
  3. ctx.ui.select 逐包 / 多轮 confirm → 生成白名单
  4. for pkg of 白名单: pi.exec("pi", ["update", `npm:${pkg}`])               ← 已验证支持单包更新
  5. （可选）更新前后各做一次指纹快照，diff 展示"这次更新改了哪些文件"

运行时防线（同一扩展内）:
  on("tool_call") 拦截 bash 中含 "pi update --extensions" / "pi update --all" 的命令
  → block 并提示 "use /safe-update"
```

依据：所有 API 均已核实存在且形态匹配（§5）；单包更新已核实（§2）；`tool_call` 可 block、`DefaultPackageManager` 公开导出、`ui.*` 交互能力均见 `docs/extensions.md`。局限：shell 直跑 `pi update` 拦不住（§4）。

### 方案 B：独立 wrapper CLI（补 shell 场景）

发布一个独立 npm 包（如 `pi-safe-update`，bin 入口），用户 `alias pi-update=safe-update`。它在外层完成 §A 的 1-3 步后调用 `pi update npm:<pkg>`。本质是 Snyk Agent Scan / Socket Firewall 的"外置扫描器"形态在 pi 上的翻版，不依赖 pi 扩展 API 的任何假设。

### 方案 C：上游提案（长期正解）

向 `earendil-works/pi` 提 feature request：package update 生命周期 hook（pre-update 事件允许扩展 block/modify 待更新列表）、或 `pi update --safe` flag。引用 #7517 已有的三条建议（默认 `--ignore-scripts`、装前显示 resolved 包名/版本/作者、未 pin 警告）+ #6845 的 min-release-age 兼容诉求。在官方支持前，A+B 组合即可覆盖主要风险面。

---

## 8. 参考来源列表

**pi 本地一手来源**（`/Users/jesse/.bun/install/global/node_modules/@earendil-works/pi-coding-agent/`）：
- `docs/packages.md`（安装/更新命令、pin 语义、安全警告全文）
- `docs/extensions.md`（事件列表、registerCommand/Tool/Flag、tool_call 可 block）
- `docs/security.md`（无沙箱、project trust 边界）
- `dist/core/package-manager.js`（:814-977 update/checkForAvailableUpdates；:1214-1232 getLatestNpmVersion；:1459-1476 getNpmInstallArgs；:1535-1547 updateGit）
- `dist/package-manager-cli.js`（:605-609 update 不加载扩展；parsePackageCommand 单包更新）
- `dist/main.js:455`（package 命令先于扩展 dispatch）
- `dist/modes/interactive/interactive-mode.js`（:815/:891/:3522 更新横幅）
- `dist/index.d.ts:15`（DefaultPackageManager 导出）
- 本机实例：`~/.pi/agent/settings.json`、`~/.pi/agent/npm/package.json`、`~/.pi/agent/npm/package-lock.json`

**官方站点/仓库**：
- https://pi.dev/packages （市场，5512 包） · https://pi.dev
- https://github.com/earendil-works/pi — issues #7517、#6845、#5785、#4929、#6028、#6126

**市场安全类扩展**（npm registry 元数据，2026-08-21 查证）：
- https://www.npmjs.com/package/pi-marketplace · https://www.npmjs.com/package/@bruschill/pi-plugin-security-audit · https://www.npmjs.com/package/pi-security-scanner · https://www.npmjs.com/package/@vtstech/pi-security · https://www.npmjs.com/package/@artale/pi-sentinel

**扫描服务官方文档**：
- https://docs.virustotal.com/docs/public-vs-premium-api （4 req/min、500/day 原文）
- https://docs.virustotal.com/reference/files-upload-url （32MB/650MB/200MB 原文）
- https://docs.virustotal.com/reference/files （结果结构）
- https://google.github.io/osv.dev/api/ （免费、无限流原文） · https://github.com/google/osv-scanner
- https://docs.socket.dev/reference 、https://docs.socket.dev/reference/getting-started （Firewall 原文）、https://docs.socket.dev/docs/socket-security-chrome-extension
- https://docs.npmjs.com/cli/commands/npm-audit · https://metadefender.com/ （20+ 引擎、30 次免费上传）

**生态先例**：
- https://github.com/snyk/agent-scan （原 invariantlabs-ai/mcp-scan）及其 `docs/scanning.md`
- https://code.claude.com/docs/en/permissions （权限模式与规则）
- https://plugins.jetbrains.com/docs/marketplace/jetbrains-marketplace-approval-guidelines.html
- https://www.brandonpugh.com/til/node/package-version-cooldown/ （npm min-release-age）
