# pi 扩展"更新前安全门禁"调研报告

> 调研日期：2026-08-27
> 调研对象：pi（pi.dev，Mario Zechner/badlogic 发起，现由 Earendil Inc. 维护，GitHub 仓库 [earendil-works/pi](https://github.com/earendil-works/pi)，npm 包 `@earendil-works/pi-coding-agent`）
> 调研问题：是否存在现成 pi 扩展解决"`pi update --extensions` 更新前的安全门禁"问题；若无，用户设想方案（下载新版本 → 提交公开安全扫描 → 标注可信度 → 选择性升级）的可行性。

---

## 1. 结论摘要

**是否存在现成方案：部分存在，但没有一个完整覆盖用户设想，且最接近的方案与设想的技术路线不同。**

- **已有最接近的现成扩展**：[`@panzenbaby/pi-secure-extension`](https://www.npmjs.com/package/@panzenbaby/pi-secure-extension) 提供 `/secure:update` 与 `/secure:update-all` 命令——检查已安装扩展的可用更新、逐个下载审计（用当前选中的 LLM 分析源码而非第三方扫描服务）、展示风险评级与 SHA-256 完整性哈希、经用户确认后才安装/更新。它实现的正是"更新前审计 + 逐包选择性升级"流程，但审计引擎是 **AI 模型**，不是 VirusTotal 等多引擎扫描服务。该包最后更新于 2026-04-25，下载量小（长期维护状态未确认）。
- **其他相关扩展**：`zmarketplace`（含 `updates` 命令 + audit，已集成可选的 Socket.dev 供应链评分）、`pi-vuln-scanner`（对**已安装**包持续扫描，数据源为 `npm audit`/OSV.dev/deps.dev/OSS Index）、`@bruschill/pi-plugin-security-audit`（静态审计 + 指纹基线 + 篡改检测，macOS）、`pi-marketplace`（安装前 metadata + tarball 关键词扫描）。详见第 3 节。
- **pi 官方无任何内建的扩展安全机制**：无签名校验、无 registry 审核、无沙箱、无安装前扫描。官方信任模型明确为"用户自担风险"（SECURITY.md 将"安装不可信扩展的风险"列为 out of scope）。唯一的内建缓解是：npm 源**带精确版本号的 spec 会被 `pi update --extensions` 跳过**（版本 pinning）。
- **关键可行性约束**：扩展**无法拦截** `pi update --extensions` CLI 命令（该命令在 pi 进程中于扩展加载前由独立的 package-manager CLI 路径处理，扩展事件系统中也没有任何 package/install/update 相关事件）。因此 `pi update --extensions --safe` 或 `pi safeupdate --extensions` 这样的**新 CLI 子命令不能通过扩展实现**；可行形态是扩展注册 slash command（如 `/safeupdate`，`@panzenbaby/pi-secure-extension` 已证明此路径可行）或外部 shell wrapper。
- **扫描对象形态已确认**：pi 安装/更新 npm 源扩展时执行的是标准 `npm install`（下载 npm registry 的 tarball），扫描对象即标准 npm `.tgz` tarball（`registry.npmjs.org/<pkg>/-/<pkg>-<version>.tgz`）。
- **一个重要风险点（一手源码确认）**：pi 安装扩展包时的 npm 命令为 `install ... --prefix <root> --legacy-peer-deps`，**不带 `--ignore-scripts`**——即扩展包的 `postinstall` 等生命周期脚本会在安装/更新时以用户权限执行。任何"扫描后再安装"的门禁都必须意识到：恶意 postinstall 在真正的 `pi install`/`pi update` 时仍会运行（`@panzenbaby/pi-secure-extension` 的 README 也明确承认此局限）。

---

## 2. pi 扩展系统现状

### 2.1 项目归属与文档入口

- pi 项目已从 `badlogic/pi-mono` 迁移至 **[earendil-works/pi](https://github.com/earendil-works/pi)**（GitHub 上 `badlogic/pi-mono` 重定向至此；作者 GitHub 首页 [badlogic](https://github.com/badlogic) 置顶仓库亦为 `earendil-works/pi`）。npm 包名为 `@earendil-works/pi-coding-agent`。
- 官方文档入口：[https://pi.dev/docs](https://pi.dev/docs)（实际页面在 `/docs/latest/` 路径下）。关键页面：
  - Pi Packages：<https://pi.dev/docs/latest/packages>
  - Extensions API：<https://pi.dev/docs/latest/extensions>
  - Security：<https://pi.dev/docs/latest/security>
  - SECURITY.md：<https://github.com/earendil-works/pi/blob/main/SECURITY.md>

### 2.2 分发渠道与包目录

- pi 包通过三种源分发（[packages 文档](https://pi.dev/docs/latest/packages)）：`npm:<scope>/<pkg>@<version>`（安装到 `~/.pi/agent/npm/`）、`git:<host>/<path>@<ref>`（clone 到 `~/.pi/agent/git/`）、本地路径。
- **pi.dev/packages 没有独立的 registry API**。官方文档原话："The [package gallery](https://pi.dev/packages) displays packages tagged with `pi-package`"——即 gallery 的数据源就是 **npm registry 上带 `pi-package` keyword 的包**，可通过 npm 公开搜索 API 完整列举：
  `https://registry.npmjs.org/-/v1/search?text=keywords:pi-package&size=250`
  - 本次调研实测：页面显示 All packages 共 **5555** 个；通过 npm search API 分页（250/页）抓到 **5247** 个唯一包名（差异原因未确认，推测与 npm 搜索索引/评分分页有关）。
  - `https://api.pi.dev/v1/packages` 返回 TLS 错误（HTTP 525）、`https://pi.dev/api/packages` 返回 501——确认无独立 API（`zmarketplace` 的 README 也注明 "pi-dev (pending — no public registry URL yet)"）。
- 每个包卡片只有三个链接：npm 页面、repo、**report**（指向 GitHub issue 模板 `earendil-works/pi/issues/new?template=package-report.yml`，即人工举报渠道，非自动扫描）。

### 2.3 install / update 的实际工作方式（源码级确认）

源码位置（均为 [earendil-works/pi](https://github.com/earendil-works/pi) 仓库 `main` 分支，`packages/coding-agent/` 下）：

- **CLI 子命令入口**：`src/package-manager-cli.ts` 中 `PackageCommand = "install" | "remove" | "update" | "list"`；`src/main.ts` 在主流程早期调用 `handlePackageCommand(args, { extensionFactories })`，处理完直接 `process.exit()`——**`pi install/update` 命令不加载用户扩展**（`extensionFactories` 仅用于 project trust 解析时加载全局扩展的 `project_trust` 事件，见 `package-manager-cli.ts` 的 `createCommandSettingsManager`）。
- **npm 安装命令**：`src/core/package-manager.ts` 的 `getNpmInstallArgs()`：
  ```ts
  return ["install", ...specs, "--prefix", installRoot, "--legacy-peer-deps"];
  ```
  （bun 为 `--omit=peer`，pnpm 为等价配置项；均**无 `--ignore-scripts`**。）对比之下，pi 自身的安装文档反而建议 `npm install -g --ignore-scripts @earendil-works/pi-coding-agent`（[docs 首页](https://pi.dev/docs/latest)）。
- **git 安装**：clone 后若存在 `package.json` 会运行 `npm install`（配置了 `npmCommand` 时用普通 `install`，否则 `install --omit=dev`）——同样执行生命周期脚本。
- **更新检查**：`src/core/package-manager.ts` 的 `checkForAvailableUpdates()` 遍历 global + project settings 中的 packages，**`parsed.pinned`（带版本号的 npm spec）与 local 源直接跳过**；npm 源向 registry 查询最新版本。
- **"Package Updates Available" 提示的来源**：`src/modes/interactive/interactive-mode.ts` 启动时异步调用 `checkForPackageUpdates()`，若有更新则渲染 `showPackageUpdateNotification()`（即用户看到的提示框）。它是**纯 UI 通知**，不经过扩展系统，扩展无法消费或拦截。
- **对 git 源的更新语义**：`pi update --extensions` 不会把 pinned git ref 移到新版本，只做 reconcile（reset + clean 到配置的 ref，并重跑 `npm install`）；要升级 git 包需重新 `pi install git:...@new-ref`（[packages 文档](https://pi.dev/docs/latest/packages)）。

### 2.4 内建安全机制：有什么、没什么

| 机制 | 状态 | 来源 |
|---|---|---|
| 扩展签名 / provenance 校验 | **无**（pi 不校验 npm provenance/attestation；依赖 npm 自身的 tarball sha512 integrity 防传输篡改，不防恶意发布者） | [packages 文档](https://pi.dev/docs/latest/packages) 仅提示 "Review source code before installing third-party packages" |
| Registry / gallery 审核 | **无**（任何 npm 包打上 `pi-package` keyword 即入目录；仅有 GitHub issue 人工举报模板） | [packages 文档 Gallery Metadata 节](https://pi.dev/docs/latest/packages)、pi.dev/packages 页面 report 链接 |
| 沙箱 | **无内建**（官方明确 "Pi does not include a built-in sandbox"，扩展以用户全权限运行任意代码；隔离需容器/VM，见 [Containerization 文档](https://pi.dev/docs/latest/containerization)） | [security 文档](https://pi.dev/docs/latest/security) |
| Project trust | 有，但**仅是输入加载防护**（防止仓库静默改 settings/extensions；对"模型/工具能做什么"无约束）；全局扩展可通过 `project_trust` 事件接管决策 | [security 文档](https://pi.dev/docs/latest/security)、[extensions 文档](https://pi.dev/docs/latest/extensions) |
| 版本 pinning | 有：npm spec 带精确版本 → update 跳过；git ref pinned → update 不移动 | [packages 文档](https://pi.dev/docs/latest/packages) + `package-manager.ts` 源码 |
| 生命周期脚本抑制 | **无**（`pi install npm:<pkg>` 会执行目标包的 install scripts；pi 自身安装才建议 `--ignore-scripts`） | `package-manager.ts` `getNpmInstallArgs()` |
| 恶意扩展的报告渠道 | 有：security@earendil.com / GitHub Security Advisories；但 SECURITY.md 明确把 "Risks from installing untrusted extensions, skills, packages, or tools" 列为 **Out Of Scope** | [SECURITY.md](https://github.com/earendil-works/pi/blob/main/SECURITY.md) |

### 2.5 扩展 API 能力（与门禁相关的部分）

[extensions 文档](https://pi.dev/docs/latest/extensions) 确认：

- **可以**：`pi.registerCommand(name, options)` 注册 slash command；`pi.registerTool()` 注册 LLM 工具；`pi.registerFlag()`；`pi.exec()` 执行外部命令；监听 `project_trust`、`resources_discover`、`session_start`、`tool_call`（可 block）等事件；`ctx.ui.*` 做交互（select/confirm/input/custom TUI）；读写文件、发 HTTP 请求（扩展本身就是全权限 TypeScript 模块，经 jiti 加载）。
- **不可以**：拦截/包装 `pi update`、`pi install` CLI 命令（无此类事件，且 CLI 路径不加载扩展）；注册新的 CLI 子命令；消费或抑制 "Package Updates Available" 通知。

> 结论：**"更新门禁"只能以"并行命令"的形式实现**（slash command 自行完成"检查更新 → 扫描 → 确认 → 逐包更新"），或以**外部 wrapper** 实现（如 `@bruschill/pi-plugin-security-audit` 的 `pi-guarded.sh` 启动包装、或 shell 函数包装 `pi update`）。`@panzenbaby/pi-secure-extension` 与 `zmarketplace` 均采用 slash command 路线。

---

## 3. pi.dev/packages 生态扫描结果

方法：通过 npm search API（`keywords:pi-package`）拉取全部 5247 个包的名称/描述/keywords，对以下关键词做正则检索：`security / audit / scan / virus / malware / safe / supply chain / update + gate/guard / trust / vet / permission / sandbox / guard`。与"扩展包自身的安全扫描/更新门禁"直接相关的结果如下（按相关度排序）：

### 3.1 直接相关（更新/安装前审计）

| 包 | 功能 | 与用户设想的关系 | 链接 |
|---|---|---|---|
| **@panzenbaby/pi-secure-extension** (v0.1.3, 2026-04-25) | `/secure:install`、`/secure:update <source>`、**`/secure:update-all`**（检查过期 → 逐个审计可用更新 → 提示更新）；审计 = 把扩展源码（npm tarball 解包或 git clone，`--ignore-scripts`）+ 可配置审计规则发给**当前选中的 AI 模型**分析；展示风险评级 + SHA-256/commit 哈希；确认后才安装 | **最接近的现成方案**。差异：审计引擎是 LLM 而非 VirusTotal 等扫描服务；无多引擎/可配置外部扫描。README 诚实列出局限（LLM 可被绕过、audit 与 install 是两次独立下载存在 TOCTOU、postinstall 在安装时仍执行） | [npm](https://www.npmjs.com/package/@panzenbaby/pi-secure-extension) |
| **zmarketplace** (v0.7.8, 2026-07-17) | 跨 agent（pi/omp/Claude/Codex/Gemini 等）marketplace：`/zmarketplace updates` 检查已安装包更新；`audit` 三层：metadata + 解压 `.tgz` 关键词扫描（`eval()`/`execSync()`/`rm -rf`/`child_process`/`process.env`/HTTP）+ **可选 Socket.dev 供应链评分（设 `SOCKET_API_KEY`）**；高危包需确认 | 已包含"更新检查 + 扫描 + 确认安装"闭环，且是**目前唯一集成 Socket.dev 的 pi 生态工具**。未做 VirusTotal 类文件级多引擎扫描 | [npm](https://www.npmjs.com/package/zmarketplace) · [GitHub](https://github.com/zico20047/zmarketplace) |
| **pi-vuln-scanner** (v0.2.1, 2026-07-31) | `/pi-scan`：扫描**本地已安装**的 pi 包（`~/.pi/agent/npm|git`、`.pi/...`）；数据源：`npm audit --json --omit=dev`、**OSV.dev**（含传递依赖）、**deps.dev**、可选 Sonatype OSS Index、npm registry 元数据（deprecated/发布时间）、lifecycle script / native-code 检测；可启动时扫描 + 缓存 | 定位是**事后持续审计**而非更新前门禁（README："advisory only: it warns and reports, but does not block"）；但其多数据源架构对用户设想极具参考价值 | [npm](https://www.npmjs.com/package/pi-vuln-scanner) |
| **@bruschill/pi-plugin-security-audit** (v1.0.1, 2026-07-19, **macOS only**) | 对已安装扩展做**静态分析**（10 类检查：install hooks、网络外联、reverse shell、eval/混淆、凭据读取、env 外泄、raw-IP、prompt-injection 标记、native payload）+ **指纹基线**：批准后对已装代码做 fingerprint，任何变更（包括被更新悄悄改掉的代码）都会触发警告；提供启动 wrapper（变更未批准则拒绝启动 pi）、in-session guard、launchd watchdog | 解决的是"**更新/篡改后**的变化检测"，与"更新前扫描"互补；组合"pi-secure-extension（更新前审计）+ 此包（更新后基线）"可形成完整链条 | [npm](https://www.npmjs.com/package/@bruschill/pi-plugin-security-audit) |
| **pi-marketplace** (v0.1.3, 2026-07-16) | `marketplace_search/detail/audit/install` 工具：搜索 pi 包（查询 `keywords:pi-package`）、审计（Layer 1 metadata：依赖数/文件数/大小/insecure flag；Layer 2 下载 tarball 扫描 `.ts/.js/.mjs/.cjs` 危险模式）、**audit → 用户确认 → `pi install`**（"never auto-installs"） | 面向"安装"场景的轻量门禁（关键词扫描，README 自承无法检测混淆代码） | [npm](https://www.npmjs.com/package/pi-marketplace) · [GitHub](https://github.com/ssdiwu/pi-marketplace) |

### 3.2 相关但属运行时防护（非更新门禁）

这些包在关键词检索中命中，但防护发生在**工具调用运行时**，不在安装/更新阶段：

- `pi-sandbox-proxy` (v0.1.5)："intercepts network operations with approval flows, vulnerability scanning, and supply chain security enforcement"（[npm](https://www.npmjs.com/package/pi-sandbox-proxy) · [GitHub](https://github.com/thegreataxios/pi-extensions)，npm 元数据无 README，细节未能确认）
- `@gotgenes/pi-permission-system`、`pi-permission-suite`、`pi-permission-gate`、`pi-guard`、`@amaster.ai/pi-security` 等：权限/审批类扩展
- `@erichll/pi-sandbox`、`pi-sandbox`、`pi-container-sandbox`、`@daytona/pi`、`pi-gondolin-mount`：OS 级/容器沙箱
- `cc-safety-net`、`pi-sensitive-guard`、`pi-secrets-guard`、`pi-hermes-memory`（secret scanning）：秘密/敏感文件防护
- `@vigolium/piolium`、`pi-codex-security`、`@xaccefy/*`：对**用户代码**做安全审计，与扩展供应链无关

### 3.3 小结

**没有任何 pi 生态包实现"下载新版本 tarball → 提交多个公开安全扫描服务（可配置，如 VirusTotal）→ 汇总标注 → 选择性升级"的完整方案。** 最接近的组合是 `@panzenbaby/pi-secure-extension`（LLM 审计门禁 + 选择性更新）与 `zmarketplace`（Socket.dev 评分 + 更新检查 + 确认安装）；`pi-vuln-scanner` 提供了 OSV/deps.dev/npm audit 的数据源组合范例。

---

## 4. 类似生态的先例（其他 agent CLI）

| CLI | 更新/安装前的安全机制 | 来源 |
|---|---|---|
| **Gemini CLI** | 扩展安装时显示**一次性知情同意对话**：列出该扩展将运行的 MCP servers、对 GEMINI.md context 的修改，提示 "Extensions may introduce unexpected behavior. Ensure you have investigated the extension source and trust the author... Do you want to continue? [Y/n]"。**无自动扫描/签名/审核**。扩展更新是显式命令 `gemini extensions update [--all]`（从 GitHub 拉取）。另有 folder trust（运行时目录信任）机制 | [官方 extensions 文档](https://google-gemini.github.io/gemini-cli/docs/extensions) · [Google Codelabs 安装实录（含提示原文）](https://codelabs.developers.google.com/gemini-cli-code-analysis) · [Trusted Folders 文档](https://geminicli.com/docs/cli/trusted-folders) |
| **Claude Code** | plugin marketplace 为 **implicit trust model**："no centralized vetting, no code signing, no runtime sandboxing"。有研究者实测指出 "Claude has no malware scanning of plugins or skills... no signature verification or code signing, no review system, and no static analysis"。且 Claude Code **会在会话启动后延迟至多 10 分钟自动后台更新**已安装插件（marketplace auto-update 开启时）——比 pi 的"仅提示、绝不自动更新"更激进。已发生真实事件：官方 marketplace 分发的 Hookify 插件被发现存在 prompt-injection 漏洞（Pluto Security 披露）；第三方 marketplace 仓库被用于 SEO 投毒分发恶意插件（PromptArmor 研究） | [Red Hat Developer: Securing Claude Code plug-ins](https://developers.redhat.com/articles/2026/08/18/securing-claude-code-plug-ins-best-practices-repository-security) · [Claude Code 官方插件文档（auto-update 行为）](https://code.claude.com/docs/en/discover-plugins) · [Pluto Security: Claude extension ecosystem](https://pluto.security/blog/claude-extension-ecosystem-security-practitioner-guide) · [PromptArmor: Hijacking via Injected Marketplace Plugins](https://promptarmor.substack.com/p/hijacking-claude-code-via-injected) |
| **Codex CLI / amp** | 未能确认存在扩展更新安全门禁机制的一手资料（本次调研未找到官方文档描述，标注为未确认） | — |

**要点**：没有一个主流 agent CLI 内建"更新前自动安全扫描"。"安装/更新时知情同意 + 用户自行审查"是行业默认；pi（只提示不自动更新）在此默认之上反而偏保守。社区工具（如 `zmarketplace` 同时覆盖 pi/Claude/Codex/Gemini）是这类门禁的主要实现载体。

---

## 5. 安全扫描方案对比

扫描对象确认：pi 的 npm 源包更新即标准 npm tarball（`.tgz`，内含 JS/TS 源码与依赖树），可从 `registry.npmjs.org/<pkg>/-/<pkg>-<version>.tgz` 或 `npm pack <pkg>@<ver>` 直接获取（`pi-marketplace` 与 `zmarketplace` 的 audit 均如此实现）。

| 服务 | API 要点（官方一手来源） | 对 npm 供应链攻击的覆盖 | 适配评估 |
|---|---|---|---|
| **VirusTotal** | 公共（免费）API v3：**4 requests/minute、500 requests/day**；明确禁止注册多账户绕过限制；公共 API "must not be used in commercial products or services"、"must not be used in business workflows that do not contribute new files"。文件上传：`POST /files` 上限 **32MB**，`/files/upload_url` 上限 **650MB**（[Public vs Premium](https://docs.virustotal.com/reference/public-vs-premium-api)、[files-scan](https://docs.virustotal.com/reference/files-scan)） | ~70 个 AV 引擎以**二进制恶意样本**为主；对纯 JS 供应链攻击（typosquatting、混淆 install script、偷渡式 exfiltrate）检出有限（此为定性判断；VT 官方不提供按语言/生态的检出率数字） | 可作为**可配置引擎之一**（尤其当 tarball 内含 native `.node`/wasm payload 时），但免费配额（500/天）与政策限制（须为"贡献新文件"的工作流）使其不宜作为唯一引擎；上传公开 npm 包 tarball 前还应注意隐私合规（tarball 是公开物，此处风险低） |
| **Socket.dev** | 免费层：**$0/月、500 API quota/小时、1000 scans/月**、检测 70+ 风险类型（[pricing](https://socket.dev/pricing)）；有 REST API、CLI（`socket package score npm <pkg>@<ver>`）与 MCP server（[docs](https://docs.socket.dev/)） | **专为此场景设计**：alert 类型包括 `installScripts`（High）、`obfuscatedFile`（High）、`typosquatting`、`networkAccess`（Medium）、`filesystemAccess`（Low）、`gptMalware`、`manifestConfusion`、`hiddenSourceCode` 等（[Alert Types](https://docs.socket.dev/docs/alert-types)） | **首选引擎**。npm 生态专有信号，免费配额充裕（500/小时），`zmarketplace` 已验证集成路径（`SOCKET_API_KEY`） |
| **osv.dev** | Google 官方漏洞库 API：`POST /v1/query`（单包版本）、`POST /v1/querybatch`（批量）；**无需认证**；官方声明 "Currently there are no limits on the API"（[API 文档](https://google.github.io/osv.dev/api/)） | **已知 CVE/漏洞**（含 GHSA），**不含**恶意软件/供应链行为信号 | 免费、无限流的漏洞层，必选基线（`pi-vuln-scanner` 已用） |
| **npm audit / npm registry advisory** | npm CLI 内建，基于 npm advisory DB（与 OSV/GHSA 同源）；`npm audit --json --omit=dev` 可在 pi 的安装根（`~/.pi/agent/npm/`）直接运行 | 同 OSV（已知漏洞） | 本地、零成本；`pi-vuln-scanner` 已用 |
| **npm provenance / attestations** | `npm publish --provenance` 由 Sigstore 签名并写入 Rekor 透明日志；消费端可验证（npm CLI 内建 `verifySignatures`，`npm audit signatures` 检查已安装包签名状态）（[npm docs: Generating provenance statements](https://docs.npmjs.com/generating-provenance-statements)、[github.com/npm/provenance](https://github.com/npm/provenance)） | 不检测恶意性，但能回答"**这个版本是否由其声明的 CI 仓库发布**"——可识破账号盗用/直接 npm publish 的投毒 | 强烈建议纳入标注信号：无 provenance 或 provenance 与 repo 不符 → 降权 |
| **Phylum** | 免费 Community 版已于 **2025-02-24 停止**（被 Veracode 收购后仅面向 Teams/Enterprise，不再支持个人授权）（[官方文档首页公告](https://docs.phylum.io)） | 供应链风险评分（malicious code/risk 等） | **不适合个人用户的设想方案**（需付费企业订阅） |
| **MetaDefender Cloud (OPSWAT)** | 提供 REST API（hash/文件多引擎扫描），需注册 API key，免费层有每日限额（具体数值本次未从官方文档确认，**标注：未能确认**）（[metadefender.com](https://metadefender.com)） | 与 VirusTotal 类似，AV 为主 | 可作为可配置的第二文件扫描引擎 |
| **ClamAV（本地）** | 开源本地 AV，可扫解包后的 tarball（含 `.node`/`.wasm`）；对纯 JS 恶意代码的签名覆盖有限（此为定性判断，官方无生态级检出统计）（[clamav.net](https://www.clamav.net/)） | 二进制 payload 可用；JS 供应链攻击覆盖弱 | 免离线兜底选项；与 Socket/OSV 互补 |

---

## 6. 对用户设想的可行性评估与建议方案

### 6.1 逐条评估

1. **"通过扩展增加 `pi update --extensions --safe` 或 `pi safeupdate --extensions` 入口"——按字面不可行，但可等效实现。**
   - 不可行原因（一手源码确认）：CLI 子命令由 `main.ts` → `handlePackageCommand()` 硬编码分发，处理完即退出，用户扩展不加载；扩展 API 只能注册**会话内** slash command / tool / flag，没有任何 package 生命周期事件。
   - 等效实现 A（已验证可行）：扩展注册 `/safeupdate`（或 `/secure:update-all` 风格）命令，自行完成"读 settings 中的 packages → 查 registry 最新版 → 扫描 → 选择性 `pi update npm:<pkg>`"。`@panzenbaby/pi-secure-extension`（`/secure:update-all`）与 `zmarketplace`（`/zmarketplace updates`）已证明此路径完全可行。注：`pi update npm:<pkg>` 支持单包更新，满足"只升级通过分类的包"。
   - 等效实现 B：shell wrapper 包装 `pi update --extensions`（先审计后放行），类似 `@bruschill/pi-plugin-security-audit` 的 `pi-guarded.sh` 思路。
2. **"下载新版本扩展包"——可行。** 对象即 npm tarball（`registry.npmjs.org/<pkg>/-/<pkg>-<version>.tgz`）；下载解包时应对包自身使用 `npm pack`/直接 HTTP 下载（不执行任何脚本），`@panzenbaby/pi-secure-extension` 明确在审计阶段以 `--ignore-scripts` 抑制生命周期脚本。
3. **"提交到公开安全扫描服务（VirusTotal 或多个可配置）"——可行但有优先级。** 建议：Socket.dev（免费 500 req/h，npm 专有信号）为主、osv.dev（免费无限流，已知漏洞）+ npm provenance 验证为基线、VirusTotal/MetaDefender 为可选的文件级引擎（免费配额 500/天 + AV 对 JS 覆盖弱，只作补充；且公共 API 政策要求工作流"contribute new files"——上传公开 npm tarball 基本符合但应留意）。Phylum 已无免费个人版，不建议。
4. **"获取扫描结果并标注可信、选择性升级"——可行。** pi settings 支持对象形式条目与 `npm:<pkg>@<version>` 精确 pin（pin 后 `pi update --extensions` 自动跳过），非常适合"批准后锁定到已审计版本"的语义。

### 6.2 必须正视的三个结构性风险（来自现有实现的自述与源码）

1. **TOCTOU（扫描与安装分离）**：审计的是下载快照，`pi install` 会再次独立从 registry 下载；若版本在两步之间被替换，安装物 ≠ 扫描物。缓解：批准时以**精确版本 pin** 安装并比对 SHA-256（`@panzenbaby/pi-secure-extension` 已展示 integrity hash 比对；npm tarball 的 `dist.integrity` sha512 可直接从 registry metadata 获取）。
2. **install scripts 在真正安装时执行**：pi 的 `npm install` 不带 `--ignore-scripts`，恶意 `postinstall` 在用户确认安装那一刻即运行——门禁的"批准"动作本身就是触发点。缓解（需要上游配合或 wrapper）：给 pi 提 feature request 支持 `--ignore-scripts` 安装选项（`npmCommand` settings 目前只能包装 npm 命令，理论上可用自定义 wrapper 注入 `--ignore-scripts`——此为可行思路，未经实测验证，标注）；或安装前用 `npm pack` + 白名单文件检查 + 手工放置到 `~/.pi/agent/npm/`。
3. **扫描器盲区**：关键词扫描查不出混淆（`pi-marketplace` 自承）、LLM 审计可被 prompt injection 绕过（`@panzenbaby` 自承）、AV 引擎对 JS 弱、OSV 只覆盖已知漏洞。多引擎分层只能降险，不能保证；`@bruschill` 的"安装后指纹基线"是很好的纵深补充（任何静默变更立刻可见）。

### 6.3 建议方案（如果自建）

- **形态**：pi 扩展，注册 `/safeupdate` 命令（不试图拦截 CLI），复用 pi 的 `ctx.ui.select/confirm` 做交互；无需 fork pi。
- **分层标注**（每层独立可配置开关，结果聚合成 PASS / WARN / FAIL）：
  - L0 metadata（零成本）：registry 元数据——发布者、发布时间、依赖数、`deprecated`、tarball 大小、provenance 有无；
  - L1 声誉/漏洞：Socket.dev score + alerts（`installScripts`/`typosquatting`/`obfuscatedFile`/`networkAccess` 等）、osv.dev querybatch、npm provenance/attestation 校验；
  - L2 静态：下载 tarball（不执行脚本）做危险 API 扫描（`child_process`、`eval`、网络外联域名清单、`fs` 敏感路径）+ diff 上一版本（多数良性更新 diff 小，突变降权）；
  - L3（可选）：本地 LLM 审计（`@panzenbaby` 的规则文件思路）。
  - 文件级多引擎（VirusTotal/MetaDefender/ClamAV）仅对含 native payload（`.node`/`.wasm`/bin）的包触发，节省配额。
- **升级动作**：对通过项执行 `pi update npm:<pkg>` 或写入精确 pin `npm:<pkg>@<version>` 后更新；对否决项自动 pin 到当前已安装版本（利用 pi 的"pinned spec 跳过 update"内建行为，从此不再出现在更新提示里）。
- **或者，务实路线**：先装 `@panzenbaby/pi-secure-extension` + `pi-vuln-scanner` + `@bruschill/pi-plugin-security-audit`（macOS）验证工作流，再决定是否自建带多引擎的 `/safeupdate`；自建时可直接参考 `zmarketplace` 的 Socket 集成与 `pi-vuln-scanner` 的 OSV/deps.dev 管道。

---

## 7. 参考来源列表

### pi 官方（文档/源码/安全政策）

1. pi 文档首页（含 `--ignore-scripts` 安装建议）：https://pi.dev/docs/latest
2. Pi Packages（安装/更新/源类型/pinning/Gallery Metadata）：https://pi.dev/docs/latest/packages
3. Extensions（API 能力、事件列表、安全警告）：https://pi.dev/docs/latest/extensions
4. Security（project trust、无沙箱声明）：https://pi.dev/docs/latest/security
5. SECURITY.md（信任边界、out of scope 含不可信扩展风险）：https://github.com/earendil-works/pi/blob/main/SECURITY.md
6. 包管理核心源码（npm install 参数、更新检查跳过 pinned）：https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/package-manager.ts
7. CLI 包命令入口源码（update 子命令、extensionFactories 仅用于 trust）：https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/package-manager-cli.ts
8. 交互模式源码（"Package Updates Available" 通知）：https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/modes/interactive/interactive-mode.ts
9. 主入口源码（package 命令在扩展加载前处理）：https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/main.ts
10. pi 包目录（数据源为 npm `pi-package` keyword）：https://pi.dev/packages ；npm 搜索 API：https://registry.npmjs.org/-/v1/search?text=keywords:pi-package&size=250
11. pi 仓库（badlogic/pi-mono 现址）：https://github.com/earendil-works/pi

### pi 生态候选扩展（npm registry 一手元数据 + README）

12. @panzenbaby/pi-secure-extension：https://www.npmjs.com/package/@panzenbaby/pi-secure-extension
13. zmarketplace：https://www.npmjs.com/package/zmarketplace · https://github.com/zico20047/zmarketplace
14. pi-vuln-scanner：https://www.npmjs.com/package/pi-vuln-scanner
15. @bruschill/pi-plugin-security-audit：https://www.npmjs.com/package/@bruschill/pi-plugin-security-audit
16. pi-marketplace：https://www.npmjs.com/package/pi-marketplace · https://github.com/ssdiwu/pi-marketplace
17. pi-sandbox-proxy：https://www.npmjs.com/package/pi-sandbox-proxy · https://github.com/thegreataxios/pi-extensions

### 其他 agent CLI 先例

18. Gemini CLI Extensions 官方文档：https://google-gemini.github.io/gemini-cli/docs/extensions
19. Gemini CLI 安装扩展的信任对话实录（Google Codelabs）：https://codelabs.developers.google.com/gemini-cli-code-analysis
20. Claude Code 插件发现/安装/自动更新官方文档：https://code.claude.com/docs/en/discover-plugins
21. Red Hat Developer：Securing Claude Code plug-ins（implicit trust model、Hookify 漏洞）：https://developers.redhat.com/articles/2026/08/18/securing-claude-code-plug-ins-best-practices-repository-security
22. Pluto Security：Claude extension ecosystem 安全分析：https://pluto.security/blog/claude-extension-ecosystem-security-practitioner-guide
23. PromptArmor：marketplace prompt injection 研究：https://promptarmor.substack.com/p/hijacking-claude-code-via-injected

### 扫描服务/API 政策（官方一手）

24. VirusTotal Public vs Premium API（4 req/min、500 req/day、使用限制）：https://docs.virustotal.com/reference/public-vs-premium-api
25. VirusTotal files-scan（32MB 上限、upload_url 650MB）：https://docs.virustotal.com/reference/files-scan
26. Socket pricing（免费层 500 API quota/h、1000 scans/月）：https://socket.dev/pricing
27. Socket Alert Types（installScripts/obfuscatedFile/typosquatting/networkAccess 等）：https://docs.socket.dev/docs/alert-types
28. Socket CLI（`socket package score`）：https://docs.socket.dev/docs/socket-cli
29. osv.dev API（query/querybatch、无限流声明）：https://google.github.io/osv.dev/api/
30. npm provenance（生成与验证、Rekor）：https://docs.npmjs.com/generating-provenance-statements · https://github.com/npm/provenance
31. Phylum 文档（免费 Community 版 2025-02-24 终止公告）：https://docs.phylum.io
32. ClamAV：https://www.clamav.net/

---

## 附：未能确认事项（明确标注）

- `pi.dev/packages` 页面计数 5555 与 npm search API 可枚举的 5247 unique 包存在差异，原因未确认（推测与 npm 搜索索引/评分分页有关）。
- Codex CLI、amp 的扩展更新安全机制：未找到官方一手描述。
- MetaDefender Cloud 免费层具体每日配额数字：未从官方文档页面确认。
- VirusTotal 对纯 JS npm 包的检出率：无官方分生态统计，本报告仅作定性判断。
- 通过 settings `npmCommand` 包装器为 pi 的包安装注入 `--ignore-scripts` 的思路：架构上可行（pi 支持自定义 npm 包装命令），但未经实测验证。
