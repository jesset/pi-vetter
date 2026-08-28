# ChatGPT 调研报告吸收笔记：值得借鉴的设计思路

> 来源：用户提供的 ChatGPT 分享对话（https://chatgpt.com/share/6a905177-a658-83e8-b51b-32f7369e88e7），重点吸收第 25/26/27 章及以后部分
> 交叉参照：本仓库一手调研报告 `pi-extension-safe-update-research.md`（2026-08-27）
> 笔记日期：2026-08-28

---

## 0. 报告可信度交叉验证（已实测）

| ChatGPT 报告的论断 | 验证结果 |
|---|---|
| `pi-security-scanner`（burggraf）存在并提供 `/security-scan` + `/security-shield` | **真实存在**（npm v0.1.0）。补充 ChatGPT 未提的事实：repo 最后 push **2026-02-27**、仅 5 stars、devDependencies 仍用旧包名 `@mariozechner/pi-coding-agent`——**已停更约半年，基于旧 SDK，只能当规则清单参考，不能当依赖** |
| `pi-dep-audit` 存在，定位是项目依赖审计（OSV/CVE/license） | **真实存在**（npm v1.0.1，作者 ZachDreamZ），确属"项目依赖树"场景而非 pi 扩展更新门禁 |
| pi issue #645 讨论 PackageManager 接口化 | **真实存在**：[earendil-works/pi#645](https://github.com/earendil-works/pi/issues/645) "Extension package management and hot reload"（closed）——说明上游确实讨论过包管理接口化，"Security Gate 上游化"（Phase 3）有讨论空间 |
| pi.dev/packages 5600+ | 与昨天实测 5555 一致 |
| 扩展无法新增顶层 CLI 子命令、只能 slash command / flag | 与昨天源码级调研结论一致（CLI 包命令在扩展加载前处理） |
| 扫描必须发生在 npm install 之前（lifecycle scripts 攻击面） | 与昨天源码调研一致（pi 的 npm install **不带 `--ignore-scripts`**） |

**结论：ChatGPT 报告事实性内容基本可信**，且补上了昨天调研遗漏的两个生态包。它对 `pi-security-scanner` 的判断（"是 Installed Package Scanner，不是 Update Gate"）与我们结论兼容，核心判断不变：**生态中仍无"多源扫描 + 更新门禁 + 选择性升级"完整方案**。

---

## 1. 最值得借鉴的核心思路（25–30 章 + 关键前文）

### 1.1 定位升级（第 24/25/30 章）—— 与用户定位吻合

不要定位成 "pi-safeupdate（一个带 VirusTotal 的更新器）"，而是：

> **Pi Package Supply Chain Security / Trust Framework**（pi 的供应链安全层），第一阶段交付 `pi-safe-update` MVP。

本质转变：把 pi 的更新流程从"盲目更新"变成 **"Evidence-driven Update"**。用户自己的定位"Pi 扩展安全扫描/评估器"与此一致。

### 1.2 三阶段产品路线（第 26/27/28 章）

```
Phase 1（MVP，不改 pi）
  extension 提供 /safe-update：读 settings → 查更新 → 下载 candidate tarball
  → 解包到临时目录（绝不执行 lifecycle scripts）→ 静态扫描 + OSV + provenance
  + version diff + reputation → risk score → 用户选择 → 只更新选中的包
Phase 2（架构化）
  SecurityScanner adapter 接口 + 外部扫描源（OSV / OpenSSF / VT / Socket / Snyk）
Phase 3（上游化）
  推动 pi 把 SecurityPolicy → SecurityGate 内建进 PackageManager.install()/update()
  （如 pi update --extensions --security=strict）；issue #645 表明有讨论空间
```

Phase 1 的 14 步流水线可直接作为 MVP 的实现清单。**"不改 pi" 是 MVP 的关键约束**——与昨天调研结论（扩展无法拦截 CLI，slash command 是已验证可行路径）完全一致。

### 1.3 SecurityScanner adapter 抽象（第 27 章）

```ts
interface SecurityScanner {
  name: string;
  scan(input: PackageArtifact): Promise<ScanResult>;
}
// StaticScanner / ReputationScanner / ProvenanceScanner / DiffScanner
// OSVScanner / VirusTotalScanner / OpenSSFScanner / SocketScanner ...
// 聚合为：
SecurityVerdict { package, version, score, level, findings[], scanners[] }
```

每个扫描器独立可开关、可配置 apiKey（分层：免费默认 static+OSV+OpenSSF；增强 +VT；进阶 +Socket/Snyk）。这直接支持用户需求中"多路评估、可配置"。

### 1.4 Fail Closed + 三态判定（第 29 章）—— 最重要的设计原则

- 用 **ALLOW / ASK / DENY** 而非 SAFE/UNSAFE（安全扫描只能证明"未发现风险"，不能证明"安全"；ASK 态给用户保留决策权）
- **Evidence-driven**：verdict 必须附逐条证据清单（✓/✗），而非只给分数：

```
pi-bar 2.0.0
  ✗ maintainer changed      ✗ new postinstall      ✗ new external endpoint
  ✗ accesses process.env    ✓ OSV clean             ✓ VT 0/68
Verdict: ASK   Risk: HIGH   Confidence: 89
```

- **Fail Closed**：扫描源不可用/超时/结果不完整时默认不放行（对应 ASK 或 DENY，而非静默 ALLOW）

这与用户在 pi-verdict 前作中已验证的 allow/ask/deny + fail-closed + evidence-driven 思路同源，可直接迁移。

### 1.5 Version Diff 是核心能力（第 8 章，报告认为"最重要的安全能力之一"）

不孤立扫描 v1.2.4，而是扫描 **v1.2.3 → v1.2.4 的变化**：新增文件、package.json/scripts 变化、依赖变化、新网络 endpoint、新 credential 访问、新 child_process。多数良性更新 diff 很小；**行为突变是比绝对扫描更强的信号**（第 11 章：OpenSSF Package Analysis 正是按"行为随版本演变"跟踪的）。

### 1.6 两个增量数据源（第 11/12 章）—— 昨天报告未覆盖

| 数据源 | 价值 | 接入方式 |
|---|---|---|
| **OpenSSF Package Analysis**（ossf/package-analysis） | 沙箱实测包的真实行为（访问哪些文件、连接哪些地址、执行什么命令）并**跟踪行为随版本的变化** | 查询其公开结果数据（BigQuery / API），无需自建沙箱 |
| **OpenSSF Malicious Packages**（ossf/malicious-packages） | 社区维护的恶意 npm/PyPI 包库，**以 OSV 格式发布**，可与 OSV 查询管道合并 | OSV API query 即可命中（GHSA/osv MAL- 前缀 ID） |

用户需求图中 "OpenSSF malicious package" 一支即此。这两个免费无配额限制，应进默认扫描栈。

### 1.7 五维信任模型（第 22 章）

| 维度 | 权重 | 数据来源 |
|---|---|---|
| Provenance | 20% | npm provenance/attestation、registry signature、repo 链接、release tag 匹配 |
| Reputation | 15% | 包龄、maintainer 历史、下载量、版本数、maintainer 是否变更 |
| Vulnerability | 20% | OSV / npm audit / GHSA |
| Malware | 25% | OpenSSF Malicious Packages、VirusTotal、（Socket） |
| Behavioral Diff | 20% | 新旧版本 diff（scripts/依赖/网络/凭据访问） |

注意：第 13 章另给了一套加法式扣分模型（已知恶意 +100、新增 postinstall +40……）。两套模型并存且不一致——**建议以证据驱动 verdict 为主、加权分数为辅助聚合**，实现时二选一统一，权重仅作初始默认值（无实证依据，可配置）。

### 1.8 UX 范式（第 18 章）

批量更新场景的 TUI：一张表（Package / Current / New / Risk）+ 选中包的 findings 详情 + `[Update Selected] [View Diff] [Skip] [Block]`。pi 的 `ctx.ui.*`（select/confirm/custom TUI）足以实现，无需 fork。

### 1.9 命名与措辞（第 13/29 章）

对外呈现用 **Risk / Trust Level** 而非 "Safe"（"Safe" 暗示了无法兑现的承诺）。包名可保留 pi-safe-update，但 UI 文案与 verdict 语义应是 risk/trust。另注意：项目仓库名 `pi-safe-update` 与定位"扫描/评估器（不负责更新本身）"存在轻微错位，发布前可再斟酌。

---

## 2. 与用户补充需求的融合（定位 / 场景 / 多路评估）

用户需求与报告思路高度兼容，融合后：

- **定位**：Pi 扩展安全扫描/评估器（supply-chain security layer）；更新执行仍复用 `pi update npm:<pkg>` / 精确 pin
- **场景**：① 安装新扩展（install 前评估）② 更新已安装扩展（candidate 版本评估）。报告第 19 章建议的第三场景 `pi safe run`（运行时门禁）**不纳入** MVP——运行时防护已有 pi-security-scanner 的 `/security-shield` 类方案，且复杂度完全不同
- **多路评估**（用户扇出图 + 聚合图），按成本分层排默认值：

```
package@version
  ├─ L0 Metadata/Reputation   npm registry 元数据、下载量、maintainer、包龄（零成本，必选）
  ├─ L1 Vulnerability          OSV querybatch + npm audit + GitHub Advisory（免费无配额）
  ├─ L1 Malware Intel          OpenSSF Malicious Packages（OSV 格式，随 OSV 管道）+ OpenSSF Package Analysis 行为数据
  ├─ L1 Provenance             npm provenance/attestation 校验（本地验证，免费）
  ├─ L2 Static Analysis        危险 API/混淆/prompt-injection 标记扫描（本地，免费）
  ├─ L2 Version Diff           candidate vs 已安装版本行为 diff（本地，免费）★核心
  └─ L3 External Engines       VirusTotal（可配置，默认关：500 req/天，AV 对 JS 弱）
                               Socket.dev（可配置，默认关或开：免费 500 req/h）
        ↓ 聚合（fail closed）
   Risk Evidence → ALLOW / ASK / DENY（+ 加权分、confidence、findings[]）
```

- **对报告方案的修正**（依据昨天一手调研的三个结构性风险）：
  1. **TOCTOU**：批准安装时以精确版本 pin + 比对 registry `dist.integrity`（sha512）→ 确保安装物 = 扫描物
  2. **install scripts 在批准安装时仍执行**（pi 的 npm install 不带 `--ignore-scripts`）：评估阶段必须用 `npm pack`/HTTP 直下 tarball 解包；执行阶段此风险无法由扩展消除，UI 需明示"批准即执行其 install scripts"；中期可探索 `npmCommand` settings wrapper 注入 `--ignore-scripts`（未实测）或向 pi 上游提 feature request
  3. **扫描器盲区**：LLM/regex 审计可被绕过是已知局限，verdict 的 Confidence 字段与证据透明化即是为此

## 3. 可直接复用的资产清单

| 资产 | 来源 | 用法 |
|---|---|---|
| 危险 API 检查规则（eval/vm/child_process/凭据路径/混淆/prompt-injection 标记） | pi-security-scanner `docs/security-checks.md`（注意其停更，规则自行维护） | L2 静态扫描的初始规则集 |
| 14 步 MVP 流水线 | ChatGPT 报告 §26 | `/safe-update` 实现骨架 |
| SecurityScanner/SecurityVerdict 接口形状 | ChatGPT 报告 §27 | 架构起点 |
| Socket 集成路径（`SOCKET_API_KEY`） | zmarketplace（昨天调研） | L3 引擎参考实现 |
| OSV/deps.dev 数据管道 | pi-vuln-scanner（昨天调研） | L1 漏洞层参考实现 |

## 4. 存疑/待办

- 五维权重与扣分表的数值无实证依据，仅作默认值，必须可配置
- OpenSSF Package Analysis 的公开查询接口形态（BigQuery dataset vs API）需在实现前确认最新文档
- ChatGPT 报告引用的部分链接指向旧仓库 `badlogic/pi-mono`（已迁移 `earendil-works/pi`），阅读时注意重定向
- `pi safe install`（安装前门禁）如何与用户实际安装流程衔接：推荐"评估器先行 + 用户手动 `pi install`"还是扩展内直接触发安装，需在 MVP 时定夺
