# pi-vetter 设计（Phase 1 MVP）

> 术语见根目录 `CONTEXT.md`；关键决策见 `docs/adr/`；事实底座见 `research/` 四份报告。
> 语法约定：TypeScript；pi 扩展由 jiti 直载，无构建步骤，Node ≥ 22.19.0。

## 1. 总览

```
/vet [specs...]                      /vet-install [specs...]
  │                                     │
  │  省略参数 = 已装包的可用更新集；spec = npm:<pkg>[@<ver>] 空格分隔多个
  ▼                                     ▼
┌─────────────────────────── Evaluation Engine ───────────────────────────┐
│                                                                          │
│  resolve targets ──► fetch tarballs ──► run enabled Scanners ──►        │
│  (candidate + baseline)   (candidate+baseline,           (并发, 带缓存)   │
│                            纯下载解包,                                │
│                            绝不执行脚本)                              │
│                                                    │                     │
│                     aggregate: Rules + fail-closed Cap + Risk Score     │
└──────────────────────────────────────────────────┬───────────────────────┘
                                                   ▼
                                          Evaluation Report(s)
                                                   │
                              /vet ──► 渲染报告, 结束（只读）
                                                   │
                              /vet-install ──► TUI 多选（非 TUI 退化）
                                                   │
                                   Approval ──► Integrity Check
                                                   │
                            pi.exec('pi install npm:<pkg>@<ver>')
```

## 2. 核心数据模型（`src/core/types.ts`）

```ts
export type Verdict = "ALLOW" | "ASK" | "DENY";
export type Layer = 0 | 1 | 2 | 3;
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** 评估对象（已解析到具体版本） */
export interface Candidate {
  name: string;          // npm 包名（可含 scope）
  version: string;       // 候选版本
  scenario: "update" | "install";  // install 场景 baseline 为 null
}

export interface Baseline {
  name: string;
  version: string;
}

/** Scanner 产物：原子事实 */
export interface Evidence {
  scanner: ScannerName;  // "metadata" | "osv" | "provenance" | "static" | "diff" | "virustotal" | "socket"
  key: string;           // 证据标识，如 "osv:mal-advisory"、"diff:new-script:postinstall"
  status: "pass" | "fail" | "info" | "skipped" | "incomplete";  // incomplete ⇒ 触发 Cap
  detail: string;        // 人类可读描述（英文）
  data?: unknown;        // 机器可读负载（advisory id、url 列表等）
}

export interface ScanResult {
  scanner: ScannerName;
  status: "ok" | "error" | "timeout" | "quota-exhausted";
  evidences: Evidence[]; // status=ok 以外的失败形态 ⇒ 整体产生一条 incomplete evidence
}

/** 规则命中 */
export interface Finding {
  ruleId: RuleId;        // 见 §5 规则集
  severity: Severity;
  message: string;
  evidenceKeys: string[];// 指向支撑证据（可解释性的锚点）
}

export interface ScannerContext {
  candidate: Candidate;
  baseline: Baseline | null;
  artifacts: Artifacts;  // 见下
}

export interface Artifacts {
  candidateDir: string;      // 解包后的目录（临时）
  baselineDir: string | null;
  candidatePackument: Packument;         // registry 完整 packument（含 time/maintainers/deprecated/versions）
  baselinePackument: Packument | null;
  candidateIntegrity: string;            // dist.integrity (sha512-...)，Integrity Check 基准
  downloads: number;        // 近 30 天下载量（api.npmjs.org，bulk）
}

/** 扫描器接口：Phase 1 的 5 个与 Phase 2 的 2 个实现同一接口 */
export interface SecurityScanner {
  readonly name: ScannerName;
  readonly layer: Layer;
  scan(ctx: ScannerContext): Promise<ScanResult>;
}

/** 单包评估结果 */
export interface EvaluationReport {
  candidate: Candidate;
  baseline: Baseline | null;
  verdict: Verdict;
  capped: boolean;           // 是否因 incomplete 被封顶
  findings: Finding[];
  evidences: Evidence[];     // 全部证据（扁平）
  riskScore: number;         // 0-100，仅展示（ADR-0001）
  hasLifecycleScripts: boolean;  // Lifecycle Script Warning 触发条件
}
```

### Verdict 聚合（`src/core/rules.ts`）

```ts
function aggregate(findings: Finding[], hasIncompleteEvidence: boolean): Verdict {
  if (findings.some(f => denyRules.has(f.ruleId))) return "DENY";
  if (findings.some(f => askRules.has(f.ruleId)))  return "ASK";
  if (hasIncompleteEvidence) return "ASK";   // fail-closed Cap（ADR-0002）
  return "ALLOW";
}
```

扫描失败形态（error/timeout/quota-exhausted）统一折算为一条 `{status: "incomplete"}` Evidence；对 DENY 级证据不受影响（如 OSV 已命中 MAL- 但随后超时，仍 DENY——Cap 只降 ALLOW，不升不降 DENY）。

## 3. 模块结构

```
src/
├── index.ts              # 扩展入口：注册 /vet、/vet-install
├── commands/
│   ├── vet.ts            # 参数解析 + 编排 + 渲染（只读）
│   └── vet-install.ts    # 同上 + 选择 + 批准执行
├── core/
│   ├── types.ts          # §2 类型
│   ├── engine.ts         # Evaluation Engine：targets → artifacts → scanners(并发) → reports
│   ├── rules.ts          # 规则表（ruleId → kind/severity/description）+ aggregate
│   └── score.ts          # Risk Score 加权求和（权重可配，不影响 Verdict）
├── scanners/
│   ├── metadata.ts       # L0：maintainers 变更、包龄、deprecated、版本节奏、下载量
│   ├── osv.ts            # L1：querybatch 覆盖 CVE + MAL-（OpenSSF 恶意包）+ GHSA；新增依赖也入查询
│   ├── provenance.ts     # L1：dist.attestations → @sigstore/verify 验证 + repo 匹配
│   ├── static-analysis.ts# L2：规则模式扫描（见 §5 输入），区分"既有/新增"（与 diff 结果融合）
│   └── diff.ts           # L2：新旧 tarball 对比（文件/清单/依赖/行为模式集合）
├── npm/
│   ├── registry.ts       # packument（完整版）、downloads bulk、dist.integrity
│   └── tarball.ts        # HTTP 直下 .tgz + 解包到临时目录（不经过 npm，天然不执行脚本）
├── install/
│   └── gated-installer.ts# Integrity Check + pi.exec("pi", ["install", spec])（ADR-0003）
├── ui/
│   ├── report.ts         # 逐包段落渲染（纯文本，任何模式可用）
│   └── select.ts         # ctx.ui.custom 多选（TUI）/ 分组 confirm 退化（非 TUI）
├── settings.ts           # 通过官方导出的 SettingsManager 读已装包清单与 autoload
├── config.ts             # ~/.pi/agent/pi-vetter/config.json 读写、默认值、迁移
└── cache.ts              # ~/.pi/agent/pi-vetter/cache/，key = scanner:pkg@version
```

依赖策略：运行时依赖仅 `@sigstore/verify`（provenance 验证）+ `@earendil-works/pi-coding-agent`（类型与 SettingsManager，peerDependencies `"*"`）。其余用 node 内置（fetch/fs/zlib——tar 解包若无轻量方案再评估加 tar 依赖）。

## 4. 命令流程

### `/vet [npm:<pkg>[@<ver>] ...]`

1. 解析 args（整段字符串按空白切分）：空 → 从 settings + `~/.pi/agent/npm/node_modules/<name>/package.json` 构建已装清单，取 registry 最新版为 Candidate（pinned 条目标注并跳过）；非空 → 解析 spec 列表（缺版本取 latest）。混用 `installed` 关键字 → 用法错误。
2. 逐包构建 Artifacts（candidate 必需；update 场景含 baseline tarball）。
3. 并发运行已启用 Scanner（缓存命中则复用；`cache.enabled=false` 直查）。
4. 聚合 → EvaluationReport[] → 渲染：每包一段（`pkg 1.2.3 → 1.2.4`、Verdict、riskScore、✓/✗ 证据、未完成项；含 lifecycle scripts 的包附固定警告行）。

### `/vet-install [specs...]`

1–4 同上。
5. 选择：TUI 模式 `ctx.ui.custom()` 多选列表（ALLOW 默认勾选、ASK 默认不勾、DENY 灰显不可选）；非 TUI 退化：ALLOW 组一条 confirm（全装/不装），ASK/DENY 逐包 confirm。
6. 逐包批准执行：Integrity Check（registry `dist.integrity` vs 评估时记录）→ 不匹配则跳过该包并提示重新评估 → 匹配则 `pi.exec("pi", ["install", "npm:<name>@<version>"])`；失败（非零退出码）中断并报告。
7. 汇总：成功（已 pin，`pi update --extensions` 今后跳过）、跳过、失败三类清单。

## 5. 规则集（初始清单，全部可配置开关）

设计原则：**行为突变优先于绝对存在**——L2 静态命中若 Baseline 中同样存在视为既有行为（info），仅 Candidate 新出现的才升级为 Finding。

**DENY 规则**
| RuleId | 触发 | 证据来源 |
|---|---|---|
| `malicious-package` | OSV 命中 MAL- 通告（本包或新增依赖） | osv |
| `provenance-conflict` | attestation 验签失败 / provenance 声称的源与 packument repository 不符 | provenance |
| `vt-detections`（P2） | VirusTotal 多引擎检出 ≥2 | virustotal |

**ASK 规则**
| RuleId | 触发 | 证据来源 |
|---|---|---|
| `new-lifecycle-script` | diff：新增 install/pre/postinstall script | diff |
| `maintainer-change` | diff：maintainers 集合变化（新增） | metadata |
| `new-dependency-flagged` | diff：新增依赖且该依赖命中 OSV 通告（MAL- 升 DENY） | osv×diff |
| `new-network-endpoint` | diff：新出现的外联 URL/host（fetch/http/axios 等） | diff×static |
| `new-child-process` | diff：child_process 由无到有 | diff×static |
| `credential-access` | 静态：读 `~/.ssh`、`~/.aws`、`.npmrc`、`process.env.{*_KEY,*_TOKEN}` 等 | static |
| `obfuscation` | 静态：超长 base64/hex 串、动态 require 链、eval 族 | static |
| `prompt-injection-marker` | 静态："ignore previous instructions" 等标记 | static |
| `young-package` | 包龄 < 7 天 | metadata |
| `rapid-release` | 24h 内 ≥3 个版本 | metadata |
| `deprecated-candidate` | 候选版本被标记 deprecated | metadata |

既有命中（Baseline 也有）→ info Finding，不影响 Verdict。

**Risk Score 初始权重**（仅展示）：DENY 级 90+，各 ASK 规则 20–50，负向修正（provenance 验证通过 -10、包龄 >1 年 -10），封顶 0–100。

## 6. 配置文件（`~/.pi/agent/pi-vetter/config.json`）

```jsonc
{
  "scanners": {
    "metadata":    { "enabled": true },
    "osv":         { "enabled": true, "timeoutMs": 10000 },
    "provenance":  { "enabled": true },
    "static":      { "enabled": true },
    "diff":        { "enabled": true },
    "virustotal":  { "enabled": false, "apiKey": "", "timeoutMs": 60000 },  // P2
    "socket":      { "enabled": false, "apiKey": "" }                       // P2
  },
  "rules": {                     // 逐条开关，键 = RuleId
    "deny":  { "malicious-package": true, "provenance-conflict": true },
    "ask":   { "new-lifecycle-script": true, "...": true }
  },
  "cache":  { "enabled": true, "ttlHours": 24 },   // virustotal hash 查询结果永久
  "score":  { "weights": { "...": 30 } }
}
```

## 7. 测试策略（vitest）

- `rules.test.ts`：聚合矩阵（DENY/ASK/incomplete 组合、Cap 不降 DENY、规则开关生效）
- `diff.test.ts`：fixture tarball 对（新增 script/依赖/URL 的检测）
- `static-analysis.test.ts`：规则模式命中与"新增 vs 既有"融合
- `osv.test.ts`：querybatch 响应解析 → Evidence（MAL-/GHSA/CVE 分类）
- `cache.test.ts`：TTL、失效、key 构造
- `gated-installer.test.ts`：integrity 不匹配跳过、pi.exec 失败中断（mock）
- 真实链路 smoke（验收用例 1）：对真实已装扩展跑 `/vet` 全流程

## 8. Implementation notes（MVP 落地时与 §2/§5 的偏差）

- **Artifacts 为内存文件映射**（`candidateFiles: Map<path, Uint8Array>`），不做磁盘解包——未受信 tarball 的解压存在路径穿越风险且无必要，static/diff 均在内存完成；tar 解析用 `tar-stream`，下载字节先经 `dist.integrity` sha512 校验。
- **provenance 为方向性验证**（MVP）：不执行完整 sigstore 验签（`@sigstore/verify` 需外部 TrustedRoot，包内不带），仅做"attestation 声称的源 vs packument.repository 矛盾检测"（fail 方向有效）；一致时给 info `provenance:declared` 而非 pass `verified`，伪造的 attestation 骗不到加分。完整验签留 Phase 2。
- **新增规则 `known-vulnerability`**（ask/high）：候选版本自身命中 GHSA/CVE 通告时触发（§5 清单在实现时补齐了该缺口）。
- **maintainer-change 依赖本地快照**（`~/.pi/agent/pi-vetter/maintainers.json`）：npm registry 不提供维护者历史，首次 vet 记录、后续比对；无快照时仅 info。

## 9. Out of scope（明确不做，未来可能重开）

- **拦截 agent 自发起的 `pi update --extensions`**（`tool_call` 事件监听 agent 通过 bash 执行更新命令的企图，提示改走 `/vet`）：防 prompt-injection 驱动的依赖更新。决策：不进 MVP，大概率不做；若未来威胁模型变化可重开。来源：`docs/research-safe-update-gate.md` 建议。
- 本地安装物与 registry 基线的偏差检测（生态已有指纹方案覆盖）。
- 依赖 tarball 的深度扫描与逐依赖 VT 上传（P2 再议）。
- OpenSSF Package Analysis 接入（仅 BigQuery，需 GCP 凭证，违背"免费无 key"原则）。
