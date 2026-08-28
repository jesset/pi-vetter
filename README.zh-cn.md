# pi-vetter

[English](./README.md)

Pi 扩展包的安全评估器——在安装或更新之前做证据驱动的门禁。

Pi 以完整用户权限安装扩展包并执行其 `postinstall` 脚本，而内建更新提示只告诉你"有更新"。pi-vetter 对每个候选版本做多路证据评估，给出 **ALLOW / ASK / DENY** 判定与完整证据清单，由你决定装什么——然后只安装你批准的版本，更新策略始终掌握在你手里。

> pi-vetter 只能证明"未发现风险信号"，永远无法证明一个包是安全的。请阅读证据，而不只看判定。

## 安装

```bash
pi install npm:pi-vetter
```

（需要 Node ≥ 22.19.0；无需任何 API key——默认扫描器全部免费）

## 用法

| 命令 | 作用 |
|---|---|
| `/vet` | 只读评估。不带参数 = 检查全部已装扩展的可用更新；也可指定：`/vet npm:foo npm:bar@1.2.3` |
| `/vet-install` | 同样评估，然后交互多选（TUI 复选框；非 TUI 模式退化为分组确认），只安装你批准的包 |

批准的包通过 `pi install npm:<pkg>@<version>` 安装——装的就是评估过的那个版本，且每次安装前重新比对 registry 完整性（TOCTOU 防护）。默认在安装成功后把 settings 条目还原为非 pin spec（ADR-0003 修订版）："让这个包从此退出更新通道"是你的决定而非评估器的副作用——安装结果会给出精确的 pin 命令供你自行执行（`install.pinOnInstall: true` 恢复旧的总是 pin 行为）。pinned 包在每次 `/vet` 中照常评估并在报告中标注。

### 判定模型

- **ALLOW** —— 已启用的扫描器未发现风险信号
- **ASK** —— 某条规则触发（如新增 lifecycle 脚本、新增外联端点、维护者变更），或证据不完整
- **DENY** —— 明确的恶意/矛盾证据（OpenSSF 恶意包通告、provenance 矛盾、VirusTotal 检出）

fail-closed：任一**已启用**的扫描器失败或超时，判定封顶为 ASK——绝不静默 ALLOW（ADR-0002）。已成立的 DENY 永不被降级。判定由规则驱动；0–100 的风险分仅作展示（ADR-0001）。

### 扫描器（Phase 1）

| 层 | 扫描器 | 来源 |
|---|---|---|
| L0 | `metadata` | npm registry packument：维护者（本地快照比对）、包龄、发布节奏、废弃标记、下载量 |
| L1 | `osv` | osv.dev querybatch —— 覆盖 CVE + GitHub Advisory (GHSA) + OpenSSF 恶意包 (MAL-)；新增依赖也一并查询 |
| L1 | `provenance` | npm attestations：对 vendored 公共 TrustedRoot 做完整 sigstore 签名链验证 + 声明仓库矛盾检测；验证通过产出 `provenance:verified` |
| L2 | `static` | 代码文件模式扫描：凭据访问、混淆特征、prompt-injection 标记、eval 族；既有命中为 info，新命中为 finding；install 场景（无基线）凭据/混淆命中降为 info，prompt-injection 始终为硬信号 |
| L2 | `diff` | 新旧 tarball 对比：新增 lifecycle 脚本、新增依赖、新增 child_process、新增外联端点 |
| L3 | `virustotal` | 先按哈希查询已有样本、未命中再上传（上传新文件不消耗每日配额）；≥2 引擎检出 → DENY。默认关闭，配置 API key 启用 |
| L3 | `socket` | Socket.dev 包告警（gptMalware、installScripts、obfuscatedFile、typosquatting 等）；高风险告警 → ASK（`socket-flagged`）。默认关闭——注意免费层每小时仅约 5 次 purl 查询，启用后常态性配额耗尽（判定将封顶 ASK） |

可选 L3 引擎默认关闭，在配置文件中按 API key 逐个启用。当已启用引擎配额耗尽或失败时，判定封顶为 ASK（fail-closed），证据中说明原因。

### 规则

规则把证据映射到判定，可在配置文件中逐条开关（如 `ask.new-lifecycle-script: false`）。当前 DENY 规则：`malicious-package`、`provenance-conflict`、`vt-detections`。当前 ASK 规则：`known-vulnerability`、`new-lifecycle-script`、`maintainer-change`、`new-dependency-flagged`、`new-network-endpoint`、`new-child-process`、`credential-access`、`obfuscation`、`prompt-injection-marker`、`young-package`、`rapid-release`、`deprecated-candidate`。

## 配置

`~/.pi/agent/pi-vetter/config.json`（首次运行自动生成默认值；样例见 [`config.example.json`](./config.example.json)）：

```jsonc
{
  "scanners": { "osv": { "enabled": true, "timeoutMs": 10000 }, "virustotal": { "enabled": false, "apiKey": "" } },
  "rules": { "deny": {}, "ask": { "young-package": true } },
  "cache": { "enabled": true, "ttlHours": 24 },
  "score": { "weights": {} },
  "network": { "timeoutMs": 30000 },
  "install": { "pinOnInstall": false }
}
```

扫描结果按 `扫描器 + 包@版本` 缓存在 `~/.pi/agent/pi-vetter/cache/`；VirusTotal 哈希查询永久缓存。缓存可整体关闭。

## 注意事项

- 批准安装仍会执行该包的 install 脚本——Pi 安装不带 `--ignore-scripts`；pi-vetter 会警告但无法阻止
- 依赖深扫（`dependencies.*` 配置，默认开启、深度 2 / 上限 20 个包）会下载并静态扫描传递依赖 tarball——每个依赖解析为声明 range 内的最高已发布版本（range 无普通 semver 形状或无匹配版本时回退 `latest`，因此扫描的 tarball 偶尔会与 npm 实际安装的版本不同）；命中以 info 证据逐依赖归属标注，本阶段不影响判定
- 自举供应链：pi-vetter 自身的运行时依赖（`@sigstore/bundle`、`@sigstore/verify`、`tar-stream`）同样是 npm 包，与它所评估的一切存在同样的理论投毒风险——评估器无法把自己举到自身供应链之上。请像审计任何拥有完整权限的工具一样审计它的 lockfile
- 非 npm 源（git/本地路径）不在 MVP 范围内——无参数的 `/vet` 不会评估它们，但会在报告 Notes 中逐条披露被跳过的源

## 开发

```bash
npm install
npm run typecheck && npm test && npm run lint
node --experimental-strip-types scripts/smoke.ts npm:<pkg>   # 真实端到端评估
```

设计文档：[`docs/design.md`](./docs/design.md)（中文）、ADR 见 [`docs/adr/`](./docs/adr/)、调研报告见 [`research/`](./research/)。

## 许可证

MIT
