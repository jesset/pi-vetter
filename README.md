# pi-vetter

Security vetting for [Pi](https://pi.dev) extension packages — an evidence-driven gate before you install or update.

Pi installs extension packages with full user permissions and runs their `postinstall` scripts; the built-in updater only tells you that updates exist. pi-vetter evaluates each candidate version against multiple evidence sources and reports an **ALLOW / ASK / DENY** verdict with the full evidence list, so you decide *what* to install — then installs exactly the versions you approved, pinned so `pi update --extensions` never touches them again.

> pi-vetter can only show that **no risk signal was found** — it can never prove a package is safe. Read the evidence, not just the verdict.

## Install

```bash
pi install git:github.com/jesset/pi-vetter
```

(requires Node ≥ 22.19.0; no API keys needed — all default scanners are free)

## Usage

| Command | What it does |
|---|---|
| `/vet` | Read-only evaluation. No arguments = all installed packages with available updates; or pass specs: `/vet npm:foo npm:bar@1.2.3` |
| `/vet-install` | Same evaluation, then an interactive multi-select (TUI) or grouped confirms (non-TUI) and installs only what you approve |

Approved packages are installed via `pi install npm:<pkg>@<version>` — the pinned spec means Pi's update check skips them afterwards (ADR-0003). Before every install, the registry integrity recorded at scan time is re-checked; a mismatch aborts that install (TOCTOU guard).

### Verdict model

- **ALLOW** — no risk signal found from enabled scanners
- **ASK** — a rule fired (e.g. new lifecycle script, new outbound endpoint, maintainer change) or evidence is incomplete
- **DENY** — hard evidence of malice/contradiction (OpenSSF malicious-package advisory, provenance conflict, VirusTotal detections)

Fail-closed: if any **enabled** scanner fails or times out, the verdict is capped at ASK — never a silent ALLOW (ADR-0002). An earned DENY is never downgraded. Verdicts are rule-driven; the 0–100 risk score is display-only (ADR-0001).

### Scanners (Phase 1)

| Layer | Scanner | Source |
|---|---|---|
| L0 | `metadata` | npm registry packument: maintainers (local snapshot diff), package age, release cadence, deprecation, downloads |
| L1 | `osv` | osv.dev querybatch — covers CVE + GitHub Advisories (GHSA) + OpenSSF malicious packages (MAL-); new dependencies are queried too |
| L1 | `provenance` | npm attestations: source-repo conflict detection (full signature-chain verification planned for Phase 2) |
| L2 | `static` | pattern scan of code files: credential access, obfuscation, prompt-injection markers, eval family; pre-existing hits are info, new hits are findings |
| L2 | `diff` | old-vs-new tarball comparison: new lifecycle scripts, new dependencies, new child_process usage, new outbound endpoints |

Phase 2 (optional, off by default): VirusTotal upload, Socket.dev.

### Rules

Rules map evidence to verdicts and can be toggled individually in the config file (`ask.new-lifecycle-script: false` etc.). Current DENY rules: `malicious-package`, `provenance-conflict`, `vt-detections`. Current ASK rules: `known-vulnerability`, `new-lifecycle-script`, `maintainer-change`, `new-dependency-flagged`, `new-network-endpoint`, `new-child-process`, `credential-access`, `obfuscation`, `prompt-injection-marker`, `young-package`, `rapid-release`, `deprecated-candidate`.

## Configuration

`~/.pi/agent/pi-vetter/config.json` (created with defaults on first run; see [`config.example.json`](./config.example.json)):

```jsonc
{
  "scanners": { "osv": { "enabled": true, "timeoutMs": 10000 }, "virustotal": { "enabled": false, "apiKey": "" } },
  "rules": { "deny": {}, "ask": { "young-package": true } },
  "cache": { "enabled": true, "ttlHours": 24 },
  "score": { "weights": {} }
}
```

Scan results are cached per `scanner + pkg@version` under `~/.pi/agent/pi-vetter/cache/`; VirusTotal hash lookups are cached forever. Caching can be disabled entirely.

## Caveats

- Approving an install still executes the package's install scripts — Pi does not install with `--ignore-scripts`; pi-vetter warns but cannot prevent this.
- pi-vetter scans the package itself, not every transitive dependency tarball (deep scanning is Phase 2).
- Non-npm sources (git/local) are out of scope for MVP.

## 中文说明

**pi-vetter 是什么**：Pi 扩展包的安全评估器。Pi 安装扩展时以完整用户权限运行其代码并执行 install 脚本，内建更新提示只告诉你"有更新"，不告诉你"能不能信"。pi-vetter 在安装/更新之前对候选版本做多路评估（registry 元数据、OSV 漏洞与恶意包通告、npm provenance、静态模式扫描、新旧版本 diff），给出 **ALLOW / ASK / DENY** 判定与完整证据清单，由你选择安装——批准后以精确版本 pin 安装，`pi update --extensions` 从此跳过它。

- `/vet` 只读评估（不带参数 = 检查全部已装扩展的可用更新；也可指定 `npm:包名[@版本]`）
- `/vet-install` 评估后多选安装（TUI 复选；非 TUI 模式自动退化为分组确认）
- fail-closed：任一已启用扫描器未完成 → 判定封顶 ASK，绝不静默放行
- 规则可逐条开关，配置在 `~/.pi/agent/pi-vetter/config.json`
- 安全扫描只能证明"未发现风险"，不能证明"安全"——请阅读证据而非只看判定

## Development

```bash
npm install
npm run typecheck && npm test && npm run lint
node --experimental-strip-types scripts/smoke.ts npm:<pkg>   # real end-to-end vet
```

Design docs: [`docs/design.md`](./docs/design.md), ADRs in [`docs/adr/`](./docs/adr/), research in [`research/`](./research/).

## License

MIT
